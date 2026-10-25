package server

import (
	"crypto/subtle"
	_ "embed"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	observer "github.com/idefav/egress-probe"
	"github.com/pion/webrtc/v4"
)

//go:embed webrtc.html
var rtcHTML string

//go:embed webrtc.js
var rtcJS string

type rtcStatus struct {
	State      string            `json:"state"`
	Candidates []string          `json:"candidates"`
	Browser    string            `json:"browser"`
	Error      string            `json:"error,omitempty"`
	Elapsed    float64           `json:"elapsed"`
	Receipt    *observer.Receipt `json:"receipt,omitempty"`
}

type rtcEntry struct {
	pc     *webrtc.PeerConnection
	status rtcStatus
}

type rtcService struct {
	mu      sync.Mutex
	api     *webrtc.API
	mux     io.Closer
	entries map[string]*rtcEntry
}

func (v *rtcService) start(conn net.PacketConn, publicIP string, loopback bool) {
	settings := webrtc.SettingEngine{}
	settings.SetNetworkTypes([]webrtc.NetworkType{webrtc.NetworkTypeUDP4})
	settings.SetLite(true)
	settings.SetSCTPMaxMessageSize(16384)
	settings.SetSCTPMaxReceiveBufferSize(65536)
	settings.SetICETimeouts(10*time.Second, 20*time.Second, 2*time.Second)
	settings.SetNAT1To1IPs([]string{publicIP}, webrtc.ICECandidateTypeHost)
	settings.SetIncludeLoopbackCandidate(loopback)
	settings.SetRemoteIPFilter(func(ip net.IP) bool {
		return loopback || ip.IsGlobalUnicast() && !ip.IsPrivate() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast()
	})
	mux := webrtc.NewICEUDPMux(nil, conn)
	settings.SetICEUDPMux(mux)
	v.mu.Lock()
	defer v.mu.Unlock()
	v.api = webrtc.NewAPI(webrtc.WithSettingEngine(settings))
	v.mux = mux
	v.entries = make(map[string]*rtcEntry)
}

// Close outside the locks: Pion callbacks may acquire the observation lock.
func (v *rtcService) remove(id string) {
	v.mu.Lock()
	e := v.entries[id]
	delete(v.entries, id)
	v.mu.Unlock()
	if e != nil && e.pc != nil {
		go e.pc.Close()
	}
}

func (v *rtcService) close() {
	v.mu.Lock()
	entries, mux := v.entries, v.mux
	v.entries = nil
	v.api = nil
	v.mu.Unlock()
	for _, e := range entries {
		if e.pc != nil {
			_ = e.pc.Close()
		}
	}
	if mux != nil {
		_ = mux.Close()
	}
}

func (v *rtcService) status(id string) rtcStatus {
	v.mu.Lock()
	defer v.mu.Unlock()
	if e := v.entries[id]; e != nil {
		return e.status
	}
	return rtcStatus{State: "pending", Candidates: []string{}}
}

func (s *Server) webRTC(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; connect-src 'self'; style-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'")
	if r.TLS == nil {
		http.Error(w, "HTTPS required", 400)
		return
	}
	if r.Method == "GET" && r.URL.Path == "/webrtc" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = io.WriteString(w, rtcHTML)
		return
	}
	if r.Method == "GET" && r.URL.Path == "/webrtc.js" {
		w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
		_, _ = io.WriteString(w, rtcJS)
		return
	}
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) != 4 || parts[0] != "v1" || parts[1] != "webrtc" || r.Method != "POST" {
		http.NotFound(w, r)
		return
	}
	// Only the same-origin browser page may exchange short-lived probe tickets.
	if r.Header.Get("Origin") != "https://"+r.Host {
		http.Error(w, "origin rejected", 403)
		return
	}
	if !strings.HasPrefix(r.Header.Get("Authorization"), "Probe ") {
		http.Error(w, "invalid authentication scheme", 403)
		return
	}
	t, ok := s.ticket(parts[2], strings.TrimPrefix(r.Header.Get("Authorization"), "Probe "))
	if !ok || t.Kind != "webrtc" {
		http.Error(w, "invalid ticket", 403)
		return
	}
	if parts[3] == "offer" {
		s.rtcOffer(w, r, t)
		return
	}
	if parts[3] != "complete" {
		http.NotFound(w, r)
		return
	}
	var in rtcStatus
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 16384)).Decode(&in) != nil || len(in.Candidates) > 64 || len(in.Browser) > 256 || len(in.Error) > 512 || in.Elapsed < 0 || in.Elapsed > 180000 {
		http.Error(w, "invalid report", 400)
		return
	}
	for _, c := range in.Candidates {
		if len(c) > 256 {
			http.Error(w, "candidate too long", 400)
			return
		}
	}
	if in.State != "complete" && in.State != "failed" && in.State != "unsupported" {
		http.Error(w, "invalid state", 400)
		return
	}
	// Reading the body may outlive ticket expiry or device/session revocation.
	// Use the same lock order as cancellation, and do not recreate removed entries.
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, valid := s.ticketLocked(t.ID, t.Nonce); !valid {
		http.Error(w, "expired or revoked ticket", 403)
		return
	}
	s.rtc.mu.Lock()
	defer s.rtc.mu.Unlock()
	e := s.rtc.entries[t.ID]
	if in.State == "complete" {
		// Exact receipt echo proves that the browser received our DataChannel response.
		if e == nil || e.status.Receipt == nil || in.Receipt == nil || *in.Receipt != *e.status.Receipt {
			http.Error(w, "data channel receipt required", 409)
			return
		}
	} else if e == nil {
		if s.rtc.api == nil || len(s.rtc.entries) >= 128 {
			http.Error(w, "quota or unavailable", 429)
			return
		}
		e = &rtcEntry{}
		s.rtc.entries[t.ID] = e
		time.AfterFunc(time.Until(t.Expires), func() { s.rtc.remove(t.ID) })
	}
	if e.status.State == "complete" {
		w.WriteHeader(204)
		return
	}
	// Candidate strings and browser identification are browser claims, not signed observations.
	e.status.State, e.status.Candidates, e.status.Browser = in.State, append([]string{}, in.Candidates...), in.Browser
	e.status.Error, e.status.Elapsed = in.Error, in.Elapsed
	if e.pc != nil {
		go e.pc.Close()
	}
	w.WriteHeader(204)
}

func (s *Server) rtcOffer(w http.ResponseWriter, r *http.Request, t observer.Ticket) {
	var offer webrtc.SessionDescription
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 65536)).Decode(&offer) != nil || offer.Type != webrtc.SDPTypeOffer {
		http.Error(w, "invalid offer", 400)
		return
	}
	s.rtc.mu.Lock()
	active := 0
	for _, e := range s.rtc.entries {
		if e.status.State == "connecting" {
			active++
		}
	}
	if s.rtc.api == nil || len(s.rtc.entries) >= 128 || active >= 4 || s.rtc.entries[t.ID] != nil {
		s.rtc.mu.Unlock()
		http.Error(w, "unavailable, quota or reused ticket", 409)
		return
	}
	pc, err := s.rtc.api.NewPeerConnection(webrtc.Configuration{})
	if err != nil {
		s.rtc.mu.Unlock()
		http.Error(w, "peer unavailable", 503)
		return
	}
	e := &rtcEntry{pc: pc, status: rtcStatus{State: "connecting", Candidates: []string{}}}
	s.rtc.entries[t.ID] = e
	s.rtc.mu.Unlock()
	// Revocation can race the initial ticket lookup before this peer is registered.
	if _, valid := s.ticket(t.ID, t.Nonce); !valid {
		s.rtc.remove(t.ID)
		http.Error(w, "expired or revoked ticket", 403)
		return
	}
	time.AfterFunc(time.Until(t.Expires), func() { s.rtc.remove(t.ID) })
	success := false
	defer func() {
		if !success {
			s.rtc.remove(t.ID)
		}
	}()
	var once sync.Once
	pc.OnDataChannel(func(dc *webrtc.DataChannel) {
		if dc.Label() != "egress-probe" {
			_ = dc.Close()
			return
		}
		dc.OnMessage(func(msg webrtc.DataChannelMessage) {
			if !msg.IsString || len(msg.Data) > 256 {
				return
			}
			var proof struct {
				ID    string `json:"id"`
				Nonce string `json:"nonce"`
			}
			if json.Unmarshal(msg.Data, &proof) != nil || proof.ID != t.ID || subtle.ConstantTimeCompare([]byte(proof.Nonce), []byte(t.Nonce)) != 1 {
				return
			}
			once.Do(func() {
				pair, err := pc.SCTP().Transport().ICETransport().GetSelectedCandidatePair()
				if err != nil || pair == nil {
					return
				}
				receipt, err := s.observe(t, "WebRTC/DTLS/SCTP", net.JoinHostPort(pair.Remote.Address, strconv.Itoa(int(pair.Remote.Port))), net.JoinHostPort(pair.Local.Address, strconv.Itoa(int(pair.Local.Port))), "", "", "")
				if err != nil {
					return
				}
				s.rtc.mu.Lock()
				if s.rtc.entries[t.ID] == e {
					e.status.Receipt = &receipt
				}
				s.rtc.mu.Unlock()
				b, _ := json.Marshal(receipt)
				_ = dc.SendText(string(b))
			})
		})
	})
	if err := pc.SetRemoteDescription(offer); err != nil {
		http.Error(w, "invalid SDP: "+safeSDPError(err, offer.SDP), 400)
		return
	}
	answer, err := pc.CreateAnswer(nil)
	if err != nil {
		http.Error(w, "answer failed", 400)
		return
	}
	gather := webrtc.GatheringCompletePromise(pc)
	if pc.SetLocalDescription(answer) != nil {
		http.Error(w, "gather failed", 500)
		return
	}
	select {
	case <-gather:
	case <-r.Context().Done():
		return
	case <-time.After(5 * time.Second):
		http.Error(w, "gather timeout", 504)
		return
	}
	success = true
	writeJSON(w, pc.LocalDescription())
}

// Useful browser compatibility diagnostics without copying ICE credentials or SDP.
func safeSDPError(err error, sdp string) string {
	message := strings.ReplaceAll(err.Error(), sdp, "[SDP]")
	for _, line := range strings.Split(sdp, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "a=ice-pwd:") || strings.HasPrefix(line, "a=ice-ufrag:") {
			_, value, _ := strings.Cut(line, ":")
			if value != "" {
				message = strings.ReplaceAll(message, value, "[redacted]")
			}
		}
	}
	if len(message) > 256 {
		message = message[:256]
	}
	return message
}
