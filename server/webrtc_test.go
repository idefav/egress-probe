package server

import (
	"encoding/json"
	"io"
	"net"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	observer "github.com/idefav/egress-probe"
	"github.com/pion/webrtc/v4"
)

type rtcRevokingBody struct {
	io.Reader
	revoke func()
}

func (b *rtcRevokingBody) Read(p []byte) (int, error) {
	if b.revoke != nil {
		b.revoke()
		b.revoke = nil
	}
	return b.Reader.Read(p)
}

func TestWebRTCReportCannotRecreateRevokedEntry(t *testing.T) {
	s := fixture(t)
	s.rtc.api = webrtc.NewAPI()
	s.rtc.entries = make(map[string]*rtcEntry)
	ticket := issue(t, s, "webrtc", "")
	id := s.sessions[ticket.SessionID].DeviceID
	body := &rtcRevokingBody{Reader: strings.NewReader(`{"state":"failed"}`), revoke: func() {
		if err := s.Auth.Revoke("devices", id); err != nil {
			t.Fatal(err)
		}
		s.cancelDevice(id)
	}}
	r := httptest.NewRequest("POST", "https://api.check.example.net/v1/webrtc/"+ticket.ID+"/complete", body)
	r.Header.Set("Authorization", "Probe "+ticket.Nonce)
	r.Header.Set("Origin", "https://api.check.example.net")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != 403 || len(s.rtc.entries) != 0 {
		t.Fatalf("revoked report recreated state: status=%d entries=%d", w.Code, len(s.rtc.entries))
	}
}

func TestObservationRejectsExpiredSessionWithUnexpiredTicket(t *testing.T) {
	s := fixture(t)
	ticket := issue(t, s, "udp", "")
	sess := s.sessions[ticket.SessionID]
	sess.Expires = time.Now().Add(-time.Second)
	if _, err := s.observe(ticket, "UDP", "203.0.113.1:1234", "203.0.113.2:3479", "", "", ""); err == nil {
		t.Fatal("accepted observation after session expiry")
	}
	if len(sess.Receipts[ticket.ID]) != 0 {
		t.Fatal("stored expired observation")
	}
}

func rtcRequest(s *Server, ticket observer.Ticket, action string, body any, origin string) *httptest.ResponseRecorder {
	b, _ := json.Marshal(body)
	r := httptest.NewRequest("POST", "https://api.check.example.net/v1/webrtc/"+ticket.ID+"/"+action, strings.NewReader(string(b)))
	r.Header.Set("Authorization", "Probe "+ticket.Nonce)
	r.Header.Set("Origin", origin)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	return w
}

func TestWebRTCDataChannelAndAuthentication(t *testing.T) {
	s := fixture(t)
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s.rtc.start(conn, "127.0.0.1", true)
	defer s.rtc.close()
	ticket := issue(t, s, "webrtc", "")
	const origin = "https://api.check.example.net"
	if w := rtcRequest(s, ticket, "offer", nil, "https://evil.example"); w.Code != 403 {
		t.Fatal("origin", w.Code)
	}
	wrong := ticket
	wrong.Nonce = "wrong"
	if w := rtcRequest(s, wrong, "offer", nil, origin); w.Code != 403 {
		t.Fatal("nonce", w.Code)
	}
	if w := rtcRequest(s, ticket, "complete", rtcStatus{State: "complete"}, origin); w.Code != 409 {
		t.Fatal("accepted fabricated success", w.Code)
	}
	if w := rtcRequest(s, ticket, "offer", webrtc.SessionDescription{Type: webrtc.SDPTypeOffer, SDP: "garbage"}, origin); w.Code != 400 {
		t.Fatal("malformed SDP", w.Code)
	}
	settings := webrtc.SettingEngine{}
	settings.SetNetworkTypes([]webrtc.NetworkType{webrtc.NetworkTypeUDP4})
	settings.SetIncludeLoopbackCandidate(true)
	pc, err := webrtc.NewAPI(webrtc.WithSettingEngine(settings)).NewPeerConnection(webrtc.Configuration{})
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	dc, err := pc.CreateDataChannel("egress-probe", nil)
	if err != nil {
		t.Fatal(err)
	}
	received := make(chan observer.Receipt, 1)
	dc.OnOpen(func() {
		b, _ := json.Marshal(observer.Message{ID: ticket.ID, Nonce: ticket.Nonce})
		_ = dc.SendText(string(b))
	})
	dc.OnMessage(func(msg webrtc.DataChannelMessage) {
		var receipt observer.Receipt
		if json.Unmarshal(msg.Data, &receipt) == nil {
			select {
			case received <- receipt:
			default:
			}
		}
	})
	offer, err := pc.CreateOffer(nil)
	if err != nil {
		t.Fatal(err)
	}
	gather := webrtc.GatheringCompletePromise(pc)
	if err = pc.SetLocalDescription(offer); err != nil {
		t.Fatal(err)
	}
	select {
	case <-gather:
	case <-time.After(10 * time.Second):
		t.Fatal("client gathering timeout")
	}
	w := rtcRequest(s, ticket, "offer", pc.LocalDescription(), origin)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	var answer webrtc.SessionDescription
	if err := json.Unmarshal(w.Body.Bytes(), &answer); err != nil {
		t.Fatal(err)
	}
	if err := pc.SetRemoteDescription(answer); err != nil {
		t.Fatal(err)
	}
	select {
	case receipt := <-received:
		observation, err := observer.Verify(s.Profile, ticket, receipt)
		if err != nil || observation.Protocol != "WebRTC/DTLS/SCTP" || net.ParseIP(observation.PeerIP) == nil {
			t.Fatal(observation, err)
		}
		if s.rtc.status(ticket.ID).State == "complete" {
			t.Fatal("one-way receipt was treated as bidirectional")
		}
		bad := receipt
		bad.Signature = "bad"
		if w := rtcRequest(s, ticket, "complete", rtcStatus{State: "complete", Receipt: &bad}, origin); w.Code != 409 {
			t.Fatal("accepted wrong receipt", w.Code)
		}
		w = rtcRequest(s, ticket, "complete", rtcStatus{State: "complete", Receipt: &receipt, Candidates: []string{"host udp masked.local:1234"}, Browser: "fixture"}, origin)
		if w.Code != 204 || s.rtc.status(ticket.ID).State != "complete" {
			t.Fatal(w.Code, w.Body.String())
		}
	case <-time.After(15 * time.Second):
		t.Fatal("data channel timeout")
	}
	if w := rtcRequest(s, ticket, "offer", pc.LocalDescription(), origin); w.Code != 409 {
		t.Fatal("reused ticket", w.Code)
	}
	w = control(s, "DELETE", "/v1/sessions/"+ticket.SessionID, "", true, "Bearer "+s.apiKey)
	if w.Code != 204 || s.rtc.status(ticket.ID).State != "pending" {
		t.Fatal("session did not clean up")
	}
}
