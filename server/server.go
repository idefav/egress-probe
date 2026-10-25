package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	observer "github.com/idefav/egress-probe"
	"github.com/quic-go/quic-go"
)

type Config struct {
	Domain     string `json:"domain"`
	IPv4       string `json:"ipv4"`
	ServerID   string `json:"serverId"`
	APIKey     string `json:"apiKey"`
	PrivateKey string `json:"privateKey"`
	CacheDir   string `json:"cacheDir"`
}

type quicPeerKey struct{}

type session struct {
	Expires  time.Time
	Tickets  map[string]observer.Ticket
	Receipts map[string][]observer.Receipt
}
type Server struct {
	Profile   observer.Profile
	key       *ecdsa.PrivateKey
	apiKey    string
	cookieKey []byte
	mu        sync.Mutex
	sessions  map[string]*session
	issued    map[string]string
	window    time.Time
	requests  int
	slots     chan struct{}
}

func New(profile observer.Profile, key *ecdsa.PrivateKey, apiKey string) (*Server, error) {
	if key == nil || key.Curve != elliptic.P256() {
		return nil, errors.New("require P-256 signing key")
	}
	if len(apiKey) < 32 || net.ParseIP(profile.IPv4).To4() == nil || profile.ServerID == "" || !validDomain(profile.Domain) {
		return nil, errors.New("require API key >=32 characters, IPv4, server ID and DNS domain")
	}
	profile.Version = observer.Version
	profile.PublicKey = observer.PublicKey(&key.PublicKey)
	return &Server{Profile: profile, key: key, apiKey: apiKey, cookieKey: []byte(observer.RandomID() + observer.RandomID()), sessions: map[string]*session{}, issued: map[string]string{}, slots: make(chan struct{}, 32)}, nil
}

func validDomain(s string) bool {
	for _, label := range strings.Split(s, ".") {
		if len(label) == 0 || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false
		}
	}
	if len(s) < 3 || len(s) > 180 || !strings.Contains(s, ".") {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '.' || c == '-') {
			return false
		}
	}
	return !strings.HasSuffix(s, ".")
}

func Profile(domain, ip, id string) observer.Profile {
	return observer.Profile{Version: 1, ServerID: id, Domain: domain, IPv4: ip, HTTPSURL: "https://api." + domain + "/v1/echo", HTTPURL: "http://http." + domain + "/v1/echo", HTTP3URL: "https://h3." + domain + "/v1/echo", TCPTarget: "tcp." + domain + ":18080", TLSTarget: "tls." + domain + ":18443", UDPTarget: "udp." + domain + ":3479", STUNTarget: "stun." + domain + ":3478", DNSTarget: ip + ":53"}
}

func (s *Server) allow() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	if now.Sub(s.window) >= time.Second {
		s.window = now
		s.requests = 0
	}
	s.requests++
	return s.requests <= 200
}

func (s *Server) cleanLocked() {
	now := time.Now()
	for id, v := range s.sessions {
		if now.After(v.Expires.Add(20 * time.Minute)) {
			for probe := range v.Tickets {
				delete(s.issued, probe)
			}
			delete(s.sessions, id)
		}
	}
}

func (s *Server) ticket(id, nonce string) (observer.Ticket, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess := s.sessions[s.issued[id]]
	if sess == nil {
		return observer.Ticket{}, false
	}
	t, ok := sess.Tickets[id]
	return t, ok && time.Now().Before(t.Expires) && time.Now().Before(sess.Expires) && subtle.ConstantTimeCompare([]byte(t.Nonce), []byte(nonce)) == 1
}

func (s *Server) observe(t observer.Ticket, protocol, remote, local, query, qtype, alpn string) (observer.Receipt, error) {
	h, p, e := net.SplitHostPort(remote)
	if e != nil {
		return observer.Receipt{}, e
	}
	var port int
	if _, e = fmt.Sscan(p, &port); e != nil {
		return observer.Receipt{}, e
	}
	o := observer.Observation{Version: 1, ServerID: s.Profile.ServerID, SessionID: t.SessionID, ProbeID: t.ID, Nonce: t.Nonce, Kind: t.Kind, Protocol: protocol, PeerIP: h, PeerPort: port, LocalEndpoint: local, ObservedAt: time.Now().UTC(), Query: query, QueryType: qtype, ALPN: alpn}
	r, e := observer.Sign(s.key, o)
	if e != nil {
		return r, e
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	sess := s.sessions[t.SessionID]
	if sess == nil || time.Now().After(t.Expires) {
		return r, errors.New("expired session")
	}
	if len(sess.Receipts[t.ID]) >= 8 {
		return r, errors.New("probe replay limit")
	}
	sess.Receipts[t.ID] = append(sess.Receipts[t.ID], r)
	return r, nil
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(v)
}

func (s *Server) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.allow() {
			http.Error(w, "rate limit", 429)
			return
		}
		if r.URL.Path == "/v1/echo" {
			s.echo(w, r)
			return
		}
		// Control credentials are never accepted on cleartext HTTP.
		if r.TLS == nil || subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+s.apiKey)) != 1 {
			http.Error(w, "unauthorized", 401)
			return
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		s.cleanLocked()
		if r.URL.Path == "/v1/capabilities" && r.Method == "GET" {
			writeJSON(w, struct {
				Profile   observer.Profile `json:"profile"`
				Protocols []string         `json:"protocols"`
			}{s.Profile, []string{"tcp", "tls", "http", "https", "h3", "udp", "stun", "dns-udp", "dns-tcp", "dns-system"}})
			return
		}
		if r.URL.Path == "/v1/sessions" && r.Method == "POST" {
			active := 0
			for _, v := range s.sessions {
				if time.Now().Before(v.Expires) {
					active++
				}
			}
			if active >= 4 || len(s.sessions) >= 128 {
				http.Error(w, "session quota", 429)
				return
			}
			id := observer.RandomID()
			s.sessions[id] = &session{time.Now().Add(10 * time.Minute), map[string]observer.Ticket{}, map[string][]observer.Receipt{}}
			writeJSON(w, map[string]any{"id": id, "expires": s.sessions[id].Expires})
			return
		}
		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		if len(parts) < 3 || parts[0] != "v1" || parts[1] != "sessions" {
			http.NotFound(w, r)
			return
		}
		sess := s.sessions[parts[2]]
		if sess == nil {
			http.NotFound(w, r)
			return
		}
		if len(parts) == 3 && r.Method == "DELETE" {
			for id := range sess.Tickets {
				delete(s.issued, id)
			}
			delete(s.sessions, parts[2])
			w.WriteHeader(204)
			return
		}
		if len(parts) == 4 && parts[3] == "probes" && r.Method == "POST" {
			if time.Now().After(sess.Expires) || len(sess.Tickets) >= 512 {
				http.Error(w, "probe quota or session expired", 429)
				return
			}
			var in struct {
				Kind  string `json:"kind"`
				Query string `json:"query"`
			}
			if json.NewDecoder(io.LimitReader(r.Body, 1024)).Decode(&in) != nil {
				http.Error(w, "invalid request", 400)
				return
			}
			switch in.Kind {
			case "tcp", "tls", "http", "https", "h3", "udp", "stun", "dns-udp", "dns-tcp", "dns-system":
			default:
				http.Error(w, "unsupported kind", 400)
				return
			}
			if strings.HasPrefix(in.Kind, "dns-") && in.Query != "A" && in.Query != "AAAA" && in.Query != "NXDOMAIN" && in.Query != "TRUNCATED" {
				http.Error(w, "unsupported DNS query", 400)
				return
			}
			t := observer.Ticket{SessionID: parts[2], ID: observer.RandomID(), Nonce: observer.RandomID(), Kind: in.Kind, Query: in.Query, Expires: time.Now().UTC().Add(3 * time.Minute)}
			t.QueryName = observer.DNSName(t, s.Profile.Domain)
			sess.Tickets[t.ID] = t
			s.issued[t.ID] = parts[2]
			writeJSON(w, t)
			return
		}
		if len(parts) == 4 && parts[3] == "observations" && r.Method == "GET" {
			id := r.URL.Query().Get("probeId")
			if _, ok := sess.Tickets[id]; !ok {
				http.NotFound(w, r)
				return
			}
			rows := sess.Receipts[id]
			if rows == nil {
				rows = []observer.Receipt{}
			}
			writeJSON(w, rows)
			return
		}
		http.NotFound(w, r)
	})
}

func (s *Server) echo(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "method", 405)
		return
	}
	t, ok := s.ticket(r.Header.Get("X-Probe-ID"), r.Header.Get("X-Probe-Nonce"))
	if !ok {
		http.Error(w, "invalid probe", 403)
		return
	}
	kind := "http"
	alpn := ""
	if r.TLS != nil {
		kind = "https"
		alpn = r.TLS.NegotiatedProtocol
	}
	if r.ProtoMajor == 3 {
		kind = "h3"
	}
	if t.Kind != kind {
		http.Error(w, "protocol mismatch", 400)
		return
	}
	local := ""
	if a, ok := r.Context().Value(http.LocalAddrContextKey).(net.Addr); ok {
		local = a.String()
	}
	remote := r.RemoteAddr
	if connection, ok := r.Context().Value(quicPeerKey{}).(*quic.Conn); ok {
		remote = connection.RemoteAddr().String()
		local = connection.LocalAddr().String()
	}
	receipt, e := s.observe(t, r.Proto, remote, local, "", "", alpn)
	if e != nil {
		http.Error(w, "probe unavailable", 409)
		return
	}
	writeJSON(w, receipt)
}

func (s *Server) stream(ctx context.Context, l net.Listener, kind string) error {
	go func() { <-ctx.Done(); l.Close() }()
	for {
		c, e := l.Accept()
		if e != nil {
			return e
		}
		select {
		case s.slots <- struct{}{}:
		default:
			c.Close()
			continue
		}
		go func() {
			defer func() { <-s.slots }()
			defer c.Close()
			c.SetDeadline(time.Now().Add(10 * time.Second))
			if !s.allow() {
				return
			}
			var m observer.Message
			if json.NewDecoder(io.LimitReader(c, 2048)).Decode(&m) != nil {
				return
			}
			t, ok := s.ticket(m.ID, m.Nonce)
			if !ok || t.Kind != kind {
				return
			}
			receipt, e := s.observe(t, strings.ToUpper(kind), c.RemoteAddr().String(), c.LocalAddr().String(), "", "", "")
			if e == nil {
				json.NewEncoder(c).Encode(receipt)
			}
		}()
	}
}

func (s *Server) cookie(addr string, t observer.Ticket) string {
	mac := hmac.New(sha256.New, s.cookieKey)
	fmt.Fprintf(mac, "%s|%s|%s", addr, t.ID, t.Nonce)
	return observer.Encoding.EncodeToString(mac.Sum(nil))
}
