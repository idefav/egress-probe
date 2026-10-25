package server

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	observer "github.com/idefav/egress-probe"
	"golang.org/x/net/dns/dnsmessage"
)

func fixture(t *testing.T) *Server {
	t.Helper()
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	s, e := New(Profile("check.example.net", "203.0.113.10", "test-server"), key, strings.Repeat("k", 64))
	if e != nil {
		t.Fatal(e)
	}
	return s
}
func control(s *Server, method, path, body string, tlsEnabled bool, auth string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "https://api.check.example.net"+path, strings.NewReader(body))
	r.RemoteAddr = "198.51.100.11:54321"
	if tlsEnabled {
		r.TLS = &tls.ConnectionState{}
	} else {
		r.TLS = nil
	}
	r.Header.Set("Authorization", auth)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	return w
}
func issue(t *testing.T, s *Server, kind, query string) observer.Ticket {
	t.Helper()
	auth := "Bearer " + s.apiKey
	r := control(s, "POST", "/v1/sessions", "{}", true, auth)
	if r.Code != 200 {
		t.Fatal(r.Code)
	}
	var sess struct {
		ID string `json:"id"`
	}
	json.Unmarshal(r.Body.Bytes(), &sess)
	b, _ := json.Marshal(map[string]string{"kind": kind, "query": query})
	r = control(s, "POST", "/v1/sessions/"+sess.ID+"/probes", string(b), true, auth)
	if r.Code != 200 {
		t.Fatal(r.Code, r.Body.String())
	}
	var ticket observer.Ticket
	json.Unmarshal(r.Body.Bytes(), &ticket)
	return ticket
}
func TestControlAuthenticationAndLifecycle(t *testing.T) {
	s := fixture(t)
	for _, v := range []struct {
		tls  bool
		auth string
	}{{false, "Bearer " + s.apiKey}, {true, ""}, {true, "Bearer wrong"}} {
		if got := control(s, "POST", "/v1/sessions", "{}", v.tls, v.auth); got.Code != 401 {
			t.Fatal("accepted unauthorized", got.Code)
		}
	}
	ticket := issue(t, s, "tcp", "")
	if _, ok := s.ticket(ticket.ID, "wrong"); ok {
		t.Fatal("accepted wrong nonce")
	}
	r := control(s, "DELETE", "/v1/sessions/"+ticket.SessionID, "", true, "Bearer "+s.apiKey)
	if r.Code != 204 {
		t.Fatal(r.Code)
	}
	if _, ok := s.ticket(ticket.ID, ticket.Nonce); ok {
		t.Fatal("ticket survived deletion")
	}
}
func TestSignedObservationBindingAndTampering(t *testing.T) {
	s := fixture(t)
	ticket := issue(t, s, "tcp", "")
	r, e := s.observe(ticket, "TCP", "198.51.100.11:12345", "203.0.113.10:18080", "", "", "")
	if e != nil {
		t.Fatal(e)
	}
	o, e := observer.Verify(s.Profile, ticket, r)
	if e != nil || o.PeerIP != "198.51.100.11" {
		t.Fatal(o, e)
	}
	bad := ticket
	bad.Nonce = observer.RandomID()
	if _, e = observer.Verify(s.Profile, bad, r); e == nil {
		t.Fatal("cross-probe receipt accepted")
	}
	r.Signature = observer.Encoding.EncodeToString(make([]byte, 64))
	if _, e = observer.Verify(s.Profile, ticket, r); e == nil {
		t.Fatal("tampered receipt accepted")
	}
}
func TestExpiredTicketAndReplayQuota(t *testing.T) {
	s := fixture(t)
	ticket := issue(t, s, "udp", "")
	for i := 0; i < 8; i++ {
		if _, e := s.observe(ticket, "UDP", "198.51.100.1:1234", "local", "", "", ""); e != nil {
			t.Fatal(e)
		}
	}
	if _, e := s.observe(ticket, "UDP", "198.51.100.1:1234", "local", "", "", ""); e == nil {
		t.Fatal("unbounded receipts")
	}
	s.mu.Lock()
	v := s.sessions[ticket.SessionID]
	expired := ticket
	expired.Expires = time.Now().Add(-time.Second)
	v.Tickets[ticket.ID] = expired
	s.mu.Unlock()
	if _, ok := s.ticket(ticket.ID, ticket.Nonce); ok {
		t.Fatal("expired ticket accepted")
	}
}

func TestTCPAndUDPRealSockets(t *testing.T) {
	s := fixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	l, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	s.Profile.TCPTarget = l.Addr().String()
	go s.stream(ctx, l, "tcp")
	ticket := issue(t, s, "tcp", "")
	deadline, stop := context.WithTimeout(ctx, 2*time.Second)
	defer stop()
	receipt, e := observer.ProbeStream(deadline, s.Profile, ticket, func(ctx context.Context, target string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp4", target)
	})
	if e != nil {
		t.Fatal(e)
	}
	o, e := observer.Verify(s.Profile, ticket, receipt)
	if e != nil || o.PeerIP != "127.0.0.1" {
		t.Fatal(o, e)
	}
	u, e := net.ListenPacket("udp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer u.Close()
	s.Profile.UDPTarget = u.LocalAddr().String()
	go s.packets(ctx, u, "udp")
	ticket = issue(t, s, "udp", "")
	receipt, e = observer.ProbeUDP(deadline, s.Profile, ticket, func(ctx context.Context, target string) (net.PacketConn, net.Addr, error) {
		c, e := net.ListenPacket("udp4", "127.0.0.1:0")
		a, _ := net.ResolveUDPAddr("udp4", target)
		return c, a, e
	})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = observer.Verify(s.Profile, ticket, receipt); e != nil {
		t.Fatal(e)
	}
}

func TestHTTPUsesSocketPeerNotForwardedHeaders(t *testing.T) {
	s := fixture(t)
	ticket := issue(t, s, "https", "")
	r := httptest.NewRequest("GET", s.Profile.HTTPSURL, nil)
	r.RemoteAddr = "198.51.100.20:43210"
	r.TLS = &tls.ConnectionState{NegotiatedProtocol: "h2"}
	r.Proto = "HTTP/2.0"
	r.Header.Set("X-Forwarded-For", "203.0.113.99")
	r.Header.Set("X-Probe-ID", ticket.ID)
	r.Header.Set("X-Probe-Nonce", ticket.Nonce)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	receipt, e := observer.ReadReceipt(w.Body)
	if e != nil {
		t.Fatal(e)
	}
	o, e := observer.Verify(s.Profile, ticket, receipt)
	if e != nil || o.PeerIP != "198.51.100.20" {
		t.Fatal(o, e)
	}
}

func TestDNSControlledQueriesAndResolverIdentity(t *testing.T) {
	for _, query := range []string{"A", "AAAA", "NXDOMAIN", "TRUNCATED"} {
		t.Run(query, func(t *testing.T) {
			s := fixture(t)
			ticket := issue(t, s, "dns-system", query)
			typ := dnsmessage.TypeA
			if query == "AAAA" {
				typ = dnsmessage.TypeAAAA
			}
			q := dnsmessage.Question{Name: dnsmessage.MustNewName(ticket.QueryName), Type: typ, Class: dnsmessage.ClassINET}
			req := dnsmessage.Message{Header: dnsmessage.Header{ID: 17, RecursionDesired: true}, Questions: []dnsmessage.Question{q}}
			b, _ := req.Pack()
			var ans dnsmessage.Message
			if e := ans.Unpack(s.dns(b, "192.0.2.53:40000", "local:53", false)); e != nil {
				t.Fatal(e)
			}
			if ans.ID != 17 || len(ans.Questions) != 1 || ans.Questions[0] != q {
				t.Fatal("query not preserved")
			}
			if query == "NXDOMAIN" && ans.RCode != dnsmessage.RCodeNameError {
				t.Fatal("not NXDOMAIN")
			}
			if query == "TRUNCATED" {
				if !ans.Truncated {
					t.Fatal("not truncated")
				}
				if ans.Unpack(s.dns(b, "192.0.2.54:40001", "local:53", true)) != nil || ans.Truncated || len(ans.Answers) == 0 {
					t.Fatal("TCP retry failed")
				}
			} else if query != "NXDOMAIN" && len(ans.Answers) != 1 {
				t.Fatal("missing answer")
			}
			s.mu.Lock()
			rows := append([]observer.Receipt(nil), s.sessions[ticket.SessionID].Receipts[ticket.ID]...)
			s.mu.Unlock()
			o, e := observer.Verify(s.Profile, ticket, rows[0])
			if e != nil || o.PeerIP != "192.0.2.53" || o.Kind != "dns-system" {
				t.Fatal(o, e)
			}
		})
	}
}

func TestDNSRefusesRecursionAndSTUNRequiresTicket(t *testing.T) {
	s := fixture(t)
	q := dnsmessage.Message{Questions: []dnsmessage.Question{{Name: dnsmessage.MustNewName("example.org."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}}}
	b, _ := q.Pack()
	var ans dnsmessage.Message
	if ans.Unpack(s.dns(b, "192.0.2.53:53", "local:53", false)) != nil || ans.RCode != dnsmessage.RCodeRefused {
		t.Fatal("open recursion")
	}
	ticket := issue(t, s, "stun", "")
	transaction := make([]byte, 12)
	rand.Read(transaction)
	wire := observer.STUNRequest(ticket, transaction)
	reply := s.stun(wire, "198.51.100.9:12345", "local:3478")
	if len(reply) != 32 || !bytes.Equal(reply[8:20], transaction) || binary.BigEndian.Uint16(reply[26:])^0x2112 != 12345 {
		t.Fatal("bad STUN reply")
	}
	wire[25] ^= 1
	if len(s.stun(wire, "198.51.100.9:12345", "local:3478")) != 0 {
		t.Fatal("unauthorized STUN accepted")
	}
}

func TestCancellationClosesPendingUDP(t *testing.T) {
	s := fixture(t)
	ticket := issue(t, s, "udp", "")
	p, e := net.ListenPacket("udp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer p.Close()
	s.Profile.UDPTarget = p.LocalAddr().String()
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(20*time.Millisecond, cancel)
	start := time.Now()
	_, e = observer.ProbeUDP(ctx, s.Profile, ticket, func(ctx context.Context, target string) (net.PacketConn, net.Addr, error) {
		c, e := net.ListenPacket("udp4", "127.0.0.1:0")
		a, _ := net.ResolveUDPAddr("udp4", target)
		return c, a, e
	})
	if e == nil || time.Since(start) > time.Second {
		t.Fatal("cancellation did not release socket", e)
	}
}

// Keep imports for fixture readers explicit and test bounded receipt parsing.
func TestReceiptSizeLimit(t *testing.T) {
	if _, e := observer.ReadReceipt(io.LimitReader(strings.NewReader(strings.Repeat("x", observer.MaxMessage+1)), observer.MaxMessage+1)); e == nil {
		t.Fatal("oversize accepted")
	}
	if r := control(fixture(t), http.MethodGet, "/v1/capabilities", "", true, "Bearer wrong"); r.Code != 401 {
		t.Fatal(r.Code)
	}
}

func TestQnameMinimizationDoesNotCutProbeSubtree(t *testing.T) {
	s := fixture(t)
	for _, name := range []string{"q.check.example.net.", "random.q.check.example.net."} {
		q := dnsmessage.Message{Questions: []dnsmessage.Question{{Name: dnsmessage.MustNewName(name), Type: dnsmessage.TypeNS, Class: dnsmessage.ClassINET}}}
		b, _ := q.Pack()
		var ans dnsmessage.Message
		if ans.Unpack(s.dns(b, "192.0.2.53:53", "local:53", false)) != nil || ans.RCode != dnsmessage.RCodeSuccess {
			t.Fatal("minimization received NXDOMAIN cut", name)
		}
	}
}
