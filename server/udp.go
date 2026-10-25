package server

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"net"
	"strings"

	observer "github.com/idefav/egress-probe"
	"golang.org/x/net/dns/dnsmessage"
)

func (s *Server) packets(ctx context.Context, c net.PacketConn, kind string) error {
	go func() { <-ctx.Done(); c.Close() }()
	buf := make([]byte, observer.MaxMessage+1)
	for {
		n, a, e := c.ReadFrom(buf)
		if e != nil {
			return e
		}
		if n > observer.MaxMessage || !s.allow() {
			continue
		}
		b := append([]byte(nil), buf[:n]...)
		var reply []byte
		switch kind {
		case "udp":
			var m observer.Message
			if json.Unmarshal(b, &m) != nil {
				continue
			}
			t, ok := s.ticket(m.ID, m.Nonce)
			if !ok || t.Kind != "udp" {
				continue
			}
			cookie := s.cookie(a.String(), t)
			if m.Cookie != cookie {
				reply, _ = json.Marshal(observer.Message{ID: t.ID, Nonce: t.Nonce, Cookie: cookie})
			} else {
				receipt, e := s.observe(t, "UDP", a.String(), c.LocalAddr().String(), "", "", "")
				if e == nil {
					reply, _ = json.Marshal(receipt)
				}
			}
			// Address challenge and receipt must not amplify the incoming packet.
			if len(reply) > n {
				continue
			}
		case "stun":
			reply = s.stun(b, a.String(), c.LocalAddr().String())
		case "dns":
			reply = s.dns(b, a.String(), c.LocalAddr().String(), false)
		}
		if len(reply) > 0 {
			c.WriteTo(reply, a)
		}
	}
}

func (s *Server) stun(b []byte, remote, local string) []byte {
	if len(b) < 24 || binary.BigEndian.Uint16(b) != 1 || binary.BigEndian.Uint32(b[4:]) != 0x2112a442 || int(binary.BigEndian.Uint16(b[2:])) != len(b)-20 {
		return nil
	}
	var m observer.Message
	for p := 20; p+4 <= len(b); {
		typ := binary.BigEndian.Uint16(b[p:])
		n := int(binary.BigEndian.Uint16(b[p+2:]))
		p += 4
		if p+n > len(b) {
			return nil
		}
		if typ == 0xc001 {
			if json.Unmarshal(b[p:p+n], &m) != nil {
				return nil
			}
		}
		p += (n + 3) &^ 3
	}
	t, ok := s.ticket(m.ID, m.Nonce)
	if !ok || t.Kind != "stun" {
		return nil
	}
	h, p, e := net.SplitHostPort(remote)
	if e != nil {
		return nil
	}
	a, e := net.ResolveUDPAddr("udp", net.JoinHostPort(h, p))
	if e != nil || a.IP.To4() == nil {
		return nil
	}
	if _, e = s.observe(t, "STUN/UDP", remote, local, "", "", ""); e != nil {
		return nil
	}
	r := make([]byte, 32)
	binary.BigEndian.PutUint16(r, 0x101)
	binary.BigEndian.PutUint16(r[2:], 12)
	copy(r[4:20], b[4:20])
	binary.BigEndian.PutUint16(r[20:], 0x20)
	binary.BigEndian.PutUint16(r[22:], 8)
	r[25] = 1
	binary.BigEndian.PutUint16(r[26:], uint16(a.Port)^0x2112)
	ip := a.IP.To4()
	for i := 0; i < 4; i++ {
		r[28+i] = ip[i] ^ b[4+i]
	}
	return r
}

func (s *Server) dns(b []byte, remote, local string, tcp bool) []byte {
	var req dnsmessage.Message
	if req.Unpack(b) != nil || req.Response || req.OpCode != 0 || len(req.Questions) != 1 {
		return nil
	}
	q := req.Questions[0]
	name := strings.ToLower(q.Name.String())
	zone := s.Profile.Domain + "."
	ans := dnsmessage.Message{Header: dnsmessage.Header{ID: req.ID, Response: true, Authoritative: true, RecursionDesired: req.RecursionDesired}, Questions: req.Questions}
	if q.Class != dnsmessage.ClassINET || !strings.HasSuffix(name, "."+zone) && name != zone {
		ans.RCode = dnsmessage.RCodeRefused
		out, _ := ans.Pack()
		return out
	}
	var ticket *observer.Ticket
	parts := strings.Split(strings.TrimSuffix(name, ".q."+zone), ".")
	if strings.HasSuffix(name, ".q."+zone) && len(parts) == 2 {
		if t, ok := s.ticket(parts[0], parts[1]); ok && strings.HasPrefix(t.Kind, "dns-") {
			ticket = &t
		}
	}
	if ticket != nil {
		t := *ticket
		proto := "DNS/UDP"
		if tcp {
			proto = "DNS/TCP"
		}
		if t.Kind == "dns-tcp" && !tcp {
			return nil
		}
		if t.Kind == "dns-udp" && tcp && t.Query != "TRUNCATED" {
			return nil
		}
		if _, e := s.observe(t, proto, remote, local, name, q.Type.String(), ""); e != nil {
			return nil
		}
		if t.Query == "NXDOMAIN" {
			ans.RCode = dnsmessage.RCodeNameError
		} else if t.Query == "TRUNCATED" && !tcp {
			ans.Truncated = true
		} else {
			addAddress(&ans, q, s.Profile.IPv4)
		}
	} else {
		static := name == zone
		for _, prefix := range []string{"api.", "control.", "http.", "h3.", "tcp.", "tls.", "udp.", "stun.", "ns."} {
			static = static || name == prefix+zone
		}
		// QNAME-minimizing resolvers must not receive an NXDOMAIN cut for
		// intermediate labels of our per-probe names.
		intermediate := name == "q."+zone || strings.HasSuffix(name, ".q."+zone) && len(strings.Split(strings.TrimSuffix(name, ".q."+zone), ".")) == 1
		if static && q.Type == dnsmessage.TypeA {
			addAddress(&ans, q, s.Profile.IPv4)
		} else if name == zone && q.Type == dnsmessage.TypeNS {
			ans.Answers = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeNS, Class: dnsmessage.ClassINET, TTL: 60}, Body: &dnsmessage.NSResource{NS: dnsmessage.MustNewName("ns." + zone)}}}
		} else if !static && !intermediate {
			ans.RCode = dnsmessage.RCodeNameError
		}
	}
	if ans.RCode == dnsmessage.RCodeNameError || len(ans.Answers) == 0 && !ans.Truncated {
		ans.Authorities = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName(zone), Type: dnsmessage.TypeSOA, Class: dnsmessage.ClassINET}, Body: &dnsmessage.SOAResource{NS: dnsmessage.MustNewName("ns." + zone), MBox: dnsmessage.MustNewName("hostmaster." + zone), Serial: 1, Refresh: 60, Retry: 60, Expire: 300, MinTTL: 0}}}
	}
	out, _ := ans.Pack()
	return out
}

func addAddress(ans *dnsmessage.Message, q dnsmessage.Question, ip string) {
	h := dnsmessage.ResourceHeader{Name: q.Name, Type: q.Type, Class: dnsmessage.ClassINET, TTL: 0}
	if q.Type == dnsmessage.TypeA {
		var a [4]byte
		copy(a[:], net.ParseIP(ip).To4())
		ans.Answers = []dnsmessage.Resource{{Header: h, Body: &dnsmessage.AResource{A: a}}}
	}
	if q.Type == dnsmessage.TypeAAAA {
		var a [16]byte
		copy(a[:], net.ParseIP("2001:db8::1").To16())
		ans.Answers = []dnsmessage.Resource{{Header: h, Body: &dnsmessage.AAAAResource{AAAA: a}}}
	}
}
