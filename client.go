package observer

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

type DialStream func(context.Context, string) (net.Conn, error)
type DialPacket func(context.Context, string) (net.PacketConn, net.Addr, error)

func ReadReceipt(r io.Reader) (Receipt, error) {
	var receipt Receipt
	b, err := io.ReadAll(io.LimitReader(r, MaxMessage+1))
	if err != nil {
		return receipt, err
	}
	if len(b) > MaxMessage {
		return receipt, errors.New("observer response exceeds limit")
	}
	err = json.Unmarshal(b, &receipt)
	return receipt, err
}

func ProbeStream(ctx context.Context, profile Profile, ticket Ticket, dial DialStream) (Receipt, error) {
	target := profile.TCPTarget
	if ticket.Kind == "tls" {
		target = profile.TLSTarget
	}
	c, err := dial(ctx, target)
	if err != nil {
		return Receipt{}, err
	}
	defer c.Close()
	stop := context.AfterFunc(ctx, func() { c.Close() })
	defer stop()
	deadline, _ := ctx.Deadline()
	c.SetDeadline(deadline)
	var stream net.Conn = c
	if ticket.Kind == "tls" {
		host, _, _ := net.SplitHostPort(target)
		t := tls.Client(c, &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12})
		if err = t.HandshakeContext(ctx); err != nil {
			return Receipt{}, err
		}
		stream = t
	}
	if err = json.NewEncoder(stream).Encode(Message{ID: ticket.ID, Nonce: ticket.Nonce}); err != nil {
		return Receipt{}, err
	}
	receipt, err := ReadReceipt(stream)
	if err == nil {
		_, err = Verify(profile, ticket, receipt)
	}
	return receipt, err
}

func ProbeUDP(ctx context.Context, profile Profile, ticket Ticket, dial DialPacket) (Receipt, error) {
	c, addr, err := dial(ctx, profile.UDPTarget)
	if err != nil {
		return Receipt{}, err
	}
	defer c.Close()
	stop := context.AfterFunc(ctx, func() { c.Close() })
	defer stop()
	deadline, _ := ctx.Deadline()
	c.SetDeadline(deadline)
	// JSON escapes NUL bytes as six-byte sequences. Printable padding keeps
	// the authenticated request below the IPv6 minimum MTU after IP/UDP headers.
	m := Message{ID: ticket.ID, Nonce: ticket.Nonce, Padding: strings.Repeat("x", 1024)}
	for attempt := 0; attempt < 2; attempt++ {
		b, _ := json.Marshal(m)
		if _, err = c.WriteTo(b, addr); err != nil {
			return Receipt{}, err
		}
		buf := make([]byte, MaxMessage+1)
		for {
			n, from, e := c.ReadFrom(buf)
			if e != nil {
				return Receipt{}, e
			}
			if from.String() != addr.String() {
				continue
			}
			if n > MaxMessage {
				return Receipt{}, errors.New("oversized UDP response")
			}
			if attempt == 0 {
				var challenge Message
				if json.Unmarshal(buf[:n], &challenge) != nil || challenge.ID != ticket.ID || challenge.Nonce != ticket.Nonce || challenge.Cookie == "" {
					return Receipt{}, errors.New("invalid UDP challenge")
				}
				m.Cookie = challenge.Cookie
				break
			}
			var receipt Receipt
			if err = json.Unmarshal(buf[:n], &receipt); err == nil {
				_, err = Verify(profile, ticket, receipt)
			}
			return receipt, err
		}
	}
	return Receipt{}, errors.New("UDP challenge incomplete")
}

// STUNRequest uses a private, short-lived authenticated ticket attribute. It is
// deliberately separate from a public unauthenticated STUN service.
func STUNRequest(t Ticket, transaction []byte) []byte {
	b := make([]byte, 20)
	binary.BigEndian.PutUint16(b, 1)
	binary.BigEndian.PutUint32(b[4:], 0x2112a442)
	copy(b[8:], transaction)
	value, _ := json.Marshal(Message{ID: t.ID, Nonce: t.Nonce})
	b = binary.BigEndian.AppendUint16(b, 0xc001)
	b = binary.BigEndian.AppendUint16(b, uint16(len(value)))
	b = append(b, value...)
	for len(b)%4 != 0 {
		b = append(b, 0)
	}
	binary.BigEndian.PutUint16(b[2:], uint16(len(b)-20))
	return b
}

func HTTPRequest(ctx context.Context, target string, ticket Ticket) (*http.Request, error) {
	r, err := http.NewRequestWithContext(ctx, "GET", target, nil)
	if err != nil {
		return nil, err
	}
	r.Header.Set("X-Probe-ID", ticket.ID)
	r.Header.Set("X-Probe-Nonce", ticket.Nonce)
	return r, nil
}

func DefaultDeadline(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, 5*time.Second)
}
