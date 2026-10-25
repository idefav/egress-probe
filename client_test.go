package observer_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net"
	"testing"
	"time"

	observer "github.com/idefav/egress-probe"
)

func TestUDPProbeFitsUnfragmentedDatagramsThroughCookieExchange(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	server, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	profile := observer.Profile{ServerID: "mtu-fixture", PublicKey: observer.PublicKey(&key.PublicKey), UDPTarget: server.LocalAddr().String()}
	ticket := observer.Ticket{SessionID: observer.RandomID(), ID: observer.RandomID(), Nonce: observer.RandomID(), Kind: "udp", Expires: time.Now().Add(time.Minute)}
	done := make(chan error, 1)
	go func() {
		server.SetDeadline(time.Now().Add(3 * time.Second))
		for step := 0; step < 2; step++ {
			buf := make([]byte, observer.MaxMessage)
			n, peer, err := server.ReadFrom(buf)
			if err != nil {
				done <- err
				return
			}
			if n > 1232 {
				done <- fmt.Errorf("UDP request needs fragmentation: %d bytes", n)
				return
			}
			var message observer.Message
			if err := json.Unmarshal(buf[:n], &message); err != nil {
				done <- err
				return
			}
			if message.ID != ticket.ID || message.Nonce != ticket.Nonce || len(message.Padding) != 1024 {
				done <- fmt.Errorf("invalid authenticated padded request")
				return
			}
			var reply []byte
			if step == 0 {
				reply, _ = json.Marshal(observer.Message{ID: ticket.ID, Nonce: ticket.Nonce, Cookie: "source-bound-cookie"})
			} else {
				if message.Cookie != "source-bound-cookie" {
					done <- fmt.Errorf("cookie missing")
					return
				}
				receipt, err := observer.Sign(key, observer.Observation{Version: observer.Version, ServerID: profile.ServerID,
					SessionID: ticket.SessionID, ProbeID: ticket.ID, Nonce: ticket.Nonce, Kind: ticket.Kind,
					Protocol: "UDP", PeerIP: "127.0.0.1", PeerPort: peer.(*net.UDPAddr).Port, ObservedAt: time.Now().UTC()})
				if err != nil {
					done <- err
					return
				}
				reply, _ = json.Marshal(receipt)
			}
			if _, err := server.WriteTo(reply, peer); err != nil {
				done <- err
				return
			}
		}
		done <- nil
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err = observer.ProbeUDP(ctx, profile, ticket, func(context.Context, string) (net.PacketConn, net.Addr, error) {
		client, err := net.ListenPacket("udp4", "127.0.0.1:0")
		return client, server.LocalAddr(), err
	})
	if err != nil {
		t.Error(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
