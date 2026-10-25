package observer

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"testing"
	"time"
)

func TestOfflineReportRequiresTrustedProfileAndSampleBinding(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	p := Profile{ServerID: "fixture", PublicKey: PublicKey(&key.PublicKey)}
	o := Observation{Version: 1, ServerID: p.ServerID, SessionID: "s", ProbeID: "probe", Nonce: "n", Kind: "udp", Protocol: "UDP", PeerIP: "198.51.100.7", PeerPort: 1234, ObservedAt: time.Now().UTC()}
	receipt, _ := Sign(key, o)
	report := map[string]any{"version": 2, "observer": p, "results": []any{map[string]any{"samples": []any{map[string]any{"id": "probe", "kind": "udp", "receipts": []Receipt{receipt}}}}}}
	b, _ := json.Marshal(report)
	if n, e := VerifyReport(bytes.NewReader(b), p); e != nil || n != 1 {
		t.Fatal(n, e)
	}
	wrong := p
	wrong.ServerID = "other"
	if _, e := VerifyReport(bytes.NewReader(b), wrong); e == nil {
		t.Fatal("untrusted profile accepted")
	}
	receipt.Signature = Encoding.EncodeToString(make([]byte, 64))
	report["results"] = []any{map[string]any{"samples": []any{map[string]any{"id": "probe", "kind": "udp", "receipts": []Receipt{receipt}}}}}
	b, _ = json.Marshal(report)
	if _, e := VerifyReport(bytes.NewReader(b), p); e == nil {
		t.Fatal("invalid signature accepted")
	}
}
