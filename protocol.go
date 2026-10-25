// Package observer defines the versioned protocol shared by observers and clients.
package observer

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"net"
	"strings"
	"time"
)

const Version = 1
const MaxMessage = 16384

var Encoding = base64.RawURLEncoding

type Profile struct {
	Version    int    `json:"version"`
	ServerID   string `json:"serverId"`
	PublicKey  string `json:"publicKey"` // Base64url SPKI, P-256.
	Domain     string `json:"domain"`
	IPv4       string `json:"ipv4"`
	HTTPSURL   string `json:"httpsUrl"`
	HTTPURL    string `json:"httpUrl"`
	HTTP3URL   string `json:"http3Url"`
	TCPTarget  string `json:"tcpTarget"`
	TLSTarget  string `json:"tlsTarget"`
	UDPTarget  string `json:"udpTarget"`
	STUNTarget string `json:"stunTarget"`
	DNSTarget  string `json:"dnsTarget"`
}

type Ticket struct {
	SessionID string    `json:"sessionId"`
	ID        string    `json:"id"`
	Nonce     string    `json:"nonce"`
	Kind      string    `json:"kind"`
	Query     string    `json:"query"`
	QueryName string    `json:"queryName"`
	Expires   time.Time `json:"expires"`
}

type Observation struct {
	Version       int       `json:"version"`
	ServerID      string    `json:"serverId"`
	SessionID     string    `json:"sessionId"`
	ProbeID       string    `json:"probeId"`
	Nonce         string    `json:"nonce"`
	Kind          string    `json:"kind"`
	Protocol      string    `json:"protocol"`
	PeerIP        string    `json:"peerIp"`
	PeerPort      int       `json:"peerPort"`
	LocalEndpoint string    `json:"localEndpoint"`
	ObservedAt    time.Time `json:"observedAt"`
	Query         string    `json:"query,omitempty"`
	QueryType     string    `json:"queryType,omitempty"`
	ALPN          string    `json:"alpn,omitempty"`
}

// Receipt signs the payload bytes, not a re-serialized JSON representation.
type Receipt struct {
	Payload   string `json:"payload"`
	Signature string `json:"signature"` // IEEE P1363 R || S, 64 bytes.
	KeyID     string `json:"keyId"`
}

type Message struct {
	ID      string `json:"id"`
	Nonce   string `json:"nonce"`
	Cookie  string `json:"cookie,omitempty"`
	Padding string `json:"padding,omitempty"`
}

func RandomID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}
func PublicKey(key *ecdsa.PublicKey) string {
	b, _ := x509.MarshalPKIXPublicKey(key)
	return Encoding.EncodeToString(b)
}
func KeyID(publicKey string) string {
	b, _ := Encoding.DecodeString(publicKey)
	hash := sha256.Sum256(b)
	return hex.EncodeToString(hash[:])
}

func Sign(key *ecdsa.PrivateKey, o Observation) (Receipt, error) {
	b, err := json.Marshal(o)
	if err != nil {
		return Receipt{}, err
	}
	h := sha256.Sum256(b)
	r, s, err := ecdsa.Sign(rand.Reader, key, h[:])
	if err != nil {
		return Receipt{}, err
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return Receipt{Encoding.EncodeToString(b), Encoding.EncodeToString(sig), KeyID(PublicKey(&key.PublicKey))}, nil
}

func Verify(profile Profile, ticket Ticket, receipt Receipt) (Observation, error) {
	var o Observation
	der, err := Encoding.DecodeString(profile.PublicKey)
	if err != nil {
		return o, err
	}
	parsed, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return o, err
	}
	key, ok := parsed.(*ecdsa.PublicKey)
	if !ok || key.Curve != elliptic.P256() {
		return o, errors.New("expected P-256 public key")
	}
	b, err := Encoding.DecodeString(receipt.Payload)
	if err != nil || len(b) > MaxMessage {
		return o, errors.New("invalid signed payload")
	}
	sig, err := Encoding.DecodeString(receipt.Signature)
	if err != nil || len(sig) != 64 {
		return o, errors.New("invalid signature encoding")
	}
	h := sha256.Sum256(b)
	if receipt.KeyID != KeyID(profile.PublicKey) || !ecdsa.Verify(key, h[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
		return o, errors.New("invalid observer signature")
	}
	if err = json.Unmarshal(b, &o); err != nil {
		return o, err
	}
	if o.Version != Version || o.ServerID != profile.ServerID || o.SessionID != ticket.SessionID || o.ProbeID != ticket.ID || o.Nonce != ticket.Nonce || o.Kind != ticket.Kind || net.ParseIP(o.PeerIP) == nil || o.PeerPort < 1 || o.PeerPort > 65535 || o.ObservedAt.After(ticket.Expires) || o.ObservedAt.Before(ticket.Expires.Add(-3*time.Minute)) {
		return o, errors.New("observation does not match this probe")
	}
	return o, nil
}

func DNSName(t Ticket, domain string) string {
	return t.ID + "." + t.Nonce + ".q." + strings.TrimSuffix(domain, ".") + "."
}
