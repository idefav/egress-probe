package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	observer "github.com/idefav/egress-probe"
)

// Control credentials are deliberately separate from the observation signing key.
type PairingCode struct {
	Version       int       `json:"version"`
	Domain        string    `json:"domain"`
	ServerID      string    `json:"serverId"`
	ID            string    `json:"id"`
	Secret        string    `json:"secret"`
	CAFingerprint string    `json:"caFingerprint"`
	Expires       time.Time `json:"expires"`
}
type pairingRecord struct {
	ID          string    `json:"id"`
	Hash        string    `json:"hash"`
	Expires     time.Time `json:"expires"`
	Revoked     bool      `json:"revoked"`
	CSRHash     string    `json:"csrHash,omitempty"`
	DeviceID    string    `json:"deviceId,omitempty"`
	Certificate string    `json:"certificate,omitempty"`
}
type deviceCertificate struct {
	PEM         string    `json:"pem"`
	AcceptUntil time.Time `json:"acceptUntil"`
	CSRHash     string    `json:"csrHash"`
}
type Device struct {
	ID           string                       `json:"id"`
	Name         string                       `json:"name"`
	Created      time.Time                    `json:"created"`
	Revoked      bool                         `json:"revoked"`
	Certificates map[string]deviceCertificate `json:"certificates"`
}
type authState struct {
	Version      int                      `json:"version"`
	Domain       string                   `json:"domain"`
	ServerID     string                   `json:"serverId"`
	CAPEM        string                   `json:"caPem"`
	CAKeyPEM     string                   `json:"caKeyPem"`
	ServerPEM    string                   `json:"serverPem"`
	ServerKeyPEM string                   `json:"serverKeyPem"`
	Pairings     map[string]pairingRecord `json:"pairings"`
	Devices      map[string]Device        `json:"devices"`
}
type rateWindow struct {
	Started time.Time
	Count   int
}
type Auth struct {
	mu    sync.Mutex
	path  string
	state authState
	ca    *x509.Certificate
	key   *ecdsa.PrivateKey
	rates map[string]rateWindow
}
type Enrollment struct {
	DeviceID    string           `json:"deviceId"`
	Certificate string           `json:"certificate"`
	CAPEM       string           `json:"caPem"`
	Profile     observer.Profile `json:"profile"`
	ControlURL  string           `json:"controlUrl"`
}

var errUnauthorized = errors.New("invalid, expired or revoked device/pairing")

func hashText(value string) string {
	h := sha256.Sum256([]byte(value))
	return hex.EncodeToString(h[:])
}
func caFingerprint(cert *x509.Certificate) string {
	h := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return hex.EncodeToString(h[:])
}
func keyPEM(key *ecdsa.PrivateKey) string {
	b, _ := x509.MarshalPKCS8PrivateKey(key)
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: b}))
}
func parseCert(value string) (*x509.Certificate, error) {
	b, _ := pem.Decode([]byte(value))
	if b == nil {
		return nil, errors.New("missing certificate")
	}
	return x509.ParseCertificate(b.Bytes)
}
func serial() *big.Int {
	n, e := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if e != nil {
		panic(e)
	}
	return n
}

func OpenAuth(dir string, profile observer.Profile) (*Auth, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	a := &Auth{path: filepath.Join(dir, "device-auth.json"), rates: map[string]rateWindow{}}
	b, err := os.ReadFile(a.path)
	if errors.Is(err, os.ErrNotExist) {
		key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if e != nil {
			return nil, e
		}
		now := time.Now().UTC()
		template := &x509.Certificate{SerialNumber: serial(), Subject: pkix.Name{CommonName: "egress-probe control CA " + profile.ServerID}, NotBefore: now.Add(-5 * time.Minute), NotAfter: now.AddDate(5, 0, 0), IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
		der, e := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
		if e != nil {
			return nil, e
		}
		a.state = authState{Version: 2, Domain: profile.Domain, ServerID: profile.ServerID, CAPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), CAKeyPEM: keyPEM(key), Pairings: map[string]pairingRecord{}, Devices: map[string]Device{}}
	} else if err != nil {
		return nil, err
	} else if json.Unmarshal(b, &a.state) != nil {
		return nil, errors.New("invalid device authentication state; refusing to regenerate")
	}
	if a.state.Version != 2 || a.state.Domain != profile.Domain || a.state.ServerID != profile.ServerID || a.state.Pairings == nil || a.state.Devices == nil {
		return nil, errors.New("authentication identity changed; explicit migration required")
	}
	a.ca, err = parseCert(a.state.CAPEM)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode([]byte(a.state.CAKeyPEM))
	if block == nil {
		return nil, errors.New("missing CA private key")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	var ok bool
	a.key, ok = key.(*ecdsa.PrivateKey)
	if !ok || a.key.Curve != elliptic.P256() || !a.key.PublicKey.Equal(a.ca.PublicKey) || !a.ca.IsCA || a.ca.CheckSignatureFrom(a.ca) != nil {
		return nil, errors.New("invalid control CA")
	}
	if err := a.refreshServerLocked(); err != nil {
		return nil, err
	}
	return a, nil
}

// A failed persistence operation restores the in-memory transaction as well.
func (a *Auth) transaction(change func() error) error {
	before, _ := json.Marshal(a.state)
	if err := change(); err != nil {
		a.state = authState{}
		_ = json.Unmarshal(before, &a.state)
		return err
	}
	if err := a.saveLocked(); err != nil {
		// Rename may already have committed before a directory fsync failed.
		if committed, readErr := os.ReadFile(a.path); readErr == nil {
			before = committed
		}
		a.state = authState{}
		_ = json.Unmarshal(before, &a.state)
		return err
	}
	return nil
}
func (a *Auth) saveLocked() error {
	b, err := json.Marshal(a.state)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(a.path), ".auth-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(b)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err = os.Rename(f.Name(), a.path); err != nil {
		return err
	}
	d, err := os.Open(filepath.Dir(a.path))
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
func (a *Auth) signCSR(csr *x509.CertificateRequest, id string, server bool) (string, *x509.Certificate, error) {
	now := time.Now().UTC()
	expires := now.Add(90 * 24 * time.Hour)
	if expires.After(a.ca.NotAfter) {
		expires = a.ca.NotAfter
	}
	if !expires.After(now) {
		return "", nil, errors.New("control CA expired; re-pair with a new CA")
	}
	t := &x509.Certificate{SerialNumber: serial(), Subject: pkix.Name{CommonName: id}, NotBefore: now.Add(-5 * time.Minute), NotAfter: expires, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, BasicConstraintsValid: true}
	if server {
		t.DNSNames = []string{"control." + a.state.Domain}
		t.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	}
	der, err := x509.CreateCertificate(rand.Reader, t, a.ca, csr.PublicKey, a.key)
	if err != nil {
		return "", nil, err
	}
	cert, err := x509.ParseCertificate(der)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), cert, err
}
func (a *Auth) refreshServerLocked() error {
	if cert, err := parseCert(a.state.ServerPEM); err == nil && cert.NotAfter.After(time.Now().Add(30*24*time.Hour)) {
		_, err = tls.X509KeyPair([]byte(a.state.ServerPEM), []byte(a.state.ServerKeyPEM))
		return err
	}
	return a.transaction(func() error {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return err
		}
		cert, _, err := a.signCSR(&x509.CertificateRequest{PublicKey: &key.PublicKey}, "control."+a.state.Domain, true)
		if err != nil {
			return err
		}
		a.state.ServerPEM = cert
		a.state.ServerKeyPEM = keyPEM(key)
		return nil
	})
}
func (a *Auth) TLSConfig() (*tls.Config, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.refreshServerLocked(); err != nil {
		return nil, err
	}
	cert, err := tls.X509KeyPair([]byte(a.state.ServerPEM), []byte(a.state.ServerKeyPEM))
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	pool.AddCert(a.ca)
	// macOS .NET's default SecureTransport backend needs TLS 1.2. Keep forward-secret
	// AEAD suites only; TLS 1.3 remains available to capable clients.
	return &tls.Config{MinVersion: tls.VersionTLS12,
		CipherSuites: []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256},
		Certificates: []tls.Certificate{cert}, ClientCAs: pool, ClientAuth: tls.VerifyClientCertIfGiven, NextProtos: []string{"h2", "http/1.1"}}, nil
}
func (a *Auth) Discovery() any {
	a.mu.Lock()
	defer a.mu.Unlock()
	return map[string]any{"version": 2, "domain": a.state.Domain, "serverId": a.state.ServerID, "controlUrl": "https://control." + a.state.Domain, "caPem": a.state.CAPEM}
}
func (a *Auth) CreatePairing(ttl time.Duration) (string, error) {
	if ttl < time.Minute || ttl > 30*time.Minute {
		return "", errors.New("expiry must be 1m through 30m")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	code := PairingCode{Version: 1, Domain: a.state.Domain, ServerID: a.state.ServerID, ID: observer.RandomID(), Secret: observer.RandomID() + observer.RandomID(), CAFingerprint: caFingerprint(a.ca), Expires: time.Now().UTC().Add(ttl)}
	err := a.transaction(func() error {
		for id, p := range a.state.Pairings {
			if time.Now().After(p.Expires) {
				delete(a.state.Pairings, id)
			}
		}
		if len(a.state.Pairings) >= 64 {
			return errors.New("pairing quota")
		}
		a.state.Pairings[code.ID] = pairingRecord{ID: code.ID, Hash: hashText(code.Secret), Expires: code.Expires}
		return nil
	})
	if err != nil {
		return "", err
	}
	b, _ := json.Marshal(code)
	return "EP1." + base64.RawURLEncoding.EncodeToString(b), nil
}
func validCSR(value string) (*x509.CertificateRequest, error) {
	if len(value) > 8192 {
		return nil, errors.New("CSR exceeds limit")
	}
	b, rest := pem.Decode([]byte(value))
	if b == nil || len(strings.TrimSpace(string(rest))) != 0 {
		return nil, errors.New("invalid CSR")
	}
	csr, err := x509.ParseCertificateRequest(b.Bytes)
	if err != nil || csr.CheckSignature() != nil {
		return nil, errors.New("invalid CSR signature")
	}
	k, ok := csr.PublicKey.(*ecdsa.PublicKey)
	if !ok || k.Curve != elliptic.P256() {
		return nil, errors.New("P-256 CSR required")
	}
	return csr, nil
}
func (a *Auth) Redeem(id, secret, csrPEM, name string) (string, string, error) {
	if len(id) != 32 || len(secret) != 64 || len(name) == 0 || len(name) > 128 || strings.ContainsAny(name, "\r\n\x00") {
		return "", "", errUnauthorized
	}
	csr, err := validCSR(csrPEM)
	if err != nil {
		return "", "", err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	p, ok := a.state.Pairings[id]
	if !ok || p.Revoked || time.Now().After(p.Expires) || subtle.ConstantTimeCompare([]byte(p.Hash), []byte(hashText(secret))) != 1 {
		return "", "", errUnauthorized
	}
	csrHash := hashText(string(csr.Raw))
	if p.DeviceID != "" {
		d, ok := a.state.Devices[p.DeviceID]
		if !ok || d.Revoked || p.CSRHash != csrHash {
			return "", "", errUnauthorized
		}
		return p.DeviceID, p.Certificate, nil
	}
	if len(a.state.Devices) >= 1024 {
		return "", "", errors.New("device quota")
	}
	deviceID := observer.RandomID()
	certPEM, cert, err := a.signCSR(csr, deviceID, false)
	if err != nil {
		return "", "", err
	}
	err = a.transaction(func() error {
		p.DeviceID = deviceID
		p.CSRHash = csrHash
		p.Certificate = certPEM
		a.state.Pairings[id] = p
		a.state.Devices[deviceID] = Device{ID: deviceID, Name: name, Created: time.Now().UTC(), Certificates: map[string]deviceCertificate{cert.SerialNumber.String(): {PEM: certPEM, AcceptUntil: cert.NotAfter, CSRHash: csrHash}}}
		return nil
	})
	return deviceID, certPEM, err
}
func (a *Auth) Active(id string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	d, ok := a.state.Devices[id]
	return ok && !d.Revoked
}
func (a *Auth) Authenticate(r *http.Request) (string, error) {
	if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.PeerCertificates) == 0 {
		return "", errUnauthorized
	}
	cert := r.TLS.PeerCertificates[0]
	a.mu.Lock()
	defer a.mu.Unlock()
	d, ok := a.state.Devices[cert.Subject.CommonName]
	if !ok || d.Revoked {
		return "", errUnauthorized
	}
	c, ok := d.Certificates[cert.SerialNumber.String()]
	if !ok || time.Now().After(c.AcceptUntil) || time.Now().After(cert.NotAfter) || time.Now().Before(cert.NotBefore) {
		return "", errUnauthorized
	}
	stored, err := parseCert(c.PEM)
	if err != nil || !cert.Equal(stored) {
		return "", errUnauthorized
	}
	return d.ID, nil
}
func (a *Auth) Renew(id, csrPEM string) (string, error) {
	csr, err := validCSR(csrPEM)
	if err != nil {
		return "", err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	d, ok := a.state.Devices[id]
	if !ok || d.Revoked {
		return "", errUnauthorized
	}
	h := hashText(string(csr.Raw))
	now := time.Now().UTC()
	for _, c := range d.Certificates {
		if c.CSRHash == h && c.AcceptUntil.After(now.Add(30*24*time.Hour)) {
			return c.PEM, nil
		}
	}
	certPEM, cert, err := a.signCSR(csr, id, false)
	if err != nil {
		return "", err
	}
	err = a.transaction(func() error {
		for serial, c := range d.Certificates {
			if c.AcceptUntil.Before(now) {
				delete(d.Certificates, serial)
				continue
			}
			if c.AcceptUntil.After(now.Add(24 * time.Hour)) {
				c.AcceptUntil = now.Add(24 * time.Hour)
				d.Certificates[serial] = c
			}
		}
		if len(d.Certificates) >= 4 {
			return errors.New("renewal overlap quota")
		}
		d.Certificates[cert.SerialNumber.String()] = deviceCertificate{PEM: certPEM, AcceptUntil: cert.NotAfter, CSRHash: h}
		a.state.Devices[id] = d
		return nil
	})
	return certPEM, err
}
func (a *Auth) Revoke(kind, id string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.transaction(func() error {
		if kind == "pairing" {
			p, ok := a.state.Pairings[id]
			if !ok {
				return errors.New("pairing not found")
			}
			p.Revoked = true
			a.state.Pairings[id] = p
			return nil
		}
		d, ok := a.state.Devices[id]
		if !ok {
			return errors.New("device not found")
		}
		d.Revoked = true
		a.state.Devices[id] = d
		return nil
	})
}
func (a *Auth) List(kind string) any {
	a.mu.Lock()
	defer a.mu.Unlock()
	rows := []map[string]any{}
	if kind == "pairing" {
		for _, p := range a.state.Pairings {
			rows = append(rows, map[string]any{"id": p.ID, "expires": p.Expires, "revoked": p.Revoked, "used": p.DeviceID != ""})
		}
	} else {
		for _, d := range a.state.Devices {
			rows = append(rows, map[string]any{"id": d.ID, "name": d.Name, "created": d.Created, "revoked": d.Revoked})
		}
	}
	return rows
}
func (a *Auth) Allow(key string, limit int) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := time.Now()
	if len(a.rates) > 2048 {
		for k, v := range a.rates {
			if now.Sub(v.Started) > time.Minute {
				delete(a.rates, k)
			}
		}
		if len(a.rates) > 2048 {
			return false
		}
	}
	r := a.rates[key]
	if now.Sub(r.Started) > time.Minute {
		r = rateWindow{Started: now}
	}
	r.Count++
	a.rates[key] = r
	return r.Count <= limit
}
func (a *Auth) ControlURL() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return fmt.Sprintf("https://control.%s", a.state.Domain)
}
func (a *Auth) CAPEM() string { a.mu.Lock(); defer a.mu.Unlock(); return a.state.CAPEM }
