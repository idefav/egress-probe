package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	observer "github.com/idefav/egress-probe"
)

func authCode(t *testing.T, a *Auth) PairingCode {
	t.Helper()
	encoded, err := a.CreatePairing(10 * time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	b, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(encoded, "EP1."))
	if err != nil {
		t.Fatal(err)
	}
	var code PairingCode
	if err := json.Unmarshal(b, &code); err != nil {
		t.Fatal(err)
	}
	return code
}

func authCSR(t *testing.T) (string, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	b, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "attacker-chosen-name"}, DNSNames: []string{"control.check.example.net"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: b})), key
}

func TestPairingAtomicRetryAndPersistence(t *testing.T) {
	dir := t.TempDir()
	profile := Profile("check.example.net", "203.0.113.10", "auth-fixture")
	a, err := OpenAuth(dir, profile)
	if err != nil {
		t.Fatal(err)
	}
	code := authCode(t, a)
	csr, _ := authCSR(t)
	var wg sync.WaitGroup
	results := make(chan string, 12)
	for range 12 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			id, cert, err := a.Redeem(code.ID, code.Secret, csr, "test")
			if err != nil {
				t.Error(err)
				return
			}
			results <- id + cert
		}()
	}
	wg.Wait()
	close(results)
	first := ""
	for value := range results {
		if first == "" {
			first = value
		}
		if value != first {
			t.Fatal("concurrent redemption changed identity")
		}
	}
	if len(a.state.Devices) != 1 {
		t.Fatal("duplicate registration")
	}
	id, certPEM, err := a.Redeem(code.ID, code.Secret, csr, "retry")
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := parseCert(certPEM)
	if cert.Subject.CommonName != id || len(cert.DNSNames) != 0 || cert.IsCA || len(cert.ExtKeyUsage) != 1 || cert.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
		t.Fatal("CSR supplied permissions escaped")
	}
	otherCSR, _ := authCSR(t)
	if _, _, err := a.Redeem(code.ID, code.Secret, otherCSR, "other"); err == nil {
		t.Fatal("reused code with a different key")
	}
	if _, _, err := a.Redeem(code.ID, strings.Repeat("0", 64), csr, "wrong"); err == nil {
		t.Fatal("accepted incorrect secret")
	}
	b, _ := os.ReadFile(filepath.Join(dir, "device-auth.json"))
	if strings.Contains(string(b), code.Secret) {
		t.Fatal("persisted pairing secret")
	}
	info, _ := os.Stat(filepath.Join(dir, "device-auth.json"))
	if info.Mode().Perm() != 0600 {
		t.Fatal("state permissions")
	}
	a, err = OpenAuth(dir, profile)
	if err != nil {
		t.Fatal(err)
	}
	got, recovered, err := a.Redeem(code.ID, code.Secret, csr, "response lost")
	if err != nil || got != id || recovered != certPEM {
		t.Fatal("retry after restart did not recover identical result", err)
	}
	if err := a.Revoke("devices", id); err != nil {
		t.Fatal(err)
	}
	a, err = OpenAuth(dir, profile)
	if err != nil {
		t.Fatal(err)
	}
	if a.Active(id) {
		t.Fatal("revocation lost after restart")
	}
	if _, _, err := a.Redeem(code.ID, code.Secret, csr, "revoked"); err == nil {
		t.Fatal("revoked device recovered")
	}
}

func TestPairingExpiryAndFailedPersistence(t *testing.T) {
	s := fixture(t)
	a := s.Auth
	code := authCode(t, a)
	csr, _ := authCSR(t)
	p := a.state.Pairings[code.ID]
	p.Expires = time.Now().Add(-time.Second)
	a.state.Pairings[code.ID] = p
	if _, _, err := a.Redeem(code.ID, code.Secret, csr, "expired"); err == nil {
		t.Fatal("expired code accepted")
	}
	code = authCode(t, a)
	oldPath := a.path
	a.path = filepath.Join(t.TempDir(), "missing", "state.json")
	if _, _, err := a.Redeem(code.ID, code.Secret, csr, "disk failed"); err == nil {
		t.Fatal("ignored persistence failure")
	}
	if a.state.Pairings[code.ID].DeviceID != "" {
		t.Fatal("failed transaction consumed pairing")
	}
	a.path = oldPath
	if _, _, err := a.Redeem(code.ID, code.Secret, csr, "retry"); err != nil {
		t.Fatal(err)
	}
}

func TestRealMutualTLSRevocationAndLegacyRejection(t *testing.T) {
	s := fixture(t)
	code := authCode(t, s.Auth)
	csr, key := authCSR(t)
	id, cert, err := s.Auth.Redeem(code.ID, code.Secret, csr, "TLS fixture")
	if err != nil {
		t.Fatal(err)
	}
	config, err := s.Auth.TLSConfig()
	if err != nil {
		t.Fatal(err)
	}
	host := httptest.NewUnstartedServer(s.Handler())
	host.TLS = config
	host.StartTLS()
	defer host.Close()
	pool := x509.NewCertPool()
	pool.AddCert(s.Auth.ca)
	pair, err := tls.X509KeyPair([]byte(cert), []byte(keyPEM(key)))
	if err != nil {
		t.Fatal(err)
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: "control." + s.Profile.Domain, Certificates: []tls.Certificate{pair}}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport}
	request := func(path string, client *http.Client) int {
		r, _ := http.NewRequest("GET", host.URL+path, nil)
		r.Host = "control." + s.Profile.Domain
		r.Header.Set("Authorization", "Bearer "+s.apiKey)
		response, err := client.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		_, _ = io.Copy(io.Discard, response.Body)
		return response.StatusCode
	}
	if got := request("/v2/capabilities", client); got != 200 {
		t.Fatal(got)
	}
	if got := request("/v1/capabilities", client); got != 426 {
		t.Fatal("legacy API remained enabled", got)
	}
	noCertTransport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: "control." + s.Profile.Domain}}
	defer noCertTransport.CloseIdleConnections()
	if got := request("/v2/capabilities", &http.Client{Transport: noCertTransport}); got != 401 {
		t.Fatal("API key granted access without device certificate", got)
	}
	if err := s.Auth.Revoke("devices", id); err != nil {
		t.Fatal(err)
	}
	if got := request("/v2/capabilities", client); got != 401 {
		t.Fatal("keep-alive connection bypassed revocation", got)
	}
}

func TestRenewalOverlapAndRetry(t *testing.T) {
	s := fixture(t)
	code := authCode(t, s.Auth)
	csr, _ := authCSR(t)
	id, oldPEM, err := s.Auth.Redeem(code.ID, code.Secret, csr, "renew")
	if err != nil {
		t.Fatal(err)
	}
	newCSR, _ := authCSR(t)
	newPEM, err := s.Auth.Renew(id, newCSR)
	if err != nil {
		t.Fatal(err)
	}
	retry, err := s.Auth.Renew(id, newCSR)
	if err != nil || retry != newPEM {
		t.Fatal("renewal retry changed certificate")
	}
	old, _ := parseCert(oldPEM)
	if s.Auth.state.Devices[id].Certificates[old.SerialNumber.String()].AcceptUntil.After(time.Now().Add(24 * time.Hour)) {
		t.Fatal("old certificate overlap exceeded 24h")
	}
	if _, err := s.Auth.Renew(id, "invalid CSR"); err == nil {
		t.Fatal("invalid CSR accepted")
	}
}

func TestDeviceCannotAccessAnotherSessionAndRevocationCancelsTickets(t *testing.T) {
	s := fixture(t)
	code := authCode(t, s.Auth)
	csr, _ := authCSR(t)
	id, certificate, err := s.Auth.Redeem(code.ID, code.Secret, csr, "second-device")
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := parseCert(certificate)
	call := func(method, path string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, "https://control.check.example.net"+path, strings.NewReader("{}"))
		r.TLS = &tls.ConnectionState{ServerName: "control.check.example.net", PeerCertificates: []*x509.Certificate{cert}, VerifiedChains: [][]*x509.Certificate{{cert, s.Auth.ca}}}
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		return w
	}
	// The fixture's original device owns this session.
	var owner string
	for candidate := range s.Auth.state.Devices {
		if candidate != id {
			owner = candidate
		}
	}
	sessionID := "first-device-session"
	ticketID := "first-device-ticket"
	s.sessions[sessionID] = &session{DeviceID: owner, Expires: time.Now().Add(time.Minute), Tickets: map[string]observer.Ticket{ticketID: {ID: ticketID, Nonce: "nonce", SessionID: sessionID, Expires: time.Now().Add(time.Minute)}}, Receipts: map[string][]observer.Receipt{}}
	s.issued[ticketID] = sessionID
	for _, method := range []string{"GET", "DELETE"} {
		if got := call(method, "/v2/sessions/"+sessionID); got.Code != 404 {
			t.Fatal("cross-device access", got.Code)
		}
	}
	if _, ok := s.ticket(ticketID, "nonce"); !ok {
		t.Fatal("fixture ticket invalid")
	}
	if err := s.Auth.Revoke("devices", owner); err != nil {
		t.Fatal(err)
	}
	s.cancelDevice(owner)
	if _, ok := s.ticket(ticketID, "nonce"); ok {
		t.Fatal("revoked device ticket survived")
	}
	if s.sessions[sessionID] != nil {
		t.Fatal("revoked device session survived")
	}
}
