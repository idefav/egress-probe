package server

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func (s *Server) controlRequest(r *http.Request) bool {
	host := strings.TrimSuffix(r.Host, ":443")
	return s.Auth != nil && r.TLS != nil && strings.EqualFold(r.TLS.ServerName, "control."+s.Profile.Domain) && strings.EqualFold(host, "control."+s.Profile.Domain)
}
func (s *Server) enrollment(id, cert string) Enrollment {
	return Enrollment{DeviceID: id, Certificate: cert, CAPEM: s.Auth.CAPEM(), Profile: s.Profile, ControlURL: s.Auth.ControlURL()}
}
func (s *Server) authEndpoint(w http.ResponseWriter, r *http.Request) bool {
	if r.URL.Path == "/.well-known/egress-probe" {
		if r.Method != "GET" || r.TLS == nil || s.Auth == nil {
			http.Error(w, "HTTPS discovery unavailable", 400)
		} else {
			writeJSON(w, s.Auth.Discovery())
		}
		return true
	}
	if r.URL.Path != "/v2/pairings/redeem" {
		return false
	}
	if r.Method != "POST" || !s.controlRequest(r) {
		http.Error(w, "control TLS required", 401)
		return true
	}
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	if !s.Auth.Allow("pair-global", 100) || !s.Auth.Allow("pair:"+ip, 20) {
		http.Error(w, "pairing rate limit", 429)
		return true
	}
	var input struct {
		ID     string `json:"id"`
		Secret string `json:"secret"`
		CSR    string `json:"csr"`
		Name   string `json:"name"`
	}
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 16384)).Decode(&input) != nil {
		http.Error(w, "invalid pairing request", 400)
		return true
	}
	id, cert, err := s.Auth.Redeem(input.ID, input.Secret, input.CSR, input.Name)
	if err != nil {
		http.Error(w, "invalid, expired, consumed or revoked pairing", 403)
		return true
	}
	log.Printf("auth event=paired device=%s", id)
	writeJSON(w, s.enrollment(id, cert))
	return true
}
func (s *Server) deviceEndpoint(w http.ResponseWriter, r *http.Request, id string) bool {
	if r.URL.Path == "/v2/devices/self/renew" && r.Method == "POST" {
		var input struct {
			CSR string `json:"csr"`
		}
		if json.NewDecoder(http.MaxBytesReader(w, r.Body, 12288)).Decode(&input) != nil {
			http.Error(w, "invalid renewal", 400)
			return true
		}
		cert, err := s.Auth.Renew(id, input.CSR)
		if err != nil {
			http.Error(w, "renewal rejected", 403)
			return true
		}
		log.Printf("auth event=renewed device=%s", id)
		writeJSON(w, s.enrollment(id, cert))
		return true
	}
	if r.URL.Path == "/v2/devices/self" && r.Method == "DELETE" {
		if err := s.Auth.Revoke("devices", id); err != nil {
			http.Error(w, "revocation persistence failed", 500)
			return true
		}
		s.cancelDevice(id)
		log.Printf("auth event=revoked device=%s", id)
		w.WriteHeader(204)
		return true
	}
	return false
}
func (s *Server) cancelDevice(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for sid, sess := range s.sessions {
		if sess.DeviceID != id {
			continue
		}
		for probe := range sess.Tickets {
			delete(s.issued, probe)
			s.rtc.remove(probe)
		}
		delete(s.sessions, sid)
	}
}

// A private directory and mode-0600 Unix socket are the only admin interface.
func (s *Server) serveAdmin(ctx context.Context, dir string) (io.Closer, error) {
	path := filepath.Join(dir, "admin.sock")
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return nil, os.ErrExist
		}
		conn, err := net.DialTimeout("unix", path, time.Second)
		if err == nil {
			conn.Close()
			return nil, os.ErrExist
		}
		if err := os.Remove(path); err != nil {
			return nil, err
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	l, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err = os.Chmod(path, 0600); err != nil {
		l.Close()
		return nil, err
	}
	h := &http.Server{ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, MaxHeaderBytes: 4096}
	h.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "POST required", 405)
			return
		}
		var in struct {
			Kind   string `json:"kind"`
			Action string `json:"action"`
			ID     string `json:"id"`
			TTL    string `json:"ttl"`
		}
		if json.NewDecoder(http.MaxBytesReader(w, r.Body, 2048)).Decode(&in) != nil || (in.Kind != "pairing" && in.Kind != "devices") {
			http.Error(w, "invalid command", 400)
			return
		}
		switch in.Action {
		case "list":
			writeJSON(w, s.Auth.List(in.Kind))
		case "create":
			if in.Kind != "pairing" {
				http.Error(w, "invalid command", 400)
				return
			}
			ttl, err := time.ParseDuration(in.TTL)
			if err != nil {
				http.Error(w, "invalid expiry", 400)
				return
			}
			code, err := s.Auth.CreatePairing(ttl)
			if err != nil {
				http.Error(w, err.Error(), 400)
				return
			}
			log.Print("auth event=pairing-created")
			writeJSON(w, map[string]string{"domain": s.Profile.Domain, "pairingCode": code, "expiresIn": in.TTL})
		case "revoke":
			if err := s.Auth.Revoke(in.Kind, in.ID); err != nil {
				http.Error(w, "revocation failed", 400)
				return
			}
			if in.Kind == "devices" {
				s.cancelDevice(in.ID)
			}
			log.Print("auth event=admin-revoked")
			w.WriteHeader(204)
		default:
			http.Error(w, "invalid command", 400)
		}
	})
	go func() { <-ctx.Done(); _ = h.Close(); _ = l.Close() }()
	go func() {
		if err := h.Serve(l); err != nil && err != http.ErrServerClosed {
			log.Print("admin interface stopped")
		}
	}()
	return h, nil
}
