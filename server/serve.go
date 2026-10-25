package server

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"golang.org/x/crypto/acme/autocert"
)

// Serve owns every listener. Any listener failure cancels and closes all others.
func (s *Server) Serve(parent context.Context, cacheDir string) error {
	return s.ServeOn(parent, cacheDir, "")
}

// ServeOn binds one local IPv4 interface without occupying a loopback DNS stub.
// The public observation address remains Profile.IPv4.
func (s *Server) ServeOn(parent context.Context, cacheDir, listenIP string) error {
	if listenIP == "" {
		listenIP = "0.0.0.0"
	}
	ip := net.ParseIP(listenIP)
	if ip == nil || ip.To4() == nil {
		return errors.New("listenIP must be a local IPv4 address")
	}
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	rtcConn, err := net.ListenPacket("udp4", net.JoinHostPort(listenIP, "3480"))
	if err != nil {
		return err
	}
	s.rtc.start(rtcConn, s.Profile.IPv4, false)
	defer s.rtc.close()
	if err := os.MkdirAll(cacheDir, 0700); err != nil {
		return err
	}
	if s.Auth == nil {
		var err error
		s.Auth, err = OpenAuth(cacheDir, s.Profile)
		if err != nil {
			return err
		}
	}
	admin, err := s.serveAdmin(ctx, cacheDir)
	if err != nil {
		return err
	}
	defer admin.Close()
	d := s.Profile.Domain
	names := []string{"api." + d, "http." + d, "h3." + d, "tls." + d}
	manager := &autocert.Manager{Prompt: autocert.AcceptTOS, Cache: autocert.DirCache(filepath.Join(cacheDir, "certificates")), HostPolicy: autocert.HostWhitelist(names...)}
	tc := &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: manager.GetCertificate, NextProtos: []string{"h2", "http/1.1"}}
	tc.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		if strings.EqualFold(hello.ServerName, "control."+d) {
			return s.Auth.TLSConfig()
		}
		return nil, nil
	}
	var closers []io.Closer
	defer func() {
		for _, c := range closers {
			c.Close()
		}
	}()
	fail := make(chan error, 8)
	run := func(f func() error) {
		go func() {
			err := f()
			select {
			case fail <- err:
			case <-ctx.Done():
			}
		}()
	}
	for _, item := range []struct{ port, kind string }{{"80", "http"}, {"443", "https"}, {"18080", "tcp"}, {"18443", "tls"}, {"53", "dns"}} {
		l, e := net.Listen("tcp4", net.JoinHostPort(listenIP, item.port))
		if e != nil {
			return e
		}
		closers = append(closers, l)
		switch item.kind {
		case "http", "https":
			handler := s.Handler()
			if item.kind == "http" {
				handler = manager.HTTPHandler(handler)
			}
			h := &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 10 * time.Second, MaxHeaderBytes: 8192, TLSConfig: tc.Clone()}
			closers = append(closers, h)
			if item.kind == "https" {
				run(func() error { return h.ServeTLS(l, "", "") })
			} else {
				run(func() error { return h.Serve(l) })
			}
		case "tls":
			l = tls.NewListener(l, tc.Clone())
			run(func() error { return s.stream(ctx, l, "tls") })
		case "tcp":
			run(func() error { return s.stream(ctx, l, "tcp") })
		case "dns":
			run(func() error { return s.dnsTCP(ctx, l) })
		}
	}
	for _, item := range []struct{ port, kind string }{{"443", "h3"}, {"3478", "stun"}, {"3479", "udp"}, {"53", "dns"}} {
		c, e := net.ListenPacket("udp4", net.JoinHostPort(listenIP, item.port))
		if e != nil {
			return e
		}
		closers = append(closers, c)
		if item.kind == "h3" {
			h := &http3.Server{Handler: s.Handler(), TLSConfig: tc.Clone(), MaxHeaderBytes: 8192, IdleTimeout: 10 * time.Second, ConnContext: func(ctx context.Context, c *quic.Conn) context.Context {
				return context.WithValue(ctx, quicPeerKey{}, c)
			}}
			closers = append(closers, h)
			run(func() error { return h.Serve(c) })
		} else {
			run(func() error { return s.packets(ctx, c, item.kind) })
		}
	}
	select {
	case <-ctx.Done():
		return nil
	case err := <-fail:
		if parent.Err() != nil || errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

func (s *Server) dnsTCP(ctx context.Context, l net.Listener) error {
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
			c.SetDeadline(time.Now().Add(5 * time.Second))
			if !s.allow() {
				return
			}
			var size [2]byte
			if _, e := io.ReadFull(c, size[:]); e != nil {
				return
			}
			n := int(binary.BigEndian.Uint16(size[:]))
			if n < 12 || n > 4096 {
				return
			}
			b := make([]byte, n)
			if _, e := io.ReadFull(c, b); e != nil {
				return
			}
			reply := s.dns(b, c.RemoteAddr().String(), c.LocalAddr().String(), true)
			if len(reply) > 0 {
				c.Write(append(binary.BigEndian.AppendUint16(nil, uint16(len(reply))), reply...))
			}
		}()
	}
}
