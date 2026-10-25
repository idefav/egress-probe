package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	observer "github.com/idefav/egress-probe"
	"github.com/idefav/egress-probe/server"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}
func run() error {
	if len(os.Args) > 1 && (os.Args[1] == "pairing" || os.Args[1] == "devices") {
		return adminCommand(os.Args[1:])
	}
	init := flag.Bool("init", false, "Generate new private config and public profile; never overwrite")
	config := flag.String("config", "/etc/egress-probe/config.json", "Private configuration file")
	domain := flag.String("domain", "", "Delegated test domain for init")
	ip := flag.String("ipv4", "", "Public IPv4 for init")
	listenIP := flag.String("listen-ip", "", "Local IPv4 interface for init (default: all IPv4 interfaces)")
	verify := flag.String("verify-report", "", "Verify historical report signatures (requires -profile)")
	profileFile := flag.String("profile", "", "Separately trusted public profile.json")
	flag.Parse()
	if *verify != "" {
		if *profileFile == "" {
			return fmt.Errorf("-profile is required for offline verification")
		}
		f, e := os.Open(*profileFile)
		if e != nil {
			return e
		}
		var p observer.Profile
		e = json.NewDecoder(f).Decode(&p)
		f.Close()
		if e != nil {
			return e
		}
		r, e := os.Open(*verify)
		if e != nil {
			return e
		}
		defer r.Close()
		n, e := observer.VerifyReport(r, p)
		if e != nil {
			return e
		}
		fmt.Printf("Verified %d historical receipts against the trusted profile; freshness and connectivity are not implied.\n", n)
		return nil
	}
	if *init {
		if *listenIP != "" && net.ParseIP(*listenIP).To4() == nil {
			return fmt.Errorf("-listen-ip must be a local IPv4 address")
		}
		key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if e != nil {
			return e
		}
		der, e := x509.MarshalECPrivateKey(key)
		if e != nil {
			return e
		}
		id := observer.RandomID()
		p := server.Profile(*domain, *ip, id)
		s, e := server.New(p, key, "")
		if e != nil {
			return e
		}
		cfg := server.Config{Domain: *domain, IPv4: *ip, ServerID: id, PrivateKey: observer.Encoding.EncodeToString(der), CacheDir: "/var/lib/egress-probe", ListenIP: *listenIP}
		if e = os.MkdirAll(filepath.Dir(*config), 0700); e != nil {
			return e
		}
		b, _ := json.MarshalIndent(cfg, "", "  ")
		f, e := os.OpenFile(*config, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if e != nil {
			return e
		}
		if _, e = f.Write(b); e != nil {
			f.Close()
			return e
		}
		if e = f.Close(); e != nil {
			return e
		}
		b, _ = json.MarshalIndent(s.Profile, "", "  ")
		profilePath := filepath.Join(filepath.Dir(*config), "profile.json")
		f, e = os.OpenFile(profilePath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
		if e != nil {
			return e
		}
		defer f.Close()
		if _, e = f.Write(b); e != nil {
			return e
		}
		fmt.Println("Created private config and public profile. Transfer profile over a trusted channel. API key is only in private config.")
		return nil
	}
	f, e := os.Open(*config)
	if e != nil {
		return e
	}
	defer f.Close()
	var cfg server.Config
	if e = json.NewDecoder(f).Decode(&cfg); e != nil {
		return e
	}
	der, e := observer.Encoding.DecodeString(cfg.PrivateKey)
	if e != nil {
		return e
	}
	key, e := x509.ParseECPrivateKey(der)
	if e != nil {
		return e
	}
	s, e := server.New(server.Profile(cfg.Domain, cfg.IPv4, cfg.ServerID), key, cfg.APIKey)
	if e != nil {
		return e
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return s.ServeOn(ctx, cfg.CacheDir, cfg.ListenIP)
}
