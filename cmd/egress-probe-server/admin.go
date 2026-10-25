package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/idefav/egress-probe/server"
)

func adminCommand(args []string) error {
	if len(args) < 2 {
		return errors.New("usage: pairing create|list|revoke [id] or devices list|revoke [id]")
	}
	kind, action := args[0], args[1]
	rest := args[2:]
	id := ""
	if action == "revoke" {
		if len(rest) == 0 {
			return errors.New("revocation ID required")
		}
		id, rest = rest[0], rest[1:]
	}
	flags := flag.NewFlagSet("admin", flag.ContinueOnError)
	config := flags.String("config", "/etc/egress-probe/config.json", "Server config path")
	ttl := flags.String("expires", "10m", "Pairing validity, 1m through 30m")
	if err := flags.Parse(rest); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected command arguments")
	}
	b, err := os.ReadFile(*config)
	if err != nil {
		return err
	}
	var cfg server.Config
	if json.Unmarshal(b, &cfg) != nil || cfg.CacheDir == "" {
		return errors.New("invalid server config")
	}
	path := filepath.Join(cfg.CacheDir, "admin.sock")
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", path)
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 15 * time.Second}
	body, _ := json.Marshal(map[string]string{"kind": kind, "action": action, "id": id, "ttl": *ttl})
	response, err := client.Post("http://unix/admin", "application/json", bytes.NewReader(body))
	if err != nil {
		return errors.New("cannot reach local administration socket; check service and permissions")
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, 1024*1024))
	if err != nil {
		return err
	}
	if response.StatusCode >= 400 {
		return fmt.Errorf("admin command rejected (%d): %s", response.StatusCode, bytes.TrimSpace(data))
	}
	if action == "create" {
		var result map[string]string
		if json.Unmarshal(data, &result) != nil {
			return errors.New("invalid admin response")
		}
		fmt.Printf("Domain: %s\nExpires in: %s\nPaste this one-time pairing string in v2rayN (do not share it):\n%s\n", result["domain"], result["expiresIn"], result["pairingCode"])
	} else if len(data) > 0 {
		_, err = os.Stdout.Write(data)
	} else {
		fmt.Println("Revoked.")
	}
	return err
}
