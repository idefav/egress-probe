package server

import (
	"context"
	"strings"
	"testing"
)

func TestServeOnRejectsInvalidOrIPv6BindBeforeOpeningListeners(t *testing.T) {
	for _, address := range []string{"localhost", "::1", "172.26.178.114:53", "invalid"} {
		t.Run(address, func(t *testing.T) {
			err := new(Server).ServeOn(context.Background(), t.TempDir(), address)
			if err == nil || !strings.Contains(err.Error(), "local IPv4") {
				t.Fatalf("expected invalid interface error, got %v", err)
			}
		})
	}
}
