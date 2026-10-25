package observer

import (
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"time"
)

// VerifyReport verifies historical receipts against a separately trusted profile.
// It does not assert freshness, successful return paths, or correct routing.
func VerifyReport(reader io.Reader, trusted Profile) (int, error) {
	var report struct {
		Version  int     `json:"version"`
		Observer Profile `json:"observer"`
		Results  []struct {
			Samples []struct {
				ID       string    `json:"id"`
				Kind     string    `json:"kind"`
				Path     string    `json:"path"`
				Target   string    `json:"target"`
				Receipts []Receipt `json:"receipts"`
			} `json:"samples"`
		} `json:"results"`
	}
	if err := json.NewDecoder(io.LimitReader(reader, 2*1024*1024+1)).Decode(&report); err != nil {
		return 0, err
	}
	if report.Version != 2 || report.Observer.ServerID != trusted.ServerID || report.Observer.PublicKey != trusted.PublicKey {
		return 0, errors.New("report does not match trusted observer profile")
	}
	count := 0
	for _, row := range report.Results {
		for _, sample := range row.Samples {
			for _, receipt := range sample.Receipts {
				b, err := Encoding.DecodeString(receipt.Payload)
				if err != nil {
					return count, err
				}
				var o Observation
				if err = json.Unmarshal(b, &o); err != nil {
					return count, err
				}
				kind := sample.Kind
				if kind == "system-dns" || sample.Path == "local-dns" {
					kind = "dns-system"
				}
				if kind == "system-http" {
					u, err := url.Parse(sample.Target)
					if err != nil {
						return count, err
					}
					kind = u.Scheme
				}
				ticket := Ticket{SessionID: o.SessionID, ID: sample.ID, Nonce: o.Nonce, Kind: kind, Expires: o.ObservedAt.Add(time.Minute)}
				if _, err = Verify(trusted, ticket, receipt); err != nil {
					return count, err
				}
				count++
			}
		}
	}
	if count == 0 {
		return 0, errors.New("report contains no signed observations")
	}
	return count, nil
}
