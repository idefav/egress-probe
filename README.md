# egress-probe

Private multi-protocol egress observer for v2rayN. The server runs independently of proxy exits and reports the actual socket peer for each nonce-bound sample. Source is public; access requires your own credential. Do not commit generated configuration, signing keys or API credentials.

## Coverage and evidence

| Protocol | Listener | Evidence |
|---|---|---|
| TCP | TCP 18080 | Signed peer IP/port on the same connection |
| TLS | TCP 18443 | Trusted hostname/certificate handshake, then signed echo |
| HTTP / HTTPS | TCP 80 / 443 | Signed request peer; ignores forwarding headers |
| HTTP3 | UDP 443 | Actual QUIC + HTTP3, no TCP fallback |
| Ordinary UDP | UDP 3479 | Address-bound cookie challenge, signed response |
| Private STUN | UDP 3478 | RFC 8489 XOR-MAPPED-ADDRESS; short-lived ticket in private attribute 0xc001; corroborating signed server observation |
| Authoritative DNS | UDP/TCP 53 | A, synthetic documentation AAAA, NXDOMAIN, controlled UDP truncation and TCP retry |

This release is IPv4 only. An AAAA answer is test data (`2001:db8::1`), not proof of IPv6 transport. A system/local recursive resolver query identifies the **recursive resolver reaching the authority**, not the client's source IP to that resolver. Other applications' WebRTC/DoH, kill switches, MTU and arbitrary Internet targets are outside coverage.

The observation server must differ from the exit under test. If using the US machine as observer, do not certify that US machine's own proxy exit with it. Use another independent observer for that path. Control HTTPS requests do not establish the egress of any data probe.

## Deploy on Linux

Use a dedicated public IPv4 host without a CDN, HTTP reverse proxy or source-NATing container bridge. Nothing in this deployment replaces SSH, changes SSH listeners or modifies proxy configuration. Existing services must not occupy any required port. Inspect first:

```sh
sudo ss -lntup
```

Allow inbound TCP **53, 80, 443, 18080, 18443** and UDP **53, 443, 3478, 3479** in both cloud security groups and the host firewall. Keep the existing management SSH port. ACME also needs outbound DNS and HTTPS.

Delegate `check.example.net` to `ns.check.example.net`, with parent glue A pointing to the observer IPv4. Replace both placeholders below. The built-in authority serves A records for `api`, `http`, `h3`, `tcp`, `tls`, `udp`, `stun`, and `ns`. Only the test zone is authoritative; it is not an open recursive resolver. QNAME minimization and zero-TTL test names are supported.

Download the matching GitHub Actions installation archive, verify its checksum, extract it, then:

```sh
sha256sum --check SHA256SUMS
sudo useradd --system --home-dir /var/lib/egress-probe --shell /usr/sbin/nologin egress-probe
sudo install -m 0755 egress-probe-server /usr/local/bin/egress-probe-server
sudo /usr/local/bin/egress-probe-server -init \
  -domain check.example.net -ipv4 203.0.113.10 \
  -config /etc/egress-probe/config.json
sudo chown -R egress-probe:egress-probe /etc/egress-probe
sudo install -m 0644 egress-probe.service /etc/systemd/system/egress-probe.service
sudo systemctl daemon-reload
sudo systemctl enable --now egress-probe.service
sudo systemctl status egress-probe.service
sudo journalctl -u egress-probe.service -n 50 --no-pager
```

`-init` creates a mode-0600 private config and a public `profile.json`; it never overwrites either. Keep the private config readable only by the service account. ACME HTTP-01 obtains trusted certificates on the first TLS request and caches/renews them under `/var/lib/egress-probe/certificates`. Ensure delegation and port 80 work before testing TLS. A first certificate issuance may exceed a normal probe timeout; warm up HTTPS once before running the suite. Monitor service logs for renewal errors.

Transfer **only** `/etc/egress-probe/profile.json` to v2rayN through a trusted channel. Retrieve `apiKey` from the private config through your existing secure SSH session and enter it into the client; never put it in a URL or command line. v2rayN verifies the separately pinned signing public key and normal TLS trust. Profile/key changes require explicit re-import.

## v2rayN usage

Use the matching `feature/precise-egress-observer` client. In Proxy check, expand Independent egress observer, import `profile.json`, enable it, enter the API credential and test the control connection. Credential persistence is deliberately **memory only** in this preview; it is not stored in settings, reports or baselines. Full checks independently exercise native/TUN, SOCKS5, HTTP CONNECT and actual system HTTP paths. HTTP CONNECT UDP is unsupported, with no direct fallback.

Configure expected IP/CIDR globally or per target. A scoped rule is `target|protocol|path=IP/CIDR`, for example `udp.check.example.net:3479|udp|socks=198.51.100.4`. Precedence is scoped target, exact target, endpoint, hostname, global. Three samples are retained individually. One confirmed mismatch remains a mismatch even if other samples time out. No expectation means observed-but-not-compared, not proof of correct proxying.

## Security and limits

Control endpoints require TLS and bearer authentication. Sessions last ten minutes, tickets three minutes, observations are retained for up to thirty minutes and may be explicitly deleted. Defaults: four active sessions, 128 retained sessions, 512 probes/session, eight records/probe, 32 concurrent stream connections, and a global 200-request/packet-per-second ceiling. These are fixed preview safety limits, not a multi-user quota system. There is no user-management UI or forwarding API.

UDP responses cannot exceed request size; cookies bind the observed source IP/port. STUN responses are smaller than authenticated requests. Standard unauthenticated STUN requests are not accepted. DNS answers remain minimal and zone-scoped; restrict DNS exposure further at the network edge if needed. The service is not designed as a public high-volume resolver or public probing endpoint.

Receipts use ECDSA P-256 / SHA-256, SPKI public keys, base64url payload bytes and IEEE-P1363 signatures. Verification binds the observer, session, sample, nonce, kind and timestamp. A valid signature proves what the trusted observer reported, not independent truth if that server is compromised. Server-only evidence after a timeout proves inbound arrival, not a working return path.

## Offline report verification

```sh
egress-probe-server -verify-report proxy-check-report.json -profile trusted-profile.json
```

Always use the separately trusted profile, not a public key copied out of an untrusted report. Verification checks historical signatures and sample bindings; it does not make old evidence fresh or establish connectivity.

## Build, test, upgrade and uninstall

```sh
go test -race ./...
go vet ./...
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o egress-probe-server ./cmd/egress-probe-server
```

CI tests changes and builds Linux amd64/arm64 archives. Version tags additionally publish a GitHub release. The Go SDK is consumed by v2rayN at a fixed version; no local path replacement belongs in committed client dependencies.

Before upgrading, back up the binary and private config. Install the verified replacement, restart only `egress-probe.service`, and check control/protocol health. If it fails, restore the old binary and restart that unit. Preserve the signing key unless deliberately rotating trust.

```sh
sudo systemctl disable --now egress-probe.service
sudo rm /etc/systemd/system/egress-probe.service
sudo systemctl daemon-reload
```

Keep private config/backups until no longer needed, then remove them separately. This procedure does not touch SSH or the running v2rayN client.
