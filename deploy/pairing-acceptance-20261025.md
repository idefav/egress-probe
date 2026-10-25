# 2026-10-25 pairing deployment acceptance

Target: `47.77.201.36`, delegated zone `check.idefav.com`.

Deployed binary SHA-256:
`17296d8bc2bbaba86a6953807f17709e157c710aa6b9ec447970231c3fd8c73c`.
Root-only pre-upgrade backup: `/root/egress-probe-before-pairing-20261025`.
Original server ID, observation signing key and ACME cache were retained.
New auth state and Unix admin socket are owned by `egress-probe`, mode 0600.

The first live .NET/macOS control handshake exposed a TLS-version incompatibility.
The final control listener supports TLS 1.2 ECDHE/ECDSA AEAD suites plus TLS 1.3;
it still validates both identities. No certificate bypass was added.

Validated:

* Real C# pairing through an SSH-issued one-time string, CA pin validation and
  mTLS capabilities/session requests.
* Device material saved to macOS Keychain. A new client process restored it after
  a service restart with no pairing input.
* Device deletion immediately rejects requests from an already-created mTLS
  client. Test credentials are deleted locally; server revocation survives restart.
* SOCKS TCP, TLS, HTTP, HTTPS, ordinary UDP, STUN and real HTTP/3: all completed,
  signed egress `43.98.191.120`.
* DNS UDP/TCP A, AAAA, NXDOMAIN and truncated-query retries: communication completed.
  The running core has `hijack-dns` for port 53 and DNS traffic, with Cloudflare DoH
  through the proxy. The authoritative server observed `172.70.204.86`, a recursive
  resolver. An initial assertion that every protocol must use `43.98.191.120`
  correctly failed eight DNS cases; that failure is retained in `pair-results.json`.
  The separate restart run verifies connectivity and records actual observations
  without asserting a shared exit (`resume-results.json`). No routing was changed.
* Real Chrome ICE/DTLS/SCTP after pairing: signed browser egress
  recorded in local `webrtc-results.json`. This is the browser path,
  distinct from explicit SOCKS traffic.
* Go race tests for server/SDK and existing worker protocol tests pass. New security
  tests cover concurrent redemption, same-CSR retry after restart, wrong/expired
  secrets, invalid CSR, device-purpose issuance, failed persistence, renewal overlap,
  cross-device sessions, old API rejection and revocation over a reused TLS connection.
* Client identity/pairing/lifecycle tests pass, including wrong CA/EKU/expiry/key,
  forged discovery, same-CSR recovery, storage failure, explicit temporary mode and
  interrupted renewal. Actual Keychain read/update/delete also passed.
* Native Avalonia Chinese dark and English light, narrow-window reviews each passed
  28 checks. Configuration remains in its owned dialog.

Remaining platform acceptance: Windows DPAPI and Linux Secret Service runtime tests
and native UI checks on those OSes. Self-contained cross-builds do not prove those
runtime behaviors. macOS actual locked-keychain/denied-consent behavior is covered
by injected failure tests, not by changing the user's live keychain lock policy.

Local artifacts reside under `artifacts/observer-pairing-live-20261025` and
`artifacts/observer-pairing-ui{,-en}-20261025` in the parent workspace. No pairing
secret, API key, device private key, CSR or SDP is included in these reports.
