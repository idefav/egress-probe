# Domain pairing and device authentication (v2 control API)

This upgrade disables legacy Bearer API keys immediately. An old client receives
HTTP 426 on the old control API and must upgrade and pair. Existing observation
signing keys, server IDs and ACME certificates remain unchanged; historical signed
reports remain verifiable. Do not run `-init` to upgrade an existing installation.

## Administrator

Run through a trusted SSH terminal on the observer host:

```sh
sudo egress-probe-server pairing create --expires 10m
sudo egress-probe-server pairing list
sudo egress-probe-server pairing revoke PAIRING_ID
sudo egress-probe-server devices list
sudo egress-probe-server devices revoke DEVICE_ID
```

Copy the complete `EP1.` string to v2rayN's **Configure service** dialog, together
with the displayed domain. The string contains a one-time secret and a SHA-256
fingerprint of the control CA SubjectPublicKeyInfo. Treat it as a credential;
do not include it in tickets, screenshots or diagnostic reports. Expiry is 1–30
minutes (default 10). A lost response can be recovered with the same CSR before
expiry; a different key cannot consume the same pairing again.

Commands connect to `admin.sock` in the configured cache/state directory. It is a
mode-0600 Unix socket, not a public network administration endpoint. The CLI's
optional `--config` argument selects a different server configuration.

## Network and identity

* `api.DOMAIN:443`: public HTTPS discovery, browser page and ticketed probes.
* `control.DOMAIN:443`: private-CA TLS, pairing redemption and authenticated device
  control. The built-in authoritative DNS supplies this hostname automatically.
* Existing probe ports remain unchanged. No new security-group port is needed.
* Control TLS permits TLS 1.2 with ECDHE/ECDSA AEAD suites and TLS 1.3. This supports
  the default macOS .NET SecureTransport backend without disabling certificate checks.
* Discovery at `https://api.DOMAIN/.well-known/egress-probe` is public metadata,
  never a trust grant. The client checks the SSH-supplied CA fingerprint before
  sending the secret over the pinned TLS connection.
* `/v2/capabilities`, `/v2/sessions/...`, `/v2/devices/self/renew` and DELETE
  `/v2/devices/self` require device mTLS. Every request checks persisted device
  status, including requests over already established TLS connections.

The private CA is valid for five years. Server and device certificates are valid
for at most 90 days (also bounded by CA expiry). Server certificates renew during
TLS setup below 30 days remaining. Clients renew on use below 30 days remaining;
the old certificate has at most 24 hours of overlap. An expired device must pair
again. CA rotation requires explicit re-pairing.

## Persistence, limits and backup

`device-auth.json` contains the private CA, server certificate/key, hashed pairing
secrets, issued device certificates and revocation state. It is atomically replaced
with mode 0600, file and directory fsync, and process-local serialization. Back up
this file together with the original configuration and ACME cache into a root-only
location. Do not delete it or restore an old copy casually: restoring old state
can resurrect devices revoked after that backup.

The service limits active pairing records to 64, device records to 1024, sessions
to four per device and 128 globally. Pairing attempts have global and source-IP
limits; authenticated control requests have device limits. Audit events contain
event types and opaque device IDs, not secrets/CSRs/SDP. The supplied systemd unit
rate-limits journal output; normal host journal size/retention limits also apply.

An upgrade backup must retain the current binary and systemd unit as well as state.
Rolling back to the old binary re-enables its old authentication behavior; document
that explicitly if a rollback becomes necessary.

## Security boundary

The CA is private to this application; it is not installed in OS trust stores.
Observation signatures still use the independent original ECDSA P-256 key.
Public probes and browser WebRTC use short-lived, device-owned tickets, never the
device private key. TCP/HTTP/UDP/DNS probes remain plaintext where their protocol
is plaintext; ticket interception and replay within the validity window remain
possible. Host compromise exposes file-protected server keys; this is not an HSM.
