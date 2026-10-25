# egress-probe

Private multi-protocol egress observer for v2rayN. The server runs independently of proxy exits and reports the actual socket peer for each nonce-bound sample. Source is public; control access requires a paired device certificate (mTLS). Never commit generated configuration, private keys or pairing strings. Legacy API Key authentication is disabled.

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
| Browser WebRTC | UDP 3480 | Real ICE → DTLS → SCTP DataChannel, signed peer address |

This release is IPv4 only. An AAAA answer is test data (`2001:db8::1`), not proof of IPv6 transport. A system/local recursive resolver query identifies the **recursive resolver reaching the authority**, not the client's source IP to that resolver. Browser WebRTC is a separate explicit check described below. Browser DoH, kill switches, MTU and arbitrary Internet targets are outside coverage.

The observation server must differ from the exit under test. If using the US machine as observer, do not certify that US machine's own proxy exit with it. Use another independent observer for that path. Control HTTPS requests do not establish the egress of any data probe.

## Deploy on Linux

Use a dedicated public IPv4 host without a CDN, HTTP reverse proxy or source-NATing container bridge. Nothing in this deployment replaces SSH, changes SSH listeners or modifies proxy configuration. Existing services must not occupy any required port. Inspect first:

```sh
sudo ss -lntup
```

Allow inbound TCP **53, 80, 443, 18080, 18443** and UDP **53, 443, 3478, 3479, 3480** in both cloud security groups and the host firewall. UDP 3480 is the WebRTC ICE/DTLS/SCTP endpoint. Keep the existing management SSH port. ACME also needs outbound DNS and HTTPS.

### 安全组与防火墙端口清单

以下为探测服务的入站端口，TCP 和 UDP 必须分别配置；保留原管理 SSH 端口，不替换 SSH 服务。

| 协议 | 端口 | 用途 |
| --- | --- | --- |
| TCP + UDP | 53 | 测试子域的权威 DNS；TCP 用于截断重试 |
| TCP | 80 | HTTP 探测、ACME HTTP-01 证书签发与续期 |
| TCP | 443 | HTTPS、公开发现、浏览器页面、配对与 mTLS 控制接口 |
| UDP | 443 | 真实 QUIC / HTTP3，无 TCP 回退 |
| TCP | 18080 | 原始 TCP 签名回显 |
| TCP | 18443 | TLS 握手与签名回显 |
| UDP | 3478 | 带短期票据的私有 STUN |
| UDP | 3479 | 普通 UDP 双向探测 |
| UDP | 3480 | 浏览器 WebRTC 数据通道；不需要 TCP 3480 |

云安全组和系统防火墙都要放行。探测源可能是代理出口、递归 DNS 或浏览器公网地址，
若按来源 IP 限制，需要覆盖这些实际来源。权威 DNS 需允许公共递归解析器访问。
出站需允许系统 DNS 解析、ACME HTTPS（TCP 443）及已允许入站流量的响应。
服务端管理命令仅使用本地 Unix socket，不需要开放额外管理端口。

Delegate `check.example.net` to `ns.check.example.net`, with parent glue A pointing to the observer IPv4. Replace both placeholders below. The built-in authority serves A records for `api`, `control`, `http`, `h3`, `tcp`, `tls`, `udp`, `stun`, and `ns`. Only the test zone is authoritative; it is not an open recursive resolver. QNAME minimization and zero-TTL test names are supported.

在父域 `example.net` 的 DNS 控制台添加：

| 类型 | 主机记录 | 记录值 |
| --- | --- | --- |
| A | `ns.check` | 探测服务器公网 IPv4 |
| NS | `check` | `ns.check.example.net` |

域内 NS 名称需要父域提供 glue 地址；确认 DNS 提供商在委派响应中返回该地址。
不要开启 CDN 代理。`api.check.example.net` 与 `control.check.example.net` 由本服务解析，
不需要在父域分别添加 A 记录。公网 IP 与服务器网卡 IP 不同时，按下文设置 `-listen-ip`。

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

### 配对 v2rayN

在服务器可信 SSH 终端执行：

```sh
sudo egress-probe-server pairing create --expires 10m
```

复制输出的完整 `EP1.` 配对串，在 v2rayN 的 **代理检查 → 配置服务** 弹窗填写
`check.example.net`、配对串和设备名称，点击“配对并连接”。无需手填端口、导入 JSON
或复制长期 API Key。配对串包含一次性秘密和控制 CA 公钥指纹，默认 10 分钟有效；
不要发到聊天、工单或截图中。客户端校验域名和 CA 后才发送秘密，私钥在本地生成。

```sh
sudo egress-probe-server pairing list
sudo egress-probe-server pairing revoke PAIRING_ID
sudo egress-probe-server devices list
sudo egress-probe-server devices revoke DEVICE_ID
```

`api.DOMAIN:443` 使用公共可信 HTTPS；`control.DOMAIN:443` 使用应用私有 CA，
通过 SNI 共用 TCP 443。不要向系统信任库导入私有 CA，也不要用忽略证书错误的方式连接。
设备证书保存在 macOS Keychain、Windows 当前用户 DPAPI 或 Linux Secret Service。
安全存储不可用时仅可明确选择“仅本次使用”，下次启动需重新配对。
详细续期、撤销、限制与备份说明见 [配对管理](deploy/pairing.md)。

If a system DNS stub already listens on loopback port 53, keep it running and pass `-listen-ip <local-interface-ip>` when initializing. This writes `listenIP` in the private config and binds all probe listeners to that interface. On a cloud host behind public IPv4 NAT, use the interface's private address for `listenIP` and the public address for `-ipv4`. Omitting `listenIP` preserves the default wildcard listener. Do not put the public address in `listenIP` unless it is actually assigned to a local interface.

## v2rayN usage

Use the matching `feature/precise-egress-observer` client and pair in the Configure service dialog as described above. Successful persistent pairing survives application restarts. Full checks independently exercise native/TUN, SOCKS5, HTTP CONNECT and actual system HTTP paths. HTTP CONNECT UDP is unsupported, with no direct fallback. Start Browser WebRTC explicitly to check the real browser path; see [WebRTC deployment and limits](deploy/webrtc.md).

Configure expected IP/CIDR globally or per target. A scoped rule is `target|protocol|path=IP/CIDR`, for example `udp.check.example.net:3479|udp|socks=198.51.100.4`. Precedence is scoped target, exact target, endpoint, hostname, global. Three samples are retained individually. One confirmed mismatch remains a mismatch even if other samples time out. No expectation means observed-but-not-compared, not proof of correct proxying.

## Security and limits

Control endpoints require device mTLS; pairing redemption instead uses a pinned TLS server plus the one-time pairing secret. Legacy control API requests receive HTTP 426 and must upgrade; no API Key fallback exists. Sessions last ten minutes, tickets three minutes, observations are retained for up to thirty minutes and may be explicitly deleted. Defaults: four active sessions per device, 128 retained sessions globally, 512 probes/session, eight records/probe, 32 concurrent stream connections, and a global 200-request/packet-per-second ceiling. Device ownership and revocation are checked on control requests; revocation cancels the device's probe sessions and WebRTC connections. There is no user-management UI or forwarding API.

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

Before upgrading, stop only `egress-probe.service` long enough to take a consistent root-only backup of the binary, systemd unit, `/etc/egress-probe` and `/var/lib/egress-probe` (including `device-auth.json` and ACME cache). Install the verified replacement, reload systemd if the unit changed, restart that unit and check control/protocol health. **Do not run `-init` again.** Preserve the signing key, server ID, control CA and revocation state. Restoring old auth state can resurrect revoked devices; reverting to the pre-pairing binary re-enables its old API Key behavior.

部署后先验证 DNS 和公共 HTTPS，再配对并逐项检查：

```sh
dig NS check.example.net
dig A api.check.example.net
dig A control.check.example.net
dig @203.0.113.10 check.example.net SOA +tcp
curl --fail https://api.check.example.net/.well-known/egress-probe
```

无票据访问探测回显路径返回 403 是预期行为。端口可达和 HTTPS 预热不等于完整协议验收；
HTTP3 必须实际协商 h3，WebRTC 必须完成浏览器数据通道，DNS 必须区分递归解析器与客户端出口。

```sh
sudo systemctl disable --now egress-probe.service
sudo rm /etc/systemd/system/egress-probe.service
sudo systemctl daemon-reload
```

Keep private config/backups until no longer needed, then remove them separately. This procedure does not touch SSH or the running v2rayN client.
