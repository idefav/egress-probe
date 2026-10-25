# check.idefav.com 部署记录

日期：2026-10-25，Asia/Shanghai。

## 服务器与域名

- 观察端公网 IPv4：47.77.201.36，美国；本机 eth0：172.26.178.114。
- 平台：Linux amd64，Ubuntu，systemd。
- 测试域：check.idefav.com。
- 父域 NS 委派：check.idefav.com → ns.check.idefav.com。
- Glue A：ns.check.idefav.com → 47.77.201.36。
- 直接监听网卡地址，保留 systemd-resolved 的回环 TCP/UDP 53 和现有 SSH 22。

## 文件与服务

- 程序：/usr/local/bin/egress-probe-server。
- 配置：/etc/egress-probe/config.json，0600，egress-probe 所有。
- 客户端公钥配置：/etc/egress-probe/profile.json，不含 API 凭证或签名私钥。
- ACME 缓存：/var/lib/egress-probe/certificates，服务自动签发、缓存和续期。
- systemd 单元：/etc/systemd/system/egress-probe.service，User/Group 为 egress-probe。
- 原上传暂存目录：/root/egress-probe-install-20261025。

新部署初始化参数为 `-domain check.idefav.com -ipv4 47.77.201.36 -listen-ip 172.26.178.114`。**本机配置已生成，维护或升级时不得重复初始化或覆盖签名密钥。**

以下 WebRTC 记录为历史验收。随后已升级域名配对与 mTLS，实际部署版本及备份见 [配对升级验收](pairing-acceptance-20261025.md)。源码后续 Review 修复不代表已自动部署，部署时应核对二进制 SHA-256。

## 网络入口

| 类型 | 端口 |
| --- | --- |
| TCP | 53、80、443、18080、18443 |
| UDP | 53、443、3478、3479、3480（WebRTC） |

用户已确认全部安全组端口放行。DNS 从本机和独立香港服务器查询均成功，Google 公共递归解析也已取得正确 A 记录。HTTP 80 的无票据请求返回 403 是预期行为；真实探测使用受认证控制接口签发的短期票据。

WebRTC 首次 Chrome 验收返回信令 400，定位为 systemd 的 `RestrictAddressFamilies` 缺少 `AF_NETLINK`。已在单元中补上 ICE 网卡/路由枚举所需的地址族，保留非 root 身份和仅 `CAP_NET_BIND_SERVICE` 的能力限制。详见 [WebRTC 维护与覆盖边界](webrtc.md)。

API、TLS、HTTP3 的证书已实际签发并通过正常信任链校验。预热 HTTP3 主机的 TCP HTTPS 仅用于证书准备；HTTP3 验收必须另行发送 QUIC/HTTP3 流量并验证签名回执中的 h3 ALPN。

## 资源与维护

机器实际内存约 401 MiB，原无 swap，vm.swappiness 为 0。部署时观测到 OOM 杀进程、PID 1 等待磁盘页、I/O 等待 74%–95%，导致 SSH 认证和 systemctl 命令长时间不返回。为部署验收增加了专用 1 GiB `/swapfile-egress-probe`（root，0600），并仅在当前运行期将 vm.swappiness 改为 60。

**未修改 fstab 或 sysctl 持久配置。重启后这项临时资源缓解不会自动重新启用。** 服务的开机自启与临时 swap 是两件不同的事。后续应明确决定持久化资源方案，再将本机作为长期稳定观察端使用。

回滚临时参数前先确认可用内存足以容纳已换出的页；内存不足时不能直接 swapoff。原参数值为 `vm.swappiness=0`。不要为了诊断该服务而替换管理 SSH 或重启整机。

旧 API Key 控制认证已停用。在可信 SSH 终端运行 `sudo egress-probe-server pairing create --expires 10m`，将完整配对串填入 v2rayN“配置服务”弹窗。不要将配对串或私有配置提交 Git、写入报告或聊天。完整步骤和端口清单见 [README](../README.md)。

该观察端为 IPv4；合成 AAAA 响应不等于 IPv6 传输验收。不得用本观察端验收它自身所在的 47.77.201.36 代理出口。

## 验收证据

工作区 artifacts/egress-probe-us-deploy-20261025 中保留 public profile、验收驱动、签名校验工具及分采样报告；没有保存 API 凭证。最终协议结果应以 acceptance-results.json 为准，不能将端口监听或证书预热等同于全链路验收。

原多协议完整验收共 90 次：SOCKS 45/45 通过；普通套接字 42/45 通过，3 次 UDP 回包超时保留在报告中。DNS 权威侧看到的递归解析器出口与数据流出口不能混为一谈。

修复 systemd 后，macOS Chrome 155 真实 WebRTC 三次双向 DataChannel 和签名验证全部通过；具体浏览器公网地址仅保留在本地验收报告，host 候选使用 `.local` mDNS 隐私地址。它与先前 SOCKS 数据流出口不同；这是本次浏览器路径的观测，不代表出口匹配。匹配必须由 v2rayN 配置预期 IP/CIDR 后独立判断。WebRTC 报告为 `webrtc-acceptance-results.json`，升级后既有协议抽检为 `post-webrtc-smoke-results.json`。
