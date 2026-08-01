# dual-protocol-script

`dual-protocol-script` 把固定的两套代理节点组合与 VPN Gate 志愿家宽出口整合在一台 VPS 上：

- VLESS XHTTP + TLS + Caddy 伪装站 + Hysteria2
- VLESS REALITY Vision + Hysteria2（不安装 Caddy）

节点配置逻辑沿用原两协议脚本；Web 面板负责节点分享、节点参数、面板参数、服务重启、协议组合重装，以及两个协议各自是否使用家宽二次出口。SSH TUI 完整保留，入口命令统一为 `tui`。

## 主要功能

- TLS 加密 Web 面板：复用 HY2 域名证书、随机高位端口、随机路径和随机密码。
- VLESS 与 Hysteria2 可分别使用 VPS 直连或指定 VPN Gate 家宽出口。
- 家宽出口在独立 network namespace 中运行，本机 SOCKS5 只监听 `127.0.0.1`。
- TCP 与目标 UDP（包括手机 DNS）都通过选定家宽出口，解决移动端“有延迟但 DNS 无法解析”的问题。
- 从面板复制或下载主节点与 Hysteria2 分享链接。
- 从面板修改全部节点参数，并可一键随机生成 HY2/Gecko 密码；REALITY 私钥不会下发到浏览器，换钥由服务器生成、推导验证后原子替换。
- 从面板修改面板端口、路径、密码和最大出口数，保存后自动重启面板。
- 从面板一键重装两种协议组合，失败自动恢复节点配置。
- 根据当前组合一键重启 Xray、Hysteria2、Caddy 或当前组合全部服务，并检查 `active` 状态。
- SSH `tui` 仍可管理节点、查看出口、修改面板端口/路径/密码、重启和看日志。

## 节点与域名规则

### XHTTP + HY2

- 必须提供两个不同且都直连 VPS 的域名。
- Caddy 占用 TCP 80/443，为 XHTTP 的 443 特定路径反代并生成伪装网页。
- HY2 使用 Caddy 证书并监听设置的 UDP 单端口或跳跃范围。
- 面板复用 HY2 域名证书，在随机 TCP 高位端口提供 TLS。

### REALITY + HY2

- REALITY 使用 TCP 443，HY2 使用设置的 UDP 端口或跳跃范围。
- 不安装 Caddy；HY2 自行通过 ACME 申请证书。
- HY2 域名必须 DNS-only 直连 VPS；面板继续复用该证书。

域名、证书或健康检查失败时，安装与重装不会被视为成功。

在 Web 面板中更改 XHTTP/HY2 域名时，必须先把新域名正确解析到本 VPS、关闭 Cloudflare/CDN 代理并放行所需端口。服务会先生成候选配置、申请并验证新证书、完成代理健康检查，之后才提交状态并清理不再使用的旧域名证书；失败时保留旧证书并恢复原配置。HY2 域名也是面板 TLS 域名，修改成功后需使用新域名重新打开面板。

## 一键安装

将本目录的所有文件（包括隐藏的 `.github` 目录）上传到仓库根目录后运行：

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/Aki1106-0116/dual-protocol-script/main/install.sh)
```

要求：

- Debian/Ubuntu + systemd
- root
- `/dev/net/tun` 可用
- 域名关闭 Cloudflare 代理并直连 VPS
- 安全组放行安装时所需的 TCP 80/443、HY2 UDP 端口范围，以及安装后显示的面板 TCP 高位端口

安装器优先下载 GitHub Release 的 `amd64`/`arm64` 预编译包；没有 Release 时才从 `main` 源码构建。建议先在 GitHub 创建一个 `v*` tag，让 Actions 自动发布二进制，避免小磁盘 VPS 临时编译 Go。

只更新程序并保留现有节点配置：

```bash
SKIP_NODE_INSTALL=1 bash <(curl -fsSL https://raw.githubusercontent.com/Aki1106-0116/dual-protocol-script/main/install.sh)
```

安装器会自动迁移上一项目名对应的面板状态，并且仅在新服务健康启动后清理旧程序文件。

## 使用

安装结束会输出：

```text
Web 面板  https://你的HY2域名:随机高位端口/随机路径/
访问密码  随机密码
SSH 管理  tui
```

常用命令：

```bash
tui
tui info
tui status
tui restart
tui log
systemctl status dual-protocol-script
```

## 关键文件

| 路径 | 用途 |
|---|---|
| `/etc/jb-combo/state.env` | 原节点安装器状态；为兼容节点 TUI 保留 |
| `/etc/default/dual-protocol-script` | 面板域名、证书、端口、最大出口数 |
| `/var/lib/dual-protocol-script/basepath` | Web 随机路径 |
| `/var/lib/dual-protocol-script/password` | Web 登录密码 |
| `/var/lib/dual-protocol-script/bindings.json` | VLESS/HY2 家宽出口绑定 |
| `/var/lib/dual-protocol-script/tunnels.json` | VPN Gate 出口状态 |
| `/root/jb-combo/main-url.txt` | 主节点分享链接 |
| `/root/jb-combo/hy2-url.txt` | Hysteria2 分享链接 |
| `/usr/local/lib/dual-protocol-script/dual-protocol-node-installer.sh` | 固定上游版本经加固后的节点 TUI/非交互后端 |

## REALITY 换钥安全性

服务使用当前 Xray 的 `x25519` 输出生成候选密钥，再由本项目独立推导公钥并比较；空值、格式异常或公私钥不匹配都会终止。候选配置先执行 Xray `run -test -format json`，随后才原子替换并重启。失败会恢复最后一个可用配置，因此后期再次换钥不会把空密钥写入正式配置。

## 性能开销（经验范围）

Web 面板本身是一个轻量 Go 服务，空闲时一般约 `15–35 MiB` RSS、CPU 接近 0；页面打开后的轮询通常只有几 KB/s。每个活动 VPN Gate/OpenVPN 出口一般再增加约 `8–25 MiB` RSS。因系统、架构、OpenVPN 版本和出口数量不同，一条家宽出口的额外常驻内存通常约 `25–60 MiB`，四条大约 `50–140 MiB`。

协议选择 VPS 直连时，Web 面板几乎不影响转发性能。选择家宽出口后，会多一层 SOCKS5、network namespace 和 OpenVPN 加密，纯本机处理通常带来约 `5–20%` 吞吐损耗；实际速度与延迟更多受志愿节点带宽、负载和地理距离影响，延迟可能增加几十到数百毫秒。

可在服务器实测：

```bash
systemd-cgtop
ps -eo pid,rss,pcpu,comm | grep -E 'dual-protocol|openvpn|xray|hysteria|caddy'
```

## 测试与发布

```bash
go test ./...
go vet ./...
python3 -m unittest discover -s scripts -p 'test_*.py'
bash -n install.sh tui-wrapper.sh sync-panel-tls.sh uninstall.sh
```

推送 `v*` tag 后，GitHub Actions 生成：

- `dual-protocol-script-linux-amd64.tar.gz`
- `dual-protocol-script-linux-arm64.tar.gz`

## 来源与许可

详见 [NOTICE.md](NOTICE.md) 与 [LICENSE](LICENSE)。VPN Gate 节点由第三方志愿者提供，稳定性、隐私与可用性不受本项目保证。
