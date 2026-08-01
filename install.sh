#!/usr/bin/env bash
set -Eeuo pipefail

REPO="${REPO:-Aki1106-0116/dual-protocol-script}"
WEB_PORT="${WEB_PORT:-}"
MAX_EXITS="${MAX_EXITS:-12}"
FORCE_SOURCE="${FORCE_SOURCE:-0}"
WORK_DIR="${WORK_DIR:-/var/lib/dual-protocol-script}"
BIN="/usr/local/bin/dual-protocol-script"
LIB_DIR="/usr/local/lib/dual-protocol-script"
SERVICE_NAME="dual-protocol-script"
LEGACY_NAME="j""b-gateway"
LEGACY_WORK="/var/lib/${LEGACY_NAME}"
LEGACY_LIB="/usr/local/lib/${LEGACY_NAME}"
LEGACY_BIN="/usr/local/bin/${LEGACY_NAME}"
LEGACY_TUI="/usr/local/bin/j""b"
LEGACY_ENV="/etc/default/${LEGACY_NAME}"
LEGACY_SERVICE="/etc/systemd/system/${LEGACY_NAME}.service"
UPSTREAM_COMMIT="${UPSTREAM_COMMIT:-68d15b2397bb8df8f058c004c29ac6872fded09d}"
UPSTREAM_URL="https://raw.githubusercontent.com/Aki1106-0116/Three-Protocol-Script/${UPSTREAM_COMMIT}/jb-combo-installer.sh"
UPSTREAM_SHA256="${UPSTREAM_SHA256:-9aa4cefdd1325794a446d458766901be7c6781de9d4262d12fcac9766c016877}"

log() { printf '\033[0;34m==>\033[0m %s\n' "$*" >&2; }
ok() { printf '\033[0;32m✓\033[0m %s\n' "$*" >&2; }
die() { printf '\033[0;31m✗\033[0m %s\n' "$*" >&2; exit 1; }

[[ "${EUID}" -eq 0 ]] || die "需要 root 权限"
[[ -f /etc/os-release ]] || die "无法识别系统"
# shellcheck disable=SC1091
. /etc/os-release
case "${ID:-}" in debian|ubuntu) ;; *) die "仅支持 Debian / Ubuntu + systemd" ;; esac
command -v systemctl >/dev/null || die "未检测到 systemd"

log "安装系统依赖"
apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
  ca-certificates curl openssl openvpn iproute2 iptables python3 tar unzip uuid-runtime \
  acl procps lsof gnupg debian-keyring debian-archive-keyring

[[ -c /dev/net/tun ]] || die "/dev/net/tun 不可用；请先在 VPS/LXC 控制台开放 TUN"
mkdir -p "$WORK_DIR" "$LIB_DIR"
if [[ -d "$LEGACY_WORK" && ! -s "$WORK_DIR/basepath" ]]; then
  log "迁移旧版本面板状态"
  cp -a "$LEGACY_WORK/." "$WORK_DIR/"
fi
if [[ -s "$LEGACY_ENV" && ! -s /etc/default/dual-protocol-script ]]; then
  cp -a "$LEGACY_ENV" /etc/default/dual-protocol-script
fi
chmod 700 "$WORK_DIR" "$LIB_DIR"

ARCH="$(uname -m)"
case "$ARCH" in
  x86_64) GOARCH=amd64 ;;
  aarch64|arm64) GOARCH=arm64 ;;
  *) die "不支持的 CPU 架构：$ARCH" ;;
esac

SOURCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd || true)"
ASSET_DIR=""
BOOTSTRAP_TEMP=""

go_is_compatible() {
  local go_bin="$1" version major minor
  version="$("$go_bin" env GOVERSION 2>/dev/null || true)"
  [[ "$version" =~ ^go([0-9]+)\.([0-9]+) ]] || return 1
  major="${BASH_REMATCH[1]}"
  minor="${BASH_REMATCH[2]}"
  (( major > 1 || (major == 1 && minor >= 18) ))
}

cleanup_bootstrap_temp() {
  local resolved_temp resolved_work
  [[ -n "$BOOTSTRAP_TEMP" ]] || return 0
  resolved_temp="$(readlink -f -- "$BOOTSTRAP_TEMP" 2>/dev/null || true)"
  resolved_work="$(readlink -f -- "$WORK_DIR" 2>/dev/null || true)"
  if [[ -n "$resolved_temp" && -n "$resolved_work" \
    && "$resolved_temp" == "$resolved_work"/bootstrap.* ]]; then
    rm -rf -- "$resolved_temp"
    BOOTSTRAP_TEMP=""
  else
    log "安全检查未通过，未清理安装临时目录：$BOOTSTRAP_TEMP"
  fi
}

download_official_go() {
  local temp="$1" metadata go_info go_version go_filename go_sha go_archive
  local available_kb extract_log

  log "服务器没有 Go 1.18+，获取 Go 官方临时工具链 (${GOARCH})"
  available_kb="$(df -Pk "$temp" 2>/dev/null | awk 'NR == 2 {print $4}')"
  if [[ "$available_kb" =~ ^[0-9]+$ ]] && (( available_kb < 327680 )); then
    df -h "$temp" >&2 || true
    die "源码编译所在磁盘可用空间不足 320 MiB；请清理空间，或先用 GitHub Actions 创建 Release"
  fi

  metadata="$temp/go-downloads.json"
  curl -fsSL --retry 3 'https://go.dev/dl/?mode=json' -o "$metadata" \
    || die "无法从 go.dev 获取 Go 发行版元数据"

  go_info="$(
    python3 - "$metadata" "$GOARCH" <<'PY'
import json
import re
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    releases = json.load(handle)

arch = sys.argv[2]
for release in releases:
    if not release.get("stable"):
        continue
    version = release.get("version", "")
    if not re.fullmatch(r"go[0-9]+\.[0-9]+(?:\.[0-9]+)?", version):
        continue
    for item in release.get("files", []):
        if (
            item.get("os") == "linux"
            and item.get("arch") == arch
            and item.get("kind") == "archive"
            and re.fullmatch(
                rf"{re.escape(version)}\.linux-{re.escape(arch)}\.tar\.gz",
                item.get("filename", ""),
            )
            and re.fullmatch(r"[0-9a-f]{64}", item.get("sha256", ""))
        ):
            print(version, item["filename"], item["sha256"], sep="\t")
            raise SystemExit(0)

raise SystemExit("没有找到匹配的稳定版 Go Linux 工具链")
PY
  )" || die "无法解析 Go 官方发行版元数据"

  IFS=$'\t' read -r go_version go_filename go_sha <<<"$go_info"
  [[ -n "$go_version" && -n "$go_filename" && -n "$go_sha" ]] \
    || die "Go 官方发行版元数据不完整"

  go_archive="$temp/$go_filename"
  curl -fsSL --retry 3 "https://go.dev/dl/${go_filename}" -o "$go_archive" \
    || die "下载 Go 官方工具链失败：$go_filename"
  printf '%s  %s\n' "$go_sha" "$go_archive" | sha256sum -c - >/dev/null \
    || die "Go 官方工具链 SHA256 校验失败"

  mkdir -p "$temp/toolchain"
  extract_log="$temp/go-extract.log"
  if ! tar --no-same-owner -xzf "$go_archive" -C "$temp/toolchain" 2>"$extract_log"; then
    log "tar 原始错误如下："
    sed -n '1,40p' "$extract_log" >&2 || true
    log "临时目录的磁盘与 inode 状态："
    df -h "$temp" >&2 || true
    df -i "$temp" >&2 || true
    die "解压 Go 官方工具链失败；诊断文件保留在 $extract_log"
  fi
  rm -f -- "$go_archive"
  [[ -x "$temp/toolchain/go/bin/go" ]] || die "Go 官方工具链内容不完整"
  go_is_compatible "$temp/toolchain/go/bin/go" \
    || die "Go 官方工具链版本低于项目要求的 Go 1.18"
  printf '%s' "$temp/toolchain/go/bin/go"
}

install_gateway_binary() {
  local temp release_url source_url source_root go_bin=""

  if [[ -n "$SOURCE_DIR" && -f "$SOURCE_DIR/main.go" && -f "$SOURCE_DIR/go.mod" ]] \
    && command -v go >/dev/null 2>&1 && go_is_compatible "$(command -v go)"; then
    log "从本地源码构建 dual-protocol-script"
    (cd "$SOURCE_DIR" && CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o "$BIN" .)
    chmod 755 "$BIN"
    ASSET_DIR="$SOURCE_DIR"
    return
  fi

  temp="$(mktemp -d "$WORK_DIR/bootstrap.XXXXXX")" \
    || die "无法在 $WORK_DIR 创建安装临时目录"
  BOOTSTRAP_TEMP="$temp"
  if [[ "$FORCE_SOURCE" == "1" ]]; then
    log "FORCE_SOURCE=1：跳过可能滞后的 Release，强制构建 main 分支源码"
  else
    log "下载 dual-protocol-script 预编译版本 (${GOARCH})"
    release_url="https://github.com/${REPO}/releases/latest/download/dual-protocol-script-linux-${GOARCH}.tar.gz"
    if curl -fsSL --retry 2 "$release_url" -o "$temp/release.tar.gz" \
      && tar xzf "$temp/release.tar.gz" -C "$temp" \
      && [[ -x "$temp/dual-protocol-script" ]]; then
      install -m 755 "$temp/dual-protocol-script" "$BIN"
      ASSET_DIR="$temp"
      return
    fi
  fi

  log "改用仓库 main 源码"
  if [[ -n "$SOURCE_DIR" && -f "$SOURCE_DIR/main.go" && -f "$SOURCE_DIR/go.mod" ]]; then
    source_root="$SOURCE_DIR"
  else
    source_root="$temp/source"
    source_url="https://github.com/${REPO}/archive/refs/heads/main.tar.gz?cachebust=$(date +%s)"
    mkdir -p "$source_root"
    curl -fsSL --retry 3 "$source_url" -o "$temp/source.tar.gz" \
      || die "Release 与 main 源码均下载失败，请检查仓库地址或网络：$REPO"
    tar xzf "$temp/source.tar.gz" -C "$source_root" --strip-components=1 \
      || die "仓库源码包解压失败"
  fi
  [[ -f "$source_root/main.go" && -f "$source_root/go.mod" ]] \
    || die "仓库 main 分支缺少 main.go 或 go.mod：$REPO"

  if command -v go >/dev/null 2>&1 && go_is_compatible "$(command -v go)"; then
    go_bin="$(command -v go)"
  else
    go_bin="$(download_official_go "$temp")"
  fi

  log "从源码构建 dual-protocol-script（$("$go_bin" env GOVERSION)）"
  (
    cd "$source_root"
    GOCACHE="$temp/go-build-cache" \
      GOMODCACHE="$temp/go-mod-cache" \
      CGO_ENABLED=0 \
      "$go_bin" build -trimpath -ldflags "-s -w" -o "$BIN" .
  ) \
    || die "dual-protocol-script 源码编译失败"
  chmod 755 "$BIN"
  ASSET_DIR="$source_root"
}

install_gateway_binary
ok "$("$BIN" -version)"

resolve_asset() {
  local name="$1" base="" local_path=""
  for base in "$ASSET_DIR" "$SOURCE_DIR"; do
    [[ -n "$base" ]] || continue
    for local_path in "$base/$name" "$base/scripts/$name"; do
      [[ -f "$local_path" ]] && { printf '%s' "$local_path"; return 0; }
    done
  done
  return 1
}

SYNC_ASSET="$(resolve_asset sync-panel-tls.sh || true)"
[[ -n "$SYNC_ASSET" ]] || die "发布包缺少 sync-panel-tls.sh"
install -m 755 "$SYNC_ASSET" "$LIB_DIR/sync-panel-tls.sh"

log "准备经过加固的两协议节点安装器"
ORIGINAL="$LIB_DIR/dual-protocol-node-installer.upstream.sh"
PATCHED="$LIB_DIR/dual-protocol-node-installer.sh"
PATCHER="$(resolve_asset harden_node_installer.py || true)"
if [[ -z "$PATCHER" ]]; then
  PATCHER="$LIB_DIR/harden_node_installer.py"
  curl -fsSL "https://raw.githubusercontent.com/${REPO}/main/scripts/harden_node_installer.py?cachebust=$(date +%s)" -o "$PATCHER"
fi
curl -fsSL "$UPSTREAM_URL" -o "$ORIGINAL"
ACTUAL_UPSTREAM_SHA256="$(sha256sum "$ORIGINAL" | awk '{print $1}')"
[[ "$ACTUAL_UPSTREAM_SHA256" == "$UPSTREAM_SHA256" ]] \
  || die "固定版本节点脚本哈希不匹配，拒绝执行"
python3 "$PATCHER" "$ORIGINAL" "$PATCHED"
bash -n "$PATCHED" || die "加固后的节点安装器未通过 bash -n"
if [[ "$(readlink -f "$PATCHER")" != "$(readlink -f "$LIB_DIR/harden_node_installer.py")" ]]; then
  install -m 755 "$PATCHER" "$LIB_DIR/harden_node_installer.py"
else
  chmod 755 "$PATCHER"
fi

if [[ "${SKIP_NODE_INSTALL:-0}" != "1" ]]; then
  log "进入节点组合安装：只提供 XHTTP+HY2 或 REALITY+Vision+HY2"
  "$PATCHED"
else
  log "SKIP_NODE_INSTALL=1：跳过交互式节点安装，保留现有节点配置"
fi

[[ -s /usr/local/etc/xray/config.json || "${SKIP_NODE_INSTALL:-0}" == "1" ]] \
  || die "节点配置没有生成，网关服务不会启动"
[[ -s /etc/hysteria/config.yaml || "${SKIP_NODE_INSTALL:-0}" == "1" ]] \
  || die "Hysteria2 配置没有生成，网关服务不会启动"

if [[ "${SKIP_NODE_INSTALL:-0}" != "1" ]]; then
  log "复用 HY2 直连域名证书并生成随机 TLS 面板端口"
  sync_args=(--max "$MAX_EXITS")
  [[ -n "$WEB_PORT" ]] && sync_args+=(--port "$WEB_PORT")
  "$LIB_DIR/sync-panel-tls.sh" "${sync_args[@]}"
  # shellcheck disable=SC1091
  source /etc/default/dual-protocol-script
else
  if [[ -r /etc/default/dual-protocol-script ]]; then
    # shellcheck disable=SC1091
    source /etc/default/dual-protocol-script
  else
    log "现有节点尚无面板环境配置，正在从 HY2 证书生成"
    sync_args=(--max "$MAX_EXITS")
    [[ -n "$WEB_PORT" ]] && sync_args+=(--port "$WEB_PORT")
    "$LIB_DIR/sync-panel-tls.sh" "${sync_args[@]}"
    # shellcheck disable=SC1091
    source /etc/default/dual-protocol-script
  fi
fi

log "安装 systemd 服务与 SSH TUI"
SERVICE="$(resolve_asset dual-protocol-script.service || true)"
WRAPPER="$(resolve_asset tui-wrapper.sh || true)"
[[ -n "$SERVICE" && -n "$WRAPPER" ]] || die "发布包缺少 service/wrapper"
install -m 644 "$SERVICE" /etc/systemd/system/dual-protocol-script.service
install -m 755 "$WRAPPER" "$LIB_DIR/tui-wrapper.sh"
install -m 755 "$WRAPPER" /usr/local/bin/tui

sysctl -qw net.ipv4.ip_forward=1
grep -q '^net.ipv4.ip_forward=1$' /etc/sysctl.conf 2>/dev/null \
  || printf '%s\n' 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf
if ! iptables -C FORWARD -s 10.98.0.0/16 -j ACCEPT 2>/dev/null; then
  iptables -I FORWARD 1 -s 10.98.0.0/16 -j ACCEPT
fi
if ! iptables -C FORWARD -d 10.98.0.0/16 -j ACCEPT 2>/dev/null; then
  iptables -I FORWARD 1 -d 10.98.0.0/16 -j ACCEPT
fi

systemctl disable --now "$LEGACY_NAME" >/dev/null 2>&1 || true
systemctl daemon-reload
systemctl enable --now "$SERVICE_NAME"
sleep 3
systemctl is-active --quiet "$SERVICE_NAME" || {
  journalctl -u "$SERVICE_NAME" -n 100 --no-pager >&2
  die "dual-protocol-script 启动失败"
}

# Only remove fixed legacy program paths after the renamed service is healthy.
rm -f -- "$LEGACY_SERVICE" "$LEGACY_ENV" "$LEGACY_BIN" "$LEGACY_TUI"
rm -rf -- "$LEGACY_LIB" "$LEGACY_WORK"
systemctl daemon-reload

BASE="$(tr -d '\r\n /' < "$WORK_DIR/basepath" 2>/dev/null || true)"
PASSWORD="$(tr -d '\r\n' < "$WORK_DIR/password" 2>/dev/null || true)"
cleanup_bootstrap_temp || log "安装临时目录清理失败：$BOOTSTRAP_TEMP"
echo
ok "安装完成"
echo "  Web 面板  https://${PANEL_DOMAIN}:${WEB_PORT}/${BASE}/"
echo "  访问口令  ${PASSWORD:-服务首次启动后见 ${WORK_DIR}/password}"
echo "  SSH 管理  tui"
echo
echo "请在 VPS 防火墙/安全组放行 TCP ${WEB_PORT}；${PANEL_DOMAIN} 必须保持 DNS-only 直连，不能开启 Cloudflare 代理。"
echo "节点参数可在 tui → 节点配置 TUI 或 Web 面板中修改；REALITY 私钥不会发送到浏览器。"
echo "Web 面板还可管理 VLESS/HY2 是否走家宽，以及绑定哪一个 VPN Gate 出口。"
