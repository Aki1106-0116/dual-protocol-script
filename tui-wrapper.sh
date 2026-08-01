#!/usr/bin/env bash
set -u

WORK_DIR="${WORK_DIR:-/var/lib/dual-protocol-script}"
NODE_SCRIPT="${NODE_SCRIPT:-/usr/local/lib/dual-protocol-script/dual-protocol-node-installer.sh}"
APP_BIN="${APP_BIN:-/usr/local/bin/dual-protocol-script}"
SYNC_SCRIPT="${SYNC_SCRIPT:-/usr/local/lib/dual-protocol-script/sync-panel-tls.sh}"
ENV_FILE="/etc/default/dual-protocol-script"
SERVICE="dual-protocol-script"

green='\033[0;32m'; yellow='\033[1;33m'; nc='\033[0m'

need_root() {
  [[ "${EUID}" -eq 0 ]] || { echo "请用 root 运行：sudo tui" >&2; exit 1; }
}

read_env() {
  WEB_PORT=""; MAX_EXITS=12; PANEL_DOMAIN=""; TLS_CERT=""; TLS_KEY=""
  if [[ -f "$ENV_FILE" ]]; then
    # shellcheck disable=SC1090
    source "$ENV_FILE"
  fi
}

show_info() {
  read_env
  local base password active
  base="$(tr -d '\r\n /' < "${WORK_DIR}/basepath" 2>/dev/null || true)"
  password="$(tr -d '\r\n' < "${WORK_DIR}/password" 2>/dev/null || true)"
  active="$(systemctl is-active "$SERVICE" 2>/dev/null || true)"
  echo
  echo "  面板服务    ${active:-unknown}"
  echo "  管理地址    https://${PANEL_DOMAIN:-<HY2-DOMAIN>}:${WEB_PORT:-<TLS-PORT>}/${base}/"
  echo "  访问密码    ${password:-见 ${WORK_DIR}/password}"
  echo "  最大出口    ${MAX_EXITS}"
  echo "  TLS 证书    ${TLS_CERT:-未配置}"
  echo
}

node_menu() {
  [[ -x "$NODE_SCRIPT" ]] || { echo "节点安装器不存在：$NODE_SCRIPT" >&2; return 1; }
  "$NODE_SCRIPT" menu
  local rc=$?
  (( rc == 0 )) || return "$rc"
  if [[ -x "$SYNC_SCRIPT" ]]; then
    "$SYNC_SCRIPT" --restart || {
      echo -e "${yellow}节点已更新，但 TLS 面板证书同步失败；请检查 HY2 域名证书与日志。${nc}" >&2
      return 1
    }
  fi
  if [[ -x "$APP_BIN" ]]; then
    "$APP_BIN" apply || echo -e "${yellow}节点已保存，但家宽出口路由暂未恢复；服务会自动重试。${nc}" >&2
  fi
  return "$rc"
}

change_port() {
  read_env
  local port
  read -r -p "新的 Web TLS 高位端口 [当前 ${WEB_PORT}]: " port
  port="${port:-$WEB_PORT}"
  [[ "$port" =~ ^[0-9]+$ ]] && (( port >= 10240 && port <= 65535 )) || { echo "端口必须在 10240-65535" >&2; return 1; }
  if [[ "$port" != "$WEB_PORT" ]] && ss -H -ltn 2>/dev/null | awk -v suffix=":${port}" '$4 ~ suffix"$" { found=1 } END { exit !found }'; then
    echo "TCP $port 已被占用" >&2; return 1
  fi
  "$SYNC_SCRIPT" --port "$port" --restart
}

change_password() {
  local password
  read -r -p "新访问密码 [回车随机生成]: " password
  password="${password:-$(openssl rand -hex 12)}"
  [[ ${#password} -ge 8 && ${#password} -le 128 ]] || { echo "密码长度必须为 8-128" >&2; return 1; }
  printf '%s\n' "$password" > "${WORK_DIR}/password"
  chmod 600 "${WORK_DIR}/password"
  systemctl restart "$SERVICE"
  echo "新密码：$password"
}

change_path() {
  local path
  read -r -p "新随机访问路径 [回车随机生成]: " path
  path="${path:-$(openssl rand -hex 12)}"; path="${path//\//}"
  [[ "$path" =~ ^[A-Za-z0-9_-]{6,64}$ ]] || { echo "路径只能含字母、数字、_、-，长度 6-64" >&2; return 1; }
  printf '%s\n' "$path" > "${WORK_DIR}/basepath"
  chmod 600 "${WORK_DIR}/basepath"
  systemctl restart "$SERVICE"
}

menu() {
  need_root
  while true; do
    show_info
    echo "=========== Dual Protocol Script SSH 管理 ==========="
    echo "  1) 节点配置 TUI（域名/证书/路径/密钥/端口）"
    echo "  2) 查看协议出口状态"
    echo "  3) 重启全部服务"
    echo "  4) 查看面板日志"
    echo "  5) 修改 Web TLS 高位端口"
    echo "  6) 修改 Web 访问密码"
    echo "  7) 修改 Web 随机路径"
    echo "  8) 查看连接信息"
    echo "  0) 退出"
    read -r -p "请选择: " choice
    case "$choice" in
      1) node_menu ;;
      2) "$APP_BIN" status ;;
      3)
        systemctl restart xray hysteria-server >/dev/null 2>&1 || true
        systemctl is-enabled --quiet caddy 2>/dev/null && systemctl restart caddy >/dev/null 2>&1 || true
        systemctl restart "$SERVICE"
        echo -e "${green}服务已重启${nc}"
        ;;
      4) journalctl -u "$SERVICE" -n 120 --no-pager ;;
      5) change_port ;;
      6) change_password ;;
      7) change_path ;;
      8) show_info ;;
      0) return 0 ;;
      *) echo "无效选项" ;;
    esac
  done
}

case "${1:-menu}" in
  info) need_root; show_info ;;
  status) need_root; "$APP_BIN" status ;;
  restart) need_root; systemctl restart "$SERVICE" ;;
  log) need_root; journalctl -u "$SERVICE" -f ;;
  node) need_root; node_menu ;;
  menu|"") menu ;;
  *) echo "用法: tui [menu|info|status|restart|log|node]" >&2; exit 2 ;;
esac
