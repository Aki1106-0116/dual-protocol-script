#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

STATE_FILE="${STATE_FILE:-/etc/jb-combo/state.env}"
ENV_FILE="${ENV_FILE:-/etc/default/dual-protocol-script}"
HY2_ACME_DIR="${HY2_ACME_DIR:-/var/lib/hysteria/acme}"
requested_port=""
requested_max=""
restart=0

while (($#)); do
  case "$1" in
    --port) requested_port="${2:-}"; shift 2 ;;
    --max) requested_max="${2:-}"; shift 2 ;;
    --restart) restart=1; shift ;;
    *) echo "未知参数：$1" >&2; exit 2 ;;
  esac
done

[[ "${EUID}" -eq 0 ]] || { echo "同步面板证书需要 root 权限" >&2; exit 1; }
[[ -s "$STATE_FILE" ]] || { echo "节点状态不存在：$STATE_FILE" >&2; exit 1; }

WEB_PORT=""
MAX_EXITS="12"
PANEL_DOMAIN=""
TLS_CERT=""
TLS_KEY=""
OLD_WEB_PORT=""
if [[ -s "$ENV_FILE" ]]; then
  # shellcheck disable=SC1090
  source "$ENV_FILE"
fi
OLD_WEB_PORT="$WEB_PORT"
[[ -n "$requested_port" ]] && WEB_PORT="$requested_port"
[[ -n "$requested_max" ]] && MAX_EXITS="$requested_max"
if [[ -z "$requested_port" ]] && { [[ ! "$WEB_PORT" =~ ^[0-9]+$ ]] || (( WEB_PORT < 10240 || WEB_PORT > 65535 )); }; then
  WEB_PORT=""
fi

# shellcheck disable=SC1090
source "$STATE_FILE"
PANEL_DOMAIN="${HY2_DOMAIN:-}"
[[ "$PANEL_DOMAIN" =~ ^([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$ ]] \
  || { echo "HY2 域名无效，无法作为 TLS 面板域名：$PANEL_DOMAIN" >&2; exit 1; }

port_busy() {
  local port="$1"
  ss -H -ltn 2>/dev/null | awk -v suffix=":${port}" '$4 ~ suffix"$" { found=1 } END { exit !found }'
}

port_overlaps_hy2() {
  local port="$1"
  if [[ "${HY2_PORT_MODE:-single}" == "hop" && "${HY2_FIRST_PORT:-}" =~ ^[0-9]+$ && "${HY2_END_PORT:-}" =~ ^[0-9]+$ ]]; then
    (( port >= HY2_FIRST_PORT && port <= HY2_END_PORT ))
    return
  fi
  [[ "${HY2_PORT:-}" =~ ^[0-9]+$ ]] && (( port == HY2_PORT ))
}

if [[ -n "$requested_port" && "$requested_port" != "$OLD_WEB_PORT" ]] && port_busy "$requested_port"; then
  echo "面板 TCP 端口 $requested_port 已被占用" >&2
  exit 1
fi

if [[ -z "$WEB_PORT" ]]; then
  for _ in $(seq 1 200); do
    candidate="$(shuf -i 20000-60999 -n 1)"
    if ! port_busy "$candidate" && ! port_overlaps_hy2 "$candidate"; then
      WEB_PORT="$candidate"
      break
    fi
  done
fi
[[ "$WEB_PORT" =~ ^[0-9]+$ ]] && (( WEB_PORT >= 10240 && WEB_PORT <= 65535 )) \
  || { echo "面板端口必须在 10240-65535 之间" >&2; exit 1; }
if port_overlaps_hy2 "$WEB_PORT"; then
  echo "面板 TCP 端口不能与 HY2 端口/跳跃范围使用相同数字" >&2
  exit 1
fi
[[ "$MAX_EXITS" =~ ^[0-9]+$ ]] && (( MAX_EXITS >= 1 && MAX_EXITS <= 200 )) \
  || { echo "MAX_EXITS 必须在 1-200 之间" >&2; exit 1; }

find_pair() {
  local cert="" key="" base
  if [[ -s "${HY2_CERT_PATH:-}" && -s "${HY2_KEY_PATH:-}" ]]; then
    printf '%s|%s\n' "$HY2_CERT_PATH" "$HY2_KEY_PATH"
    return 0
  fi
  for base in \
    "$HY2_ACME_DIR/certificates" \
    "/var/lib/caddy/.local/share/caddy/certificates"; do
    [[ -d "$base" ]] || continue
    cert="$(find "$base" -type f -name "${PANEL_DOMAIN}.crt" 2>/dev/null | sort | tail -n 1 || true)"
    key="$(find "$base" -type f -name "${PANEL_DOMAIN}.key" 2>/dev/null | sort | tail -n 1 || true)"
    if [[ -s "$cert" && -s "$key" ]]; then
      printf '%s|%s\n' "$cert" "$key"
      return 0
    fi
  done
  return 1
}

pair=""
for _ in $(seq 1 60); do
  pair="$(find_pair || true)"
  [[ -n "$pair" ]] && break
  sleep 2
done
[[ -n "$pair" ]] || {
  echo "未找到 $PANEL_DOMAIN 的证书。请确认域名直连 VPS、未开启 Cloudflare 代理，且 HY2/Caddy 已成功签发证书。" >&2
  exit 1
}
TLS_CERT="${pair%%|*}"
TLS_KEY="${pair#*|}"

openssl x509 -in "$TLS_CERT" -noout -checkend 3600 >/dev/null 2>&1 \
  || { echo "面板证书已过期或将在一小时内过期：$TLS_CERT" >&2; exit 1; }
openssl x509 -in "$TLS_CERT" -noout -checkhost "$PANEL_DOMAIN" >/dev/null 2>&1 \
  || { echo "证书不包含面板域名 $PANEL_DOMAIN" >&2; exit 1; }
cert_pub="$(openssl x509 -in "$TLS_CERT" -pubkey -noout 2>/dev/null | openssl pkey -pubin -outform DER 2>/dev/null | sha256sum | awk '{print $1}')"
key_pub="$(openssl pkey -in "$TLS_KEY" -pubout -outform DER 2>/dev/null | sha256sum | awk '{print $1}')"
[[ -n "$cert_pub" && "$cert_pub" == "$key_pub" ]] \
  || { echo "面板证书与私钥不匹配" >&2; exit 1; }

mkdir -p "$(dirname "$ENV_FILE")"
tmp="$(mktemp "${ENV_FILE}.tmp.XXXXXX")"
cat > "$tmp" <<EOF
WEB_PORT=${WEB_PORT}
MAX_EXITS=${MAX_EXITS}
PANEL_DOMAIN=${PANEL_DOMAIN}
TLS_CERT=${TLS_CERT}
TLS_KEY=${TLS_KEY}
EOF
install -m 600 "$tmp" "$ENV_FILE"
rm -f "$tmp"

if (( restart == 1 )); then
  systemctl restart dual-protocol-script
  systemctl is-active --quiet dual-protocol-script
fi

echo "PANEL_URL=https://${PANEL_DOMAIN}:${WEB_PORT}"
echo "TLS_CERT=${TLS_CERT}"
echo "TLS_KEY=${TLS_KEY}"
