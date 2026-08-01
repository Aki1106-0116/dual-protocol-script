#!/usr/bin/env python3
"""Harden and integrate the pinned dual-protocol node installer.

The upstream script remains the source of truth for protocol, Caddy, ACME and
TUI behavior. This transformer makes only the integration changes that must be
kept in lockstep with dual-protocol-script:

1. Keep the node-only command internal; `tui` is the combined TUI.
2. Generate REALITY keys through dual-protocol-script's verified X25519
   parser and never mutate live variables until a complete pair exists.
3. Write REALITY config through a validated temporary file and roll back both
   configuration and state if the restarted Xray service is unhealthy.
4. Generate current Xray JSON fields first and fall back to the legacy schema
   only when the installed Xray rejects the current schema. Neither candidate
   is committed before `xray run -test` succeeds.
5. Store Hysteria ACME material at a deterministic CertMagic directory so the
   TLS-only management panel can reuse and hot-reload the HY2 domain cert.
"""

from __future__ import annotations

import argparse
import pathlib
import re
import sys

UPSTREAM_TUI_NAME = "j" + "b"
UPSTREAM_TUI_COMMAND = f'JB_CMD="/usr/local/bin/{UPSTREAM_TUI_NAME}"'
UPSTREAM_TUI_FALLBACK = f'JB_CMD_FALLBACK="/usr/bin/{UPSTREAM_TUI_NAME}"'

KEY_FUNCTIONS = r'''generate_reality_x25519_keys() {
  local output new_private new_public

  if [[ ! -x "${DPS_BIN:-/usr/local/bin/dual-protocol-script}" ]]; then
    err "未找到 REALITY 安全密钥助手：${DPS_BIN:-/usr/local/bin/dual-protocol-script}"
    return 1
  fi
  if [[ ! -x "$XRAY_BIN" ]]; then
    err "未找到可执行的 Xray：$XRAY_BIN"
    return 1
  fi

  if ! output="$("${DPS_BIN:-/usr/local/bin/dual-protocol-script}" keypair --xray "$XRAY_BIN" 2>&1)"; then
    err "REALITY X25519 密钥生成或配对校验失败；旧密钥和旧配置均未修改。"
    printf '%s\n' "$output" >&2
    return 1
  fi
  new_private="$(printf '%s\n' "$output" | sed -n 's/^PRIVATE=//p' | head -n 1)"
  new_public="$(printf '%s\n' "$output" | sed -n 's/^PUBLIC=//p' | head -n 1)"
  if [[ -z "$new_private" || -z "$new_public" ]]; then
    err "密钥助手未返回完整密钥对；旧密钥和旧配置均未修改。"
    return 1
  fi

  # Only commit to the live shell state after both keys passed independent
  # X25519 derivation verification in dual-protocol-script.
  REALITY_PRIVATE_KEY="$new_private"
  REALITY_PUBLIC_KEY="$new_public"
  ok "REALITY X25519 密钥已生成并验证配对关系。"
}

ensure_reality_keys_present() {
  if [[ -z "${REALITY_PRIVATE_KEY:-}" || -z "${REALITY_PUBLIC_KEY:-}" ]]; then
    warn "检测到 REALITY 密钥不完整，尝试安全重建。"
    generate_reality_x25519_keys || return 1
  fi
  if [[ -z "${REALITY_SHORT_ID:-}" ]]; then
    REALITY_SHORT_ID="$(generate_shortid)"
  fi
  if [[ -z "${REALITY_PRIVATE_KEY:-}" || -z "${REALITY_PUBLIC_KEY:-}" || -z "${REALITY_SHORT_ID:-}" ]]; then
    err "REALITY 密钥仍不完整；拒绝生成配置。"
    return 1
  fi
}

'''


WRITE_HY2_ACME = r'''write_hy2_config_acme() {
  mkdir -p /etc/hysteria
  mkdir -p /var/lib/hysteria/acme
  if id hysteria >/dev/null 2>&1; then
    chown -R hysteria:hysteria /var/lib/hysteria/acme
  fi
  chmod 700 /var/lib/hysteria/acme

  local pwdq emailq listen domainq obfs_block
  listen="$(hy2_listen_value)"
  pwdq="$(yaml_quote "$HY2_PASSWORD")"; emailq="$(yaml_quote "$HY2_ACME_EMAIL")"; domainq="$(yaml_quote "$HY2_DOMAIN")"
  obfs_block="$(hy2_obfs_yaml_block)"
  cat > "$HY2_CONFIG" <<YAML
listen: ${listen}

acme:
  domains:
    - ${domainq}
  email: ${emailq}
  ca: letsencrypt
  dir: /var/lib/hysteria/acme
  type: http
  http:
    altPort: 80

quic:
  initStreamReceiveWindow: 16777216
  maxStreamReceiveWindow: 16777216
  initConnReceiveWindow: 33554432
  maxConnReceiveWindow: 33554432

auth:
  type: password
  password: ${pwdq}
${obfs_block}

bandwidth:
  up: 100 mbps
  down: 100 mbps

masquerade:
  type: string
  string:
    content: |
$(hy2_masquerade_html | sed 's/^/      /')
    headers:
      content-type: text/html; charset=utf-8
      server: nginx
    statusCode: 200
YAML
}

'''


WRITE_XHTTP = r'''write_xhttp_xray_config() {
  mkdir -p "$(dirname "$XRAY_CONFIG")"

  local tmp rollback="${XRAY_CONFIG}.dps-last-good"
  tmp="$(mktemp --suffix=.json "${XRAY_CONFIG}.tmp.XXXXXX")"

  # Use the documented compatibility-stable fields. Xray versions that silently
  # ignore unknown settings.users would otherwise accept an inbound with no users.
  cat > "$tmp" <<JSON
{
  "log": { "loglevel": "warning" },
  "inbounds": [
    {
      "tag": "vless-xhttp-in",
      "listen": "127.0.0.1",
      "port": ${XHTTP_BACKEND_PORT},
      "protocol": "vless",
      "settings": {
        "clients": [ { "id": "${XHTTP_UUID}", "email": "xhttp@${XHTTP_DOMAIN}" } ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "xhttp",
        "security": "none",
        "xhttpSettings": {
          "path": "${XHTTP_PATH}",
          "mode": "auto",
          "extra": { "xPaddingBytes": "100-1000" }
        }
      }
    }
  ],
  "outbounds": [ { "tag": "direct", "protocol": "freedom" } ]
}
JSON

  if ! "$XRAY_BIN" run -test -config "$tmp" -format json >/tmp/xray-test.log 2>&1; then
    warn "当前 Xray 不接受新版 XHTTP 字段，正在验证兼容字段。"
    cat > "$tmp" <<JSON
{
  "log": { "loglevel": "warning" },
  "inbounds": [
    {
      "tag": "vless-xhttp-in",
      "listen": "127.0.0.1",
      "port": ${XHTTP_BACKEND_PORT},
      "protocol": "vless",
      "settings": {
        "clients": [ { "id": "${XHTTP_UUID}", "email": "xhttp@${XHTTP_DOMAIN}" } ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "xhttp",
        "security": "none",
        "xhttpSettings": {
          "path": "${XHTTP_PATH}",
          "mode": "auto",
          "extra": { "xPaddingBytes": "100-1000" }
        }
      }
    }
  ],
  "outbounds": [ { "tag": "direct", "protocol": "freedom" } ]
}
JSON
    if ! "$XRAY_BIN" run -test -config "$tmp" -format json >/tmp/xray-test.log 2>&1; then
      err "Xray 同时拒绝新版与兼容版 XHTTP 配置；现有配置未修改。"
      cat /tmp/xray-test.log >&2
      rm -f "$tmp"
      return 1
    fi
  fi

  if [[ -s "$XRAY_CONFIG" ]]; then
    cp -a "$XRAY_CONFIG" "$rollback"
    chmod 600 "$rollback" 2>/dev/null || true
  fi
  if ! install -m 644 "$tmp" "$XRAY_CONFIG"; then
    err "写入 XHTTP 配置失败；现有配置未修改。"
    rm -f "$tmp"
    return 1
  fi
  rm -f "$tmp"
}

'''


WRITE_REALITY = r'''write_reality_xray_config() {
  mkdir -p "$(dirname "$XRAY_CONFIG")"
  ensure_reality_keys_present || return 1

  local tmp rollback="${XRAY_CONFIG}.dps-last-good"
  tmp="$(mktemp --suffix=.json "${XRAY_CONFIG}.tmp.XXXXXX")"
  cat > "$tmp" <<JSON
{
  "log": { "loglevel": "warning" },
  "inbounds": [
    {
      "tag": "vless-reality-vision-in",
      "listen": "0.0.0.0",
      "port": 443,
      "protocol": "vless",
      "settings": {
        "clients": [ { "id": "${REALITY_UUID}", "flow": "xtls-rprx-vision", "email": "reality" } ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "raw",
        "security": "reality",
        "realitySettings": {
          "show": false,
          "target": "${REALITY_SNI}:443",
          "xver": 0,
          "serverNames": [ "${REALITY_SNI}" ],
          "privateKey": "${REALITY_PRIVATE_KEY}",
          "shortIds": [ "${REALITY_SHORT_ID}" ]
        }
      }
    }
  ],
  "outbounds": [ { "tag": "direct", "protocol": "freedom" } ]
}
JSON

  if ! "$XRAY_BIN" run -test -config "$tmp" -format json >/tmp/xray-test.log 2>&1; then
    warn "当前 Xray 不接受 network=raw/target，正在验证旧别名 tcp/dest。"
    cat > "$tmp" <<JSON
{
  "log": { "loglevel": "warning" },
  "inbounds": [
    {
      "tag": "vless-reality-vision-in",
      "listen": "0.0.0.0",
      "port": 443,
      "protocol": "vless",
      "settings": {
        "clients": [ { "id": "${REALITY_UUID}", "flow": "xtls-rprx-vision", "email": "reality" } ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
          "show": false,
          "dest": "${REALITY_SNI}:443",
          "xver": 0,
          "serverNames": [ "${REALITY_SNI}" ],
          "privateKey": "${REALITY_PRIVATE_KEY}",
          "shortIds": [ "${REALITY_SHORT_ID}" ]
        }
      }
    }
  ],
  "outbounds": [ { "tag": "direct", "protocol": "freedom" } ]
}
JSON
    if ! "$XRAY_BIN" run -test -config "$tmp" -format json >/tmp/xray-test.log 2>&1; then
      err "Xray 同时拒绝新版与兼容版 REALITY 配置；旧配置未修改。"
      cat /tmp/xray-test.log >&2
      rm -f "$tmp"
      return 1
    fi
  fi
  if [[ -s "$XRAY_CONFIG" ]]; then
    cp -a "$XRAY_CONFIG" "$rollback"
    chmod 600 "$rollback" 2>/dev/null || true
  fi
  if ! install -m 644 "$tmp" "$XRAY_CONFIG"; then
    err "写入 REALITY 配置失败；旧配置仍保存在 $rollback"
    rm -f "$tmp"
    return 1
  fi
  rm -f "$tmp"
}

reality_local_self_test() {
  local port tmp log_file pid="" ready=0 i
  port="$(find_free_local_port)"
  tmp="$(mktemp --suffix=.json /tmp/dps-reality-client.XXXXXX)"
  log_file="/tmp/dps-reality-selftest.log"

  cat > "$tmp" <<JSON
{
  "log": { "loglevel": "warning" },
  "inbounds": [
    {
      "listen": "127.0.0.1",
      "port": ${port},
      "protocol": "socks",
      "settings": { "auth": "noauth", "udp": false }
    }
  ],
  "outbounds": [
    {
      "tag": "reality-selftest",
      "protocol": "vless",
      "settings": {
        "vnext": [
          {
            "address": "127.0.0.1",
            "port": 443,
            "users": [
              {
                "id": "${REALITY_UUID}",
                "encryption": "none",
                "flow": "xtls-rprx-vision"
              }
            ]
          }
        ]
      },
      "streamSettings": {
        "network": "raw",
        "security": "reality",
        "realitySettings": {
          "serverName": "${REALITY_SNI}",
          "fingerprint": "${FP}",
          "password": "${REALITY_PUBLIC_KEY}",
          "shortId": "${REALITY_SHORT_ID}",
          "spiderX": "/"
        }
      }
    }
  ]
}
JSON

  if ! "$XRAY_BIN" run -test -config "$tmp" -format json >"$log_file" 2>&1; then
    err "本机 REALITY 客户端自测配置未通过。"
    cat "$log_file" >&2
    rm -f "$tmp"
    return 1
  fi

  "$XRAY_BIN" run -config "$tmp" -format json >"$log_file" 2>&1 &
  pid=$!
  for i in $(seq 1 40); do
    if ss -H -ltn "sport = :${port}" 2>/dev/null | grep -q .; then
      ready=1
      break
    fi
    kill -0 "$pid" 2>/dev/null || break
    sleep 0.25
  done
  if [[ "$ready" != "1" ]]; then
    err "本机 REALITY 自测客户端没有启动。"
    cat "$log_file" >&2
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
    rm -f "$tmp"
    return 1
  fi

  if ! curl -sS --output /dev/null --connect-timeout 8 --max-time 20 \
    --socks5-hostname "127.0.0.1:${port}" "https://${REALITY_SNI}/"; then
    err "本机 REALITY 完整握手失败；不会把该节点标记为可用。"
    cat "$log_file" >&2
    journalctl -u xray --no-pager -n 60 >&2 || true
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
    rm -f "$tmp"
    return 1
  fi

  kill "$pid" 2>/dev/null || true
  wait "$pid" 2>/dev/null || true
  rm -f "$tmp"
  ok "REALITY 本机完整握手与代理请求自测通过。"
}

'''


CHANGE_REALITY = r'''change_reality_target() {
  load_state || return 1
  [[ "$MAIN_MODE" == "reality" ]] || { warn "当前不是 REALITY 模式。"; return 0; }

  local old_address="$REALITY_ADDRESS" old_sni="$REALITY_SNI"
  local old_private="$REALITY_PRIVATE_KEY" old_public="$REALITY_PUBLIC_KEY" old_short="$REALITY_SHORT_ID"
  local new_address new_sni output new_private new_public rollback="${XRAY_CONFIG}.dps-last-good"

  new_address="$(prompt_host_address "新的 REALITY 连接地址" "$REALITY_ADDRESS")"
  new_sni="$(prompt_domain "新的 REALITY 目标 SNI" "$REALITY_SNI")"
  if ! output="$("${DPS_BIN:-/usr/local/bin/dual-protocol-script}" keypair --xray "$XRAY_BIN" 2>&1)"; then
    err "新密钥生成失败；地址、SNI、密钥、配置和服务均保持原样。"
    printf '%s\n' "$output" >&2
    return 1
  fi
  new_private="$(printf '%s\n' "$output" | sed -n 's/^PRIVATE=//p' | head -n 1)"
  new_public="$(printf '%s\n' "$output" | sed -n 's/^PUBLIC=//p' | head -n 1)"
  if [[ -z "$new_private" || -z "$new_public" ]]; then
    err "新密钥不完整；所有旧值保持原样。"
    return 1
  fi

  REALITY_ADDRESS="$new_address"
  REALITY_SNI="$new_sni"
  REALITY_PRIVATE_KEY="$new_private"
  REALITY_PUBLIC_KEY="$new_public"
  REALITY_SHORT_ID="$(generate_shortid)"

  if ! write_reality_xray_config; then
    REALITY_ADDRESS="$old_address"; REALITY_SNI="$old_sni"
    REALITY_PRIVATE_KEY="$old_private"; REALITY_PUBLIC_KEY="$old_public"; REALITY_SHORT_ID="$old_short"
    return 1
  fi
  if ! systemctl restart xray || ! systemctl is-active --quiet xray \
    || ! reality_local_self_test; then
    err "Xray 新配置未通过启动与 REALITY 握手自测，正在自动回滚。"
    [[ -s "$rollback" ]] && install -m 644 "$rollback" "$XRAY_CONFIG"
    REALITY_ADDRESS="$old_address"; REALITY_SNI="$old_sni"
    REALITY_PRIVATE_KEY="$old_private"; REALITY_PUBLIC_KEY="$old_public"; REALITY_SHORT_ID="$old_short"
    save_state
    generate_main_outputs
    systemctl restart xray >/dev/null 2>&1 || true
    err "已恢复旧密钥、旧配置与旧分享链接。"
    return 1
  fi

  save_state
  generate_main_outputs
  "${DPS_BIN:-/usr/local/bin/dual-protocol-script}" apply >/dev/null 2>&1 || true
  ok "REALITY 地址、SNI 与已验证密钥已安全更新。"
}

'''

WEB_CONFIG_FUNCTIONS = r'''web_export_config() {
  load_state || { err "节点尚未安装，无法读取配置。"; return 1; }
  local reality_private_key_configured="0"
  [[ -n "${REALITY_PRIVATE_KEY:-}" ]] && reality_private_key_configured="1"
  export STACK_MODE MAIN_MODE NODE_NAME FP
  export XHTTP_DOMAIN XHTTP_PATH XHTTP_UUID XHTTP_BACKEND_PORT
  export REALITY_ADDRESS REALITY_SNI REALITY_UUID REALITY_PUBLIC_KEY REALITY_SHORT_ID
  export HY2_DOMAIN HY2_PASSWORD HY2_PORT_MODE HY2_PORT HY2_FIRST_PORT HY2_END_PORT
  export HY2_HOP_INTERVAL HY2_MIN_HOP_INTERVAL HY2_MAX_HOP_INTERVAL
  export HY2_CERT_SOURCE HY2_ACME_EMAIL HY2_OBFS_TYPE HY2_OBFS_PASSWORD
  export HY2_GECKO_MIN_PACKET_SIZE HY2_GECKO_MAX_PACKET_SIZE
  REALITY_PRIVATE_KEY_CONFIGURED="$reality_private_key_configured" python3 - <<'PY'
import json
import os

fields = (
    "STACK_MODE MAIN_MODE NODE_NAME FP "
    "XHTTP_DOMAIN XHTTP_PATH XHTTP_UUID XHTTP_BACKEND_PORT "
    "REALITY_ADDRESS REALITY_SNI REALITY_UUID REALITY_PUBLIC_KEY REALITY_SHORT_ID "
    "HY2_DOMAIN HY2_PASSWORD HY2_PORT_MODE HY2_PORT HY2_FIRST_PORT HY2_END_PORT "
    "HY2_HOP_INTERVAL HY2_MIN_HOP_INTERVAL HY2_MAX_HOP_INTERVAL "
    "HY2_CERT_SOURCE HY2_ACME_EMAIL HY2_OBFS_TYPE HY2_OBFS_PASSWORD "
    "HY2_GECKO_MIN_PACKET_SIZE HY2_GECKO_MAX_PACKET_SIZE"
).split()
result = {name.lower(): os.environ.get(name, "") for name in fields}
for name in (
    "XHTTP_BACKEND_PORT HY2_PORT HY2_FIRST_PORT HY2_END_PORT "
    "HY2_HOP_INTERVAL HY2_MIN_HOP_INTERVAL HY2_MAX_HOP_INTERVAL "
    "HY2_GECKO_MIN_PACKET_SIZE HY2_GECKO_MAX_PACKET_SIZE"
).split():
    value = os.environ.get(name, "")
    result[name.lower()] = int(value) if value.isdigit() else 0
result["reality_private_key_configured"] = (
    os.environ.get("REALITY_PRIVATE_KEY_CONFIGURED") == "1"
)
print(json.dumps(result, ensure_ascii=False, separators=(",", ":")))
PY
}

web_require_apply_environment() {
  local name
  [[ "${DPS_WEB_APPLY:-}" == "1" ]] || {
    err "拒绝缺少 Web 应用标记的非交互请求。"
    return 1
  }
  for name in \
    DPS_WEB_NODE_NAME DPS_WEB_FINGERPRINT \
    DPS_WEB_XHTTP_DOMAIN DPS_WEB_XHTTP_PATH DPS_WEB_XHTTP_UUID DPS_WEB_XHTTP_BACKEND_PORT \
    DPS_WEB_REALITY_ADDRESS DPS_WEB_REALITY_SNI DPS_WEB_REALITY_UUID DPS_WEB_ROTATE_REALITY_KEYS \
    DPS_WEB_HY2_DOMAIN DPS_WEB_HY2_PASSWORD DPS_WEB_HY2_PORT_MODE DPS_WEB_HY2_PORT \
    DPS_WEB_HY2_FIRST_PORT DPS_WEB_HY2_END_PORT DPS_WEB_HY2_HOP_INTERVAL \
    DPS_WEB_HY2_MIN_HOP_INTERVAL DPS_WEB_HY2_MAX_HOP_INTERVAL \
    DPS_WEB_HY2_ACME_EMAIL DPS_WEB_HY2_OBFS_TYPE DPS_WEB_HY2_OBFS_PASSWORD \
    DPS_WEB_HY2_GECKO_MIN_PACKET_SIZE DPS_WEB_HY2_GECKO_MAX_PACKET_SIZE; do
    [[ -v "$name" ]] || {
      err "Web 配置请求缺少字段：$name"
      return 1
    }
  done
}

web_valid_uuid() {
  [[ "$1" =~ ^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$ ]]
}

web_valid_secret() {
  local value="$1" min="${2:-1}" max="${3:-256}"
  python3 - "$value" "$min" "$max" <<'PY' >/dev/null 2>&1
import sys

value = sys.argv[1]
minimum = int(sys.argv[2])
maximum = int(sys.argv[3])
raise SystemExit(
    0 if minimum <= len(value) <= maximum
    and not any(ord(char) < 32 or ord(char) == 127 for char in value)
    else 1
)
PY
}

web_valid_uint() {
  local value="$1" min="$2" max="$3"
  [[ "$value" =~ ^[0-9]+$ ]] || return 1
  value=$((10#$value))
  (( value >= min && value <= max ))
}

web_backup_path() {
  local source="$1" name="$2"
  if [[ -e "$source" ]]; then
    cp -a "$source" "${WEB_BACKUP_DIR}/${name}"
  else
    : > "${WEB_BACKUP_DIR}/${name}.missing"
  fi
}

web_restore_path() {
  local destination="$1" name="$2"
  if [[ -e "${WEB_BACKUP_DIR}/${name}.missing" ]]; then
    rm -f "$destination"
  elif [[ -e "${WEB_BACKUP_DIR}/${name}" ]]; then
    cp -a "${WEB_BACKUP_DIR}/${name}" "$destination"
  fi
}

web_rollback_config() {
  local failed_xhttp_domain="${XHTTP_DOMAIN:-}" failed_hy2_domain="${HY2_DOMAIN:-}"
  set +e
  err "新节点配置未通过校验或服务健康检查，正在恢复修改前的完整配置。"
  web_restore_path "$STATE_FILE" state
  web_restore_path "$XRAY_CONFIG" xray
  web_restore_path "$HY2_CONFIG" hy2
  web_restore_path "$CADDYFILE" caddy
  load_state >/dev/null 2>&1 || true
  generate_main_outputs >/dev/null 2>&1 || true
  systemctl restart xray >/dev/null 2>&1 || true
  if [[ "${CADDY_REQUIRED:-0}" == "1" ]]; then
    systemctl restart caddy >/dev/null 2>&1 || true
  else
    systemctl disable --now caddy >/dev/null 2>&1 || true
  fi
  systemctl restart hysteria-server >/dev/null 2>&1 || true
  web_cleanup_replaced_domains "$failed_xhttp_domain" "$failed_hy2_domain" >/dev/null 2>&1 || true
  set -e
}

web_validate_cert_pair() {
  local domain="$1" cert="$2" key="$3" cert_pub="" key_pub=""
  [[ -s "$cert" && -s "$key" ]] || return 1
  openssl x509 -in "$cert" -noout -checkend 3600 >/dev/null 2>&1 || return 1
  openssl x509 -in "$cert" -noout -checkhost "$domain" >/dev/null 2>&1 || return 1
  cert_pub="$(openssl x509 -in "$cert" -pubkey -noout 2>/dev/null | openssl pkey -pubin -outform DER 2>/dev/null | sha256sum | awk '{print $1}')"
  key_pub="$(openssl pkey -in "$key" -pubout -outform DER 2>/dev/null | sha256sum | awk '{print $1}')"
  [[ -n "$cert_pub" && "$cert_pub" == "$key_pub" ]]
}

web_wait_for_caddy_cert_only() {
  local domain="$1" pair="" cert="" key="" i
  log "等待 Caddy 为 ${domain} 签发/加载证书"
  for i in $(seq 1 60); do
    pair="$(find_caddy_cert_pair "$domain" || true)"
    cert="${pair%%|*}"
    key="${pair#*|}"
    if [[ -n "$pair" ]] && web_validate_cert_pair "$domain" "$cert" "$key"; then
      ok "已验证 ${domain} 的 Caddy 证书。"
      return 0
    fi
    sleep 2
  done
  err "未能找到 ${domain} 的 Caddy 证书；请检查 DNS 直连、TCP 80/443 与 CDN 状态。"
  journalctl -u caddy --no-pager -n 100 >&2 || true
  return 1
}

web_find_hy2_acme_pair() {
  local domain="$1" base="/var/lib/hysteria/acme/certificates" cert="" key=""
  [[ -d "$base" ]] || return 1
  cert="$(find "$base" -type f -name "${domain}.crt" 2>/dev/null | sort | tail -n 1 || true)"
  key="$(find "$base" -type f -name "${domain}.key" 2>/dev/null | sort | tail -n 1 || true)"
  web_validate_cert_pair "$domain" "$cert" "$key" || return 1
  printf '%s|%s\n' "$cert" "$key"
}

web_wait_for_hy2_acme_cert() {
  local domain="$1" pair="" i
  log "等待 Hysteria2 为 ${domain} 完成 ACME 签发并验证证书"
  for i in $(seq 1 90); do
    pair="$(web_find_hy2_acme_pair "$domain" || true)"
    if [[ -n "$pair" ]]; then
      HY2_CERT_PATH="${pair%%|*}"
      HY2_KEY_PATH="${pair#*|}"
      ok "已验证 ${domain} 的 Hysteria2 ACME 证书。"
      return 0
    fi
    sleep 2
  done
  err "未能取得 ${domain} 的 Hysteria2 ACME 证书；请确认 DNS 已直连本 VPS、CDN 代理关闭，且 TCP 80 可从公网访问。"
  journalctl -u hysteria-server --no-pager -n 100 >&2 || true
  return 1
}

web_remove_domain_assets_from_root() {
  local root="$1" domain="$2" resolved_root="" candidate="" resolved=""
  [[ -n "$domain" && -d "$root" ]] || return 0
  valid_domain "$domain" || return 1
  resolved_root="$(readlink -f -- "$root" 2>/dev/null || true)"
  [[ -n "$resolved_root" && "$resolved_root" != "/" ]] || return 1

  while IFS= read -r -d '' candidate; do
    resolved="$(readlink -f -- "$candidate" 2>/dev/null || true)"
    case "$resolved" in
      "$resolved_root"/*) rm -rf -- "$resolved" ;;
      *) warn "跳过不在证书存储目录内的路径：$candidate" ;;
    esac
  done < <(find "$resolved_root" -depth -type d -name "$domain" -print0 2>/dev/null)

  while IFS= read -r -d '' candidate; do
    resolved="$(readlink -f -- "$candidate" 2>/dev/null || true)"
    case "$resolved" in
      "$resolved_root"/*) rm -f -- "$resolved" ;;
      *) warn "跳过不在证书存储目录内的文件：$candidate" ;;
    esac
  done < <(find "$resolved_root" -type f \( -name "${domain}.crt" -o -name "${domain}.key" -o -name "${domain}.json" \) -print0 2>/dev/null)
}

web_cleanup_replaced_domains() {
  local old_xhttp_domain="${1:-}" old_hy2_domain="${2:-}" domain=""
  for domain in "$old_xhttp_domain" "$old_hy2_domain"; do
    [[ -n "$domain" ]] || continue
    if [[ "$domain" == "${XHTTP_DOMAIN:-}" || "$domain" == "${HY2_DOMAIN:-}" ]]; then
      continue
    fi
    web_remove_domain_assets_from_root "${CADDY_DATA:-/var/lib/caddy/.local/share/caddy}/certificates" "$domain" || return 1
    web_remove_domain_assets_from_root "/var/lib/hysteria/acme/certificates" "$domain" || return 1
    ok "已清理旧域名 ${domain} 的证书缓存；新服务配置也不会再为它自动续签。"
  done
}

web_apply_exit() {
  local rc=$?
  trap - EXIT HUP INT TERM
  if (( rc != 0 )) && [[ "${WEB_APPLY_COMMITTED:-0}" != "1" ]]; then
    web_rollback_config
  fi
  [[ -z "${WEB_BACKUP_DIR:-}" ]] || rm -rf -- "$WEB_BACKUP_DIR"
  exit "$rc"
}

web_validate_and_assign_config() {
  local normalized panel_port="" web_min_hop="" web_max_hop="" web_fixed_hop=""

  web_valid_secret "$DPS_WEB_NODE_NAME" 1 80 || {
    err "节点名称长度必须为 1-80，且不能包含控制字符。"
    return 1
  }
  [[ "$DPS_WEB_FINGERPRINT" == "chrome" || "$DPS_WEB_FINGERPRINT" == "firefox" ]] || {
    err "客户端指纹只能是 chrome 或 firefox。"
    return 1
  }
  NODE_NAME="$DPS_WEB_NODE_NAME"
  FP="$DPS_WEB_FINGERPRINT"

  normalized="$(normalize_domain "$DPS_WEB_HY2_DOMAIN")"
  valid_domain "$normalized" || { err "HY2 域名格式无效。"; return 1; }
  HY2_DOMAIN="$normalized"
  web_valid_secret "$DPS_WEB_HY2_PASSWORD" 1 256 || {
    err "HY2 密码长度必须为 1-256，且不能包含控制字符。"
    return 1
  }
  HY2_PASSWORD="$DPS_WEB_HY2_PASSWORD"

  case "$DPS_WEB_HY2_PORT_MODE" in
    single)
      web_valid_uint "$DPS_WEB_HY2_PORT" 1 65535 || { err "HY2 单端口无效。"; return 1; }
      HY2_PORT=$((10#$DPS_WEB_HY2_PORT))
      hy2_reserved_port "$HY2_PORT" && { err "HY2 端口禁止使用 80/443/2053/8443。"; return 1; }
      HY2_PORT_MODE="single"
      HY2_FIRST_PORT=""; HY2_END_PORT=""
      HY2_HOP_INTERVAL=""; HY2_MIN_HOP_INTERVAL=""; HY2_MAX_HOP_INTERVAL=""
      ;;
    hop)
      web_valid_uint "$DPS_WEB_HY2_FIRST_PORT" 1 65534 || { err "HY2 跳跃起始端口无效。"; return 1; }
      web_valid_uint "$DPS_WEB_HY2_END_PORT" 2 65535 || { err "HY2 跳跃结束端口无效。"; return 1; }
      HY2_FIRST_PORT=$((10#$DPS_WEB_HY2_FIRST_PORT))
      HY2_END_PORT=$((10#$DPS_WEB_HY2_END_PORT))
      (( HY2_END_PORT > HY2_FIRST_PORT )) || { err "HY2 结束端口必须大于起始端口。"; return 1; }
      hy2_range_contains_reserved "$HY2_FIRST_PORT" "$HY2_END_PORT" && {
        err "HY2 跳跃范围不能包含 80/443/2053/8443。"
        return 1
      }
      HY2_PORT_MODE="hop"
      HY2_PORT="$HY2_FIRST_PORT"
      web_min_hop="$DPS_WEB_HY2_MIN_HOP_INTERVAL"
      web_max_hop="$DPS_WEB_HY2_MAX_HOP_INTERVAL"
      web_fixed_hop="$DPS_WEB_HY2_HOP_INTERVAL"
      [[ "$web_min_hop" == "0" ]] && web_min_hop=""
      [[ "$web_max_hop" == "0" ]] && web_max_hop=""
      [[ "$web_fixed_hop" == "0" ]] && web_fixed_hop=""
      if [[ -n "$web_min_hop" || -n "$web_max_hop" ]]; then
        [[ -n "$web_min_hop" && -n "$web_max_hop" ]] || {
          err "随机跳跃必须同时填写最小和最大间隔。"
          return 1
        }
        web_valid_uint "$web_min_hop" 5 600 || { err "最小跳跃间隔无效。"; return 1; }
        web_valid_uint "$web_max_hop" 5 600 || { err "最大跳跃间隔无效。"; return 1; }
        HY2_MIN_HOP_INTERVAL=$((10#$web_min_hop))
        HY2_MAX_HOP_INTERVAL=$((10#$web_max_hop))
        (( HY2_MAX_HOP_INTERVAL >= HY2_MIN_HOP_INTERVAL )) || {
          err "最大跳跃间隔不能小于最小跳跃间隔。"
          return 1
        }
        HY2_HOP_INTERVAL=""
      else
        web_valid_uint "$web_fixed_hop" 5 600 || { err "固定跳跃间隔无效。"; return 1; }
        HY2_HOP_INTERVAL=$((10#$web_fixed_hop))
        HY2_MIN_HOP_INTERVAL=""; HY2_MAX_HOP_INTERVAL=""
      fi
      ;;
    *)
      err "HY2 端口模式只能是 single 或 hop。"
      return 1
      ;;
  esac

  if [[ -s /etc/default/dual-protocol-script ]]; then
    panel_port="$(sed -n 's/^WEB_PORT=//p' /etc/default/dual-protocol-script | head -n 1)"
  fi
  if [[ "$panel_port" =~ ^[0-9]+$ ]]; then
    if [[ "$HY2_PORT_MODE" == "single" && "$HY2_PORT" -eq "$panel_port" ]] ||
       [[ "$HY2_PORT_MODE" == "hop" && "$panel_port" -ge "$HY2_FIRST_PORT" && "$panel_port" -le "$HY2_END_PORT" ]]; then
      err "HY2 端口/跳跃范围不能包含当前 Web TLS 端口 $panel_port。"
      return 1
    fi
  fi

  case "$DPS_WEB_HY2_OBFS_TYPE" in
    none)
      HY2_OBFS_TYPE="none"
      HY2_OBFS_PASSWORD=""
      HY2_GECKO_MIN_PACKET_SIZE="512"
      HY2_GECKO_MAX_PACKET_SIZE="1200"
      ;;
    gecko)
      web_valid_secret "$DPS_WEB_HY2_OBFS_PASSWORD" 1 256 || {
        err "Gecko 混淆密码长度必须为 1-256，且不能包含控制字符。"
        return 1
      }
      web_valid_uint "$DPS_WEB_HY2_GECKO_MIN_PACKET_SIZE" 64 1500 || {
        err "Gecko 最小分片必须在 64-1500。"
        return 1
      }
      web_valid_uint "$DPS_WEB_HY2_GECKO_MAX_PACKET_SIZE" 64 1500 || {
        err "Gecko 最大分片必须在 64-1500。"
        return 1
      }
      HY2_GECKO_MIN_PACKET_SIZE=$((10#$DPS_WEB_HY2_GECKO_MIN_PACKET_SIZE))
      HY2_GECKO_MAX_PACKET_SIZE=$((10#$DPS_WEB_HY2_GECKO_MAX_PACKET_SIZE))
      (( HY2_GECKO_MAX_PACKET_SIZE >= HY2_GECKO_MIN_PACKET_SIZE )) || {
        err "Gecko 最大分片不能小于最小分片。"
        return 1
      }
      HY2_OBFS_TYPE="gecko"
      HY2_OBFS_PASSWORD="$DPS_WEB_HY2_OBFS_PASSWORD"
      ;;
    *)
      err "HY2 混淆类型只能是 none 或 gecko。"
      return 1
      ;;
  esac

  case "$MAIN_MODE" in
    xhttp)
      normalized="$(normalize_domain "$DPS_WEB_XHTTP_DOMAIN")"
      valid_domain "$normalized" || { err "XHTTP 域名格式无效。"; return 1; }
      [[ "$normalized" != "$HY2_DOMAIN" ]] || { err "XHTTP 与 HY2 必须使用不同域名。"; return 1; }
      XHTTP_DOMAIN="$normalized"
      XHTTP_PATH="$(normalize_path "$DPS_WEB_XHTTP_PATH")" || { err "XHTTP 路径格式无效。"; return 1; }
      web_valid_uuid "$DPS_WEB_XHTTP_UUID" || { err "XHTTP UUID 格式无效。"; return 1; }
      web_valid_uint "$DPS_WEB_XHTTP_BACKEND_PORT" 1024 65535 || { err "XHTTP 后端端口无效。"; return 1; }
      XHTTP_UUID="${DPS_WEB_XHTTP_UUID,,}"
      XHTTP_BACKEND_PORT=$((10#$DPS_WEB_XHTTP_BACKEND_PORT))
      MAIN_DOMAIN="$XHTTP_DOMAIN"
      MANAGED_DOMAINS="$XHTTP_DOMAIN $HY2_DOMAIN"
      ;;
    reality)
      normalized="$(normalize_host_address "$DPS_WEB_REALITY_ADDRESS")"
      valid_host_address "$normalized" || { err "REALITY 连接地址格式无效。"; return 1; }
      REALITY_ADDRESS="$normalized"
      normalized="$(normalize_domain "$DPS_WEB_REALITY_SNI")"
      valid_domain "$normalized" || { err "REALITY 目标 SNI 格式无效。"; return 1; }
      REALITY_SNI="$normalized"
      web_valid_uuid "$DPS_WEB_REALITY_UUID" || { err "REALITY UUID 格式无效。"; return 1; }
      REALITY_UUID="${DPS_WEB_REALITY_UUID,,}"
      [[ "$DPS_WEB_ROTATE_REALITY_KEYS" == "0" || "$DPS_WEB_ROTATE_REALITY_KEYS" == "1" ]] || {
        err "REALITY 密钥轮换参数无效。"
        return 1
      }
      if [[ "$DPS_WEB_ROTATE_REALITY_KEYS" == "1" ]]; then
        generate_reality_x25519_keys || return 1
        REALITY_SHORT_ID="$(generate_shortid)"
      else
        ensure_reality_keys_present || return 1
      fi
      web_valid_secret "$DPS_WEB_HY2_ACME_EMAIL" 3 254 || { err "ACME 邮箱格式无效。"; return 1; }
      [[ "$DPS_WEB_HY2_ACME_EMAIL" =~ ^[^[:space:]@]+@[^[:space:]@]+\.[^[:space:]@]+$ ]] || {
        err "ACME 邮箱格式无效。"
        return 1
      }
      HY2_ACME_EMAIL="$DPS_WEB_HY2_ACME_EMAIL"
      MAIN_DOMAIN="$REALITY_ADDRESS"
      MANAGED_DOMAINS="$HY2_DOMAIN"
      ;;
    *)
      err "当前节点组合不受 Web 配置器支持：${MAIN_MODE:-unknown}"
      return 1
      ;;
  esac
}

web_apply_config() {
  load_state || { err "节点尚未安装，无法保存配置。"; return 1; }
  web_require_apply_environment || return 1

  local old_hy2_domain="$HY2_DOMAIN" old_xhttp_domain="${XHTTP_DOMAIN:-}"

  WEB_APPLY_COMMITTED=0
  WEB_BACKUP_DIR="$(mktemp -d /tmp/dual-protocol-web-config.XXXXXX)"
  chmod 700 "$WEB_BACKUP_DIR"
  web_backup_path "$STATE_FILE" state
  web_backup_path "$XRAY_CONFIG" xray
  web_backup_path "$HY2_CONFIG" hy2
  web_backup_path "$CADDYFILE" caddy
  trap web_apply_exit EXIT
  trap 'exit 143' HUP INT TERM

  web_validate_and_assign_config
  case "$MAIN_MODE" in
    xhttp)
      write_xhttp_xray_config
      write_caddyfile_xhttp_hy2
      start_xray
      start_caddy
      if [[ "$XHTTP_DOMAIN" != "$old_xhttp_domain" ]]; then
        web_wait_for_caddy_cert_only "$XHTTP_DOMAIN"
      fi
      if [[ "$HY2_DOMAIN" != "$old_hy2_domain" ]]; then
        web_wait_for_caddy_cert_only "$HY2_DOMAIN"
        wait_for_caddy_cert "$HY2_DOMAIN"
        grant_cert_read_permissions "$HY2_CERT_PATH" "$HY2_KEY_PATH"
      fi
      write_hy2_config_tls
      start_hy2
      ;;
    reality)
      write_reality_xray_config
      write_hy2_config_acme
      start_xray
      reality_local_self_test
      start_hy2
      if [[ "$HY2_DOMAIN" != "$old_hy2_domain" ]]; then
        web_wait_for_hy2_acme_cert "$HY2_DOMAIN"
      fi
      ;;
  esac

  save_state
  generate_main_outputs
  WEB_APPLY_COMMITTED=1
  trap - EXIT HUP INT TERM
  rm -rf -- "$WEB_BACKUP_DIR"
  WEB_BACKUP_DIR=""
  web_cleanup_replaced_domains "$old_xhttp_domain" "$old_hy2_domain" || warn "节点已经更新，但部分旧域名证书缓存清理失败。"
  ok "节点配置已保存，Xray/Hysteria2/Caddy 已按当前组合完成健康检查。"
}

web_prepare_reinstall_target() {
  case "${DPS_WEB_TARGET_MODE:-}" in
    xhttp)
      MAIN_MODE="xhttp"; STACK_MODE="xhttp_hy2"
      CADDY_REQUIRED="1"; WEB_ENABLED="1"; HY2_CERT_SOURCE="caddy"
      ;;
    reality)
      MAIN_MODE="reality"; STACK_MODE="reality_hy2"
      CADDY_REQUIRED="0"; WEB_ENABLED="0"; HY2_CERT_SOURCE="acme"
      ;;
    *)
      err "网页重装目标只能是 xhttp 或 reality。"
      return 1
      ;;
  esac
}

web_require_tcp_port_free() {
  local port="$1" purpose="$2"
  if port_in_use_tcp "$port"; then
    err "TCP ${port} 已被其他进程占用，无法重装 ${purpose}。"
    show_port_users
    return 1
  fi
}

web_reinstall_stack() {
  load_state || { err "节点尚未安装，无法从网页重装组合。"; return 1; }
  web_require_apply_environment || return 1
  [[ -n "${DPS_WEB_TARGET_MODE:-}" ]] || { err "缺少网页重装目标。"; return 1; }

  local old_hy2_domain="$HY2_DOMAIN" old_xhttp_domain="${XHTTP_DOMAIN:-}"
  WEB_APPLY_COMMITTED=0
  WEB_BACKUP_DIR="$(mktemp -d /tmp/dual-protocol-reinstall.XXXXXX)"
  chmod 700 "$WEB_BACKUP_DIR"
  web_backup_path "$STATE_FILE" state
  web_backup_path "$XRAY_CONFIG" xray
  web_backup_path "$HY2_CONFIG" hy2
  web_backup_path "$CADDYFILE" caddy
  trap web_apply_exit EXIT
  trap 'exit 143' HUP INT TERM

  web_prepare_reinstall_target
  web_validate_and_assign_config
  systemctl stop xray hysteria-server caddy >/dev/null 2>&1 || true

  case "$MAIN_MODE" in
    xhttp)
      web_require_tcp_port_free 80 "XHTTP + HY2"
      web_require_tcp_port_free 443 "XHTTP + HY2"
      install_base_packages
      install_caddy_official
      install_xray_official
      install_hysteria_official
      create_speedtest_site
      write_xhttp_xray_config
      write_caddyfile_xhttp_hy2
      start_xray
      start_caddy
      web_wait_for_caddy_cert_only "$XHTTP_DOMAIN"
      web_wait_for_caddy_cert_only "$HY2_DOMAIN"
      wait_for_caddy_cert "$HY2_DOMAIN"
      grant_cert_read_permissions "$HY2_CERT_PATH" "$HY2_KEY_PATH"
      write_hy2_config_tls
      start_hy2
      ;;
    reality)
      web_require_tcp_port_free 80 "REALITY + HY2 的 ACME"
      web_require_tcp_port_free 443 "REALITY"
      install_base_packages
      install_xray_official
      install_hysteria_official
      write_reality_xray_config
      write_hy2_config_acme
      systemctl disable caddy >/dev/null 2>&1 || true
      start_xray
      reality_local_self_test
      start_hy2
      web_wait_for_hy2_acme_cert "$HY2_DOMAIN"
      ;;
  esac

  save_state
  generate_main_outputs
  WEB_APPLY_COMMITTED=1
  trap - EXIT HUP INT TERM
  rm -rf -- "$WEB_BACKUP_DIR"
  WEB_BACKUP_DIR=""
  web_cleanup_replaced_domains "$old_xhttp_domain" "$old_hy2_domain" || warn "协议组合已经重装，但部分旧域名证书缓存清理失败。"
  if [[ "$MAIN_MODE" == "reality" ]]; then
    apt-get purge -y caddy >/dev/null 2>&1 || true
    rm -f /usr/bin/caddy
    rm -rf /etc/caddy
    rm -rf /var/lib/caddy
  fi
  ok "协议组合已从网页重装完成，节点分享链接已重新生成。"
}

'''


def replace_section(text: str, start: str, end: str, replacement: str) -> str:
    pattern = re.compile(
        rf"(?ms)^{re.escape(start)}\(\) \{{.*?(?=^{re.escape(end)}\(\) \{{)"
    )
    result, count = pattern.subn(replacement, text, count=1)
    if count != 1:
        raise ValueError(f"cannot locate section {start} .. {end}")
    return result


def transform(text: str) -> str:
    required = [
        "generate_reality_x25519_keys()",
        "write_hy2_config_acme()",
        "write_xhttp_xray_config()",
        "write_reality_xray_config()",
        "change_reality_target()",
        UPSTREAM_TUI_COMMAND,
    ]
    missing = [item for item in required if item not in text]
    if missing:
        raise ValueError("upstream script shape changed; missing: " + ", ".join(missing))

    text = text.replace('APP_NAME="jb-combo"', 'APP_NAME="dual-protocol-node"', 1)
    text = text.replace(UPSTREAM_TUI_COMMAND, 'JB_CMD="/usr/local/bin/dual-protocol-node"', 1)
    text = text.replace(UPSTREAM_TUI_FALLBACK, 'JB_CMD_FALLBACK="/usr/bin/dual-protocol-node"', 1)
    text = text.replace(
        'THIS_SCRIPT="/usr/local/lib/jb-combo-installer.sh"',
        'THIS_SCRIPT="/usr/local/lib/dual-protocol-script/dual-protocol-node-installer.sh"',
        1,
    )
    text = text.replace(
        'HY2_BIN="/usr/local/bin/hysteria"',
        'HY2_BIN="/usr/local/bin/hysteria"\nDPS_BIN="${DPS_BIN:-/usr/local/bin/dual-protocol-script}"',
        1,
    )
    text = replace_section(
        text,
        "generate_reality_x25519_keys",
        "install_hysteria_official",
        KEY_FUNCTIONS,
    )
    text = replace_section(
        text,
        "write_hy2_config_acme",
        "write_service_restart_override",
        WRITE_HY2_ACME,
    )
    text = replace_section(
        text,
        "write_xhttp_xray_config",
        "write_reality_xray_config",
        WRITE_XHTTP,
    )
    text = replace_section(
        text,
        "write_reality_xray_config",
        "write_caddyfile_xhttp_hy2",
        WRITE_REALITY,
    )
    text = replace_section(
        text,
        "change_reality_target",
        "show_info",
        CHANGE_REALITY,
    )
    if text.count("show_info() {") != 1:
        raise ValueError("cannot locate show_info for Web configuration functions")
    text = text.replace("show_info() {", WEB_CONFIG_FUNCTIONS + "\nshow_info() {", 1)
    client_old = '''        "network": "tcp",
        "security": "reality",
        "realitySettings": { "serverName": "${REALITY_SNI}", "fingerprint": "${FP}", "publicKey": "${REALITY_PUBLIC_KEY}", "shortId": "${REALITY_SHORT_ID}", "spiderX": "/" }'''
    client_new = '''        "network": "raw",
        "security": "reality",
        "realitySettings": { "serverName": "${REALITY_SNI}", "fingerprint": "${FP}", "password": "${REALITY_PUBLIC_KEY}", "shortId": "${REALITY_SHORT_ID}", "spiderX": "/" }'''
    if text.count(client_old) != 1:
        raise ValueError("cannot locate REALITY client JSON")
    text = text.replace(client_old, client_new, 1)

    initial_start = """  start_xray
  start_hy2
  save_state"""
    tested_start = """  start_xray
  reality_local_self_test || exit 1
  start_hy2
  save_state"""
    if text.count(initial_start) != 1:
        raise ValueError("cannot locate initial REALITY service start")
    text = text.replace(initial_start, tested_start, 1)

    text = text.replace(
        f"================ {UPSTREAM_TUI_NAME} 组合节点控制面板 ================",
        "================ dual-protocol-script 节点控制面板 ================",
    )
    text = text.replace(f"管理命令：{UPSTREAM_TUI_NAME}", "管理命令：tui")
    text = text.replace(f"管理命令: {UPSTREAM_TUI_NAME}", "管理命令: tui")
    text = text.replace(
        f"输入 {UPSTREAM_TUI_NAME} 进入控制面板",
        "输入 tui 进入控制面板",
    )
    text = text.replace(
        f"# - Run `{UPSTREAM_TUI_NAME}` after installation to open the control panel.",
        "# - Run `tui` after installation to open the combined control panel.",
    )
    text = text.replace(
        f'echo "{UPSTREAM_TUI_NAME}: missing \\$SCRIPT and curl/wget is unavailable"',
        'echo "dual-protocol-node: missing \\$SCRIPT and curl/wget is unavailable"',
    )
    text = text.replace(
        f"已安装控制面板命令：{UPSTREAM_TUI_NAME}",
        "已安装内部节点命令：dual-protocol-node；统一管理入口：tui",
    )

    main_start = """main() {
  require_root
  check_os"""
    web_main_start = """main() {
  require_root
  case "${1:-}" in
    web-export) web_export_config; exit $? ;;
    web-apply) web_apply_config; exit $? ;;
    web-reinstall) web_reinstall_stack; exit $? ;;
  esac
  check_os"""
    if text.count(main_start) != 1:
        raise ValueError("cannot locate main command dispatch")
    text = text.replace(main_start, web_main_start, 1)

    banner = (
        "# dual-protocol-script integration: verified keys, rollback and Web API\n"
    )
    return text.replace("#!/usr/bin/env bash\n", "#!/usr/bin/env bash\n" + banner, 1)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("source", type=pathlib.Path)
    parser.add_argument("destination", type=pathlib.Path)
    args = parser.parse_args()
    source = args.source.read_text(encoding="utf-8")
    try:
        output = transform(source)
    except ValueError as exc:
        print(f"harden_node_installer: {exc}", file=sys.stderr)
        return 1
    args.destination.parent.mkdir(parents=True, exist_ok=True)
    args.destination.write_text(output, encoding="utf-8", newline="\n")
    args.destination.chmod(0o755)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
