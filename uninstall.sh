#!/usr/bin/env bash
set -Eeuo pipefail

[[ "${EUID}" -eq 0 ]] || { echo "需要 root 权限" >&2; exit 1; }
read -r -p "输入 UNINSTALL 删除 Dual Protocol Script 家宽出口服务（不删除 Xray/HY2/Caddy 节点）：" answer
[[ "$answer" == "UNINSTALL" ]] || { echo "已取消"; exit 0; }

systemctl disable --now dual-protocol-script >/dev/null 2>&1 || true
for ns in $(ip netns list 2>/dev/null | awk '/^dps[0-9]+/{print $1}'); do
  ip netns del "$ns" >/dev/null 2>&1 || true
done
rm -f /etc/systemd/system/dual-protocol-script.service /etc/default/dual-protocol-script
rm -f /usr/local/bin/dual-protocol-script /usr/local/bin/tui
rm -rf /usr/local/lib/dual-protocol-script
systemctl daemon-reload
echo "Dual Protocol Script 已卸载。Xray、Hysteria2、Caddy 与节点配置均保留。"
