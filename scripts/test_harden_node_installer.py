import unittest

import harden_node_installer


class XrayCandidateFormatTests(unittest.TestCase):
    def test_xhttp_candidates_have_json_suffix_and_explicit_format(self):
        template = harden_node_installer.WRITE_XHTTP
        self.assertIn(
            'mktemp --suffix=.json "${XRAY_CONFIG}.tmp.XXXXXX"',
            template,
        )
        self.assertEqual(
            template.count('run -test -config "$tmp" -format json'),
            2,
        )
        self.assertIn('"clients": [', template)
        self.assertIn('"network": "xhttp"', template)
        self.assertNotIn('"users": [', template)
        self.assertNotIn('"method": "xhttp"', template)

    def test_reality_candidates_have_json_suffix_and_explicit_format(self):
        template = harden_node_installer.WRITE_REALITY
        self.assertIn(
            'mktemp --suffix=.json "${XRAY_CONFIG}.tmp.XXXXXX"',
            template,
        )
        self.assertEqual(
            template.count('run -test -config "$tmp" -format json'),
            3,
        )
        self.assertEqual(template.count('"clients": ['), 2)
        self.assertIn('"network": "raw"', template)
        self.assertIn('"target": "${REALITY_SNI}:443"', template)
        self.assertNotIn('"method": "raw"', template)

    def test_reality_self_test_uses_current_client_fields(self):
        template = harden_node_installer.WRITE_REALITY
        self.assertIn("reality_local_self_test()", template)
        self.assertIn('"password": "${REALITY_PUBLIC_KEY}"', template)
        self.assertIn('"network": "raw"', template)
        self.assertIn("--socks5-hostname", template)

    def test_transform_updates_outputs_and_initial_install(self):
        source = """#!/usr/bin/env bash
generate_reality_x25519_keys() {
}
install_hysteria_official() {
}
write_hy2_config_acme() {
}
write_service_restart_override() {
}
write_xhttp_xray_config() {
}
write_reality_xray_config() {
}
write_caddyfile_xhttp_hy2() {
}
change_reality_target() {
}
show_info() {
}
generate_main_outputs() {
        "network": "tcp",
        "security": "reality",
        "realitySettings": { "serverName": "${REALITY_SNI}", "fingerprint": "${FP}", "publicKey": "${REALITY_PUBLIC_KEY}", "shortId": "${REALITY_SHORT_ID}", "spiderX": "/" }
}
install_stack_reality_hy2() {
  start_xray
  start_hy2
  save_state
}
main() {
  require_root
  check_os
}
JB_CMD="/usr/local/bin/{harden_node_installer.UPSTREAM_TUI_NAME}"
JB_CMD_FALLBACK="/usr/bin/{harden_node_installer.UPSTREAM_TUI_NAME}"
THIS_SCRIPT="/usr/local/lib/jb-combo-installer.sh"
HY2_BIN="/usr/local/bin/hysteria"
echo "管理命令：{harden_node_installer.UPSTREAM_TUI_NAME}"
"""
        source = source.replace(
            "{harden_node_installer.UPSTREAM_TUI_NAME}",
            harden_node_installer.UPSTREAM_TUI_NAME,
        )
        transformed = harden_node_installer.transform(source)
        self.assertIn('"network": "raw"', transformed)
        self.assertIn('"password": "${REALITY_PUBLIC_KEY}"', transformed)
        self.assertIn("reality_local_self_test || exit 1", transformed)
        self.assertIn("web_export_config()", transformed)
        self.assertIn("web_apply_config()", transformed)
        self.assertIn("web_reinstall_stack()", transformed)
        self.assertIn("web-export) web_export_config", transformed)
        self.assertIn("web-reinstall) web_reinstall_stack", transformed)
        self.assertIn("管理命令：tui", transformed)
        self.assertNotIn(
            'export REALITY_PRIVATE_KEY ',
            harden_node_installer.WEB_CONFIG_FUNCTIONS,
        )

    def test_web_apply_uses_health_checks_and_rollback(self):
        template = harden_node_installer.WEB_CONFIG_FUNCTIONS
        self.assertIn("web_validate_and_assign_config", template)
        self.assertIn("web_rollback_config", template)
        self.assertEqual(template.count("trap 'exit 143' HUP INT TERM"), 2)
        self.assertIn("trap - EXIT HUP INT TERM", template)
        self.assertIn("reality_local_self_test", template)
        self.assertIn("start_xray", template)
        self.assertIn("start_hy2", template)
        self.assertIn("start_caddy", template)
        self.assertIn("DPS_WEB_TARGET_MODE", template)

    def test_fixed_hopping_treats_zero_random_intervals_as_empty(self):
        template = harden_node_installer.WEB_CONFIG_FUNCTIONS
        self.assertIn('[[ "$web_min_hop" == "0" ]] && web_min_hop=""', template)
        self.assertIn('[[ "$web_max_hop" == "0" ]] && web_max_hop=""', template)
        self.assertIn('web_valid_uint "$web_fixed_hop" 5 600', template)
        self.assertNotIn(
            'if [[ -n "$DPS_WEB_HY2_MIN_HOP_INTERVAL" || -n "$DPS_WEB_HY2_MAX_HOP_INTERVAL" ]]',
            template,
        )

    def test_domain_changes_wait_for_new_cert_before_old_cert_cleanup(self):
        template = harden_node_installer.WEB_CONFIG_FUNCTIONS
        wait_pos = template.index('web_wait_for_hy2_acme_cert "$HY2_DOMAIN"')
        commit_pos = template.index("WEB_APPLY_COMMITTED=1", wait_pos)
        cleanup_pos = template.index("web_cleanup_replaced_domains", commit_pos)
        self.assertLess(wait_pos, commit_pos)
        self.assertLess(commit_pos, cleanup_pos)
        self.assertIn("web_wait_for_caddy_cert_only", template)
        self.assertIn("openssl x509", template)
        self.assertIn("新服务配置也不会再为它自动续签", template)


if __name__ == "__main__":
    unittest.main()
