package main

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

func (t *Tunnel) setupNetns() error {
	ns, subnet := t.nsName(), t.subnet()
	hostVeth, nsVeth := fmt.Sprintf("dpsv%d", t.Slot), fmt.Sprintf("dpsp%d", t.Slot)
	t.teardownNetns()

	steps := [][]string{
		{"netns", "add", ns},
		{"netns", "exec", ns, "ip", "link", "set", "lo", "up"},
		{"link", "add", hostVeth, "type", "veth", "peer", "name", nsVeth},
		{"link", "set", nsVeth, "netns", ns},
		{"addr", "add", subnet + ".1/30", "dev", hostVeth},
		{"link", "set", hostVeth, "up"},
		{"netns", "exec", ns, "ip", "addr", "add", subnet + ".2/30", "dev", nsVeth},
		{"netns", "exec", ns, "ip", "link", "set", nsVeth, "up"},
		{"netns", "exec", ns, "ip", "route", "add", "default", "via", subnet + ".1"},
	}
	for _, args := range steps {
		if err := run("ip", args...); err != nil {
			t.teardownNetns()
			return err
		}
	}

	nsDir := filepath.Join("/etc/netns", ns)
	if err := os.MkdirAll(nsDir, 0755); err != nil {
		t.teardownNetns()
		return fmt.Errorf("创建 %s 失败: %w", nsDir, err)
	}
	if err := os.WriteFile(filepath.Join(nsDir, "resolv.conf"), []byte("nameserver 1.1.1.1\nnameserver 8.8.8.8\n"), 0644); err != nil {
		t.teardownNetns()
		return fmt.Errorf("写入 netns DNS 失败: %w", err)
	}

	cidr := subnet + ".0/30"
	ensureRule("nat", "POSTROUTING", "-s", cidr, "-j", "MASQUERADE")
	ensureRuleInsert("filter", "FORWARD", "-s", cidr, "-j", "ACCEPT")
	ensureRuleInsert("filter", "FORWARD", "-d", cidr, "-j", "ACCEPT")
	return nil
}

func ensureRule(table, chain string, spec ...string) {
	check := append([]string{"-w", "5", "-t", table, "-C", chain}, spec...)
	if exec.Command("iptables", check...).Run() == nil {
		return
	}
	add := append([]string{"-w", "5", "-t", table, "-A", chain}, spec...)
	runQuiet("iptables", add...)
}

func ensureRuleInsert(table, chain string, spec ...string) {
	check := append([]string{"-w", "5", "-t", table, "-C", chain}, spec...)
	if exec.Command("iptables", check...).Run() == nil {
		return
	}
	insert := append([]string{"-w", "5", "-t", table, "-I", chain, "1"}, spec...)
	runQuiet("iptables", insert...)
}

func (t *Tunnel) teardownNetns() {
	ns, subnet := t.nsName(), t.subnet()
	cidr := subnet + ".0/30"
	runQuiet("ip", "netns", "del", ns)
	runQuiet("ip", "link", "del", fmt.Sprintf("dpsv%d", t.Slot))
	runQuiet("iptables", "-w", "5", "-t", "nat", "-D", "POSTROUTING", "-s", cidr, "-j", "MASQUERADE")
	runQuiet("iptables", "-w", "5", "-D", "FORWARD", "-s", cidr, "-j", "ACCEPT")
	runQuiet("iptables", "-w", "5", "-D", "FORWARD", "-d", cidr, "-j", "ACCEPT")
	_ = os.RemoveAll(filepath.Join("/etc/netns", ns))
}

func (t *Tunnel) startOpenVPN(workDir string) error {
	node := t.nodeNow()
	configPath := filepath.Join(workDir, t.nsName()+".ovpn")
	authPath := filepath.Join(workDir, "vpngate-auth.txt")
	logPath := filepath.Join(workDir, t.nsName()+".log")
	if err := os.WriteFile(configPath, []byte(node.Config), 0600); err != nil {
		return fmt.Errorf("写 OpenVPN 配置失败: %w", err)
	}
	if err := os.WriteFile(authPath, []byte("vpn\nvpn\n"), 0600); err != nil {
		return fmt.Errorf("写 VPN Gate 凭据失败: %w", err)
	}
	cmd := exec.Command("ip", "netns", "exec", t.nsName(), "openvpn",
		"--config", configPath,
		"--auth-user-pass", authPath,
		"--auth-nocache",
		"--dev", "tun0",
		"--connect-retry-max", "2",
		"--connect-timeout", "20",
		"--data-ciphers", "AES-128-CBC:AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305",
		"--script-security", "1",
		"--verb", "3",
		"--log", logPath,
	)
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("启动 OpenVPN 失败: %w", err)
	}
	t.mu.Lock()
	t.ovpn = cmd
	t.mu.Unlock()
	go func() { _ = cmd.Wait() }()

	deadline := time.Now().Add(40 * time.Second)
	for time.Now().Before(deadline) {
		out, err := exec.Command("ip", "netns", "exec", t.nsName(), "ip", "-4", "addr", "show", "tun0").Output()
		if err == nil && strings.Contains(string(out), "inet ") {
			return nil
		}
		if cmd.ProcessState != nil && cmd.ProcessState.Exited() {
			return fmt.Errorf("OpenVPN 提前退出，详见 %s", logPath)
		}
		time.Sleep(time.Second)
	}
	return fmt.Errorf("等待 tun0 就绪超时，详见 %s", logPath)
}

func (t *Tunnel) ensureSOCKS() error {
	t.mu.Lock()
	if t.listener != nil {
		t.mu.Unlock()
		return nil
	}
	port := t.Port
	t.mu.Unlock()

	var listener net.Listener
	var err error
	for i := 0; i < 5; i++ {
		listener, err = net.Listen("tcp4", fmt.Sprintf("127.0.0.1:%d", port))
		if err == nil {
			break
		}
		time.Sleep(time.Second)
	}
	if err != nil {
		replacement, replacementErr := freeRandomPort(map[int]bool{port: true})
		if replacementErr != nil {
			return fmt.Errorf("SOCKS5 端口 %d 被占用且无法另选: %w", port, err)
		}
		listener, err = net.Listen("tcp4", fmt.Sprintf("127.0.0.1:%d", replacement))
		if err != nil {
			return fmt.Errorf("监听 SOCKS5 端口 %d 失败: %w", replacement, err)
		}
		t.setPort(replacement)
	}
	t.mu.Lock()
	t.listener = listener
	t.mu.Unlock()

	dial := dialerInNetns(t.nsName())
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go serveSOCKS(conn, dial)
		}
	}()
	return nil
}

func (t *Tunnel) probeExitIP() (string, error) {
	out, err := exec.Command("ip", "netns", "exec", t.nsName(),
		"curl", "-4fsS", "--max-time", "15", "https://api.ipify.org").Output()
	if err != nil {
		return "", fmt.Errorf("查询家宽出口 IP 失败: %w", err)
	}
	ip := strings.TrimSpace(string(out))
	if net.ParseIP(ip) == nil {
		return "", fmt.Errorf("家宽出口 IP 返回异常: %q", ip)
	}
	return ip, nil
}

func (t *Tunnel) killOpenVPN() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.ovpn != nil && t.ovpn.Process != nil {
		_ = t.ovpn.Process.Kill()
		t.ovpn = nil
	}
}

func (t *Tunnel) stop() {
	t.mu.Lock()
	if t.listener != nil {
		_ = t.listener.Close()
		t.listener = nil
	}
	if t.ovpn != nil && t.ovpn.Process != nil {
		_ = t.ovpn.Process.Kill()
		t.ovpn = nil
	}
	t.status = "stopped"
	t.exitIP = ""
	t.mu.Unlock()
	t.teardownNetns()
}
