package main

import (
	"log"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

const (
	healthInterval = 10 * time.Second
	healthTimeout  = 6 * time.Second
	healthFailures = 2
)

func (m *Manager) WatchHealth() {
	failures := map[int]int{}
	ticker := time.NewTicker(healthInterval)
	defer ticker.Stop()
	for range ticker.C {
		for _, tunnel := range m.Tunnels() {
			if tunnel.statusNow() != "up" {
				continue
			}
			if m.tunnelHealthy(tunnel) {
				failures[tunnel.Slot] = 0
				continue
			}
			failures[tunnel.Slot]++
			if failures[tunnel.Slot] < healthFailures {
				log.Printf("出口 %d 健康检查失败 %d 次", tunnel.Slot, failures[tunnel.Slot])
				continue
			}
			failures[tunnel.Slot] = 0
			log.Printf("出口 %d 已失效，正在同地区自动换节点", tunnel.Slot)
			m.reconnect(tunnel, "健康检查失败，自动切换")
		}
	}
}

func (m *Manager) tunnelHealthy(tunnel *Tunnel) bool {
	out, err := exec.Command("ip", "netns", "exec", tunnel.nsName(),
		"curl", "-4fsS", "--max-time", strconv.Itoa(int(healthTimeout.Seconds())),
		"https://api.ipify.org").Output()
	if err != nil {
		return false
	}
	got := strings.TrimSpace(string(out))
	return got != "" && got == tunnel.exitIPNow()
}
