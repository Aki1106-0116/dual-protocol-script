package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

type persistedTunnel struct {
	Slot        int    `json:"slot"`
	Port        int    `json:"port"`
	HostName    string `json:"hostname"`
	IP          string `json:"ip"`
	CountryCode string `json:"country_code"`
	Country     string `json:"country"`
	Config      string `json:"config"`
}

type persistedState struct {
	Tunnels []persistedTunnel `json:"tunnels"`
}

func (m *Manager) statePath() string {
	return filepath.Join(m.workDir, "tunnels.json")
}

func (m *Manager) saveState() error {
	state := persistedState{}
	for _, tunnel := range m.Tunnels() {
		view := tunnel.view()
		if view.Status == "stopped" {
			continue
		}
		state.Tunnels = append(state.Tunnels, persistedTunnel{
			Slot: view.Slot, Port: view.Port,
			HostName: view.Node.HostName, IP: view.Node.IP,
			CountryCode: view.Node.CountryCode, Country: view.Node.Country,
			Config: view.Node.Config,
		})
	}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	path := m.statePath()
	temp := path + ".tmp"
	if err := os.WriteFile(temp, data, 0600); err != nil {
		return err
	}
	return os.Rename(temp, path)
}

func (m *Manager) restoreState() (int, error) {
	data, err := os.ReadFile(m.statePath())
	if os.IsNotExist(err) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	var state persistedState
	if err := json.Unmarshal(data, &state); err != nil {
		return 0, fmt.Errorf("解析隧道状态失败: %w", err)
	}
	known := map[string]Node{}
	for _, node := range m.nodes {
		known[node.HostName] = node
	}
	for _, saved := range state.Tunnels {
		node, ok := known[saved.HostName]
		if !ok {
			node = Node{
				HostName: saved.HostName, IP: saved.IP,
				CountryCode: saved.CountryCode, Country: saved.Country,
			}
		}
		node.Config = saved.Config
		tunnel := newTunnel(saved.Slot, saved.Port, node)
		m.mu.Lock()
		if saved.Slot < 1 || saved.Slot > m.maxSlots {
			m.mu.Unlock()
			continue
		}
		m.tunnels[saved.Slot] = tunnel
		m.mu.Unlock()
		go m.bringUp(tunnel)
	}
	return len(state.Tunnels), nil
}
