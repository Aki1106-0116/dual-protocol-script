package main

import (
	"fmt"
	"log"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"time"
)

type Manager struct {
	mu       sync.RWMutex
	tunnels  map[int]*Tunnel
	nodes    []Node
	fetched  time.Time
	workDir  string
	maxSlots int
	router   *Router
	jobs     JobStore
}

func NewManager(maxSlots int, workDir string, router *Router) *Manager {
	return &Manager{
		tunnels: make(map[int]*Tunnel), workDir: workDir,
		maxSlots: maxSlots, router: router,
	}
}

func (m *Manager) RefreshNodes() (int, error) {
	nodes, err := fetchNodes(60 * time.Second)
	if err != nil {
		return 0, err
	}
	m.mu.Lock()
	m.nodes, m.fetched = nodes, time.Now()
	m.mu.Unlock()
	return len(nodes), nil
}

func (m *Manager) Nodes() ([]Node, time.Time) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := append([]Node(nil), m.nodes...)
	return out, m.fetched
}

func (m *Manager) Tunnels() []*Tunnel {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]*Tunnel, 0, len(m.tunnels))
	for _, tunnel := range m.tunnels {
		out = append(out, tunnel)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Slot < out[j].Slot })
	return out
}

func (m *Manager) TunnelViews() []TunnelView {
	return sortedTunnelViews(m.Tunnels())
}

func (m *Manager) tunnel(slot int) (*Tunnel, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	tunnel, ok := m.tunnels[slot]
	return tunnel, ok
}

func (m *Manager) freeSlotLocked() (int, error) {
	for slot := 1; slot <= m.maxSlots; slot++ {
		if _, exists := m.tunnels[slot]; !exists {
			return slot, nil
		}
	}
	return 0, fmt.Errorf("出口槽位已满（上限 %d）", m.maxSlots)
}

func (m *Manager) Start(node Node) (*Tunnel, error) {
	m.mu.Lock()
	slot, err := m.freeSlotLocked()
	if err != nil {
		m.mu.Unlock()
		return nil, err
	}
	taken := map[int]bool{}
	for _, tunnel := range m.tunnels {
		taken[tunnel.view().Port] = true
	}
	port, err := freeRandomPort(taken)
	if err != nil {
		m.mu.Unlock()
		return nil, err
	}
	tunnel := newTunnel(slot, port, node)
	m.tunnels[slot] = tunnel
	m.mu.Unlock()
	go m.bringUp(tunnel)
	return tunnel, nil
}

func (m *Manager) bringUp(tunnel *Tunnel) {
	candidates := m.candidatesFor(tunnel.nodeNow())
	var lastErr error
	for i, node := range candidates {
		if i > 0 && m.nodeInUse(node.HostName, tunnel.Slot) {
			continue
		}
		tunnel.replaceNode(node)
		detail := ""
		if i > 0 {
			detail = fmt.Sprintf("第 %d 个同地区候选", i+1)
		}
		tunnel.setState("starting", "", detail)
		if err := tunnel.setupNetns(); err != nil {
			lastErr = err
			continue
		}
		if err := tunnel.startOpenVPN(m.workDir); err != nil {
			lastErr = err
			tunnel.killOpenVPN()
			tunnel.teardownNetns()
			continue
		}
		if err := tunnel.ensureSOCKS(); err != nil {
			lastErr = err
			tunnel.killOpenVPN()
			tunnel.teardownNetns()
			continue
		}
		exitIP, err := tunnel.probeExitIP()
		if err != nil {
			lastErr = err
			tunnel.killOpenVPN()
			tunnel.teardownNetns()
			continue
		}
		tunnel.setState("up", exitIP, "")
		if err := m.saveState(); err != nil {
			log.Printf("保存隧道状态失败: %v", err)
		}
		m.notifyRouter()
		return
	}
	message := fmt.Sprintf("尝试 %d 个节点均失败", len(candidates))
	if lastErr != nil {
		message += ": " + lastErr.Error()
	}
	tunnel.setState("failed", "", message)
	if err := m.saveState(); err != nil {
		log.Printf("保存隧道状态失败: %v", err)
	}
}

func (m *Manager) candidatesFor(first Node) []Node {
	const maxCandidates = 6
	m.mu.RLock()
	defer m.mu.RUnlock()
	used := map[string]bool{first.HostName: true}
	for _, tunnel := range m.tunnels {
		used[tunnel.nodeNow().HostName] = true
	}
	region := first.CountryCode
	if region == "" {
		for _, node := range m.nodes {
			if node.HostName == first.HostName {
				region = node.CountryCode
				break
			}
		}
	}
	out := []Node{first}
	for _, node := range m.nodes {
		if len(out) >= maxCandidates {
			break
		}
		if used[node.HostName] || (region != "" && node.CountryCode != region) {
			continue
		}
		out = append(out, node)
	}
	return out
}

func (m *Manager) Stop(slot int) error {
	m.mu.Lock()
	tunnel, ok := m.tunnels[slot]
	if ok {
		delete(m.tunnels, slot)
	}
	m.mu.Unlock()
	if !ok {
		return fmt.Errorf("出口槽位 %d 不存在", slot)
	}

	if m.router != nil {
		if err := m.router.DropSlot(slot, m.Tunnels()); err != nil {
			m.mu.Lock()
			m.tunnels[slot] = tunnel
			m.mu.Unlock()
			_ = m.router.Apply(m.Tunnels())
			return fmt.Errorf("停止前切回直连失败，出口仍保留: %w", err)
		}
	}
	tunnel.stop()
	if err := m.saveState(); err != nil {
		log.Printf("保存隧道状态失败: %v", err)
	}
	return nil
}

func (m *Manager) Swap(slot int) error {
	tunnel, ok := m.tunnel(slot)
	if !ok {
		return fmt.Errorf("出口槽位 %d 不存在", slot)
	}
	if tunnel.statusNow() == "starting" {
		return fmt.Errorf("该出口正在连接中")
	}
	region := tunnel.nodeNow().CountryCode
	picks, err := m.pickNodes(region, 1)
	if err != nil {
		return err
	}
	tunnel.replaceNode(picks[0])
	m.reconnect(tunnel, "用户手动切换")
	return nil
}

func (m *Manager) reconnect(tunnel *Tunnel, reason string) {
	tunnel.setState("starting", "", reason)
	tunnel.killOpenVPN()
	tunnel.teardownNetns()
	go m.bringUp(tunnel)
}

func (m *Manager) nodeInUse(host string, exceptSlot int) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for slot, tunnel := range m.tunnels {
		if slot != exceptSlot && tunnel.nodeNow().HostName == host {
			return true
		}
	}
	return false
}

func (m *Manager) pickNodes(region string, count int) ([]Node, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	used := map[string]bool{}
	for _, tunnel := range m.tunnels {
		used[tunnel.nodeNow().HostName] = true
	}
	var out []Node
	for _, node := range m.nodes {
		if len(out) >= count {
			break
		}
		if used[node.HostName] || (region != "" && !strings.EqualFold(node.CountryCode, region)) {
			continue
		}
		out = append(out, node)
	}
	if len(out) == 0 {
		if region != "" {
			return nil, fmt.Errorf("%s 暂无空闲可用节点", region)
		}
		return nil, fmt.Errorf("暂无空闲可用节点，请刷新列表")
	}
	return out, nil
}

func (m *Manager) Regions() []RegionStat {
	m.mu.RLock()
	defer m.mu.RUnlock()
	used := map[string]bool{}
	for _, tunnel := range m.tunnels {
		used[tunnel.nodeNow().HostName] = true
	}
	grouped := map[string]*RegionStat{}
	for _, node := range m.nodes {
		if used[node.HostName] || node.CountryCode == "" {
			continue
		}
		stat := grouped[node.CountryCode]
		if stat == nil {
			stat = &RegionStat{Code: node.CountryCode, Name: node.Country}
			grouped[node.CountryCode] = stat
		}
		stat.Available++
		if node.SpeedMbps > stat.BestSpeed {
			stat.BestSpeed = node.SpeedMbps
		}
		if node.Ping > 0 && (stat.BestPing == 0 || node.Ping < stat.BestPing) {
			stat.BestPing = node.Ping
		}
	}
	out := make([]RegionStat, 0, len(grouped))
	for _, stat := range grouped {
		out = append(out, *stat)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Available != out[j].Available {
			return out[i].Available > out[j].Available
		}
		return out[i].Code < out[j].Code
	})
	return out
}

func (m *Manager) notifyRouter() {
	if m.router == nil {
		return
	}
	if err := m.router.Apply(m.Tunnels()); err != nil {
		log.Printf("同步协议出口失败: %v", err)
	}
}

func (m *Manager) Shutdown() {
	for _, tunnel := range m.Tunnels() {
		tunnel.stop()
	}
}

func prepareHost() error {
	if err := exec.Command("sysctl", "-qw", "net.ipv4.ip_forward=1").Run(); err != nil {
		return fmt.Errorf("开启 IPv4 转发失败: %w", err)
	}
	return nil
}
