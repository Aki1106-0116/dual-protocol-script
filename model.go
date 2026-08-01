package main

import (
	"fmt"
	"net"
	"os/exec"
	"sync"
	"time"
)

// Node is one public VPN Gate volunteer server.
type Node struct {
	HostName    string  `json:"hostname"`
	IP          string  `json:"ip"`
	Country     string  `json:"country"`
	CountryCode string  `json:"country_code"`
	Ping        int     `json:"ping"`
	SpeedMbps   float64 `json:"speed_mbps"`
	Sessions    int     `json:"sessions"`
	Config      string  `json:"-"`
}

// Tunnel is one stable slot: a network namespace, OpenVPN process and
// host-local SOCKS5 listener. Swapping the VPN Gate node keeps Slot and Port.
type Tunnel struct {
	Slot int  `json:"slot"`
	Port int  `json:"port"`
	Node Node `json:"node"`

	mu       sync.RWMutex
	status   string
	exitIP   string
	errText  string
	since    time.Time
	listener net.Listener
	ovpn     *exec.Cmd
}

type TunnelView struct {
	Slot   int       `json:"slot"`
	Port   int       `json:"port"`
	Node   Node      `json:"node"`
	Status string    `json:"status"`
	ExitIP string    `json:"exit_ip"`
	Error  string    `json:"error,omitempty"`
	Since  time.Time `json:"since"`
}

func newTunnel(slot, port int, node Node) *Tunnel {
	return &Tunnel{
		Slot: slot, Port: port, Node: node,
		status: "starting", since: time.Now(),
	}
}

func (t *Tunnel) nsName() string { return fmt.Sprintf("dps%d", t.Slot) }
func (t *Tunnel) subnet() string { return fmt.Sprintf("10.98.%d", t.Slot) }

func (t *Tunnel) view() TunnelView {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return TunnelView{
		Slot: t.Slot, Port: t.Port, Node: t.Node,
		Status: t.status, ExitIP: t.exitIP, Error: t.errText, Since: t.since,
	}
}

func (t *Tunnel) setState(status, exitIP, errText string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.status, t.exitIP, t.errText = status, exitIP, errText
	if status == "starting" {
		t.since = time.Now()
	}
}

func (t *Tunnel) statusNow() string {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.status
}

func (t *Tunnel) exitIPNow() string {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.exitIP
}

func (t *Tunnel) nodeNow() Node {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.Node
}

func (t *Tunnel) replaceNode(node Node) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.Node = node
}

func (t *Tunnel) setPort(port int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.Port = port
}

type RegionStat struct {
	Code      string  `json:"code"`
	Name      string  `json:"name"`
	Available int     `json:"available"`
	BestPing  int     `json:"best_ping"`
	BestSpeed float64 `json:"best_speed_mbps"`
}

type ProtocolBinding struct {
	Slot int `json:"slot"`
}

type BindingState struct {
	VLESS ProtocolBinding `json:"vless"`
	HY2   ProtocolBinding `json:"hy2"`
}

type ProtocolRoute struct {
	Protocol string `json:"protocol"`
	Label    string `json:"label"`
	Slot     int    `json:"slot"`
	Mode     string `json:"mode"`
	ExitIP   string `json:"exit_ip,omitempty"`
	Country  string `json:"country,omitempty"`
	Ready    bool   `json:"ready"`
	Note     string `json:"note,omitempty"`
}

type RouterStatus struct {
	Stack       string          `json:"stack"`
	MainLabel   string          `json:"main_label"`
	Routes      []ProtocolRoute `json:"routes"`
	XrayConfig  string          `json:"xray_config"`
	HY2Config   string          `json:"hy2_config"`
	LastApplied time.Time       `json:"last_applied,omitempty"`
	LastError   string          `json:"last_error,omitempty"`
}
