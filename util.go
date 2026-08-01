package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"os/exec"
	"sort"
	"strings"
)

const (
	randomPortMin = 21000
	randomPortMax = 59000
)

func run(name string, args ...string) error {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func runQuiet(name string, args ...string) {
	_ = exec.Command(name, args...).Run()
}

func freeRandomPort(taken map[int]bool) (int, error) {
	const tries = 256
	buf := make([]byte, 2)
	for i := 0; i < tries; i++ {
		if _, err := rand.Read(buf); err != nil {
			return 0, err
		}
		raw := int(buf[0])<<8 | int(buf[1])
		p := randomPortMin + raw%(randomPortMax-randomPortMin+1)
		if taken[p] {
			continue
		}
		ln, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", fmt.Sprint(p)))
		if err != nil {
			continue
		}
		_ = ln.Close()
		return p, nil
	}
	return 0, fmt.Errorf("无法分配空闲本地端口")
}

func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "fallback"
	}
	return hex.EncodeToString(b)
}

func sortedTunnelViews(tunnels []*Tunnel) []TunnelView {
	out := make([]TunnelView, 0, len(tunnels))
	for _, t := range tunnels {
		out = append(out, t.view())
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Slot < out[j].Slot })
	return out
}
