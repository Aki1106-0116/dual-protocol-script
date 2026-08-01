package main

import (
	"encoding/base64"
	"encoding/csv"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

const vpnGateAPI = "https://www.vpngate.net/api/iphone/"
const maxVPNGateResponse = 32 << 20

func fetchNodes(timeout time.Duration) ([]Node, error) {
	client := &http.Client{Timeout: timeout}
	resp, err := client.Get(vpnGateAPI)
	if err != nil {
		return nil, fmt.Errorf("拉取 VPN Gate 列表失败: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("VPN Gate 返回 HTTP %d", resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxVPNGateResponse+1))
	if err != nil {
		return nil, fmt.Errorf("读取 VPN Gate 列表失败: %w", err)
	}
	if len(raw) > maxVPNGateResponse {
		return nil, fmt.Errorf("VPN Gate 列表超过 %d MiB，拒绝解析", maxVPNGateResponse>>20)
	}
	return parseNodeCSV(string(raw))
}

func parseNodeCSV(body string) ([]Node, error) {
	var lines []string
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimRight(line, "\r")
		if line == "" || strings.HasPrefix(line, "*") {
			continue
		}
		lines = append(lines, strings.TrimPrefix(line, "#"))
	}
	if len(lines) < 2 {
		return nil, fmt.Errorf("VPN Gate 列表格式异常")
	}
	r := csv.NewReader(strings.NewReader(strings.Join(lines, "\n")))
	r.FieldsPerRecord = -1
	records, err := r.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("解析 VPN Gate CSV 失败: %w", err)
	}
	index := map[string]int{}
	for i, name := range records[0] {
		index[strings.TrimSpace(name)] = i
	}
	required := []string{
		"HostName", "IP", "CountryLong", "CountryShort",
		"Ping", "Speed", "OpenVPN_ConfigData_Base64",
	}
	for _, key := range required {
		if _, ok := index[key]; !ok {
			return nil, fmt.Errorf("VPN Gate 列表缺少 %s", key)
		}
	}
	get := func(record []string, key string) string {
		i, ok := index[key]
		if !ok || i >= len(record) {
			return ""
		}
		return record[i]
	}
	var nodes []Node
	for _, record := range records[1:] {
		host, encoded := get(record, "HostName"), get(record, "OpenVPN_ConfigData_Base64")
		if host == "" || encoded == "" {
			continue
		}
		config, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			continue
		}
		ping, _ := strconv.Atoi(get(record, "Ping"))
		speed, _ := strconv.ParseFloat(get(record, "Speed"), 64)
		sessions, _ := strconv.Atoi(get(record, "NumVpnSessions"))
		nodes = append(nodes, Node{
			HostName: host, IP: get(record, "IP"),
			Country: get(record, "CountryLong"), CountryCode: get(record, "CountryShort"),
			Ping: ping, SpeedMbps: speed / 1e6, Sessions: sessions, Config: string(config),
		})
	}
	if len(nodes) == 0 {
		return nil, fmt.Errorf("VPN Gate 当前没有可解析节点")
	}
	sort.Slice(nodes, func(i, j int) bool {
		if nodes[i].SpeedMbps == nodes[j].SpeedMbps {
			return nodes[i].Ping < nodes[j].Ping
		}
		return nodes[i].SpeedMbps > nodes[j].SpeedMbps
	})
	return nodes, nil
}
