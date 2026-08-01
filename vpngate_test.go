package main

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestParseNodeCSV(t *testing.T) {
	config := "client\nremote 203.0.113.9 1194\n"
	header := "#HostName,IP,Score,Ping,Speed,CountryLong,CountryShort,NumVpnSessions,Uptime,TotalUsers,TotalTraffic,LogType,Operator,Message,OpenVPN_ConfigData_Base64\n"
	row := strings.Join([]string{
		"vpn1", "203.0.113.9", "1", "22", "125000000", "Japan", "JP", "4",
		"0", "0", "0", "", "", "", base64.StdEncoding.EncodeToString([]byte(config)),
	}, ",")
	nodes, err := parseNodeCSV("*vpn_servers\n" + header + row + "\n*\n")
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 1 || nodes[0].CountryCode != "JP" || nodes[0].Config != config {
		t.Fatalf("unexpected nodes: %#v", nodes)
	}
	if nodes[0].SpeedMbps != 125 {
		t.Fatalf("unexpected speed: %v", nodes[0].SpeedMbps)
	}
}
