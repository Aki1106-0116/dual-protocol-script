package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func validXHTTPNodeConfig() NodeConfig {
	return NodeConfig{
		StackMode:             "xhttp_hy2",
		MainMode:              "xhttp",
		NodeName:              "edge xhttp + hy2",
		FP:                    "chrome",
		XHTTPDomain:           "x.example.com",
		XHTTPPath:             "/api/v1",
		XHTTPUUID:             "123e4567-e89b-12d3-a456-426614174000",
		XHTTPBackendPort:      10080,
		HY2Domain:             "h.example.com",
		HY2Password:           "hy2-secret",
		HY2PortMode:           "hop",
		HY2Port:               30000,
		HY2FirstPort:          30000,
		HY2EndPort:            30075,
		HY2HopInterval:        25,
		HY2CertSource:         "caddy",
		HY2ObfsType:           "none",
		HY2GeckoMinPacketSize: 512,
		HY2GeckoMaxPacketSize: 1200,
	}
}

func validRealityNodeConfig() NodeConfig {
	return NodeConfig{
		StackMode:             "reality_hy2",
		MainMode:              "reality",
		NodeName:              "edge reality + hy2",
		FP:                    "firefox",
		RealityAddress:        "203.0.113.10",
		RealitySNI:            "www.example.com",
		RealityUUID:           "123e4567-e89b-12d3-a456-426614174000",
		HY2Domain:             "h.example.com",
		HY2Password:           "hy2-secret",
		HY2PortMode:           "single",
		HY2Port:               45678,
		HY2CertSource:         "acme",
		HY2ACMEEmail:          "acme@example.com",
		HY2ObfsType:           "gecko",
		HY2ObfsPassword:       "gecko-secret",
		HY2GeckoMinPacketSize: 512,
		HY2GeckoMaxPacketSize: 1200,
	}
}

func TestValidateNodeConfigBothSupportedStacks(t *testing.T) {
	for name, config := range map[string]NodeConfig{
		"xhttp":   validXHTTPNodeConfig(),
		"reality": validRealityNodeConfig(),
	} {
		t.Run(name, func(t *testing.T) {
			if err := validateNodeConfig(config); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestValidateNodeConfigRejectsDangerousAndConflictingValues(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*NodeConfig)
	}{
		{"control character", func(c *NodeConfig) { c.HY2Password = "bad\nvalue" }},
		{"same xhttp and hy2 domain", func(c *NodeConfig) { c.XHTTPDomain = c.HY2Domain }},
		{"reserved hopping port", func(c *NodeConfig) { c.HY2FirstPort, c.HY2EndPort = 2000, 2100 }},
		{"invalid uuid", func(c *NodeConfig) { c.XHTTPUUID = "$(touch /tmp/no)" }},
		{"invalid path", func(c *NodeConfig) { c.XHTTPPath = "/ok;restart" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := validXHTTPNodeConfig()
			test.mutate(&config)
			if err := validateNodeConfig(config); err == nil {
				t.Fatal("invalid configuration was accepted")
			}
		})
	}
}

func TestNodeConfigNormalizeMatchesInstallerRules(t *testing.T) {
	config := validRealityNodeConfig()
	config.RealityAddress = "HTTPS://[2001:db8::10]:443/path"
	config.RealitySNI = "HTTPS://WWW.EXAMPLE.COM/path"
	config.HY2Domain = "H.EXAMPLE.COM"
	config.normalize()
	if config.RealityAddress != "2001:db8::10" {
		t.Fatalf("reality address = %q", config.RealityAddress)
	}
	if config.RealitySNI != "www.example.com" || config.HY2Domain != "h.example.com" {
		t.Fatalf("domains were not normalized: %#v", config)
	}
	if err := validateNodeConfig(config); err != nil {
		t.Fatal(err)
	}
}

func TestNodeConfigEnvironmentUsesValuesNotShellCode(t *testing.T) {
	config := validRealityNodeConfig()
	config.NodeName = "literal $(reboot) ; value"
	config.RotateRealityKeys = true
	environment := nodeConfigEnvironment(config)
	joined := strings.Join(environment, "\n")
	if !strings.Contains(joined, "DPS_WEB_NODE_NAME=literal $(reboot) ; value") {
		t.Fatalf("node name was not passed literally: %s", joined)
	}
	if !strings.Contains(joined, "DPS_WEB_ROTATE_REALITY_KEYS=1") {
		t.Fatalf("rotation flag missing: %s", joined)
	}
}

func TestNodeConfigEnvironmentOmitsInactiveHopIntervals(t *testing.T) {
	fixed := validXHTTPNodeConfig()
	fixed.HY2HopInterval = 25
	fixed.HY2MinHopInterval = 0
	fixed.HY2MaxHopInterval = 0
	joined := strings.Join(nodeConfigEnvironment(fixed), "\n")
	if !strings.Contains(joined, "DPS_WEB_HY2_HOP_INTERVAL=25") ||
		!strings.Contains(joined, "DPS_WEB_HY2_MIN_HOP_INTERVAL=\n") ||
		!strings.Contains(joined, "DPS_WEB_HY2_MAX_HOP_INTERVAL=\n") {
		t.Fatalf("fixed hopping exported inactive random values: %s", joined)
	}

	random := fixed
	random.HY2HopInterval = 0
	random.HY2MinHopInterval = 15
	random.HY2MaxHopInterval = 25
	joined = strings.Join(nodeConfigEnvironment(random), "\n")
	if !strings.Contains(joined, "DPS_WEB_HY2_HOP_INTERVAL=\n") ||
		!strings.Contains(joined, "DPS_WEB_HY2_MIN_HOP_INTERVAL=15") ||
		!strings.Contains(joined, "DPS_WEB_HY2_MAX_HOP_INTERVAL=25") {
		t.Fatalf("random hopping exported incorrect intervals: %s", joined)
	}
}

func TestRealityPrivateKeyIsNotPartOfWebSchema(t *testing.T) {
	config := validRealityNodeConfig()
	environment := strings.Join(nodeConfigEnvironment(config), "\n")
	if strings.Contains(environment, "PRIVATE_KEY") {
		t.Fatalf("private key leaked into Web apply environment: %s", environment)
	}
}

func TestLoadNodeLinksValidatesAndExportsFiles(t *testing.T) {
	dir := t.TempDir()
	files := map[string]string{
		"main-url.txt":  "vless://main-link\n",
		"hy2-url.txt":   "hysteria2://hy2-link\n",
		"node-info.txt": "node details\n",
	}
	for name, value := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(value), 0600); err != nil {
			t.Fatal(err)
		}
	}
	links, err := LoadNodeLinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	if links.MainURL != "vless://main-link" || links.HY2URL != "hysteria2://hy2-link" || links.Info != "node details" {
		t.Fatalf("unexpected links: %#v", links)
	}
	if err := os.WriteFile(filepath.Join(dir, "main-url.txt"), []byte("https://invalid"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadNodeLinks(dir); err == nil {
		t.Fatal("invalid share link was accepted")
	}
}
