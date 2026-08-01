package main

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func TestParseRealityKeyPairVerifiesDerivation(t *testing.T) {
	private, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	privateText := base64.RawURLEncoding.EncodeToString(private.Bytes())
	publicText := base64.RawURLEncoding.EncodeToString(private.PublicKey().Bytes())
	output := "PrivateKey: " + privateText + "\nPassword: " + publicText + "\nHash32: ignored\n"
	pair, err := parseRealityKeyPair(output)
	if err != nil {
		t.Fatalf("valid pair rejected: %v", err)
	}
	if pair.Private != privateText || pair.Public != publicText {
		t.Fatalf("wrong pair parsed: %#v", pair)
	}
}

func TestParseRealityKeyPairRejectsMismatchedPublic(t *testing.T) {
	first, _ := ecdh.X25519().GenerateKey(rand.Reader)
	second, _ := ecdh.X25519().GenerateKey(rand.Reader)
	output := "Private key: " + base64.RawURLEncoding.EncodeToString(first.Bytes()) +
		"\nPublic key: " + base64.RawURLEncoding.EncodeToString(second.PublicKey().Bytes())
	if _, err := parseRealityKeyPair(output); err == nil {
		t.Fatal("mismatched pair was accepted")
	}
}

func TestTransformXrayConfigRoundTrip(t *testing.T) {
	source := []byte(`{
  "inbounds": [{
    "tag":"vless-reality-vision-in",
    "protocol":"vless",
    "settings":{"users":[{"id":"test"}]},
    "streamSettings":{"method":"raw"}
  }],
  "outbounds": [{"tag":"direct","protocol":"freedom"}],
  "routing": {"rules":[{"type":"field","domain":["example.com"],"outboundTag":"direct"}]}
}`)
	bound, err := transformXrayConfig(source, 23456)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(bound, []byte(`"tag": "dual-protocol-script-vless"`)) ||
		!bytes.Contains(bound, []byte(`"vless-reality-vision-in"`)) ||
		!bytes.Contains(bound, []byte(`"address": "127.0.0.1"`)) {
		t.Fatalf("managed route missing:\n%s", bound)
	}
	boundAgain, err := transformXrayConfig(bound, 23456)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(bound, boundAgain) {
		t.Fatal("transform is not idempotent")
	}
	direct, err := transformXrayConfig(bound, 0)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(direct, []byte(managedXrayTag)) {
		t.Fatalf("managed route not removed:\n%s", direct)
	}
	var parsed map[string]any
	if err := json.Unmarshal(direct, &parsed); err != nil {
		t.Fatal(err)
	}
	routing := parsed["routing"].(map[string]any)
	if len(routing["rules"].([]any)) != 1 {
		t.Fatal("unrelated routing rule was not preserved")
	}
}

func TestTransformXrayConfigUsesLegacySocksForLegacyNodeConfig(t *testing.T) {
	source := []byte(`{
  "inbounds": [{
    "tag":"vless-xhttp-in",
    "protocol":"vless",
    "settings":{"clients":[{"id":"test"}]},
    "streamSettings":{"network":"xhttp"}
  }],
  "outbounds": [{"tag":"direct","protocol":"freedom"}]
}`)
	bound, err := transformXrayConfig(source, 23456)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(bound, []byte(`"servers": [`)) {
		t.Fatalf("legacy SOCKS settings not selected:\n%s", bound)
	}
}

func TestTransformHY2ConfigRoundTrip(t *testing.T) {
	source := []byte("listen: :4433\n\nauth:\n  type: password\n  password: secret\n")
	bound, err := transformHY2Config(source, 24567)
	if err != nil {
		t.Fatal(err)
	}
	text := string(bound)
	for _, want := range []string{hy2BlockBegin, "UDP ASSOCIATE", "addr: 127.0.0.1:24567"} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "disableUDP: true") {
		t.Fatalf("HY2 destination UDP was unexpectedly disabled:\n%s", text)
	}
	boundAgain, err := transformHY2Config(bound, 24567)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(bound, boundAgain) {
		t.Fatal("HY2 transform is not idempotent")
	}
	direct, err := transformHY2Config(bound, 0)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(direct), hy2BlockBegin) {
		t.Fatal("managed HY2 block not removed")
	}
	if strings.Contains(string(direct), "disableUDP: true") {
		t.Fatal("managed disableUDP setting was not removed")
	}
	if !strings.Contains(string(direct), "password: secret") {
		t.Fatal("base HY2 config was damaged")
	}
}

func TestTransformHY2MigratesLegacyTCPOnlyBlock(t *testing.T) {
	legacy := []byte(`listen: :4433
auth:
  type: password
  password: secret

# BEGIN DUAL-PROTOCOL-SCRIPT MANAGED OUTBOUND
# VPN Gate SOCKS5 is TCP-only.
disableUDP: true
outbounds:
  - name: dual-protocol-script
    type: socks5
    socks5:
      addr: 127.0.0.1:24001
# END DUAL-PROTOCOL-SCRIPT MANAGED OUTBOUND
`)
	migrated, err := transformHY2Config(legacy, 24002)
	if err != nil {
		t.Fatal(err)
	}
	text := string(migrated)
	if strings.Contains(text, "disableUDP: true") || strings.Contains(text, "TCP-only") {
		t.Fatalf("legacy TCP-only settings remain:\n%s", text)
	}
	if strings.Count(text, hy2BlockBegin) != 1 || !strings.Contains(text, "addr: 127.0.0.1:24002") {
		t.Fatalf("managed block was not replaced cleanly:\n%s", text)
	}
}

func TestTransformHY2RejectsUnexpectedFile(t *testing.T) {
	if _, err := transformHY2Config([]byte("hello: world\n"), 1234); err == nil {
		t.Fatal("unexpected config was accepted")
	}
}
