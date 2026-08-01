package main

import (
	"crypto/ecdh"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
)

type realityKeyPair struct {
	Private string
	Public  string
}

var keyChars = regexp.MustCompile(`^[A-Za-z0-9_-]{40,64}={0,2}$`)
var nonKeyLabelChars = regexp.MustCompile(`[^a-z0-9]+`)

// generateRealityKeyPair deliberately delegates generation to the installed
// Xray binary, then independently verifies that the parsed public key is
// actually derived from the parsed private key. This prevents Hash32 or a
// changed output label from ever being written as a REALITY key.
func generateRealityKeyPair(xrayBin string) (realityKeyPair, error) {
	out, err := exec.Command(xrayBin, "x25519").CombinedOutput()
	if err != nil {
		return realityKeyPair{}, fmt.Errorf("%s x25519 失败: %w: %s", xrayBin, err, strings.TrimSpace(string(out)))
	}
	return parseRealityKeyPair(string(out))
}

func parseRealityKeyPair(output string) (realityKeyPair, error) {
	var pair realityKeyPair
	for _, raw := range strings.Split(output, "\n") {
		key, value, ok := strings.Cut(raw, ":")
		if !ok {
			continue
		}
		normalized := nonKeyLabelChars.ReplaceAllString(strings.ToLower(key), "")
		value = strings.TrimSpace(value)
		switch {
		case normalized == "privatekey" || normalized == "private" || normalized == "privkey":
			pair.Private = value
		case normalized == "publickey" || normalized == "public" || normalized == "pubkey" ||
			normalized == "password" || normalized == "passwordpublickey":
			pair.Public = value
		case strings.Contains(normalized, "publickey") && !strings.Contains(normalized, "hash"):
			pair.Public = value
		}
	}
	if pair.Private == "" || pair.Public == "" {
		return realityKeyPair{}, fmt.Errorf("无法从 Xray 输出解析完整密钥对；原始输出: %q", strings.TrimSpace(output))
	}
	if !keyChars.MatchString(pair.Private) || !keyChars.MatchString(pair.Public) {
		return realityKeyPair{}, errors.New("Xray 返回的 REALITY 密钥字符或长度异常")
	}
	privateRaw, err := decodeX25519Key(pair.Private)
	if err != nil {
		return realityKeyPair{}, fmt.Errorf("解码 REALITY 私钥失败: %w", err)
	}
	publicRaw, err := decodeX25519Key(pair.Public)
	if err != nil {
		return realityKeyPair{}, fmt.Errorf("解码 REALITY 公钥失败: %w", err)
	}
	privateKey, err := ecdh.X25519().NewPrivateKey(privateRaw)
	if err != nil {
		return realityKeyPair{}, fmt.Errorf("REALITY 私钥无效: %w", err)
	}
	derived := privateKey.PublicKey().Bytes()
	if subtle.ConstantTimeCompare(derived, publicRaw) != 1 {
		return realityKeyPair{}, errors.New("Xray 输出的公钥与私钥不匹配，拒绝写入")
	}
	return pair, nil
}

func decodeX25519Key(value string) ([]byte, error) {
	value = strings.TrimRight(value, "=")
	raw, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return nil, err
	}
	if len(raw) != 32 {
		return nil, fmt.Errorf("需要 32 字节，实际 %d", len(raw))
	}
	return raw, nil
}
