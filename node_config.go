package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	defaultNodeInstaller = "/usr/local/lib/dual-protocol-script/dual-protocol-node-installer.sh"
	defaultPanelSync     = "/usr/local/lib/dual-protocol-script/sync-panel-tls.sh"
	defaultNodeOutputDir = "/root/jb-combo"
)

var (
	nodeDomainPattern = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$`)
	nodeUUIDPattern   = regexp.MustCompile(`^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$`)
	xhttpPathPattern  = regexp.MustCompile(`^/[A-Za-z0-9._~/-]+$`)
	emailPattern      = regexp.MustCompile(`^[^\s@]+@[^\s@]+\.[^\s@]+$`)
	ansiPattern       = regexp.MustCompile(`\x1b\[[0-9;]*[A-Za-z]`)
)

// NodeConfig is the allowlisted, noninteractive view of the pinned node
// installer's state. REALITY private keys are intentionally never returned to
// the browser; callers can request a verified atomic key rotation instead.
type NodeConfig struct {
	StackMode string `json:"stack_mode"`
	MainMode  string `json:"main_mode"`
	NodeName  string `json:"node_name"`
	FP        string `json:"fp"`

	XHTTPDomain      string `json:"xhttp_domain"`
	XHTTPPath        string `json:"xhttp_path"`
	XHTTPUUID        string `json:"xhttp_uuid"`
	XHTTPBackendPort int    `json:"xhttp_backend_port"`

	RealityAddress              string `json:"reality_address"`
	RealitySNI                  string `json:"reality_sni"`
	RealityUUID                 string `json:"reality_uuid"`
	RealityPublicKey            string `json:"reality_public_key"`
	RealityShortID              string `json:"reality_short_id"`
	RealityPrivateKeyConfigured bool   `json:"reality_private_key_configured"`
	RotateRealityKeys           bool   `json:"rotate_reality_keys"`

	HY2Domain             string `json:"hy2_domain"`
	HY2Password           string `json:"hy2_password"`
	HY2PortMode           string `json:"hy2_port_mode"`
	HY2Port               int    `json:"hy2_port"`
	HY2FirstPort          int    `json:"hy2_first_port"`
	HY2EndPort            int    `json:"hy2_end_port"`
	HY2HopInterval        int    `json:"hy2_hop_interval"`
	HY2MinHopInterval     int    `json:"hy2_min_hop_interval"`
	HY2MaxHopInterval     int    `json:"hy2_max_hop_interval"`
	HY2CertSource         string `json:"hy2_cert_source"`
	HY2ACMEEmail          string `json:"hy2_acme_email"`
	HY2ObfsType           string `json:"hy2_obfs_type"`
	HY2ObfsPassword       string `json:"hy2_obfs_password"`
	HY2GeckoMinPacketSize int    `json:"hy2_gecko_min_packet_size"`
	HY2GeckoMaxPacketSize int    `json:"hy2_gecko_max_packet_size"`
}

type NodeConfigService struct {
	mu         sync.Mutex
	nodeScript string
	syncScript string
}

type NodeLinks struct {
	MainURL string `json:"main_url"`
	HY2URL  string `json:"hy2_url"`
	Info    string `json:"info"`
}

func NewNodeConfigService(nodeScript, syncScript string) *NodeConfigService {
	if nodeScript == "" {
		nodeScript = defaultNodeInstaller
	}
	if syncScript == "" {
		syncScript = defaultPanelSync
	}
	return &NodeConfigService{nodeScript: nodeScript, syncScript: syncScript}
}

func (s *NodeConfigService) Load(ctx context.Context) (NodeConfig, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.load(ctx)
}

func (s *NodeConfigService) load(ctx context.Context) (NodeConfig, error) {
	output, err := exec.CommandContext(ctx, s.nodeScript, "web-export").Output()
	if err != nil {
		var exitError *exec.ExitError
		if errors.As(err, &exitError) {
			return NodeConfig{}, fmt.Errorf("读取节点配置失败: %s", commandMessage(exitError.Stderr))
		}
		return NodeConfig{}, fmt.Errorf("读取节点配置失败: %w", err)
	}
	var config NodeConfig
	if err := json.Unmarshal(output, &config); err != nil {
		return NodeConfig{}, fmt.Errorf("节点安装器返回了无效配置: %w", err)
	}
	config.normalize()
	return config, nil
}

func (s *NodeConfigService) Apply(ctx context.Context, requested NodeConfig) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	current, err := s.load(ctx)
	if err != nil {
		return false, err
	}
	requested.normalize()
	if requested.StackMode != current.StackMode || requested.MainMode != current.MainMode {
		return false, errors.New("普通保存不能切换协议组合，请使用网页的重装组合功能或 SSH 的 tui 菜单")
	}
	if requested.HY2CertSource != current.HY2CertSource {
		return false, errors.New("证书来源由协议组合决定，不能在网页中修改")
	}
	if err := validateNodeConfig(requested); err != nil {
		return false, err
	}

	command := exec.CommandContext(ctx, s.nodeScript, "web-apply")
	command.Env = append(os.Environ(), nodeConfigEnvironment(requested)...)
	output, err := command.CombinedOutput()
	if err != nil {
		message := commandMessage(output)
		if message == "" {
			message = err.Error()
		}
		return false, fmt.Errorf("保存节点配置失败，旧配置已自动恢复: %s", message)
	}
	return requested.HY2Domain != current.HY2Domain, nil
}

func (s *NodeConfigService) Reinstall(ctx context.Context, requested NodeConfig) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	requested.normalize()
	switch requested.MainMode {
	case "xhttp":
		requested.StackMode = "xhttp_hy2"
		requested.HY2CertSource = "caddy"
		requested.RotateRealityKeys = false
	case "reality":
		requested.StackMode = "reality_hy2"
		requested.HY2CertSource = "acme"
		requested.RotateRealityKeys = true
	default:
		return errors.New("只能重装 XHTTP + HY2 或 REALITY + HY2")
	}
	if err := validateNodeConfig(requested); err != nil {
		return err
	}
	command := exec.CommandContext(ctx, s.nodeScript, "web-reinstall")
	command.Env = append(os.Environ(), nodeConfigEnvironment(requested)...)
	command.Env = append(command.Env, "DPS_WEB_TARGET_MODE="+requested.MainMode)
	output, err := command.CombinedOutput()
	if err != nil {
		message := commandMessage(output)
		if message == "" {
			message = err.Error()
		}
		return fmt.Errorf("重装协议组合失败，已尝试恢复原配置: %s", message)
	}
	return nil
}

func LoadNodeLinks(outputDir string) (NodeLinks, error) {
	if outputDir == "" {
		outputDir = defaultNodeOutputDir
	}
	read := func(name string, max int64) (string, error) {
		path := filepath.Join(outputDir, name)
		info, err := os.Stat(path)
		if err != nil {
			return "", err
		}
		if !info.Mode().IsRegular() || info.Size() > max {
			return "", fmt.Errorf("节点导出文件无效: %s", name)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(string(data)), nil
	}
	mainURL, err := read("main-url.txt", 16<<10)
	if err != nil {
		return NodeLinks{}, fmt.Errorf("读取主节点分享链接失败: %w", err)
	}
	hy2URL, err := read("hy2-url.txt", 16<<10)
	if err != nil {
		return NodeLinks{}, fmt.Errorf("读取 HY2 分享链接失败: %w", err)
	}
	info, err := read("node-info.txt", 128<<10)
	if err != nil {
		return NodeLinks{}, fmt.Errorf("读取节点详情失败: %w", err)
	}
	if !strings.HasPrefix(mainURL, "vless://") || !strings.HasPrefix(hy2URL, "hysteria2://") {
		return NodeLinks{}, errors.New("节点分享链接格式无效，请先重新生成节点输出")
	}
	return NodeLinks{MainURL: mainURL, HY2URL: hy2URL, Info: info}, nil
}

func (s *NodeConfigService) SchedulePanelSync() {
	script := s.syncScript
	go func() {
		// Let the API response reach the browser before systemd restarts this
		// process with the new panel domain and certificate.
		time.Sleep(1500 * time.Millisecond)
		output, err := exec.Command(script, "--restart").CombinedOutput()
		if err != nil {
			log.Printf("节点域名已修改，但面板 TLS 同步失败: %s", commandMessage(output))
		}
	}()
}

func nodeConfigEnvironment(config NodeConfig) []string {
	boolInt := "0"
	if config.RotateRealityKeys {
		boolInt = "1"
	}
	optionalInt := func(value int) string {
		if value <= 0 {
			return ""
		}
		return strconv.Itoa(value)
	}
	return []string{
		"DPS_WEB_APPLY=1",
		"DPS_WEB_NODE_NAME=" + config.NodeName,
		"DPS_WEB_FINGERPRINT=" + config.FP,
		"DPS_WEB_XHTTP_DOMAIN=" + config.XHTTPDomain,
		"DPS_WEB_XHTTP_PATH=" + config.XHTTPPath,
		"DPS_WEB_XHTTP_UUID=" + config.XHTTPUUID,
		"DPS_WEB_XHTTP_BACKEND_PORT=" + strconv.Itoa(config.XHTTPBackendPort),
		"DPS_WEB_REALITY_ADDRESS=" + config.RealityAddress,
		"DPS_WEB_REALITY_SNI=" + config.RealitySNI,
		"DPS_WEB_REALITY_UUID=" + config.RealityUUID,
		"DPS_WEB_ROTATE_REALITY_KEYS=" + boolInt,
		"DPS_WEB_HY2_DOMAIN=" + config.HY2Domain,
		"DPS_WEB_HY2_PASSWORD=" + config.HY2Password,
		"DPS_WEB_HY2_PORT_MODE=" + config.HY2PortMode,
		"DPS_WEB_HY2_PORT=" + strconv.Itoa(config.HY2Port),
		"DPS_WEB_HY2_FIRST_PORT=" + strconv.Itoa(config.HY2FirstPort),
		"DPS_WEB_HY2_END_PORT=" + strconv.Itoa(config.HY2EndPort),
		"DPS_WEB_HY2_HOP_INTERVAL=" + optionalInt(config.HY2HopInterval),
		"DPS_WEB_HY2_MIN_HOP_INTERVAL=" + optionalInt(config.HY2MinHopInterval),
		"DPS_WEB_HY2_MAX_HOP_INTERVAL=" + optionalInt(config.HY2MaxHopInterval),
		"DPS_WEB_HY2_ACME_EMAIL=" + config.HY2ACMEEmail,
		"DPS_WEB_HY2_OBFS_TYPE=" + config.HY2ObfsType,
		"DPS_WEB_HY2_OBFS_PASSWORD=" + config.HY2ObfsPassword,
		"DPS_WEB_HY2_GECKO_MIN_PACKET_SIZE=" + strconv.Itoa(config.HY2GeckoMinPacketSize),
		"DPS_WEB_HY2_GECKO_MAX_PACKET_SIZE=" + strconv.Itoa(config.HY2GeckoMaxPacketSize),
	}
}

func (config *NodeConfig) normalize() {
	config.StackMode = strings.TrimSpace(config.StackMode)
	config.MainMode = strings.TrimSpace(strings.ToLower(config.MainMode))
	config.NodeName = strings.TrimSpace(config.NodeName)
	config.FP = strings.TrimSpace(strings.ToLower(config.FP))
	config.XHTTPDomain = normalizeDomainValue(config.XHTTPDomain)
	config.XHTTPPath = strings.TrimSpace(config.XHTTPPath)
	if config.XHTTPPath != "" && !strings.HasPrefix(config.XHTTPPath, "/") {
		config.XHTTPPath = "/" + config.XHTTPPath
	}
	if config.XHTTPPath != "/" {
		config.XHTTPPath = strings.TrimSuffix(config.XHTTPPath, "/")
	}
	config.XHTTPUUID = strings.ToLower(strings.TrimSpace(config.XHTTPUUID))
	config.RealityAddress = normalizeHostValue(config.RealityAddress)
	config.RealitySNI = normalizeDomainValue(config.RealitySNI)
	config.RealityUUID = strings.ToLower(strings.TrimSpace(config.RealityUUID))
	config.HY2Domain = normalizeDomainValue(config.HY2Domain)
	config.HY2PortMode = strings.TrimSpace(strings.ToLower(config.HY2PortMode))
	config.HY2CertSource = strings.TrimSpace(strings.ToLower(config.HY2CertSource))
	config.HY2ACMEEmail = strings.TrimSpace(config.HY2ACMEEmail)
	config.HY2ObfsType = strings.TrimSpace(strings.ToLower(config.HY2ObfsType))
}

func normalizeDomainValue(value string) string {
	value = strings.TrimSpace(strings.ToLower(value))
	value = strings.TrimPrefix(value, "https://")
	value = strings.TrimPrefix(value, "http://")
	if slash := strings.IndexByte(value, '/'); slash >= 0 {
		value = value[:slash]
	}
	if colon := strings.IndexByte(value, ':'); colon >= 0 {
		value = value[:colon]
	}
	return value
}

func normalizeHostValue(value string) string {
	value = strings.TrimSpace(strings.ToLower(value))
	value = strings.TrimPrefix(value, "https://")
	value = strings.TrimPrefix(value, "http://")
	if slash := strings.IndexByte(value, '/'); slash >= 0 {
		value = value[:slash]
	}
	if strings.HasPrefix(value, "[") {
		if end := strings.IndexByte(value, ']'); end > 0 {
			return value[1:end]
		}
	}
	if strings.Count(value, ":") == 1 {
		host, _, err := net.SplitHostPort(value)
		if err == nil {
			return host
		}
	}
	return value
}

func validateNodeConfig(config NodeConfig) error {
	if !validText(config.NodeName, 1, 80) {
		return errors.New("节点名称长度必须为 1-80，且不能包含控制字符")
	}
	if config.FP != "chrome" && config.FP != "firefox" {
		return errors.New("客户端指纹只能是 chrome 或 firefox")
	}
	if !validDomainValue(config.HY2Domain) {
		return errors.New("HY2 域名格式无效")
	}
	if !validText(config.HY2Password, 1, 256) {
		return errors.New("HY2 密码长度必须为 1-256，且不能包含控制字符")
	}
	if err := validateHY2Ports(config); err != nil {
		return err
	}
	switch config.HY2ObfsType {
	case "none":
	case "gecko":
		if !validText(config.HY2ObfsPassword, 1, 256) {
			return errors.New("Gecko 混淆密码长度必须为 1-256，且不能包含控制字符")
		}
		if config.HY2GeckoMinPacketSize < 64 || config.HY2GeckoMinPacketSize > 1500 ||
			config.HY2GeckoMaxPacketSize < config.HY2GeckoMinPacketSize ||
			config.HY2GeckoMaxPacketSize > 1500 {
			return errors.New("Gecko 分片范围必须为 64-1500，且最大值不能小于最小值")
		}
	default:
		return errors.New("HY2 混淆类型只能是 none 或 gecko")
	}

	switch config.MainMode {
	case "xhttp":
		if config.StackMode != "xhttp_hy2" {
			return errors.New("节点组合状态与 XHTTP 模式不一致")
		}
		if !validDomainValue(config.XHTTPDomain) || config.XHTTPDomain == config.HY2Domain {
			return errors.New("XHTTP 与 HY2 必须使用两个不同的有效域名")
		}
		if config.XHTTPPath == "/" || !xhttpPathPattern.MatchString(config.XHTTPPath) {
			return errors.New("XHTTP 路径格式无效")
		}
		if !nodeUUIDPattern.MatchString(config.XHTTPUUID) {
			return errors.New("XHTTP UUID 格式无效")
		}
		if config.XHTTPBackendPort < 1024 || config.XHTTPBackendPort > 65535 {
			return errors.New("XHTTP 后端端口必须在 1024-65535")
		}
		if config.HY2CertSource != "caddy" {
			return errors.New("XHTTP 组合必须使用 Caddy 证书")
		}
	case "reality":
		if config.StackMode != "reality_hy2" {
			return errors.New("节点组合状态与 REALITY 模式不一致")
		}
		if !validHostValue(config.RealityAddress) {
			return errors.New("REALITY 连接地址格式无效")
		}
		if !validDomainValue(config.RealitySNI) {
			return errors.New("REALITY 目标 SNI 格式无效")
		}
		if !nodeUUIDPattern.MatchString(config.RealityUUID) {
			return errors.New("REALITY UUID 格式无效")
		}
		if !validText(config.HY2ACMEEmail, 3, 254) || !emailPattern.MatchString(config.HY2ACMEEmail) {
			return errors.New("ACME 邮箱格式无效")
		}
		if config.HY2CertSource != "acme" {
			return errors.New("REALITY 组合必须使用 Hysteria2 ACME 证书")
		}
	default:
		return errors.New("当前节点组合不受网页配置器支持")
	}
	return nil
}

func validateHY2Ports(config NodeConfig) error {
	reserved := func(port int) bool {
		return port == 80 || port == 443 || port == 2053 || port == 8443
	}
	switch config.HY2PortMode {
	case "single":
		if config.HY2Port < 1 || config.HY2Port > 65535 || reserved(config.HY2Port) {
			return errors.New("HY2 单端口必须在 1-65535，且不能使用 80/443/2053/8443")
		}
	case "hop":
		if config.HY2FirstPort < 1 || config.HY2EndPort > 65535 ||
			config.HY2EndPort <= config.HY2FirstPort {
			return errors.New("HY2 跳跃端口范围无效")
		}
		for _, port := range []int{80, 443, 2053, 8443} {
			if port >= config.HY2FirstPort && port <= config.HY2EndPort {
				return errors.New("HY2 跳跃范围不能包含 80/443/2053/8443")
			}
		}
		randomInterval := config.HY2MinHopInterval != 0 || config.HY2MaxHopInterval != 0
		if randomInterval {
			if config.HY2MinHopInterval < 5 || config.HY2MaxHopInterval < config.HY2MinHopInterval ||
				config.HY2MaxHopInterval > 600 {
				return errors.New("HY2 随机跳跃间隔必须在 5-600 秒，且最大值不能小于最小值")
			}
		} else if config.HY2HopInterval < 5 || config.HY2HopInterval > 600 {
			return errors.New("HY2 固定跳跃间隔必须在 5-600 秒")
		}
	default:
		return errors.New("HY2 端口模式只能是 single 或 hop")
	}
	return nil
}

func validDomainValue(value string) bool {
	return len(value) <= 253 && nodeDomainPattern.MatchString(value)
}

func validHostValue(value string) bool {
	return net.ParseIP(value) != nil || validDomainValue(value)
}

func validText(value string, min, max int) bool {
	if !utf8.ValidString(value) {
		return false
	}
	length := utf8.RuneCountInString(value)
	if length < min || length > max {
		return false
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

func commandMessage(output []byte) string {
	message := strings.TrimSpace(ansiPattern.ReplaceAllString(string(output), ""))
	const max = 6000
	if len(message) > max {
		message = message[len(message)-max:]
	}
	return message
}
