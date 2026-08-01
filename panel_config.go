package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	defaultPanelEnvFile = "/etc/default/dual-protocol-script"
	defaultServiceName  = "dual-protocol-script"
)

var panelPathPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{6,64}$`)

type PanelConfig struct {
	Domain             string `json:"domain"`
	Port               int    `json:"port"`
	Path               string `json:"path"`
	MaxExits           int    `json:"max_exits"`
	NewPassword        string `json:"new_password,omitempty"`
	PasswordConfigured bool   `json:"password_configured"`
}

type PanelConfigService struct {
	mu          sync.Mutex
	workDir     string
	envFile     string
	syncScript  string
	serviceName string
}

func NewPanelConfigService(workDir, envFile, syncScript, serviceName string) *PanelConfigService {
	if envFile == "" {
		envFile = defaultPanelEnvFile
	}
	if syncScript == "" {
		syncScript = defaultPanelSync
	}
	if serviceName == "" {
		serviceName = defaultServiceName
	}
	return &PanelConfigService{
		workDir: workDir, envFile: envFile, syncScript: syncScript, serviceName: serviceName,
	}
}

func (s *PanelConfigService) Load() (PanelConfig, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.load()
}

func (s *PanelConfigService) load() (PanelConfig, error) {
	values, err := readSimpleEnvironment(s.envFile)
	if err != nil {
		return PanelConfig{}, err
	}
	port, err := strconv.Atoi(values["WEB_PORT"])
	if err != nil || port < 10240 || port > 65535 {
		return PanelConfig{}, errors.New("面板端口状态无效")
	}
	maxExits, err := strconv.Atoi(values["MAX_EXITS"])
	if err != nil || maxExits < 1 || maxExits > 200 {
		return PanelConfig{}, errors.New("面板最大出口数状态无效")
	}
	pathData, err := os.ReadFile(filepath.Join(s.workDir, "basepath"))
	if err != nil {
		return PanelConfig{}, fmt.Errorf("读取面板路径失败: %w", err)
	}
	path := strings.Trim(strings.TrimSpace(string(pathData)), "/")
	if !panelPathPattern.MatchString(path) {
		return PanelConfig{}, errors.New("面板路径状态无效")
	}
	_, passwordErr := os.Stat(filepath.Join(s.workDir, "password"))
	return PanelConfig{
		Domain: values["PANEL_DOMAIN"], Port: port, Path: path, MaxExits: maxExits,
		PasswordConfigured: passwordErr == nil,
	}, nil
}

func (s *PanelConfigService) Apply(requested PanelConfig) (PanelConfig, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	current, err := s.load()
	if err != nil {
		return PanelConfig{}, err
	}
	requested.Path = strings.Trim(strings.TrimSpace(requested.Path), "/")
	if requested.Port < 10240 || requested.Port > 65535 {
		return PanelConfig{}, errors.New("面板 TLS 端口必须在 10240-65535")
	}
	if requested.MaxExits < 1 || requested.MaxExits > 200 {
		return PanelConfig{}, errors.New("最大家宽出口数必须在 1-200")
	}
	if !panelPathPattern.MatchString(requested.Path) {
		return PanelConfig{}, errors.New("面板路径只能包含字母、数字、下划线、短横线，长度 6-64")
	}
	if requested.NewPassword != "" && !validText(requested.NewPassword, 8, 128) {
		return PanelConfig{}, errors.New("新面板密码长度必须为 8-128，且不能包含控制字符")
	}

	basePath := filepath.Join(s.workDir, "basepath")
	passwordPath := filepath.Join(s.workDir, "password")
	oldEnv, err := os.ReadFile(s.envFile)
	if err != nil {
		return PanelConfig{}, err
	}
	oldBase, err := os.ReadFile(basePath)
	if err != nil {
		return PanelConfig{}, err
	}
	oldPassword, passwordReadErr := os.ReadFile(passwordPath)

	rollback := func() {
		_ = atomicWriteFile(s.envFile, oldEnv, 0600)
		_ = atomicWriteFile(basePath, oldBase, 0600)
		if passwordReadErr == nil {
			_ = atomicWriteFile(passwordPath, oldPassword, 0600)
		} else {
			_ = os.Remove(passwordPath)
		}
	}
	if requested.Port != current.Port || requested.MaxExits != current.MaxExits {
		output, commandErr := exec.Command(
			s.syncScript,
			"--port", strconv.Itoa(requested.Port),
			"--max", strconv.Itoa(requested.MaxExits),
		).CombinedOutput()
		if commandErr != nil {
			return PanelConfig{}, fmt.Errorf("面板端口校验失败: %s", commandMessage(output))
		}
	}
	if err := atomicWriteFile(basePath, []byte(requested.Path+"\n"), 0600); err != nil {
		rollback()
		return PanelConfig{}, fmt.Errorf("保存面板路径失败: %w", err)
	}
	if requested.NewPassword != "" {
		if err := atomicWriteFile(passwordPath, []byte(requested.NewPassword+"\n"), 0600); err != nil {
			rollback()
			return PanelConfig{}, fmt.Errorf("保存面板密码失败: %w", err)
		}
	}
	updated, err := s.load()
	if err != nil {
		rollback()
		return PanelConfig{}, err
	}
	return updated, nil
}

func (s *PanelConfigService) ScheduleRestart() {
	serviceName := s.serviceName
	go func() {
		time.Sleep(1500 * time.Millisecond)
		_ = exec.Command("systemctl", "restart", serviceName).Run()
	}()
}

func readSimpleEnvironment(path string) (map[string]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("读取面板环境配置失败: %w", err)
	}
	result := make(map[string]string)
	for _, line := range strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		result[strings.TrimSpace(key)] = strings.Trim(strings.TrimSpace(value), `"'`)
	}
	return result, nil
}
