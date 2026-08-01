//go:build linux

package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

var version = "dev"

const (
	defaultWorkDir    = "/var/lib/dual-protocol-script"
	defaultXrayConfig = "/usr/local/etc/xray/config.json"
	defaultHY2Config  = "/etc/hysteria/config.yaml"
	defaultXrayBin    = "/usr/local/bin/xray"
)

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "keypair":
			runKeypairCommand(os.Args[2:])
			return
		case "apply":
			runApplyCommand(os.Args[2:])
			return
		case "status":
			runStatusCommand(os.Args[2:])
			return
		}
	}
	runServer()
}

func runKeypairCommand(args []string) {
	flags := flag.NewFlagSet("keypair", flag.ExitOnError)
	xray := flags.String("xray", defaultXrayBin, "Xray 可执行文件")
	_ = flags.Parse(args)
	pair, err := generateRealityKeyPair(*xray)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("PRIVATE=%s\nPUBLIC=%s\n", pair.Private, pair.Public)
}

func commonPaths(name string, args []string) (*flag.FlagSet, *string, *string, *string, *string) {
	flags := flag.NewFlagSet(name, flag.ExitOnError)
	workDir := flags.String("dir", defaultWorkDir, "工作目录")
	xrayConfig := flags.String("xray-config", defaultXrayConfig, "Xray 配置")
	hy2Config := flags.String("hy2-config", defaultHY2Config, "Hysteria2 配置")
	xrayBin := flags.String("xray-bin", defaultXrayBin, "Xray 可执行文件")
	_ = flags.Parse(args)
	return flags, workDir, xrayConfig, hy2Config, xrayBin
}

func runApplyCommand(args []string) {
	if os.Geteuid() != 0 {
		log.Fatal("apply 需要 root 权限")
	}
	_, workDir, xrayConfig, hy2Config, xrayBin := commonPaths("apply", args)
	router, err := NewRouter(*workDir, *xrayConfig, *hy2Config, *xrayBin)
	if err != nil {
		log.Fatal(err)
	}
	tunnels, err := loadPersistedTunnels(*workDir)
	if err != nil {
		log.Fatal(err)
	}
	if err := router.Apply(tunnels); err != nil {
		log.Fatal(err)
	}
	fmt.Println("协议出口路由已同步")
}

func runStatusCommand(args []string) {
	_, workDir, xrayConfig, hy2Config, xrayBin := commonPaths("status", args)
	router, err := NewRouter(*workDir, *xrayConfig, *hy2Config, *xrayBin)
	if err != nil {
		log.Fatal(err)
	}
	tunnels, err := loadPersistedTunnels(*workDir)
	if err != nil {
		log.Fatal(err)
	}
	data, _ := json.MarshalIndent(router.Status(tunnels), "", "  ")
	fmt.Println(string(data))
}

func loadPersistedTunnels(workDir string) ([]*Tunnel, error) {
	data, err := os.ReadFile(filepath.Join(workDir, "tunnels.json"))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var state persistedState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, err
	}
	var tunnels []*Tunnel
	for _, saved := range state.Tunnels {
		node := Node{
			HostName: saved.HostName, IP: saved.IP,
			CountryCode: saved.CountryCode, Country: saved.Country, Config: saved.Config,
		}
		tunnel := newTunnel(saved.Slot, saved.Port, node)
		tunnel.setState("up", "", "")
		tunnels = append(tunnels, tunnel)
	}
	return tunnels, nil
}

func runServer() {
	flags := flag.NewFlagSet("dual-protocol-script", flag.ExitOnError)
	webPort := flags.Int("web", 0, "Web 管理 TLS 端口")
	panelDomain := flags.String("domain", "", "Web 面板 TLS 域名")
	tlsCert := flags.String("tls-cert", "", "Web 面板证书文件")
	tlsKey := flags.String("tls-key", "", "Web 面板私钥文件")
	maxSlots := flags.Int("max", 12, "最多同时运行的家宽出口")
	workDir := flags.String("dir", defaultWorkDir, "工作目录")
	xrayConfig := flags.String("xray-config", defaultXrayConfig, "Xray 配置")
	hy2Config := flags.String("hy2-config", defaultHY2Config, "Hysteria2 配置")
	xrayBin := flags.String("xray-bin", defaultXrayBin, "Xray 可执行文件")
	showVersion := flags.Bool("version", false, "显示版本")
	_ = flags.Parse(os.Args[1:])
	if *showVersion {
		fmt.Println("dual-protocol-script", version)
		return
	}
	if os.Geteuid() != 0 {
		log.Fatal("服务需要 root 权限（创建 netns 与管理 iptables）")
	}
	if *maxSlots < 1 || *maxSlots > 200 {
		log.Fatal("-max 必须在 1-200 之间")
	}
	if *webPort < 1024 || *webPort > 65535 {
		log.Fatal("-web 必须是 1024-65535 之间的 TLS 端口")
	}
	certificates, err := newCertificateReloader(*panelDomain, *tlsCert, *tlsKey)
	if err != nil {
		log.Fatalf("初始化面板 TLS 失败: %v", err)
	}
	if err := os.MkdirAll(*workDir, 0700); err != nil {
		log.Fatalf("创建工作目录失败: %v", err)
	}
	if err := prepareHost(); err != nil {
		log.Fatal(err)
	}
	router, err := NewRouter(*workDir, *xrayConfig, *hy2Config, *xrayBin)
	if err != nil {
		log.Fatalf("初始化路由管理器失败: %v", err)
	}
	manager := NewManager(*maxSlots, *workDir, router)
	nodeConfig := NewNodeConfigService(defaultNodeInstaller, defaultPanelSync)
	panelConfig := NewPanelConfigService(*workDir, defaultPanelEnvFile, defaultPanelSync, defaultServiceName)
	if count, err := manager.RefreshNodes(); err != nil {
		log.Printf("首次拉取 VPN Gate 列表失败，可稍后从 Web 刷新: %v", err)
	} else {
		log.Printf("已载入 %d 个 VPN Gate 节点", count)
	}
	if count, err := manager.restoreState(); err != nil {
		log.Printf("恢复出口状态失败: %v", err)
	} else if count > 0 {
		log.Printf("正在恢复 %d 个家宽出口", count)
	}
	if err := router.Apply(manager.Tunnels()); err != nil {
		log.Printf("首次同步协议路由失败: %v", err)
	}
	go manager.WatchHealth()
	go func() {
		ticker := time.NewTicker(15 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			if err := router.Apply(manager.Tunnels()); err != nil {
				log.Printf("路由配置巡检失败: %v", err)
			}
		}
	}()

	auth, created, err := NewAuth(*workDir)
	if err != nil {
		log.Fatalf("初始化面板口令失败: %v", err)
	}
	if created {
		log.Printf("已生成面板口令: %s", filepath.Join(*workDir, "password"))
	}
	basePath, created, err := LoadBasePath(*workDir)
	if err != nil {
		log.Fatalf("初始化随机访问路径失败: %v", err)
	}
	if created {
		log.Printf("已生成随机访问路径: %s", filepath.Join(*workDir, "basepath"))
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", handleIndex)
	mux.HandleFunc("/api/status", apiStatus(manager, router))
	mux.HandleFunc("/api/regions", apiRegions(manager))
	mux.HandleFunc("/api/refresh", apiRefresh(manager))
	mux.HandleFunc("/api/provision", apiProvision(manager))
	mux.HandleFunc("/api/jobs", apiJobs(manager))
	mux.HandleFunc("/api/jobs/dismiss", apiJobDismiss(manager))
	mux.HandleFunc("/api/swap", apiSwap(manager))
	mux.HandleFunc("/api/stop", apiStop(manager))
	mux.HandleFunc("/api/bind", apiBind(manager, router))
	mux.HandleFunc("/api/node-config", apiNodeConfig(nodeConfig, manager, router))
	mux.HandleFunc("/api/node-links", apiNodeLinks(defaultNodeOutputDir))
	mux.HandleFunc("/api/node-reinstall", apiNodeReinstall(nodeConfig, manager, router))
	mux.HandleFunc("/api/panel-config", apiPanelConfig(panelConfig))
	mux.HandleFunc("/api/services/restart", apiRestartServices(router))

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-stop
		log.Println("停止服务并清理运行态 netns")
		manager.Shutdown()
		os.Exit(0)
	}()
	addr := fmt.Sprintf(":%d", *webPort)
	log.Printf("管理面板: https://%s%s%s/", *panelDomain, addr, basePath)
	server := &http.Server{
		Addr:              addr,
		Handler:           StripBasePath(basePath, auth.Wrap(mux)),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      20 * time.Minute,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 20,
		TLSConfig: &tls.Config{
			MinVersion:     tls.VersionTLS12,
			GetCertificate: certificates.GetCertificate,
			NextProtos:     []string{"h2", "http/1.1"},
		},
	}
	if err := server.ListenAndServeTLS("", ""); err != nil {
		log.Fatal(err)
	}
}

func requirePost(w http.ResponseWriter, req *http.Request) bool {
	if req.Method == http.MethodPost {
		return true
	}
	writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "只允许 POST"})
	return false
}

func apiStatus(manager *Manager, router *Router) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		tunnels := manager.Tunnels()
		writeJSON(w, http.StatusOK, map[string]any{
			"router": router.Status(tunnels), "exits": sortedTunnelViews(tunnels),
		})
	}
}

func apiRegions(manager *Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		writeJSON(w, http.StatusOK, manager.Regions())
	}
}

func apiRefresh(manager *Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		if !requirePost(w, req) {
			return
		}
		count, err := manager.RefreshNodes()
		if err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]int{"count": count})
	}
}

func apiProvision(manager *Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		if !requirePost(w, req) {
			return
		}
		count, err := strconv.Atoi(req.URL.Query().Get("count"))
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "count 参数无效"})
			return
		}
		job, err := manager.Provision(ProvisionRequest{Region: req.URL.Query().Get("region"), Count: count})
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"job": job.ID()})
	}
}

func apiJobs(manager *Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		writeJSON(w, http.StatusOK, manager.jobs.Views())
	}
}

func apiJobDismiss(manager *Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		if !requirePost(w, req) {
			return
		}
		manager.jobs.Dismiss(req.URL.Query().Get("id"))
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

func apiSwap(manager *Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		if !requirePost(w, req) {
			return
		}
		slot, err := strconv.Atoi(req.URL.Query().Get("slot"))
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "slot 参数无效"})
			return
		}
		if err := manager.Swap(slot); err != nil {
			writeJSON(w, http.StatusConflict, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"ok": "正在切换"})
	}
}

func apiStop(manager *Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		if !requirePost(w, req) {
			return
		}
		slot, err := strconv.Atoi(req.URL.Query().Get("slot"))
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "slot 参数无效"})
			return
		}
		if err := manager.Stop(slot); err != nil {
			writeJSON(w, http.StatusConflict, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

func apiBind(manager *Manager, router *Router) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		if !requirePost(w, req) {
			return
		}
		protocol := strings.ToLower(req.URL.Query().Get("protocol"))
		slot, err := strconv.Atoi(req.URL.Query().Get("slot"))
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "slot 参数无效"})
			return
		}
		if err := router.Bind(protocol, slot, manager.Tunnels()); err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

func apiNodeConfig(service *NodeConfigService, manager *Manager, router *Router) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		switch req.Method {
		case http.MethodGet:
			ctx, cancel := context.WithTimeout(req.Context(), 15*time.Second)
			defer cancel()
			config, err := service.Load(ctx)
			if err != nil {
				writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
				return
			}
			writeJSON(w, http.StatusOK, config)
		case http.MethodPost:
			var config NodeConfig
			decoder := json.NewDecoder(http.MaxBytesReader(w, req.Body, 32<<10))
			decoder.DisallowUnknownFields()
			if err := decoder.Decode(&config); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "节点配置请求无效: " + err.Error()})
				return
			}
			if err := decoder.Decode(&struct{}{}); err != io.EOF {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "节点配置请求只能包含一个 JSON 对象"})
				return
			}

			// Configuration writes are server-side transactions. Do not abort the
			// installer (and bypass its rollback trap) merely because the browser
			// closed the page or changed networks while ACME was still running.
			ctx, cancel := context.WithTimeout(context.Background(), 12*time.Minute)
			defer cancel()
			panelRestart, err := service.Apply(ctx, config)
			if err != nil {
				writeJSON(w, http.StatusConflict, map[string]string{"error": err.Error()})
				return
			}
			result := map[string]any{
				"ok":            true,
				"panel_restart": panelRestart,
			}
			if err := router.Apply(manager.Tunnels()); err != nil {
				result["warning"] = "节点服务已保存并重启，但家宽出口绑定暂未恢复，将由 15 秒巡检重试: " + err.Error()
			}
			if panelRestart {
				result["panel_domain"] = config.HY2Domain
				service.SchedulePanelSync()
			}
			writeJSON(w, http.StatusOK, result)
		default:
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "只允许 GET 或 POST"})
		}
	}
}

func apiNodeLinks(outputDir string) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodGet {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "只允许 GET"})
			return
		}
		links, err := LoadNodeLinks(outputDir)
		if err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, links)
	}
}

func apiPanelConfig(service *PanelConfigService) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		switch req.Method {
		case http.MethodGet:
			config, err := service.Load()
			if err != nil {
				writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
				return
			}
			writeJSON(w, http.StatusOK, config)
		case http.MethodPost:
			var config PanelConfig
			if err := decodeOneJSON(w, req, 16<<10, &config); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "面板配置请求无效: " + err.Error()})
				return
			}
			updated, err := service.Apply(config)
			if err != nil {
				writeJSON(w, http.StatusConflict, map[string]string{"error": err.Error()})
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{
				"ok": true, "domain": updated.Domain, "port": updated.Port,
				"path": updated.Path, "max_exits": updated.MaxExits,
			})
			service.ScheduleRestart()
		default:
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "只允许 GET 或 POST"})
		}
	}
}

func apiNodeReinstall(service *NodeConfigService, manager *Manager, router *Router) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		if !requirePost(w, req) {
			return
		}
		var config NodeConfig
		if err := decodeOneJSON(w, req, 32<<10, &config); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "重装配置请求无效: " + err.Error()})
			return
		}
		// Reinstallation must either commit or run the installer's rollback even
		// when the requesting browser disconnects midway through the operation.
		ctx, cancel := context.WithTimeout(context.Background(), 18*time.Minute)
		defer cancel()
		if err := service.Reinstall(ctx, config); err != nil {
			writeJSON(w, http.StatusConflict, map[string]string{"error": err.Error()})
			return
		}
		result := map[string]any{
			"ok": true, "panel_restart": true, "panel_domain": config.HY2Domain,
		}
		if err := router.Apply(manager.Tunnels()); err != nil {
			result["warning"] = "协议组合已重装，但家宽出口绑定将由巡检重试: " + err.Error()
		}
		writeJSON(w, http.StatusOK, result)
		// The certificate source may change between Caddy and HY2 ACME even if
		// the domain did not change, so always resync and restart the panel.
		service.SchedulePanelSync()
	}
}

func decodeOneJSON(w http.ResponseWriter, req *http.Request, limit int64, target any) error {
	decoder := json.NewDecoder(http.MaxBytesReader(w, req.Body, limit))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return errors.New("请求只能包含一个 JSON 对象")
	}
	return nil
}

func apiRestartServices(router *Router) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		if !requirePost(w, req) {
			return
		}
		var input struct {
			Service string `json:"service"`
		}
		if err := decodeOneJSON(w, req, 4096, &input); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "重启请求无效: " + err.Error()})
			return
		}
		stack, _ := detectStack(router.xrayConfig)
		services := []string{}
		switch strings.TrimSpace(strings.ToLower(input.Service)) {
		case "xray":
			services = []string{"xray"}
		case "hysteria2", "hysteria-server":
			services = []string{"hysteria-server"}
		case "caddy":
			if stack != "xhttp_hy2" {
				writeJSON(w, http.StatusConflict, map[string]string{"error": "当前 REALITY 组合不安装 Caddy"})
				return
			}
			services = []string{"caddy"}
		case "all":
			if stack != "xhttp_hy2" && stack != "reality_hy2" {
				writeJSON(w, http.StatusConflict, map[string]string{"error": "当前节点组合未识别，拒绝批量重启"})
				return
			}
			services = []string{"xray"}
			if stack == "xhttp_hy2" {
				services = append(services, "caddy")
			}
			services = append(services, "hysteria-server")
		default:
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "只允许重启 Xray、Hysteria2、Caddy 或当前组合全部服务"})
			return
		}

		ctx, cancel := context.WithTimeout(req.Context(), 90*time.Second)
		defer cancel()
		results := make(map[string]string, len(services))
		for _, service := range services {
			output, restartErr := exec.CommandContext(ctx, "systemctl", "restart", service).CombinedOutput()
			activeErr := exec.CommandContext(ctx, "systemctl", "is-active", "--quiet", service).Run()
			if restartErr != nil || activeErr != nil {
				message := commandMessage(output)
				if message == "" {
					message = fmt.Sprintf("restart=%v active=%v", restartErr, activeErr)
				}
				writeJSON(w, http.StatusBadGateway, map[string]any{
					"error":   service + " 重启或健康检查失败: " + message,
					"results": results,
				})
				return
			}
			results[service] = "active"
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "stack": stack, "results": results})
	}
}
