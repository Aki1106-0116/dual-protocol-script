package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

type certificateFileStamp struct {
	size    int64
	modTime int64
}

// certificateReloader serves only the configured DNS name and reloads renewed
// certificate files without restarting dual-protocol-script. If a renewal briefly
// exposes a mismatched cert/key pair, the last still-valid pair remains active.
type certificateReloader struct {
	mu       sync.Mutex
	domain   string
	certFile string
	keyFile  string
	cert     *tls.Certificate
	certMark certificateFileStamp
	keyMark  certificateFileStamp
}

func newCertificateReloader(domain, certFile, keyFile string) (*certificateReloader, error) {
	reloader := &certificateReloader{
		domain:   strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), ".")),
		certFile: certFile,
		keyFile:  keyFile,
	}
	if reloader.domain == "" || certFile == "" || keyFile == "" {
		return nil, fmt.Errorf("面板 TLS 域名、证书和私钥路径均不能为空")
	}
	reloader.mu.Lock()
	defer reloader.mu.Unlock()
	if _, err := reloader.reloadLocked(true); err != nil {
		return nil, err
	}
	return reloader, nil
}

func (r *certificateReloader) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	serverName := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(hello.ServerName), "."))
	if serverName != r.domain {
		return nil, fmt.Errorf("TLS SNI %q 与面板域名不匹配", hello.ServerName)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.reloadLocked(false)
}

func (r *certificateReloader) reloadLocked(force bool) (*tls.Certificate, error) {
	certInfo, certErr := os.Stat(r.certFile)
	keyInfo, keyErr := os.Stat(r.keyFile)
	if certErr != nil || keyErr != nil {
		return r.lastGoodOrError(fmt.Errorf("读取面板 TLS 文件失败: cert=%v key=%v", certErr, keyErr))
	}
	certMark := certificateFileStamp{size: certInfo.Size(), modTime: certInfo.ModTime().UnixNano()}
	keyMark := certificateFileStamp{size: keyInfo.Size(), modTime: keyInfo.ModTime().UnixNano()}
	if !force && r.cert != nil && certMark == r.certMark && keyMark == r.keyMark {
		return r.lastGoodOrError(nil)
	}

	pair, err := tls.LoadX509KeyPair(r.certFile, r.keyFile)
	if err != nil {
		return r.lastGoodOrError(fmt.Errorf("加载面板 TLS 密钥对失败: %w", err))
	}
	if len(pair.Certificate) == 0 {
		return r.lastGoodOrError(fmt.Errorf("面板证书链为空"))
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return r.lastGoodOrError(fmt.Errorf("解析面板证书失败: %w", err))
	}
	if err := leaf.VerifyHostname(r.domain); err != nil {
		return r.lastGoodOrError(fmt.Errorf("证书不包含面板域名 %s: %w", r.domain, err))
	}
	now := time.Now()
	if now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) {
		return r.lastGoodOrError(fmt.Errorf("面板证书不在有效期内: %s - %s", leaf.NotBefore, leaf.NotAfter))
	}
	pair.Leaf = leaf
	r.cert, r.certMark, r.keyMark = &pair, certMark, keyMark
	return r.cert, nil
}

func (r *certificateReloader) lastGoodOrError(reloadErr error) (*tls.Certificate, error) {
	if r.cert != nil && r.cert.Leaf != nil {
		now := time.Now()
		if !now.Before(r.cert.Leaf.NotBefore) && now.Before(r.cert.Leaf.NotAfter) {
			return r.cert, nil
		}
	}
	if reloadErr == nil {
		reloadErr = fmt.Errorf("没有可用的面板 TLS 证书")
	}
	return nil, reloadErr
}
