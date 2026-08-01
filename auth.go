package main

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const sessionCookie = "dual_protocol_script_session"

type loginFailure struct {
	Count int
	Until time.Time
}

type Auth struct {
	mu       sync.Mutex
	password string
	sessions map[string]time.Time
	failures map[string]loginFailure
}

func NewAuth(dir string) (*Auth, bool, error) {
	path := filepath.Join(dir, "password")
	created := false
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		raw := make([]byte, 12)
		if _, err := rand.Read(raw); err != nil {
			return nil, false, err
		}
		data = []byte(hex.EncodeToString(raw))
		if err := os.WriteFile(path, append(data, '\n'), 0600); err != nil {
			return nil, false, err
		}
		created = true
	} else if err != nil {
		return nil, false, err
	}
	return &Auth{
		password: strings.TrimSpace(string(data)),
		sessions: map[string]time.Time{},
		failures: map[string]loginFailure{},
	}, created, nil
}

func (a *Auth) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		setSecurityHeaders(w)
		if req.URL.Path == "/api/login" {
			a.login(w, req)
			return
		}
		if a.valid(req) {
			next.ServeHTTP(w, req)
			return
		}
		if strings.HasPrefix(req.URL.Path, "/api/") {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "登录已失效"})
			return
		}
		handleLoginPage(w, req)
	})
}

func setSecurityHeaders(w http.ResponseWriter) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Strict-Transport-Security", "max-age=31536000")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src 'self' data:; connect-src 'self'")
}

func (a *Auth) valid(req *http.Request) bool {
	cookie, err := req.Cookie(sessionCookie)
	if err != nil {
		return false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	expires, ok := a.sessions[cookie.Value]
	if !ok || time.Now().After(expires) {
		delete(a.sessions, cookie.Value)
		return false
	}
	return true
}

func (a *Auth) login(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "只允许 POST"})
		return
	}
	ip := clientIP(req)
	a.mu.Lock()
	failure := a.failures[ip]
	if time.Now().Before(failure.Until) {
		a.mu.Unlock()
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "失败次数过多，请稍后再试"})
		return
	}
	a.mu.Unlock()

	var input struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, req.Body, 4096)).Decode(&input); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "请求格式错误"})
		return
	}
	if subtle.ConstantTimeCompare([]byte(input.Password), []byte(a.password)) != 1 {
		a.mu.Lock()
		failure = a.failures[ip]
		failure.Count++
		if failure.Count >= 5 {
			failure.Until = time.Now().Add(10 * time.Minute)
			failure.Count = 0
		}
		a.failures[ip] = failure
		a.mu.Unlock()
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "访问口令错误"})
		return
	}

	raw := make([]byte, 24)
	if _, err := rand.Read(raw); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "无法创建会话"})
		return
	}
	token := hex.EncodeToString(raw)
	expires := time.Now().Add(24 * time.Hour)
	a.mu.Lock()
	a.sessions[token] = expires
	delete(a.failures, ip)
	a.mu.Unlock()
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: token, Path: "/",
		HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode, Expires: expires,
	})
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func clientIP(req *http.Request) string {
	host, _, err := net.SplitHostPort(req.RemoteAddr)
	if err == nil {
		return host
	}
	return req.RemoteAddr
}
