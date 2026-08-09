package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

const sessionLifetime = 12 * time.Hour

type sessionManager struct {
	secret []byte
	now    func() time.Time
}

func newSessionManager() (*sessionManager, error) {
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return nil, err
	}
	return &sessionManager{secret: secret, now: time.Now}, nil
}

func (m *sessionManager) cookieName(app string) string {
	sum := sha256.Sum256([]byte(app))
	return "datashelf_session_" + hex.EncodeToString(sum[:8])
}

func (m *sessionManager) issue(app string, version [32]byte) string {
	payload := fmt.Sprintf("%s\n%x\n%d", app, version, m.now().Unix())
	mac := hmac.New(sha256.New, m.secret)
	mac.Write([]byte(payload))
	return base64.RawURLEncoding.EncodeToString([]byte(payload)) + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func (m *sessionManager) valid(token, app string, version [32]byte) bool {
	payload64, sig64, ok := strings.Cut(token, ".")
	if !ok {
		return false
	}
	payload, err := base64.RawURLEncoding.DecodeString(payload64)
	if err != nil {
		return false
	}
	sig, err := base64.RawURLEncoding.DecodeString(sig64)
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, m.secret)
	mac.Write(payload)
	if !hmac.Equal(sig, mac.Sum(nil)) {
		return false
	}
	parts := strings.Split(string(payload), "\n")
	if len(parts) != 3 || parts[0] != app || parts[1] != hex.EncodeToString(version[:]) {
		return false
	}
	issued, err := strconv.ParseInt(parts[2], 10, 64)
	if err != nil {
		return false
	}
	age := m.now().Sub(time.Unix(issued, 0))
	return age >= -time.Minute && age <= sessionLifetime
}

func requestIsHTTPS(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback() && strings.EqualFold(strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")), "https")
}

func safeReturnTarget(target, app string) string {
	if target == "" {
		return "/a/" + url.PathEscape(app) + "/"
	}
	u, err := url.Parse(target)
	if err != nil || u.IsAbs() || u.Host != "" || u.RawQuery != "" || u.Fragment != "" || !strings.HasPrefix(u.Path, "/") {
		return "/a/" + url.PathEscape(app) + "/"
	}
	segments, err := decodePathSegments(u.EscapedPath())
	if err != nil || len(segments) < 2 || segments[0] != "a" || segments[1] != app {
		return "/a/" + url.PathEscape(app) + "/"
	}
	return u.EscapedPath()
}

func decodePathSegments(escapedPath string) ([]string, error) {
	if escapedPath == "" || escapedPath[0] != '/' {
		return nil, errors.New("path must be absolute")
	}
	raw := strings.Split(strings.TrimPrefix(escapedPath, "/"), "/")
	segments := make([]string, 0, len(raw))
	for _, item := range raw {
		if item == "" {
			segments = append(segments, "")
			continue
		}
		decoded, err := url.PathUnescape(item)
		if err != nil {
			return nil, errors.New("invalid path encoding")
		}
		if decoded == "." || decoded == ".." || strings.ContainsAny(decoded, "\x00/\\") || filepath.IsAbs(decoded) {
			return nil, errors.New("unsafe path segment")
		}
		if containsEncodedOctet(decoded) {
			return nil, errors.New("double-encoded path segment")
		}
		segments = append(segments, decoded)
	}
	return segments, nil
}

func containsEncodedOctet(value string) bool {
	for i := 0; i+2 < len(value); i++ {
		if value[i] == '%' && isHex(value[i+1]) && isHex(value[i+2]) {
			return true
		}
	}
	return false
}

func isHex(value byte) bool {
	return value >= '0' && value <= '9' || value >= 'a' && value <= 'f' || value >= 'A' && value <= 'F'
}

func isPrivateName(name string) bool {
	return strings.HasPrefix(name, ".") || strings.EqualFold(name, "app.json")
}

type attemptKey struct {
	app string
	ip  string
}

type attemptWindow struct {
	count int
	start time.Time
}

type loginLimiter struct {
	mu      sync.Mutex
	entries map[attemptKey]attemptWindow
	now     func() time.Time
	max     int
}

func newLoginLimiter() *loginLimiter {
	return &loginLimiter{entries: make(map[attemptKey]attemptWindow), now: time.Now, max: 2048}
}

func (l *loginLimiter) allowed(app, source string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	key := attemptKey{app, source}
	entry := l.entries[key]
	if now.Sub(entry.start) >= 5*time.Minute {
		entry = attemptWindow{start: now}
	}
	if entry.count >= 5 {
		l.entries[key] = entry
		return false
	}
	entry.count++
	l.entries[key] = entry
	if len(l.entries) > l.max {
		for candidate, value := range l.entries {
			if now.Sub(value.start) >= 5*time.Minute || candidate != key {
				delete(l.entries, candidate)
				if len(l.entries) <= l.max {
					break
				}
			}
		}
	}
	return true
}

func (l *loginLimiter) reset(app, source string) {
	l.mu.Lock()
	delete(l.entries, attemptKey{app, source})
	l.mu.Unlock()
}

func sourceIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return r.RemoteAddr
}
