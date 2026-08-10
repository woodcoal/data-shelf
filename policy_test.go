package main

import (
	"crypto/rand"
	"encoding/base64"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDirectoryEnvIsLocalAndPasswordInherits(t *testing.T) {
	root := t.TempDir()
	appDir := filepath.Join(root, "docs")
	deep := filepath.Join(appDir, "private", "leaf")
	if err := os.MkdirAll(deep, 0o755); err != nil {
		t.Fatal(err)
	}
	rootHash, err := hashPassword("根目录密码123")
	if err != nil {
		t.Fatal(err)
	}
	childHash, err := hashPassword("子目录密码123")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".env"), []byte("title='资料架'\ndescription='根说明'\npassword='"+rootHash+"'\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(appDir, ".env"), []byte("title='应用说明'\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(appDir, "private", ".env"), []byte("title='独立目录'\ndescription='仅此处展示'\npassword='"+childHash+"'\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := newServer(root, "fallback", log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatal(err)
	}
	app := s.apps["docs"]
	appPolicy := s.resolveDirectoryPolicy(app, nil)
	if appPolicy.Title != "应用说明" || appPolicy.Description != "" || !verifyConfiguredPassword(appPolicy.Password, "根目录密码123") {
		t.Fatalf("unexpected application policy: %+v", appPolicy)
	}
	deepPolicy := s.resolveDirectoryPolicy(app, []string{"private"})
	if deepPolicy.Title != "独立目录" || deepPolicy.Description != "仅此处展示" || !verifyConfiguredPassword(deepPolicy.Password, "子目录密码123") || deepPolicy.Boundary != "private" {
		t.Fatalf("unexpected nested policy: %+v", deepPolicy)
	}
	if err := os.WriteFile(filepath.Join(appDir, "private", ".env"), []byte("title='坏配置'\nPASSWORD='x'\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if policy := s.resolveDirectoryPolicy(app, []string{"private", "leaf"}); !policy.Locked || !policy.Protected {
		t.Fatalf("invalid mixed-case child config did not fail closed: %+v", policy)
	}
}

func TestHTMLAndShareStayInTheirOwnAuthorizationBoundaries(t *testing.T) {
	root := t.TempDir()
	appDir := filepath.Join(root, "docs")
	if err := os.Mkdir(appDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(appDir, "report.html"), []byte("<script>parent.postMessage(document.cookie,'*')</script><form action=https://bad.invalid><input></form>"), 0o644); err != nil {
		t.Fatal(err)
	}
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		t.Fatal(err)
	}
	token := base64.RawURLEncoding.EncodeToString(tokenBytes)
	passwordHash, err := hashPassword("分享密码123")
	if err != nil {
		t.Fatal(err)
	}
	env := "title='文档'\nSHARE_DOC_ENABLED='true'\nSHARE_DOC_SCOPE='file'\nSHARE_DOC_PATH='report.html'\nSHARE_DOC_TOKEN='" + token + "'\nSHARE_DOC_EXPIRES_AT='2026-08-20T12:00:00+08:00'\nSHARE_DOC_PASSWORD='" + passwordHash + "'\nSHARE_DOC_ALLOW_DOWNLOAD='false'\n"
	if err := os.WriteFile(filepath.Join(appDir, ".env"), []byte(env), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := newServer(root, "fallback", log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatal(err)
	}

	// The ordinary HTML file goes to the trusted shell; the untrusted response
	// is only reachable through a double sandbox after application authorization.
	w := request(t, s, http.MethodGet, appURL("docs", []string{"report.html"}, false), nil)
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != appResourceURL("docs", "_html", []string{"report.html"}) {
		t.Fatalf("HTML route=%d location=%q", w.Code, w.Header().Get("Location"))
	}
	w = request(t, s, http.MethodGet, appResourceURL("docs", "_html-content", []string{"report.html"}), nil)
	if w.Code != http.StatusOK || w.Header().Get("Content-Type") != "text/html; charset=utf-8" || !strings.Contains(w.Header().Get("Content-Security-Policy"), "sandbox allow-scripts") || strings.Contains(w.Header().Get("Content-Security-Policy"), "allow-same-origin") || !strings.Contains(w.Header().Get("Cache-Control"), "no-store") {
		t.Fatalf("HTML content headers status=%d csp=%q cache=%q", w.Code, w.Header().Get("Content-Security-Policy"), w.Header().Get("Cache-Control"))
	}

	gate := "/_s/" + token + "/"
	w = request(t, s, http.MethodGet, gate, nil)
	if w.Code != http.StatusOK || strings.Contains(w.Body.String(), "report.html") {
		t.Fatalf("share gate leaked metadata: %d %q", w.Code, w.Body.String())
	}
	form := url.Values{"password": {"分享密码123"}}
	r := httptest.NewRequest(http.MethodPost, "/_s/"+token+"/_auth", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.RemoteAddr = "127.0.0.1:12345"
	w = httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("share authentication status=%d", w.Code)
	}
	cookies := w.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Path != gate {
		t.Fatalf("share cookie scope=%+v", cookies)
	}
	w = request(t, s, http.MethodGet, "/_s/"+token+"/_html-content", nil, cookies[0])
	if w.Code != http.StatusOK || !strings.Contains(w.Header().Get("Content-Security-Policy"), "sandbox") {
		t.Fatalf("share HTML content=%d csp=%q", w.Code, w.Header().Get("Content-Security-Policy"))
	}
	w = request(t, s, http.MethodGet, "/_s/"+token+"/_download", nil, cookies[0])
	if w.Code != http.StatusNotFound {
		t.Fatalf("disabled share download status=%d", w.Code)
	}
	w = request(t, s, http.MethodGet, appResourceURL("docs", "_preview", []string{"report.html"}), nil, cookies[0])
	if w.Code != http.StatusOK {
		t.Fatalf("share cookie should not be an application session: %d", w.Code)
	}
	if time.Now().After(time.Date(2026, 8, 20, 4, 0, 0, 0, time.UTC)) {
		t.Fatal("test fixture expiry must remain future")
	}
}
