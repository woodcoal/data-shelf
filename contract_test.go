package main

import (
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRequestSnapshotReflectsApplicationCreationAndRemoval(t *testing.T) {
	root := t.TempDir()
	s, err := newServer(root, "资料架", log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatal(err)
	}
	if w := request(t, s, http.MethodGet, "/", nil); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "尚无可用应用") || w.Header().Get("Cache-Control") != "no-cache" {
		t.Fatalf("initial home=%d %q", w.Code, w.Body.String())
	}
	if err := os.Mkdir(filepath.Join(root, "新增应用"), 0o755); err != nil {
		t.Fatal(err)
	}
	if w := request(t, s, http.MethodGet, "/", nil); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "新增应用") {
		t.Fatalf("new application absent from request snapshot: %d %q", w.Code, w.Body.String())
	}
	if err := os.Remove(filepath.Join(root, "新增应用")); err != nil {
		t.Fatal(err)
	}
	if w := request(t, s, http.MethodGet, "/新增应用/", nil); w.Code != http.StatusNotFound {
		t.Fatalf("removed application remained reachable: %d", w.Code)
	}
}

func TestDirectoryPolicyInheritsOptionsAndMigratesDirectPasswords(t *testing.T) {
	root := t.TempDir()
	appDir := filepath.Join(root, "docs")
	deepDir := filepath.Join(appDir, "team", "private")
	if err := os.MkdirAll(deepDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".env"), []byte("password='根目录密码123'\nhtml_scripts='deny'\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(appDir, ".env"), []byte("title='文档'\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(appDir, "team", ".env"), []byte("html_scripts='allow'\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(deepDir, ".env"), []byte("password='子目录密码123'\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := newServer(root, "资料架", log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatal(err)
	}
	app, ok := s.app("docs")
	if !ok {
		t.Fatal("application missing")
	}
	rootPolicy := s.resolveDirectoryPolicy(app, nil)
	if !rootPolicy.Protected || rootPolicy.HTMLScriptsAllowed || !verifyConfiguredPassword(rootPolicy.Password, "根目录密码123") {
		t.Fatalf("root inheritance policy=%+v", rootPolicy)
	}
	deepPolicy := s.resolveDirectoryPolicy(app, []string{"team", "private"})
	if !deepPolicy.Protected || !deepPolicy.HTMLScriptsAllowed || !verifyConfiguredPassword(deepPolicy.Password, "子目录密码123") {
		t.Fatalf("deep override policy=%+v", deepPolicy)
	}
	for _, path := range []string{filepath.Join(root, ".env"), filepath.Join(deepDir, ".env")} {
		raw, err := os.ReadFile(path)
		if err != nil || !strings.Contains(string(raw), "password='hash:") || strings.Contains(string(raw), "plain:") {
			t.Fatalf("direct password was not migrated at %s: %q (%v)", path, raw, err)
		}
	}
}

func TestInheritedPolicySessionCrossesEmptyDirectoriesAndInvalidatesForSecurityChanges(t *testing.T) {
	root := t.TempDir()
	appDir := filepath.Join(root, "docs")
	deepDir := filepath.Join(appDir, "nested", "leaf")
	if err := os.MkdirAll(deepDir, 0o755); err != nil {
		t.Fatal(err)
	}
	rootPassword := protectedHash(t)
	childPassword, err := hashPassword("子目录密码123")
	if err != nil {
		t.Fatal(err)
	}
	rotatedPassword, err := hashPassword("轮换后的密码123")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".env"), []byte("password='"+rootPassword+"'\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(appDir, ".env"), []byte("title='文档'\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := newServer(root, "资料架", log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatal(err)
	}
	deepURL := appURL("docs", []string{"nested", "leaf"}, true)
	loginAt := func(password string) *http.Cookie {
		t.Helper()
		form := url.Values{"password": {password}, "return": {deepURL}}
		r := httptest.NewRequest(http.MethodPost, appResourceURL("docs", "_auth", nil)+"?return="+url.QueryEscape(deepURL), strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.RemoteAddr = "127.0.0.1:43210"
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		if w.Code != http.StatusSeeOther || w.Header().Get("Location") != deepURL {
			t.Fatalf("login status=%d location=%q", w.Code, w.Header().Get("Location"))
		}
		cookies := w.Result().Cookies()
		if len(cookies) != 1 || cookies[0].Path != appURL("docs", nil, true) {
			t.Fatalf("login cookies=%+v", cookies)
		}
		return cookies[0]
	}
	assertStatus := func(cookie *http.Cookie, want int, label string) {
		t.Helper()
		w := request(t, s, http.MethodGet, deepURL, nil, cookie)
		if w.Code != want {
			t.Fatalf("%s status=%d want=%d location=%q", label, w.Code, want, w.Header().Get("Location"))
		}
	}

	// The root password is inherited through both empty directory levels.
	rootCookie := loginAt("测试密码123")
	assertStatus(rootCookie, http.StatusOK, "root session through empty directories")

	childEnv := filepath.Join(appDir, "nested", ".env")
	if err := os.WriteFile(childEnv, []byte("password='"+childPassword+"'\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	assertStatus(rootCookie, http.StatusSeeOther, "old session after child password added")
	childCookie := loginAt("子目录密码123")
	assertStatus(childCookie, http.StatusOK, "child password session")

	if err := os.WriteFile(childEnv, []byte("password='"+rotatedPassword+"'\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	assertStatus(childCookie, http.StatusSeeOther, "old session after child password changed")
	rotatedCookie := loginAt("轮换后的密码123")
	assertStatus(rotatedCookie, http.StatusOK, "rotated child password session")

	if err := os.Remove(childEnv); err != nil {
		t.Fatal(err)
	}
	assertStatus(rotatedCookie, http.StatusSeeOther, "old session after child password removed")
	rootCookie = loginAt("测试密码123")
	assertStatus(rootCookie, http.StatusOK, "root session after child password removed")

	if err := os.WriteFile(childEnv, []byte("html_scripts='deny'\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	assertStatus(rootCookie, http.StatusSeeOther, "old session after HTML policy changed")
	rootCookie = loginAt("测试密码123")
	assertStatus(rootCookie, http.StatusOK, "session reauthenticated for HTML policy")
	if policy := s.resolveDirectoryPolicy(s.apps["docs"], []string{"nested", "leaf"}); policy.HTMLScriptsAllowed {
		t.Fatalf("HTML policy was not inherited: %+v", policy)
	}
}

func TestHTMLScriptDenyAndVersionedAssets(t *testing.T) {
	s, slug := makeTestServer(t, true)
	appDir := s.apps[slug].Dir
	if err := os.WriteFile(filepath.Join(appDir, ".env"), []byte("password='"+protectedHash(t)+"'\nhtml_scripts='deny'\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(appDir, "page.html"), []byte("<script>window.ran=true</script>"), 0o644); err != nil {
		t.Fatal(err)
	}
	cookie := login(t, s, slug)
	w := request(t, s, http.MethodGet, htmlURL(slug, []string{"page.html"}), nil, cookie)
	if w.Code != http.StatusOK || strings.Contains(w.Body.String(), "allow-scripts") || strings.Contains(w.Body.String(), "allow-same-origin") {
		t.Fatalf("deny shell=%d %q", w.Code, w.Body.String())
	}
	w = request(t, s, http.MethodGet, htmlContentURL(slug, []string{"page.html"}), nil, cookie)
	if w.Code != http.StatusOK || !strings.Contains(w.Header().Get("Content-Security-Policy"), "script-src 'none'") {
		t.Fatalf("deny content=%d csp=%q", w.Code, w.Header().Get("Content-Security-Policy"))
	}
	asset := assetURL("app.css")
	w = request(t, s, http.MethodGet, asset, nil)
	if w.Code != http.StatusOK || !strings.Contains(w.Header().Get("Cache-Control"), "immutable") || w.Header().Get("ETag") == "" {
		t.Fatalf("asset=%d cache=%q etag=%q", w.Code, w.Header().Get("Cache-Control"), w.Header().Get("ETag"))
	}
	w = request(t, s, http.MethodGet, "/_assets/app.deadbeef.css", nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("stale asset path=%d", w.Code)
	}
}
