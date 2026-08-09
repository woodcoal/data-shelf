package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

var (
	testHashOnce sync.Once
	testHash     string
	testHashErr  error
)

func protectedHash(t *testing.T) string {
	t.Helper()
	testHashOnce.Do(func() { testHash, testHashErr = hashPassword("测试密码123") })
	if testHashErr != nil {
		t.Fatal(testHashErr)
	}
	return testHash
}

func makeTestServer(t *testing.T, protected bool) (*server, string) {
	t.Helper()
	root := t.TempDir()
	appDir := filepath.Join(root, "资料 应用")
	if err := os.Mkdir(appDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(appDir, "secret.txt"), []byte("classified-content"), 0o644); err != nil {
		t.Fatal(err)
	}
	if protected {
		env := fmt.Sprintf("NAME='受保护资料'\nPASSWORD='%s'\n", protectedHash(t))
		if err := os.WriteFile(filepath.Join(appDir, ".env"), []byte(env), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	s, err := newServer(root, "Test Shelf", log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatal(err)
	}
	return s, "资料 应用"
}

func request(t *testing.T, s http.Handler, method, target string, headers map[string]string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(method, target, nil)
	for key, value := range headers {
		r.Header.Set(key, value)
	}
	for _, cookie := range cookies {
		r.AddCookie(cookie)
	}
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	return w
}

func login(t *testing.T, s *server, slug string) *http.Cookie {
	t.Helper()
	form := url.Values{"password": {"测试密码123"}, "return": {appURL(slug, []string{"secret.txt"}, false)}}
	r := httptest.NewRequest(http.MethodPost, "/_auth/"+url.PathEscape(slug), strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.RemoteAddr = "127.0.0.1:43210"
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("login status=%d body=%s", w.Code, w.Body.String())
	}
	result := w.Result().Cookies()
	if len(result) != 1 {
		t.Fatalf("expected session cookie, got %d", len(result))
	}
	return result[0]
}

func TestProtectedRequestsRevealNoFileMetadataBeforeAuth(t *testing.T) {
	s, slug := makeTestServer(t, true)
	target := appURL(slug, []string{"secret.txt"}, false)
	methods := []struct {
		method  string
		headers map[string]string
	}{
		{http.MethodGet, nil},
		{http.MethodHead, nil},
		{http.MethodGet, map[string]string{"Range": "bytes=0-2"}},
		{http.MethodGet, map[string]string{"If-Modified-Since": "Wed, 21 Oct 2037 07:28:00 GMT"}},
		{http.MethodGet, map[string]string{"If-None-Match": "*"}},
	}
	for _, tc := range methods {
		w := request(t, s, tc.method, target, tc.headers)
		if w.Code != http.StatusSeeOther {
			t.Fatalf("%s returned %d", tc.method, w.Code)
		}
		for _, header := range []string{"Last-Modified", "ETag", "Accept-Ranges", "Content-Range"} {
			if value := w.Header().Get(header); value != "" {
				t.Fatalf("%s leaked %s=%q", tc.method, header, value)
			}
		}
		if !strings.Contains(w.Header().Get("Cache-Control"), "no-store") {
			t.Fatalf("protected response is cacheable: %q", w.Header().Get("Cache-Control"))
		}
	}
}

func TestLoginDeepLinkRangeAndSessionInvalidation(t *testing.T) {
	s, slug := makeTestServer(t, true)
	cookie := login(t, s, slug)
	target := appURL(slug, []string{"secret.txt"}, false)
	w := request(t, s, http.MethodGet, target, map[string]string{"Range": "bytes=0-3"}, cookie)
	if w.Code != http.StatusPartialContent || w.Body.String() != "clas" {
		t.Fatalf("range status=%d body=%q", w.Code, w.Body.String())
	}
	if got := w.Header().Get("Content-Range"); got != "bytes 0-3/18" {
		t.Fatalf("unexpected content range: %q", got)
	}
	app := s.apps[slug]
	envPath := filepath.Join(app.Dir, ".env")
	changed := fmt.Sprintf("NAME='已改密码'\nPASSWORD='%s'\n", protectedHash(t))
	if err := os.WriteFile(envPath, []byte(changed), 0o600); err != nil {
		t.Fatal(err)
	}
	w = request(t, s, http.MethodGet, target, nil, cookie)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("old session survived configuration change: %d", w.Code)
	}
}

func TestSessionIsScopedToOneApplication(t *testing.T) {
	s, first := makeTestServer(t, true)
	second := "另一个应用"
	secondDir := filepath.Join(s.root, second)
	if err := os.Mkdir(secondDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(secondDir, "secret.txt"), []byte("other"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(secondDir, ".env"), []byte(fmt.Sprintf("PASSWORD='%s'\n", protectedHash(t))), 0o600); err != nil {
		t.Fatal(err)
	}
	info, _ := os.Stat(secondDir)
	s.apps[second] = &application{Slug: second, Dir: secondDir, ModTime: info.ModTime()}
	s.apps[second].state.config, _ = loadAppConfig(secondDir, second)
	cookie := login(t, s, first)
	w := request(t, s, http.MethodGet, appURL(second, []string{"secret.txt"}, false), nil, cookie)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("cross-app cookie authorized request: %d", w.Code)
	}
}

func TestPrivateLinkedAndTraversalPathsAreDenied(t *testing.T) {
	s, slug := makeTestServer(t, false)
	appDir := s.apps[slug].Dir
	if err := os.WriteFile(filepath.Join(appDir, "app.json"), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(s.root, "outside.txt")
	if err := os.WriteFile(outside, []byte("outside"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(appDir, "linked.txt")); err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{
		appURL(slug, []string{".env"}, false),
		appURL(slug, []string{"app.json"}, false),
		appURL(slug, []string{"linked.txt"}, false),
		"/a/" + url.PathEscape(slug) + "/%2e%2e/outside.txt",
		"/a/" + url.PathEscape(slug) + "/%252e%252e/outside.txt",
		"/a/" + url.PathEscape(slug) + "/%2Fetc/passwd",
	} {
		w := request(t, s, http.MethodGet, target, nil)
		if w.Code != http.StatusNotFound {
			t.Fatalf("unsafe target %q returned %d", target, w.Code)
		}
	}
}

func TestRootIndexRunsButNestedHTMLIsPlainText(t *testing.T) {
	s, slug := makeTestServer(t, false)
	appDir := s.apps[slug].Dir
	if err := os.WriteFile(filepath.Join(appDir, "index.html"), []byte("<h1>root</h1>"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(appDir, "nested"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(appDir, "nested", "index.html"), []byte("<h1>nested</h1>"), 0o644); err != nil {
		t.Fatal(err)
	}
	w := request(t, s, http.MethodGet, appURL(slug, nil, true), nil)
	if w.Code != http.StatusOK || !strings.HasPrefix(w.Header().Get("Content-Type"), "text/html") {
		t.Fatalf("root index status=%d type=%q", w.Code, w.Header().Get("Content-Type"))
	}
	w = request(t, s, http.MethodGet, appURL(slug, []string{"nested", "index.html"}, false), nil)
	if w.Code != http.StatusOK || w.Header().Get("Content-Type") != "text/plain; charset=utf-8" {
		t.Fatalf("nested html status=%d type=%q", w.Code, w.Header().Get("Content-Type"))
	}
}

func TestUnicodeSpaceHashAndPercentNamesRoundTrip(t *testing.T) {
	s, slug := makeTestServer(t, false)
	name := "中文 空格#百分号%.txt"
	content := "ok"
	if err := os.WriteFile(filepath.Join(s.apps[slug].Dir, name), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	w := request(t, s, http.MethodGet, appURL(slug, []string{name}, false), nil)
	if w.Code != http.StatusOK || w.Body.String() != content {
		t.Fatalf("round trip status=%d body=%q", w.Code, w.Body.String())
	}
}

func TestEmbeddedDirectoryTemplateEscapesNamesAndShowsMetadata(t *testing.T) {
	s, slug := makeTestServer(t, false)
	name := "<资料> #%.txt"
	if err := os.WriteFile(filepath.Join(s.apps[slug].Dir, name), []byte("ok"), 0o644); err != nil {
		t.Fatal(err)
	}
	w := request(t, s, http.MethodGet, appURL(slug, nil, true), nil)
	if w.Code != http.StatusOK {
		t.Fatalf("directory status=%d", w.Code)
	}
	body := w.Body.String()
	for _, want := range []string{"目录浏览", "文件", " B", "&lt;资料&gt; #%.txt"} {
		if !strings.Contains(body, want) {
			t.Errorf("directory page missing %q: %s", want, body)
		}
	}
	if strings.Contains(body, "<资料> #%.txt") {
		t.Error("directory name was rendered without HTML escaping")
	}
}

func TestDirectoryTemplateUsesServerPreviewContract(t *testing.T) {
	s, slug := makeTestServer(t, false)
	for name := range map[string]string{
		"cover.png":     "image",
		"guide.pdf":     "pdf",
		"readme.html":   "text",
		"archive.zip":   "",
		"untrusted.svg": "",
	} {
		if err := os.WriteFile(filepath.Join(s.apps[slug].Dir, name), []byte("content"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	w := request(t, s, http.MethodGet, appURL(slug, nil, true), nil)
	if w.Code != http.StatusOK {
		t.Fatalf("directory status=%d", w.Code)
	}
	body := w.Body.String()
	for _, want := range []string{
		`data-preview-kind="image"`,
		`data-preview-kind="pdf"`,
		`data-preview-kind="text"`,
		`data-preview-url=`,
		`target="_blank"`,
		`rel="noopener"`,
		`资料架首页`,
		`aria-modal="true"`,
		`datashelf-ui-preferences-v1`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("directory page missing %q", want)
		}
	}
	if strings.Contains(body, `data-preview-kind="svg"`) || strings.Contains(body, `data-preview-kind="zip"`) {
		t.Error("unsafe file type was made previewable")
	}
}

func TestPreviewKindForUsesNarrowAllowList(t *testing.T) {
	cases := map[string]string{
		"photo.AVIF":   "image",
		"report.PDF":   "pdf",
		"payload.html": "text",
		"vector.svg":   "",
		"script.wasm":  "",
		"office.docx":  "",
	}
	for name, want := range cases {
		if got := previewKindFor(name); got != want {
			t.Errorf("previewKindFor(%q)=%q, want %q", name, got, want)
		}
	}
}

func TestDeepDirectoryShowsCurrentNameAndClickableAncestors(t *testing.T) {
	s, slug := makeTestServer(t, false)
	if err := os.MkdirAll(filepath.Join(s.apps[slug].Dir, "2026", "交付"), 0o755); err != nil {
		t.Fatal(err)
	}
	w := request(t, s, http.MethodGet, appURL(slug, []string{"2026", "交付"}, true), nil)
	if w.Code != http.StatusOK {
		t.Fatalf("directory status=%d", w.Code)
	}
	body := w.Body.String()
	for _, want := range []string{`>资料架首页<`, `>资料 应用<`, `>2026<`, `aria-current="page">交付<`, `<h1>交付</h1>`} {
		if !strings.Contains(body, want) {
			t.Errorf("deep directory page missing %q", want)
		}
	}
}

func TestHomeUsesServerGeneratedApplicationURL(t *testing.T) {
	s, slug := makeTestServer(t, false)
	w := request(t, s, http.MethodGet, "/", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("home status=%d", w.Code)
	}
	if want := `href="` + appURL(slug, nil, true) + `"`; !strings.Contains(w.Body.String(), want) {
		t.Errorf("home page missing application URL %q", want)
	}
}

func TestSVGIsDeliveredAsAttachment(t *testing.T) {
	s, slug := makeTestServer(t, false)
	if err := os.WriteFile(filepath.Join(s.apps[slug].Dir, "untrusted.svg"), []byte(`<svg xmlns="http://www.w3.org/2000/svg"/>`), 0o644); err != nil {
		t.Fatal(err)
	}
	w := request(t, s, http.MethodGet, appURL(slug, []string{"untrusted.svg"}, false), nil)
	if w.Code != http.StatusOK || !strings.HasPrefix(w.Header().Get("Content-Disposition"), "attachment;") {
		t.Fatalf("svg response status=%d disposition=%q", w.Code, w.Header().Get("Content-Disposition"))
	}
}

func TestEmbeddedLoginTemplateProvidesAccessibleErrorAndKeyboardForm(t *testing.T) {
	s, slug := makeTestServer(t, true)
	form := url.Values{"password": {"错误密码"}, "return": {appURL(slug, nil, true)}}
	r := httptest.NewRequest(http.MethodPost, "/_auth/"+url.PathEscape(slug), strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.RemoteAddr = "127.0.0.1:43210"
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("login status=%d", w.Code)
	}
	body := w.Body.String()
	for _, want := range []string{"role=\"alert\"", "autofocus", "autocomplete=\"current-password\"", "按 Enter 键即可提交"} {
		if !strings.Contains(body, want) {
			t.Errorf("login page missing %q", want)
		}
	}
}

func TestEmbeddedAccessErrorTemplate(t *testing.T) {
	s, _ := makeTestServer(t, false)
	r := httptest.NewRequest(http.MethodGet, "/a/missing/file.txt", nil)
	w := httptest.NewRecorder()
	s.renderErrorPage(w, r, http.StatusForbidden, "无法访问此文件", "当前资料无法读取。", "./")
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "返回上一层") {
		t.Fatalf("error page status=%d body=%s", w.Code, w.Body.String())
	}
}
