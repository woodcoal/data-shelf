package main

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/cookiejar"
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
	return loginWithPassword(t, s, slug, "测试密码123")
}

func loginWithPassword(t *testing.T, s *server, slug, password string) *http.Cookie {
	return loginCookies(t, s, slug, password)[0]
}

func loginCookieForOperation(t *testing.T, s *server, slug, password, operation string) *http.Cookie {
	t.Helper()
	wantName := s.sessions.controlledCookieName(slug, operation)
	for _, cookie := range loginCookies(t, s, slug, password) {
		if cookie.Name == wantName {
			return cookie
		}
	}
	t.Fatalf("missing %s session cookie", operation)
	return nil
}

func loginCookies(t *testing.T, s *server, slug, password string) []*http.Cookie {
	t.Helper()
	form := url.Values{"password": {password}, "return": {appURL(slug, []string{"secret.txt"}, false)}}
	r := httptest.NewRequest(http.MethodPost, "/_auth/"+url.PathEscape(slug), strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.RemoteAddr = "127.0.0.1:43210"
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("login status=%d body=%s", w.Code, w.Body.String())
	}
	result := w.Result().Cookies()
	if len(result) != 3 {
		t.Fatalf("expected three scoped session cookies, got %d", len(result))
	}
	return result
}

func TestCanonicalRoutesLegacyRedirectAndReturnTargets(t *testing.T) {
	s, slug := makeTestServer(t, true)
	canonicalRoot := appURL(slug, nil, true)
	w := request(t, s, http.MethodGet, strings.TrimSuffix(canonicalRoot, "/"), nil)
	if w.Code != http.StatusPermanentRedirect || w.Header().Get("Location") != canonicalRoot {
		t.Fatalf("canonical root redirect status=%d location=%q", w.Code, w.Header().Get("Location"))
	}
	w = request(t, s, http.MethodGet, "/a/"+url.PathEscape(slug)+"/secret.txt", nil)
	if w.Code != http.StatusPermanentRedirect || w.Header().Get("Location") != appURL(slug, []string{"secret.txt"}, false) {
		t.Fatalf("legacy redirect status=%d location=%q", w.Code, w.Header().Get("Location"))
	}
	w = request(t, s, http.MethodPost, "/a/"+url.PathEscape(slug)+"/secret.txt", nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("legacy POST status=%d", w.Code)
	}
	w = request(t, s, http.MethodGet, appURL(slug, []string{"secret.txt"}, false), nil)
	if w.Code != http.StatusSeeOther || !strings.Contains(w.Header().Get("Location"), "return="+url.QueryEscape(appURL(slug, []string{"secret.txt"}, false))) {
		t.Fatalf("deep-link login redirect status=%d location=%q", w.Code, w.Header().Get("Location"))
	}
	cookies := loginCookies(t, s, slug, "测试密码123")
	cookie := cookies[0]
	if cookie.Path != canonicalRoot {
		t.Fatalf("cookie path=%q want=%q", cookie.Path, canonicalRoot)
	}
	paths := map[string]string{}
	for _, issued := range cookies {
		paths[issued.Name] = issued.Path
	}
	for name, wantPath := range map[string]string{
		s.sessions.controlledCookieName(slug, "preview"):  "/_preview/" + url.PathEscape(slug) + "/",
		s.sessions.controlledCookieName(slug, "download"): "/_download/" + url.PathEscape(slug) + "/",
	} {
		if paths[name] != wantPath {
			t.Errorf("cookie %s path=%q want=%q", name, paths[name], wantPath)
		}
	}
	for _, target := range []string{"https://example.invalid/", "/other/secret.txt", "/a/" + url.PathEscape(slug) + "/secret.txt", "/" + url.PathEscape(slug) + "/%252e%252e/secret.txt"} {
		if got := safeReturnTarget(target, slug); got != canonicalRoot {
			t.Errorf("unsafe return %q accepted as %q", target, got)
		}
	}
}

func TestReservedApplicationNamesAreNotPublished(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"a", "_preview", "正常应用"} {
		if err := os.Mkdir(filepath.Join(root, name), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	s, err := newServer(root, "Test Shelf", log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatal(err)
	}
	if _, exists := s.apps["a"]; exists {
		t.Fatal("reserved a directory was published")
	}
	if _, exists := s.apps["_preview"]; exists {
		t.Fatal("reserved internal directory was published")
	}
	if _, exists := s.apps["正常应用"]; !exists {
		t.Fatal("normal application was not published")
	}
}

func TestGlobalPasswordOnlyProtectsPublicApps(t *testing.T) {
	s, slug := makeTestServer(t, false)
	s.global = globalConfig{Password: protectedHash(t)}
	s.global.Version[0] = 1
	target := appURL(slug, []string{"secret.txt"}, false)
	w := request(t, s, http.MethodGet, target, nil)
	if w.Code != http.StatusSeeOther || !strings.Contains(w.Header().Get("Cache-Control"), "no-store") {
		t.Fatalf("global-protected public app status=%d cache=%q", w.Code, w.Header().Get("Cache-Control"))
	}
	globalCookie := login(t, s, slug)
	w = request(t, s, http.MethodGet, target, nil, globalCookie)
	if w.Code != http.StatusOK {
		t.Fatalf("global password did not authorize public app: %d", w.Code)
	}

	privateSlug := "私有应用"
	privateDir := filepath.Join(s.root, privateSlug)
	if err := os.Mkdir(privateDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(privateDir, "secret.txt"), []byte("private"), 0o644); err != nil {
		t.Fatal(err)
	}
	privateHash, err := hashPassword("私有密码六位")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(privateDir, ".env"), []byte("PASSWORD='"+privateHash+"'\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	info, _ := os.Stat(privateDir)
	s.apps[privateSlug] = &application{Slug: privateSlug, Dir: privateDir, ModTime: info.ModTime()}
	w = request(t, s, http.MethodGet, appURL(privateSlug, []string{"secret.txt"}, false), nil, globalCookie)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("global cookie crossed into private application: %d", w.Code)
	}
	form := url.Values{"password": {"测试密码123"}, "return": {appURL(privateSlug, nil, true)}}
	r := httptest.NewRequest(http.MethodPost, "/_auth/"+url.PathEscape(privateSlug), strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.RemoteAddr = "127.0.0.1:43210"
	w = httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("global password unlocked private app: %d", w.Code)
	}
	privateCookie := loginWithPassword(t, s, privateSlug, "私有密码六位")
	w = request(t, s, http.MethodGet, appURL(privateSlug, []string{"secret.txt"}, false), nil, privateCookie)
	if w.Code != http.StatusOK {
		t.Fatalf("private password did not authorize private app: %d", w.Code)
	}
}

func TestInvalidPrivateConfigCannotFallBackToGlobalPassword(t *testing.T) {
	s, slug := makeTestServer(t, false)
	s.global = globalConfig{Password: protectedHash(t)}
	if err := os.WriteFile(filepath.Join(s.apps[slug].Dir, ".env"), []byte("PASSWORD='invalid'\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	w := request(t, s, http.MethodGet, appURL(slug, []string{"secret.txt"}, false), nil)
	if w.Code != http.StatusLocked || !strings.Contains(w.Header().Get("Cache-Control"), "no-store") {
		t.Fatalf("invalid private config fell back to global password: status=%d cache=%q", w.Code, w.Header().Get("Cache-Control"))
	}
}

func TestPreviewEndpointRemainsClassifiedAndAuthorized(t *testing.T) {
	s, slug := makeTestServer(t, true)
	appDir := s.apps[slug].Dir
	if err := os.WriteFile(filepath.Join(appDir, "note.txt"), []byte("previewable"), 0o644); err != nil {
		t.Fatal(err)
	}
	noteInfo, err := os.Stat(filepath.Join(appDir, "note.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if kind, mode := previewFor("note.txt", noteInfo); kind != "text" || mode != "modal" {
		t.Fatalf("text classification=%s/%s", kind, mode)
	}
	w := request(t, s, http.MethodGet, previewURL(slug, []string{"note.txt"}), nil)
	if w.Code != http.StatusSeeOther || !strings.Contains(w.Header().Get("Cache-Control"), "no-store") {
		t.Fatalf("unauthenticated preview status=%d cache=%q", w.Code, w.Header().Get("Cache-Control"))
	}
	previewCookie := loginCookieForOperation(t, s, slug, "测试密码123", "preview")
	w = request(t, s, http.MethodGet, previewURL(slug, []string{"note.txt"}), nil, previewCookie)
	if w.Code != http.StatusOK || w.Body.String() != "previewable" || !strings.Contains(w.Header().Get("Content-Security-Policy"), "sandbox") {
		t.Fatalf("preview response status=%d body=%q csp=%q", w.Code, w.Body.String(), w.Header().Get("Content-Security-Policy"))
	}
	if err := os.WriteFile(filepath.Join(appDir, "unsafe.svg"), []byte("<svg/>"), 0o644); err != nil {
		t.Fatal(err)
	}
	w = request(t, s, http.MethodGet, previewURL(slug, []string{"unsafe.svg"}), nil, previewCookie)
	if w.Code != http.StatusNotFound {
		t.Fatalf("unsafe preview status=%d", w.Code)
	}
}

func TestScopedSessionCookiesAuthorizePreviewAndDownloadWithoutCrossAppAccess(t *testing.T) {
	s, slug := makeTestServer(t, true)
	appDir := s.apps[slug].Dir
	asciiSlug := "app"
	asciiDir := filepath.Join(s.root, asciiSlug)
	if err := os.Rename(appDir, asciiDir); err != nil {
		t.Fatal(err)
	}
	delete(s.apps, slug)
	info, err := os.Stat(asciiDir)
	if err != nil {
		t.Fatal(err)
	}
	s.apps[asciiSlug] = &application{Slug: asciiSlug, Dir: asciiDir, ModTime: info.ModTime()}
	slug, appDir = asciiSlug, asciiDir
	if err := os.WriteFile(filepath.Join(appDir, "note.txt"), []byte("previewable"), 0o644); err != nil {
		t.Fatal(err)
	}
	second := "other"
	secondDir := filepath.Join(s.root, second)
	if err := os.Mkdir(secondDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(secondDir, "note.txt"), []byte("other"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(secondDir, ".env"), []byte(fmt.Sprintf("PASSWORD='%s'\n", protectedHash(t))), 0o600); err != nil {
		t.Fatal(err)
	}
	info, err = os.Stat(secondDir)
	if err != nil {
		t.Fatal(err)
	}
	s.apps[second] = &application{Slug: second, Dir: secondDir, ModTime: info.ModTime()}

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Jar: jar, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	httpServer := httptest.NewServer(s)
	defer httpServer.Close()
	form := url.Values{"password": {"测试密码123"}, "return": {appURL(slug, nil, true)}}
	loginRequest, err := http.NewRequest(http.MethodPost, httpServer.URL+"/_auth/"+url.PathEscape(slug), strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	loginRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := client.Do(loginRequest)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusSeeOther {
		t.Fatalf("login status=%d", response.StatusCode)
	}
	for _, target := range []string{previewURL(slug, []string{"note.txt"}), downloadURL(slug, []string{"note.txt"})} {
		response, err = client.Get(httpServer.URL + target)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode != http.StatusOK {
			t.Fatalf("controlled endpoint %s status=%d", target, response.StatusCode)
		}
	}
	response, err = client.Get(httpServer.URL + previewURL(second, []string{"note.txt"}))
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusSeeOther || !strings.Contains(response.Header.Get("Location"), "/_auth/"+url.PathEscape(second)) {
		t.Fatalf("first application session crossed into second application: status=%d location=%q", response.StatusCode, response.Header.Get("Location"))
	}
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

func TestDirectoryTemplateDoesNotForceMinimumViewportWidth(t *testing.T) {
	s, slug := makeTestServer(t, false)
	w := request(t, s, http.MethodGet, appURL(slug, nil, true), nil)
	if w.Code != http.StatusOK {
		t.Fatalf("directory status=%d", w.Code)
	}
	if strings.Contains(w.Body.String(), "min-width:320px") {
		t.Error("directory template forces a 320px minimum body width")
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
		`data-open-url=`,
		`data-download-url=`,
		`data-can-zoom="true"`,
		`target="_blank"`,
		`rel="noopener noreferrer"`,
		`资料架首页`,
		`aria-modal="true"`,
		`aria-haspopup="menu"`,
		`datashelf.theme.v1`,
		`zoom-controls`,
		`preview-download`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("directory page missing %q", want)
		}
	}
	if strings.Contains(body, `data-preview-kind="svg"`) || strings.Contains(body, `data-preview-kind="zip"`) {
		t.Error("unsafe file type was made previewable")
	}
}

func TestDirectoryTemplateRendersOnlyServerProvidedPreviewActions(t *testing.T) {
	s, _ := makeTestServer(t, false)
	type item struct {
		Name, URL, PreviewURL, PreviewKind, OpenMode, OpenURL, DownloadURL, Kind, Size, Modified string
		CanZoom                                                                                  bool
	}
	var body strings.Builder
	err := s.pages.ExecuteTemplate(&body, "directory", map[string]any{
		"Items": []item{{
			Name: "guide.md", URL: "/guide.md", PreviewKind: "markdown", OpenMode: "modal",
			PreviewURL: "/_preview/资料/guide.md", OpenURL: "/_preview/资料/guide.md", DownloadURL: "/_download/资料/guide.md",
		}},
	})
	if err != nil {
		t.Fatalf("render preview actions: %v", err)
	}
	for _, want := range []string{
		`data-preview-kind="markdown"`,
		`data-open-url="/_preview/`,
		`data-download-url="/_download/`,
		`kind==="markdown"`,
		`allow-popups allow-popups-to-escape-sandbox`,
	} {
		if !strings.Contains(body.String(), want) {
			t.Errorf("preview action contract missing %q", want)
		}
	}
	if strings.Contains(body.String(), "innerHTML") {
		t.Error("template must not inject preview content with innerHTML")
	}
}

func TestDirectoryTemplateHonorsServerDownloadOpenMode(t *testing.T) {
	s, _ := makeTestServer(t, false)
	type item struct {
		Name, URL, PreviewURL, PreviewKind, OpenMode, Kind, Size, Modified string
	}
	var body strings.Builder
	err := s.pages.ExecuteTemplate(&body, "directory", map[string]any{
		"Items": []item{{Name: "archive.zip", URL: "/archive.zip", OpenMode: "download", Kind: "文件"}},
	})
	if err != nil {
		t.Fatalf("render download entry: %v", err)
	}
	for _, want := range []string{`href="/archive.zip" download`, `download>下载</a>`} {
		if !strings.Contains(body.String(), want) {
			t.Errorf("download entry missing %q", want)
		}
	}
}

func TestPreviewKindForUsesNarrowAllowList(t *testing.T) {
	cases := map[string]string{
		"photo.AVIF":   "image",
		"report.PDF":   "pdf",
		"guide.md":     "markdown",
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

func TestMarkdownPreviewIsSanitizedAndAuthorizedBeforeRead(t *testing.T) {
	s, slug := makeTestServer(t, true)
	name := "危险.md"
	source := "# 标题\n\n<script>alert(1)</script>\n\n[危险](javascript:alert(1)) [站外](https://example.test/a) [同应用](guide.txt)\n\n![远程图片](https://example.test/x.png)"
	if err := os.WriteFile(filepath.Join(s.apps[slug].Dir, name), []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	preview := previewURL(slug, []string{name})
	w := request(t, s, http.MethodGet, preview, nil)
	if w.Code != http.StatusSeeOther || strings.Contains(w.Body.String(), "标题") {
		t.Fatalf("unauthorized markdown leaked: status=%d body=%q", w.Code, w.Body.String())
	}
	previewCookie := loginCookieForOperation(t, s, slug, "测试密码123", "preview")
	w = request(t, s, http.MethodGet, preview, nil, previewCookie)
	if w.Code != http.StatusOK {
		t.Fatalf("markdown preview status=%d body=%s", w.Code, w.Body.String())
	}
	for key, want := range map[string]string{
		"Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store", "Referrer-Policy": "no-referrer",
	} {
		if !strings.Contains(w.Header().Get(key), want) {
			t.Errorf("%s=%q, want %q", key, w.Header().Get(key), want)
		}
	}
	body := w.Body.String()
	for _, forbidden := range []string{"<script>", "javascript:", "<img"} {
		if strings.Contains(strings.ToLower(body), forbidden) {
			t.Errorf("unsafe markdown output contains %q: %s", forbidden, body)
		}
	}
	for _, want := range []string{`href="https://example.test/a" target="_blank" rel="noopener noreferrer"`, `href="` + appURL(slug, []string{"guide.txt"}, false) + `"`, "远程图片"} {
		if !strings.Contains(body, want) {
			t.Errorf("markdown output missing %q", want)
		}
	}
}

func TestMarkdownLimitsAndDownloadEndpointKeepProtection(t *testing.T) {
	s, slug := makeTestServer(t, true)
	appDir := s.apps[slug].Dir
	if err := os.WriteFile(filepath.Join(appDir, "large.md"), bytes.Repeat([]byte("x"), maxMarkdownInput+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(appDir, "archive.zip"), []byte("zip data"), 0o600); err != nil {
		t.Fatal(err)
	}
	previewCookie := loginCookieForOperation(t, s, slug, "测试密码123", "preview")
	w := request(t, s, http.MethodGet, previewURL(slug, []string{"large.md"}), nil, previewCookie)
	if w.Code != http.StatusRequestEntityTooLarge || !strings.Contains(w.Header().Get("Cache-Control"), "no-store") {
		t.Fatalf("large markdown status=%d cache=%q", w.Code, w.Header().Get("Cache-Control"))
	}
	download := downloadURL(slug, []string{"archive.zip"})
	w = request(t, s, http.MethodHead, download, nil)
	if w.Code != http.StatusSeeOther || !strings.Contains(w.Header().Get("Cache-Control"), "no-store") {
		t.Fatalf("unauthorized download status=%d", w.Code)
	}
	downloadCookie := loginCookieForOperation(t, s, slug, "测试密码123", "download")
	w = request(t, s, http.MethodGet, download, nil, downloadCookie)
	if w.Code != http.StatusOK || !strings.HasPrefix(w.Header().Get("Content-Disposition"), "attachment;") || w.Body.String() != "zip data" {
		t.Fatalf("download status=%d disposition=%q body=%q", w.Code, w.Header().Get("Content-Disposition"), w.Body.String())
	}
}

func TestRootPasswordInvalidatesOnlyPublicApplicationSessions(t *testing.T) {
	s, publicSlug := makeTestServer(t, false)
	rootPassword := protectedHash(t)
	s.global = globalConfig{Password: rootPassword, Version: sha256.Sum256([]byte(rootPassword))}
	publicCookie := login(t, s, publicSlug)
	privateDir := filepath.Join(s.root, "私有")
	if err := os.Mkdir(privateDir, 0o755); err != nil {
		t.Fatal(err)
	}
	privatePassword := protectedHash(t)
	if err := os.WriteFile(filepath.Join(privateDir, ".env"), []byte("PASSWORD='"+privatePassword+"'\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	info, _ := os.Stat(privateDir)
	s.apps["私有"] = &application{Slug: "私有", Dir: privateDir, ModTime: info.ModTime()}
	privateCookie := loginWithPassword(t, s, "私有", "测试密码123")
	newRootPassword, err := hashPassword("新根密码六位数")
	if err != nil {
		t.Fatal(err)
	}
	s.global = globalConfig{Password: newRootPassword, Version: sha256.Sum256([]byte(newRootPassword))}
	if w := request(t, s, http.MethodGet, appURL(publicSlug, nil, true), nil, publicCookie); w.Code != http.StatusSeeOther {
		t.Fatalf("old root session survived: %d", w.Code)
	}
	if w := request(t, s, http.MethodGet, appURL("私有", nil, true), nil, privateCookie); w.Code != http.StatusOK {
		t.Fatalf("private session was affected: %d", w.Code)
	}
}
