package main

import (
	"crypto/sha256"
	_ "embed"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"log"
	"mime"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type application struct {
	Slug    string
	Dir     string
	ModTime time.Time
	state   configState
}

type server struct {
	root     string
	title    string
	global   globalConfig
	apps     map[string]*application
	sessions *sessionManager
	limiter  *loginLimiter
	logger   *log.Logger
	pages    *template.Template
}

func newServer(root, title string, logger *log.Logger) (*server, error) {
	return newServerWithConfig(root, title, globalConfig{SiteTitle: title}, logger)
}

func newServerWithConfig(root, title string, global globalConfig, logger *log.Logger) (*server, error) {
	absoluteRoot, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	rootInfo, err := os.Lstat(absoluteRoot)
	if err != nil {
		return nil, fmt.Errorf("inspect data directory: %w", err)
	}
	if !rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("data directory must be a real directory")
	}
	sessions, err := newSessionManager()
	if err != nil {
		return nil, fmt.Errorf("initialize sessions: %w", err)
	}
	pages, err := template.New("pages").Funcs(template.FuncMap{"pathEscape": url.PathEscape}).Parse(pageTemplates)
	if err != nil {
		return nil, err
	}
	s := &server{
		root: absoluteRoot, title: title, global: global, apps: make(map[string]*application),
		sessions: sessions, limiter: newLoginLimiter(), logger: logger, pages: pages,
	}
	if err := s.scanApps(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *server) scanApps() error {
	entries, err := os.ReadDir(s.root)
	if err != nil {
		return fmt.Errorf("scan data directory: %w", err)
	}
	for _, entry := range entries {
		if isPrivateName(entry.Name()) || entry.Name() == "a" || strings.HasPrefix(entry.Name(), "_") || entry.Type()&os.ModeSymlink != 0 || !entry.IsDir() {
			if entry.Name() == "a" || strings.HasPrefix(entry.Name(), "_") {
				s.logger.Printf("application %q is skipped because its name is reserved", entry.Name())
			}
			continue
		}
		path := filepath.Join(s.root, entry.Name())
		info, err := os.Lstat(path)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			continue
		}
		cfg, cfgErr := loadAppConfig(path, entry.Name())
		if cfgErr != nil {
			s.logger.Printf("application %q is locked: %v", entry.Name(), cfgErr)
		}
		app := &application{Slug: entry.Name(), Dir: path, ModTime: info.ModTime()}
		app.state.config = cfg
		s.apps[entry.Name()] = app
	}
	return nil
}

func (s *server) refreshConfig(app *application) appConfig {
	cfg, err := loadAppConfig(app.Dir, app.Slug)
	if err != nil {
		s.logger.Printf("application %q is locked: %v", app.Slug, err)
	}
	app.state.mu.Lock()
	app.state.config = cfg
	app.state.mu.Unlock()
	return cfg
}

func (s *server) effectiveConfig(app *application) appConfig {
	cfg := s.refreshConfig(app)
	if cfg.Protected || cfg.Locked || s.global.Password == "" {
		return cfg
	}
	cfg.Password = s.global.Password
	cfg.Protected = true
	cfg.Version = s.global.Version
	return cfg
}

func (s *server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	segments, err := decodePathSegments(r.URL.EscapedPath())
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if len(segments) == 1 && segments[0] == "" {
		s.home(w, r)
		return
	}
	if len(segments) >= 2 && segments[0] == "_s" {
		s.share(w, r, segments[1:])
		return
	}
	if len(segments) == 2 && segments[0] == "_auth" && segments[1] != "" {
		s.auth(w, r, segments[1])
		return
	}
	if len(segments) >= 2 && segments[0] == "_preview" && segments[1] != "" {
		s.redirectLegacyResource(w, r, segments[1], "_preview", segments[2:])
		return
	}
	if len(segments) >= 2 && segments[0] == "_download" && segments[1] != "" {
		s.redirectLegacyResource(w, r, segments[1], "_download", segments[2:])
		return
	}
	if len(segments) >= 2 && segments[0] == "a" && segments[1] != "" {
		s.redirectLegacyApp(w, r, segments[1], segments[2:])
		return
	}
	if len(segments) >= 1 && segments[0] != "" && !strings.HasPrefix(segments[0], "_") {
		s.serveApplicationRoute(w, r, segments[0], segments[1:])
		return
	}
	http.NotFound(w, r)
}

func (s *server) redirectLegacyResource(w http.ResponseWriter, r *http.Request, slug, operation string, segments []string) {
	if (r.Method != http.MethodGet && r.Method != http.MethodHead) || len(segments) == 0 || s.apps[slug] == nil {
		http.NotFound(w, r)
		return
	}
	for _, segment := range segments {
		if segment == "" || isPrivateName(segment) {
			http.NotFound(w, r)
			return
		}
	}
	http.Redirect(w, r, appResourceURL(slug, operation, segments), http.StatusPermanentRedirect)
}

func (s *server) serveApplicationRoute(w http.ResponseWriter, r *http.Request, slug string, segments []string) {
	if len(segments) > 0 && strings.HasPrefix(segments[0], "_") {
		switch segments[0] {
		case "_auth":
			s.authApp(w, r, slug)
			return
		case "_preview":
			s.previewApp(w, r, slug, segments[1:])
			return
		case "_download":
			s.downloadApp(w, r, slug, segments[1:])
			return
		case "_html":
			s.htmlShell(w, r, slug, segments[1:])
			return
		case "_html-content":
			s.htmlContent(w, r, slug, segments[1:])
			return
		default:
			http.NotFound(w, r)
			return
		}
	}
	s.serveApp(w, r, slug, segments)
}

func (s *server) redirectLegacyApp(w http.ResponseWriter, r *http.Request, slug string, segments []string) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.NotFound(w, r)
		return
	}
	if _, ok := s.apps[slug]; !ok {
		http.NotFound(w, r)
		return
	}
	for _, segment := range segments {
		if isPrivateName(segment) {
			http.NotFound(w, r)
			return
		}
	}
	http.Redirect(w, r, appURL(slug, trimTrailingEmpty(segments), len(segments) == 0 || strings.HasSuffix(r.URL.EscapedPath(), "/")), http.StatusPermanentRedirect)
}

func (s *server) home(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	type card struct {
		Slug, Name, Description, URL string
		Protected, Locked            bool
		ModTime                      time.Time
	}
	cards := make([]card, 0, len(s.apps))
	for _, app := range s.apps {
		policy := s.resolveDirectoryPolicy(app, nil)
		cards = append(cards, card{app.Slug, policy.Title, policy.Description, appURL(app.Slug, nil, true), policy.Protected, policy.Locked, app.ModTime})
	}
	if r.URL.Query().Get("sort") == "name" {
		sort.Slice(cards, func(i, j int) bool { return strings.ToLower(cards[i].Name) < strings.ToLower(cards[j].Name) })
	} else {
		sort.Slice(cards, func(i, j int) bool { return cards[i].ModTime.After(cards[j].ModTime) })
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	setPageSecurityHeaders(w)
	if r.Method == http.MethodHead {
		return
	}
	if err := s.pages.ExecuteTemplate(w, "home", map[string]any{
		"PageTitle":   s.title,
		"Title":       s.title,
		"Description": s.global.Description,
		"Apps":        cards,
		"SortByName":  r.URL.Query().Get("sort") == "name",
	}); err != nil {
		s.logger.Printf("render home: %v", err)
	}
}

func (s *server) auth(w http.ResponseWriter, r *http.Request, slug string) {
	app, ok := s.apps[slug]
	if !ok {
		http.NotFound(w, r)
		return
	}
	cfg := s.effectiveConfig(app)
	policy := s.resolveDirectoryPolicy(app, nil)
	if policy.Protected || policy.Locked {
		cfg.Password, cfg.Protected, cfg.Locked, cfg.Version = policy.Password, policy.Protected, policy.Locked, policy.Version
	}
	if !cfg.Protected {
		http.Redirect(w, r, appURL(slug, nil, true), http.StatusSeeOther)
		return
	}
	w.Header().Set("Cache-Control", "private, no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	target := safeReturnTarget(r.URL.Query().Get("return"), slug)
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		s.renderLogin(w, r, cfg, slug, target, "")
	case http.MethodPost:
		if cfg.Locked {
			s.renderLogin(w, r, cfg, slug, target, "管理员需修改本地配置")
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 8*1024)
		if err := r.ParseForm(); err != nil {
			http.Error(w, "请求无效", http.StatusBadRequest)
			return
		}
		target = safeReturnTarget(r.Form.Get("return"), slug)
		source := sourceIP(r)
		if !s.limiter.allowed(slug, source) {
			s.renderLoginStatus(w, r, cfg, slug, target, "尝试次数过多，请稍后再试", http.StatusTooManyRequests)
			return
		}
		if !verifyPassword(cfg.Password, r.Form.Get("password")) {
			s.renderLoginStatus(w, r, cfg, slug, target, "密码不正确", http.StatusUnauthorized)
			return
		}
		s.limiter.reset(slug, source)
		for _, cookie := range s.sessionCookies(slug, cfg.Version, requestIsHTTPS(r)) {
			http.SetCookie(w, cookie)
		}
		http.Redirect(w, r, target, http.StatusSeeOther)
	default:
		w.Header().Set("Allow", "GET, HEAD, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// authApp is the canonical application-prefix login endpoint.  Keeping it
// below /<slug>/ is what makes the single Path=/slug/ session cookie reach
// every protected view without widening it to the site root.
func (s *server) authApp(w http.ResponseWriter, r *http.Request, slug string) {
	app, ok := s.apps[slug]
	if !ok {
		http.NotFound(w, r)
		return
	}
	target := safeReturnTarget(r.URL.Query().Get("return"), slug)
	segments, _ := decodePathSegments(target)
	resource := trimTrailingEmpty(segments[1:])
	if len(resource) > 0 && strings.HasPrefix(resource[0], "_") {
		resource = resource[1:]
	}
	if len(resource) > 0 && !strings.HasSuffix(target, "/") {
		resource = resource[:len(resource)-1]
	}
	policy := s.resolveDirectoryPolicy(app, resource)
	cfg := appConfig{Name: policy.Title, Description: policy.Description, Password: policy.Password, Protected: policy.Protected, Locked: policy.Locked, Version: policy.Version}
	if !cfg.Protected {
		http.Redirect(w, r, target, http.StatusSeeOther)
		return
	}
	w.Header().Set("Cache-Control", "private, no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		s.renderLogin(w, r, cfg, slug, target, "")
	case http.MethodPost:
		if cfg.Locked {
			s.renderLogin(w, r, cfg, slug, target, "管理员需修改本地配置")
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 8<<10)
		if err := r.ParseForm(); err != nil {
			http.Error(w, "请求无效", http.StatusBadRequest)
			return
		}
		target = safeReturnTarget(r.Form.Get("return"), slug)
		if !s.limiter.allowed(slug+"\x00"+policy.Boundary, sourceIP(r)) {
			s.renderLoginStatus(w, r, cfg, slug, target, "尝试次数过多，请稍后再试", http.StatusTooManyRequests)
			return
		}
		if !verifyConfiguredPassword(cfg.Password, r.Form.Get("password")) {
			s.renderLoginStatus(w, r, cfg, slug, target, "密码不正确", http.StatusUnauthorized)
			return
		}
		s.limiter.reset(slug+"\x00"+policy.Boundary, sourceIP(r))
		for _, cookie := range s.sessionCookies(slug, cfg.Version, requestIsHTTPS(r)) {
			http.SetCookie(w, cookie)
		}
		http.Redirect(w, r, target, http.StatusSeeOther)
	default:
		w.Header().Set("Allow", "GET, HEAD, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *server) renderLogin(w http.ResponseWriter, r *http.Request, cfg appConfig, slug, target, message string) {
	status := http.StatusOK
	if cfg.Locked {
		message = "管理员需修改本地配置"
		status = http.StatusLocked
	}
	s.renderLoginStatus(w, r, cfg, slug, target, message, status)
}

func (s *server) renderLoginStatus(w http.ResponseWriter, r *http.Request, cfg appConfig, slug, target, message string, status int) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	setPageSecurityHeaders(w)
	w.WriteHeader(status)
	if r.Method == http.MethodHead {
		return
	}
	if err := s.pages.ExecuteTemplate(w, "login", map[string]any{
		"PageTitle": cfg.Name + " - 访问验证", "Name": cfg.Name, "Slug": slug,
		"Return": target, "Message": message, "Locked": cfg.Locked,
	}); err != nil {
		s.logger.Printf("render login: %v", err)
	}
}

func (s *server) serveApp(w http.ResponseWriter, r *http.Request, slug string, segments []string) {
	app, ok := s.apps[slug]
	if !ok {
		http.NotFound(w, r)
		return
	}
	if len(segments) == 0 && !strings.HasSuffix(r.URL.EscapedPath(), "/") {
		http.Redirect(w, r, appURL(slug, nil, true), http.StatusPermanentRedirect)
		return
	}
	pathSegments := trimTrailingEmpty(segments)
	policySegments := pathSegments
	if !strings.HasSuffix(r.URL.EscapedPath(), "/") && len(policySegments) > 0 {
		policySegments = policySegments[:len(policySegments)-1]
	}
	policy := s.resolveDirectoryPolicy(app, policySegments)
	if !s.authorizePolicy(w, r, app, policy) {
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	for _, segment := range segments {
		if segment == "" {
			continue
		}
		if isPrivateName(segment) {
			http.NotFound(w, r)
			return
		}
	}
	target, info, err := resolveSafePath(app.Dir, pathSegments)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if info.IsDir() {
		if !strings.HasSuffix(r.URL.EscapedPath(), "/") {
			http.Redirect(w, r, r.URL.EscapedPath()+"/", http.StatusPermanentRedirect)
			return
		}
		if len(pathSegments) == 0 {
			indexPath, indexInfo, indexErr := resolveSafePath(app.Dir, []string{"index.html"})
			if indexErr == nil && indexInfo.Mode().IsRegular() {
				_ = indexPath
				http.Redirect(w, r, appResourceURL(slug, "_html", []string{"index.html"}), http.StatusSeeOther)
				return
			}
		}
		policy = s.resolveDirectoryPolicy(app, pathSegments)
		if !s.authorizePolicy(w, r, app, policy) {
			return
		}
		cfg := appConfig{Name: policy.Title, Description: policy.Description, Protected: policy.Protected, Locked: policy.Locked, Version: policy.Version}
		s.serveDirectory(w, r, app, cfg, target, pathSegments)
		return
	}
	if isHTMLName(info.Name()) {
		http.Redirect(w, r, appResourceURL(slug, "_html", pathSegments), http.StatusSeeOther)
		return
	}
	s.serveFile(w, r, target, info, false)
}

func (s *server) authorizePolicy(w http.ResponseWriter, r *http.Request, app *application, policy directoryPolicy) bool {
	if !policy.Protected {
		return true
	}
	w.Header().Set("Cache-Control", "private, no-store")
	if policy.Locked {
		http.Error(w, "管理员需修改本地配置", http.StatusLocked)
		return false
	}
	cookie, err := r.Cookie(s.sessions.cookieName(app.Slug))
	if err != nil || !s.sessions.valid(cookie.Value, app.Slug, policy.Version) {
		http.Redirect(w, r, appResourceURL(app.Slug, "_auth", nil)+"?return="+url.QueryEscape(r.URL.EscapedPath()), http.StatusSeeOther)
		return false
	}
	return true
}

func (s *server) authorizeApp(w http.ResponseWriter, r *http.Request, slug string, cfg appConfig) bool {
	if !cfg.Protected {
		return true
	}
	w.Header().Set("Cache-Control", "private, no-store")
	if cfg.Locked {
		http.Error(w, "管理员需修改本地配置", http.StatusLocked)
		return false
	}
	cookie, err := r.Cookie(s.sessions.cookieNameForRequest(slug, r.URL.EscapedPath()))
	if err != nil || !s.sessions.valid(cookie.Value, slug, cfg.Version) {
		target := r.URL.EscapedPath()
		http.Redirect(w, r, "/_auth/"+url.PathEscape(slug)+"?return="+url.QueryEscape(target), http.StatusSeeOther)
		return false
	}
	return true
}

func (s *server) sessionCookies(slug string, version [32]byte, secure bool) []*http.Cookie {
	value := s.sessions.issue(slug, version)
	escapedSlug := url.PathEscape(slug)
	return []*http.Cookie{
		{Name: s.sessions.cookieName(slug), Value: value, Path: "/" + escapedSlug + "/", HttpOnly: true, SameSite: http.SameSiteLaxMode, Secure: secure},
	}
}

func trimTrailingEmpty(segments []string) []string {
	for len(segments) > 0 && segments[len(segments)-1] == "" {
		segments = segments[:len(segments)-1]
	}
	return segments
}

func resolveSafePath(root string, segments []string) (string, fs.FileInfo, error) {
	rootInfo, err := os.Lstat(root)
	if err != nil || !rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 {
		return "", nil, errors.New("unsafe application root")
	}
	current := root
	info := rootInfo
	for _, segment := range segments {
		if segment == "" || isPrivateName(segment) {
			return "", nil, errors.New("unsafe path")
		}
		current = filepath.Join(current, segment)
		info, err = os.Lstat(current)
		if err != nil || info.Mode()&os.ModeSymlink != 0 {
			return "", nil, errors.New("path is missing or linked")
		}
		if !info.Mode().IsRegular() && !info.IsDir() {
			return "", nil, errors.New("unsupported file type")
		}
	}
	return current, info, nil
}

func (s *server) serveDirectory(w http.ResponseWriter, r *http.Request, app *application, cfg appConfig, dir string, segments []string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		s.renderErrorPage(w, r, http.StatusForbidden, "无法访问此目录", "当前资料无法读取。请联系资料管理员确认目录权限。", appURL(app.Slug, trimTrailingEmpty(segments), true))
		return
	}
	type item struct {
		Name, URL, Kind, Size, Modified                         string
		PreviewKind, OpenMode, PreviewURL, OpenURL, DownloadURL string
		CanZoom, CanNavigateImages                              bool
	}
	items := make([]item, 0, len(entries))
	for _, entry := range entries {
		if isPrivateName(entry.Name()) || entry.Type()&os.ModeSymlink != 0 {
			continue
		}
		info, err := entry.Info()
		if err != nil || !info.IsDir() && !info.Mode().IsRegular() {
			continue
		}
		childSegments := append(append([]string{}, segments...), entry.Name())
		itemURL := appURL(app.Slug, childSegments, info.IsDir())
		previewKind, openMode := previewFor(entry.Name(), info)
		previewResourceURL := ""
		openResourceURL := ""
		downloadResourceURL := ""
		if previewKind != "none" {
			previewResourceURL = previewURL(app.Slug, childSegments)
			openResourceURL = previewResourceURL
			if isHTMLName(entry.Name()) {
				openResourceURL = appResourceURL(app.Slug, "_html", childSegments)
			}
		} else {
			previewKind = ""
		}
		if info.Mode().IsRegular() {
			downloadResourceURL = downloadURL(app.Slug, childSegments)
		}
		kind, size := "文件", humanSize(info.Size())
		if info.IsDir() {
			kind, size = "目录", ""
		}
		items = append(items, item{
			Name: entry.Name(), URL: itemURL, Kind: kind, Size: size,
			Modified:    info.ModTime().Format("2006-01-02 15:04"),
			PreviewKind: previewKind, OpenMode: openMode, PreviewURL: previewResourceURL,
			// The template consumes only server-generated capabilities. In particular,
			// DownloadURL uses the authenticated attachment endpoint rather than the
			// file's browse URL, so the browser cannot choose an unsafe disposition.
			OpenURL: openResourceURL, DownloadURL: downloadResourceURL, CanZoom: previewKind == "image",
		})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].Kind != items[j].Kind {
			return items[i].Kind == "目录"
		}
		return strings.ToLower(items[i].Name) < strings.ToLower(items[j].Name)
	})
	imageCount := 0
	for _, item := range items {
		if item.PreviewKind == "image" {
			imageCount++
		}
	}
	for i := range items {
		items[i].CanNavigateImages = items[i].PreviewKind == "image" && imageCount >= 2
	}
	type crumb struct{ Name, URL string }
	appPolicy := s.resolveDirectoryPolicy(app, nil)
	crumbs := []crumb{{appPolicy.Title, appURL(app.Slug, nil, true)}}
	for i, segment := range segments {
		if i == len(segments)-1 {
			break
		}
		crumbs = append(crumbs, crumb{segment, appURL(app.Slug, segments[:i+1], true)})
	}
	displayName := cfg.Name
	if len(segments) > 0 {
		displayName = segments[len(segments)-1]
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	setPageSecurityHeaders(w)
	if r.Method == http.MethodHead {
		return
	}
	if err := s.pages.ExecuteTemplate(w, "directory", map[string]any{
		"PageTitle": cfg.Name,
		"Name":      displayName,
		"Items":     items,
		"Crumbs":    crumbs,
		"Protected": cfg.Protected,
		"Locked":    cfg.Locked,
	}); err != nil {
		s.logger.Printf("render directory: %v", err)
	}
}

// previewKindFor is the sole format allow-list used by the embedded UI. The
// template only receives this classification and a server-generated URL; it
// never promotes a file to previewable status based on its own extension check.
func previewKindFor(name string) string {
	switch strings.ToLower(filepath.Ext(name)) {
	case ".jpg", ".jpeg", ".png", ".gif", ".webp", ".avif", ".bmp", ".ico":
		return "image"
	case ".pdf":
		return "pdf"
	case ".md", ".markdown":
		return "markdown"
	case ".txt", ".csv", ".log", ".json", ".xml", ".yaml", ".yml", ".toml", ".ini", ".html", ".htm", ".js", ".mjs", ".css", ".go", ".c", ".h", ".cs", ".ts", ".tsx", ".jsx", ".py", ".sh", ".sql":
		return "text"
	default:
		return ""
	}
}

func isHTMLName(name string) bool {
	ext := strings.ToLower(filepath.Ext(name))
	return ext == ".html" || ext == ".htm"
}

func (s *server) appResource(w http.ResponseWriter, r *http.Request, slug string, segments []string, operation string) (*application, string, fs.FileInfo, directoryPolicy, bool) {
	app, ok := s.apps[slug]
	if !ok || len(segments) == 0 || (r.Method != http.MethodGet && r.Method != http.MethodHead) {
		http.NotFound(w, r)
		return nil, "", nil, directoryPolicy{}, false
	}
	for _, segment := range segments {
		if segment == "" || isPrivateName(segment) {
			http.NotFound(w, r)
			return nil, "", nil, directoryPolicy{}, false
		}
	}
	policy := s.resolveDirectoryPolicy(app, segments[:len(segments)-1])
	if !s.authorizePolicy(w, r, app, policy) {
		return nil, "", nil, directoryPolicy{}, false
	}
	target, info, err := resolveSafePath(app.Dir, segments)
	if err != nil || !info.Mode().IsRegular() {
		http.NotFound(w, r)
		return nil, "", nil, directoryPolicy{}, false
	}
	return app, target, info, policy, true
}

func (s *server) previewApp(w http.ResponseWriter, r *http.Request, slug string, segments []string) {
	_, target, info, _, ok := s.appResource(w, r, slug, segments, "_preview")
	if !ok {
		return
	}
	kind, _ := previewFor(info.Name(), info)
	if kind == "none" && isMarkdownName(info.Name()) {
		kind = "markdown"
	}
	if kind == "none" {
		http.NotFound(w, r)
		return
	}
	if kind == "markdown" {
		s.serveMarkdown(w, r, slug, segments, target, info)
		return
	}
	w.Header().Set("Cache-Control", "private, no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	if kind == "text" {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	}
	w.Header().Set("Content-Security-Policy", "sandbox; default-src 'none'; object-src 'none'; base-uri 'none'; frame-ancestors 'self'")
	s.serveFile(w, r, target, info, false)
}

func (s *server) downloadApp(w http.ResponseWriter, r *http.Request, slug string, segments []string) {
	_, target, info, _, ok := s.appResource(w, r, slug, segments, "_download")
	if !ok {
		return
	}
	w.Header().Set("Cache-Control", "private, no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	s.serveDownload(w, r, target, info)
}

func (s *server) htmlShell(w http.ResponseWriter, r *http.Request, slug string, segments []string) {
	_, _, info, _, ok := s.appResource(w, r, slug, segments, "_html")
	if !ok {
		return
	}
	if !isHTMLName(info.Name()) {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "private, no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; frame-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
	if r.Method == http.MethodHead {
		return
	}
	name := template.HTMLEscapeString(info.Name())
	content := template.HTMLEscapeString(appResourceURL(slug, "_html-content", segments))
	source := template.HTMLEscapeString(appResourceURL(slug, "_preview", segments))
	download := template.HTMLEscapeString(appResourceURL(slug, "_download", segments))
	_, _ = fmt.Fprintf(w, "<!doctype html><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'><title>%s</title><p><a href='../'>返回</a> · <a href='%s'>查看源码</a> · <a href='%s'>下载</a></p><p>外部资源与脚本已禁用，页面可能与原始站点不同。</p><iframe title='%s' sandbox src='%s' style='width:100%%;min-height:80vh;border:1px solid #bbb'></iframe>", name, source, download, name, content)
}

func (s *server) htmlContent(w http.ResponseWriter, r *http.Request, slug string, segments []string) {
	_, target, info, _, ok := s.appResource(w, r, slug, segments, "_html-content")
	if !ok {
		return
	}
	if !isHTMLName(info.Name()) {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "private, no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Permissions-Policy", "accelerometer=(), camera=(), clipboard-read=(), clipboard-write=(), geolocation=(), microphone=(), payment=(), usb=()")
	w.Header().Set("Content-Security-Policy", "sandbox; default-src 'none'; script-src 'none'; connect-src 'none'; img-src data:; style-src 'unsafe-inline'; font-src 'none'; media-src 'none'; object-src 'none'; frame-src 'none'; form-action 'none'; base-uri 'none'; frame-ancestors 'self'")
	s.serveHTMLContent(w, r, target, info)
}

func (s *server) preview(w http.ResponseWriter, r *http.Request, slug string, segments []string) {
	app, ok := s.apps[slug]
	if !ok || len(segments) == 0 || r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.NotFound(w, r)
		return
	}
	cfg := s.effectiveConfig(app)
	if !s.authorizeApp(w, r, slug, cfg) {
		return
	}
	for _, segment := range segments {
		if segment == "" || isPrivateName(segment) {
			http.NotFound(w, r)
			return
		}
	}
	target, info, err := resolveSafePath(app.Dir, segments)
	if err != nil || !info.Mode().IsRegular() {
		http.NotFound(w, r)
		return
	}
	kind, _ := previewFor(info.Name(), info)
	if kind == "none" && isMarkdownName(info.Name()) {
		kind = "markdown"
	}
	if kind == "none" {
		http.NotFound(w, r)
		return
	}
	if kind == "markdown" {
		s.serveMarkdown(w, r, slug, segments, target, info)
		return
	}
	w.Header().Set("Content-Security-Policy", "sandbox; default-src 'none'; object-src 'none'; base-uri 'none'; frame-ancestors 'self'")
	s.serveFile(w, r, target, info, false)
}

func (s *server) serveMarkdown(w http.ResponseWriter, r *http.Request, slug string, segments []string, path string, info fs.FileInfo) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Cache-Control", "private, no-store")
	w.Header().Set("Content-Security-Policy", "sandbox allow-popups allow-popups-to-escape-sandbox; default-src 'none'; style-src 'unsafe-inline'; img-src 'none'; media-src 'none'; font-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'self'")
	if info.Size() > maxMarkdownInput {
		http.Error(w, "Markdown 文件过大", http.StatusRequestEntityTooLarge)
		return
	}
	source, err := os.ReadFile(path)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	body, err := renderMarkdown(source, slug, segments)
	if err != nil {
		if errors.Is(err, errMarkdownTooLarge) {
			http.Error(w, "Markdown 文件过大", http.StatusRequestEntityTooLarge)
		} else if errors.Is(err, errMarkdownUnsupportedEncoding) {
			http.Error(w, "Markdown 编码不受支持", http.StatusUnsupportedMediaType)
		} else {
			http.Error(w, "Markdown 无法渲染", http.StatusUnprocessableEntity)
		}
		return
	}
	if r.Method == http.MethodHead {
		return
	}
	_, _ = fmt.Fprintf(w, "<!doctype html><html><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"><title>Markdown 预览</title><style>body{margin:0 auto;max-width:72rem;padding:2rem;font:16px/1.65 system-ui,sans-serif}pre{overflow:auto;padding:1rem;background:#f4f4f4}table{border-collapse:collapse}th,td{border:1px solid #bbb;padding:.4rem}</style></head><body>%s</body></html>", body)
}

func (s *server) download(w http.ResponseWriter, r *http.Request, slug string, segments []string) {
	app, ok := s.apps[slug]
	if !ok || len(segments) == 0 || (r.Method != http.MethodGet && r.Method != http.MethodHead) {
		http.NotFound(w, r)
		return
	}
	cfg := s.effectiveConfig(app)
	if !s.authorizeApp(w, r, slug, cfg) {
		return
	}
	target, info, err := resolveSafePath(app.Dir, segments)
	if err != nil || !info.Mode().IsRegular() {
		http.NotFound(w, r)
		return
	}
	s.serveDownload(w, r, target, info)
}

func previewFor(name string, info fs.FileInfo) (kind, openMode string) {
	if info.IsDir() {
		return "none", "navigate"
	}
	ext := strings.ToLower(filepath.Ext(name))
	switch ext {
	case ".jpg", ".jpeg", ".png", ".gif", ".webp", ".avif", ".bmp", ".ico":
		return "image", "modal"
	case ".pdf":
		return "pdf", "modal"
	case ".md", ".markdown":
		if info.Size() <= 1<<20 {
			return "markdown", "modal"
		}
	case ".txt", ".csv", ".log", ".json", ".xml", ".yaml", ".yml", ".toml", ".ini", ".go", ".c", ".h", ".cs", ".ts", ".tsx", ".jsx", ".py", ".sh", ".sql", ".html", ".htm", ".js", ".mjs", ".css":
		if info.Size() <= 2<<20 {
			return "text", "modal"
		}
	}
	return "none", "external"
}

func isMarkdownName(name string) bool {
	ext := strings.ToLower(filepath.Ext(name))
	return ext == ".md" || ext == ".markdown"
}

func (s *server) serveDownload(w http.ResponseWriter, r *http.Request, path string, info fs.FileInfo) {
	file, err := os.Open(path)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil || !openedInfo.Mode().IsRegular() || openedInfo.Name() != info.Name() {
		http.NotFound(w, r)
		return
	}
	contentType, _ := contentDisposition(path, false)
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": info.Name()}))
	http.ServeContent(w, r, info.Name(), info.ModTime(), file)
}

func (s *server) serveFile(w http.ResponseWriter, r *http.Request, path string, info fs.FileInfo, rootIndex bool) {
	file, err := os.Open(path)
	if err != nil {
		s.renderErrorPage(w, r, http.StatusForbidden, "无法访问此文件", "当前资料无法读取。请联系资料管理员确认文件权限。", "./")
		return
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil || !openedInfo.Mode().IsRegular() || openedInfo.Name() != info.Name() {
		http.NotFound(w, r)
		return
	}
	contentType, attachment := contentDisposition(path, rootIndex)
	w.Header().Set("Content-Type", contentType)
	if attachment {
		w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": info.Name()}))
	}
	http.ServeContent(w, r, info.Name(), info.ModTime(), file)
}

// serveHTMLContent is intentionally only used after the HTML sandbox headers
// have been installed.  The ordinary file service maps HTML to text/plain so
// an untrusted document cannot accidentally become executable at a browse URL.
func (s *server) serveHTMLContent(w http.ResponseWriter, r *http.Request, path string, info fs.FileInfo) {
	file, err := os.Open(path)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || opened.Name() != info.Name() {
		http.NotFound(w, r)
		return
	}
	http.ServeContent(w, r, info.Name(), info.ModTime(), file)
}

func shareCookieName(token string) string {
	// The token itself never reaches a cookie name or a log line.
	return "datashelf_share_" + fmt.Sprintf("%x", sha256.Sum256([]byte(token)))[:16]
}

func (s *server) share(w http.ResponseWriter, r *http.Request, segments []string) {
	if len(segments) == 0 || segments[0] == "" {
		http.NotFound(w, r)
		return
	}
	share, ok := s.findShare(segments[0])
	if !ok || time.Now().After(share.Expires) {
		w.Header().Set("Cache-Control", "no-store")
		http.NotFound(w, r)
		return
	}
	token := segments[0]
	if len(segments) == 1 || segments[1] == "" {
		s.shareGate(w, r, share, token)
		return
	}
	if segments[1] == "_auth" {
		s.shareAuth(w, r, share, token)
		return
	}
	if !s.authorizeShare(w, r, share, token) {
		return
	}
	if len(segments) != 2 {
		http.NotFound(w, r)
		return
	}
	path, info, err := resolveSafePath(share.OwnerDir, []string{share.Filename})
	if err != nil || !info.Mode().IsRegular() {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Cache-Control", "private, no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	switch segments[1] {
	case "_preview":
		kind, _ := previewFor(info.Name(), info)
		if kind == "none" {
			http.NotFound(w, r)
			return
		}
		if kind == "markdown" {
			s.serveMarkdown(w, r, share.App.Slug, []string{share.Filename}, path, info)
			return
		}
		if kind == "text" {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		}
		w.Header().Set("Content-Security-Policy", "sandbox; default-src 'none'; object-src 'none'; base-uri 'none'; frame-ancestors 'self'")
		s.serveFile(w, r, path, info, false)
	case "_download":
		if !share.AllowDownload {
			http.NotFound(w, r)
			return
		}
		s.serveDownload(w, r, path, info)
	case "_html":
		if !isHTMLName(info.Name()) {
			http.NotFound(w, r)
			return
		}
		s.shareHTMLShell(w, r, share, token, info)
	case "_html-content":
		if !isHTMLName(info.Name()) {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Permissions-Policy", "accelerometer=(), camera=(), clipboard-read=(), clipboard-write=(), geolocation=(), microphone=(), payment=(), usb=()")
		w.Header().Set("Content-Security-Policy", "sandbox; default-src 'none'; script-src 'none'; connect-src 'none'; img-src data:; style-src 'unsafe-inline'; font-src 'none'; media-src 'none'; object-src 'none'; frame-src 'none'; form-action 'none'; base-uri 'none'; frame-ancestors 'self'")
		s.serveHTMLContent(w, r, path, info)
	default:
		http.NotFound(w, r)
	}
}

func (s *server) shareGate(w http.ResponseWriter, r *http.Request, share shareDefinition, token string) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.NotFound(w, r)
		return
	}
	if s.shareAuthorized(r, share, token) {
		http.Redirect(w, r, "/_s/"+url.PathEscape(token)+"/_preview", http.StatusSeeOther)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "private, no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	setPageSecurityHeaders(w)
	if r.Method == http.MethodHead {
		return
	}
	_, _ = fmt.Fprintf(w, "<!doctype html><meta charset=utf-8><title>分享访问</title><form method=post action='%s'><label>访问密码 <input type=password name=password autocomplete=current-password required></label><button>打开分享</button></form>", template.HTMLEscapeString("/_s/"+url.PathEscape(token)+"/_auth"))
}

func (s *server) shareAuth(w http.ResponseWriter, r *http.Request, share shareDefinition, token string) {
	if r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Cache-Control", "private, no-store")
	r.Body = http.MaxBytesReader(w, r.Body, 8<<10)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "请求无效", http.StatusBadRequest)
		return
	}
	key := "share:" + share.ID
	if !s.limiter.allowed(key, sourceIP(r)) {
		http.Error(w, "尝试次数过多，请稍后再试", http.StatusTooManyRequests)
		return
	}
	if !verifyConfiguredPassword(share.Password, r.Form.Get("password")) {
		http.Error(w, "密码不正确", http.StatusUnauthorized)
		return
	}
	s.limiter.reset(key, sourceIP(r))
	value := s.sessions.issue("share:"+share.ID, share.Version)
	maxAge := int(time.Until(share.Expires).Seconds())
	if maxAge > int((8 * time.Hour).Seconds()) {
		maxAge = int((8 * time.Hour).Seconds())
	}
	http.SetCookie(w, &http.Cookie{Name: shareCookieName(token), Value: value, Path: "/_s/" + url.PathEscape(token) + "/", HttpOnly: true, SameSite: http.SameSiteLaxMode, Secure: requestIsHTTPS(r), MaxAge: maxAge})
	http.Redirect(w, r, "/_s/"+url.PathEscape(token)+"/_preview", http.StatusSeeOther)
}

func (s *server) shareAuthorized(r *http.Request, share shareDefinition, token string) bool {
	cookie, err := r.Cookie(shareCookieName(token))
	return err == nil && s.sessions.valid(cookie.Value, "share:"+share.ID, share.Version)
}

func (s *server) authorizeShare(w http.ResponseWriter, r *http.Request, share shareDefinition, token string) bool {
	if s.shareAuthorized(r, share, token) {
		return true
	}
	w.Header().Set("Cache-Control", "private, no-store")
	http.Redirect(w, r, "/_s/"+url.PathEscape(token)+"/", http.StatusSeeOther)
	return false
}

func (s *server) shareHTMLShell(w http.ResponseWriter, r *http.Request, share shareDefinition, token string, info fs.FileInfo) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; frame-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
	if r.Method == http.MethodHead {
		return
	}
	base := "/_s/" + url.PathEscape(token) + "/"
	_, _ = fmt.Fprintf(w, "<!doctype html><meta charset=utf-8><title>%s</title><p><a href='%s_preview'>查看源码</a></p><iframe title='%s' sandbox src='%s_html-content' style='width:100%%;min-height:80vh;border:1px solid #bbb'></iframe>", template.HTMLEscapeString(info.Name()), base, template.HTMLEscapeString(info.Name()), base)
}

// renderErrorPage keeps user-visible file access failures inside the same
// embedded UI. Callers reach it only after authorization has completed.
func (s *server) renderErrorPage(w http.ResponseWriter, r *http.Request, status int, heading, detail, backURL string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	setPageSecurityHeaders(w)
	w.WriteHeader(status)
	if r.Method == http.MethodHead {
		return
	}
	if err := s.pages.ExecuteTemplate(w, "error", map[string]string{
		"PageTitle": heading + " - " + s.title,
		"Heading":   heading,
		"Detail":    detail,
		"BackURL":   backURL,
	}); err != nil {
		s.logger.Printf("render error page: %v", err)
	}
}

func contentDisposition(path string, rootIndex bool) (string, bool) {
	ext := strings.ToLower(filepath.Ext(path))
	if rootIndex && ext == ".html" {
		return "text/html; charset=utf-8", false
	}
	switch ext {
	case ".html", ".htm", ".txt", ".md", ".markdown", ".csv", ".log", ".xml", ".json", ".yaml", ".yml", ".toml", ".ini", ".go", ".c", ".h", ".cs", ".ts", ".tsx", ".jsx", ".py", ".sh", ".sql", ".js", ".mjs", ".css":
		return "text/plain; charset=utf-8", false
	case ".svg":
		return "application/octet-stream", true
	case ".pdf":
		return "application/pdf", false
	}
	mediaType := mime.TypeByExtension(ext)
	if strings.HasPrefix(mediaType, "image/") || strings.HasPrefix(mediaType, "audio/") || strings.HasPrefix(mediaType, "video/") || strings.HasPrefix(mediaType, "font/") {
		return mediaType, false
	}
	if mediaType != "" && (ext == ".wasm" || ext == ".map") {
		return mediaType, false
	}
	return "application/octet-stream", true
}

func appURL(slug string, segments []string, directory bool) string {
	parts := []string{"", url.PathEscape(slug)}
	for _, segment := range segments {
		parts = append(parts, url.PathEscape(segment))
	}
	result := strings.Join(parts, "/")
	if directory && !strings.HasSuffix(result, "/") {
		result += "/"
	}
	return result
}

func previewURL(slug string, segments []string) string {
	return appResourceURL(slug, "_preview", segments)
}

func appResourceURL(slug, operation string, segments []string) string {
	parts := []string{"", url.PathEscape(slug), operation}
	for _, segment := range segments {
		parts = append(parts, url.PathEscape(segment))
	}
	return strings.Join(parts, "/")
}

func downloadURL(slug string, segments []string) string {
	return appResourceURL(slug, "_download", segments)
}

func setPageSecurityHeaders(w http.ResponseWriter) {
	w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'")
}

func humanSize(size int64) string {
	const unit = 1024
	if size < unit {
		return fmt.Sprintf("%d B", size)
	}
	div, exp := int64(unit), 0
	for n := size / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(size)/float64(div), "KMGTPE"[exp])
}

// pageTemplates is bundled into the executable, so DataShelf has no runtime
// dependency on a template or static-assets directory.
//
//go:embed web/pages.tmpl
var pageTemplates string
