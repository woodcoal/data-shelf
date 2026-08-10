package main

import (
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
	return newServerWithConfig(root, title, globalConfig{DataDir: root, SiteTitle: title}, logger)
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
	if len(segments) == 2 && segments[0] == "_auth" && segments[1] != "" {
		s.auth(w, r, segments[1])
		return
	}
	if len(segments) >= 2 && segments[0] == "_preview" && segments[1] != "" {
		s.preview(w, r, segments[1], segments[2:])
		return
	}
	if len(segments) >= 2 && segments[0] == "a" && segments[1] != "" {
		s.redirectLegacyApp(w, r, segments[1], segments[2:])
		return
	}
	if len(segments) >= 1 && segments[0] != "" && !strings.HasPrefix(segments[0], "_") {
		s.serveApp(w, r, segments[0], segments[1:])
		return
	}
	http.NotFound(w, r)
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
		cfg := s.effectiveConfig(app)
		cards = append(cards, card{app.Slug, cfg.Name, cfg.Description, appURL(app.Slug, nil, true), cfg.Protected, cfg.Locked, app.ModTime})
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
		"PageTitle":  s.title,
		"Title":      s.title,
		"Apps":       cards,
		"SortByName": r.URL.Query().Get("sort") == "name",
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
		http.SetCookie(w, &http.Cookie{
			Name: s.sessions.cookieName(slug), Value: s.sessions.issue(slug, cfg.Version),
			Path: "/" + url.PathEscape(slug) + "/", HttpOnly: true, SameSite: http.SameSiteLaxMode,
			Secure: requestIsHTTPS(r),
		})
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
	cfg := s.effectiveConfig(app)
	if !s.authorizeApp(w, r, slug, cfg) {
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
	pathSegments := trimTrailingEmpty(segments)
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
				s.serveFile(w, r, indexPath, indexInfo, true)
				return
			}
		}
		s.serveDirectory(w, r, app, cfg, target, pathSegments)
		return
	}
	s.serveFile(w, r, target, info, false)
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
	cookie, err := r.Cookie(s.sessions.cookieName(slug))
	if err != nil || !s.sessions.valid(cookie.Value, slug, cfg.Version) {
		target := r.URL.EscapedPath()
		http.Redirect(w, r, "/_auth/"+url.PathEscape(slug)+"?return="+url.QueryEscape(target), http.StatusSeeOther)
		return false
	}
	return true
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
		Name, URL, Kind, Size, Modified   string
		PreviewKind, OpenMode, PreviewURL string
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
		if previewKind != "none" {
			previewResourceURL = previewURL(app.Slug, childSegments)
		} else {
			previewKind = ""
		}
		kind, size := "文件", humanSize(info.Size())
		if info.IsDir() {
			kind, size = "目录", ""
		}
		items = append(items, item{
			Name: entry.Name(), URL: itemURL, Kind: kind, Size: size,
			Modified:    info.ModTime().Format("2006-01-02 15:04"),
			PreviewKind: previewKind, OpenMode: openMode, PreviewURL: previewResourceURL,
		})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].Kind != items[j].Kind {
			return items[i].Kind == "目录"
		}
		return strings.ToLower(items[i].Name) < strings.ToLower(items[j].Name)
	})
	type crumb struct{ Name, URL string }
	crumbs := []crumb{{cfg.Name, appURL(app.Slug, nil, true)}}
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
	case ".txt", ".md", ".markdown", ".csv", ".log", ".json", ".xml", ".yaml", ".yml", ".toml", ".ini", ".html", ".htm", ".js", ".mjs", ".css", ".go", ".c", ".h", ".cs", ".ts", ".tsx", ".jsx", ".py", ".sh", ".sql":
		return "text"
	default:
		return ""
	}
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
	if kind == "none" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Security-Policy", "sandbox; default-src 'none'; object-src 'none'; base-uri 'none'; frame-ancestors 'self'")
	s.serveFile(w, r, target, info, false)
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
	case ".txt", ".md", ".markdown", ".csv", ".log", ".json", ".xml", ".yaml", ".yml", ".toml", ".ini", ".go", ".c", ".h", ".cs", ".ts", ".tsx", ".jsx", ".py", ".sh", ".sql", ".html", ".htm", ".js", ".mjs", ".css":
		if info.Size() <= 2<<20 {
			return "text", "modal"
		}
	}
	return "none", "external"
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
	parts := []string{"", "_preview", url.PathEscape(slug)}
	for _, segment := range segments {
		parts = append(parts, url.PathEscape(segment))
	}
	return strings.Join(parts, "/")
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
