package main

import (
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
	apps     map[string]*application
	sessions *sessionManager
	limiter  *loginLimiter
	logger   *log.Logger
	pages    *template.Template
}

func newServer(root, title string, logger *log.Logger) (*server, error) {
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
		root: absoluteRoot, title: title, apps: make(map[string]*application),
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
		if isPrivateName(entry.Name()) || entry.Type()&os.ModeSymlink != 0 || !entry.IsDir() {
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
	if len(segments) >= 2 && segments[0] == "a" && segments[1] != "" {
		s.serveApp(w, r, segments[1], segments[2:])
		return
	}
	http.NotFound(w, r)
}

func (s *server) home(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	type card struct {
		Slug, Name, Description string
		Protected, Locked       bool
		ModTime                 time.Time
	}
	cards := make([]card, 0, len(s.apps))
	for _, app := range s.apps {
		cfg := s.refreshConfig(app)
		cards = append(cards, card{app.Slug, cfg.Name, cfg.Description, cfg.Protected, cfg.Locked, app.ModTime})
	}
	if r.URL.Query().Get("sort") == "name" {
		sort.Slice(cards, func(i, j int) bool { return strings.ToLower(cards[i].Name) < strings.ToLower(cards[j].Name) })
	} else {
		sort.Slice(cards, func(i, j int) bool { return cards[i].ModTime.After(cards[j].ModTime) })
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if r.Method == http.MethodHead {
		return
	}
	if err := s.pages.ExecuteTemplate(w, "home", map[string]any{"PageTitle": s.title, "Title": s.title, "Apps": cards}); err != nil {
		s.logger.Printf("render home: %v", err)
	}
}

func (s *server) auth(w http.ResponseWriter, r *http.Request, slug string) {
	app, ok := s.apps[slug]
	if !ok {
		http.NotFound(w, r)
		return
	}
	cfg := s.refreshConfig(app)
	if !cfg.Protected {
		http.Redirect(w, r, "/a/"+url.PathEscape(slug)+"/", http.StatusSeeOther)
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
			Path: "/a/" + url.PathEscape(slug), HttpOnly: true, SameSite: http.SameSiteLaxMode,
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
	cfg := s.refreshConfig(app)
	if cfg.Protected {
		w.Header().Set("Cache-Control", "private, no-store")
		if cfg.Locked {
			http.Error(w, "管理员需修改本地配置", http.StatusLocked)
			return
		}
		cookie, err := r.Cookie(s.sessions.cookieName(slug))
		if err != nil || !s.sessions.valid(cookie.Value, slug, cfg.Version) {
			target := r.URL.EscapedPath()
			http.Redirect(w, r, "/_auth/"+url.PathEscape(slug)+"?return="+url.QueryEscape(target), http.StatusSeeOther)
			return
		}
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
		http.Error(w, "无法读取目录", http.StatusForbidden)
		return
	}
	type item struct {
		Name, URL, Kind, Size string
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
		kind, size := "文件", humanSize(info.Size())
		if info.IsDir() {
			kind, size = "目录", ""
		}
		items = append(items, item{entry.Name(), itemURL, kind, size})
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
		crumbs = append(crumbs, crumb{segment, appURL(app.Slug, segments[:i+1], true)})
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if r.Method == http.MethodHead {
		return
	}
	if err := s.pages.ExecuteTemplate(w, "directory", map[string]any{"PageTitle": cfg.Name, "Name": cfg.Name, "Items": items, "Crumbs": crumbs}); err != nil {
		s.logger.Printf("render directory: %v", err)
	}
}

func (s *server) serveFile(w http.ResponseWriter, r *http.Request, path string, info fs.FileInfo, rootIndex bool) {
	file, err := os.Open(path)
	if err != nil {
		http.Error(w, "无法读取文件", http.StatusForbidden)
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

func contentDisposition(path string, rootIndex bool) (string, bool) {
	ext := strings.ToLower(filepath.Ext(path))
	if rootIndex && ext == ".html" {
		return "text/html; charset=utf-8", false
	}
	switch ext {
	case ".html", ".htm", ".txt", ".md", ".markdown", ".csv", ".log", ".xml", ".json", ".yaml", ".yml", ".toml", ".ini", ".go", ".c", ".h", ".cs", ".ts", ".tsx", ".jsx", ".py", ".sh", ".sql":
		return "text/plain; charset=utf-8", false
	case ".js", ".mjs":
		return "text/javascript; charset=utf-8", false
	case ".css":
		return "text/css; charset=utf-8", false
	case ".svg":
		return "image/svg+xml", false
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
	parts := []string{"", "a", url.PathEscape(slug)}
	for _, segment := range segments {
		parts = append(parts, url.PathEscape(segment))
	}
	result := strings.Join(parts, "/")
	if directory && !strings.HasSuffix(result, "/") {
		result += "/"
	}
	return result
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

const pageTemplates = `{{define "base-head"}}<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><style>
body{margin:0;background:#f5f7fa;color:#182230;font:16px/1.5 system-ui,sans-serif}main{max-width:960px;margin:auto;padding:32px 20px}h1{margin:.2em 0}.toolbar,.crumbs{display:flex;gap:12px;flex-wrap:wrap;margin:16px 0}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:16px}.card,.panel{display:block;background:white;border:1px solid #dfe4ea;border-radius:12px;padding:18px;color:inherit;text-decoration:none}.muted{color:#65758b}.lock{font-size:.85rem}.error{color:#a12622}.items{list-style:none;padding:0}.items li{background:white;border-bottom:1px solid #e5e9ef}.items a{display:flex;justify-content:space-between;gap:12px;padding:13px;color:inherit;text-decoration:none}input,button{box-sizing:border-box;width:100%;padding:11px;margin-top:8px;font:inherit}button{cursor:pointer;background:#1769e0;color:white;border:0;border-radius:7px}@media(max-width:560px){main{padding:20px 14px}.grid{grid-template-columns:1fr}}
</style><title>{{.PageTitle}}</title></head><body><main>{{end}}
{{define "home"}}{{template "base-head" .}}<h1>{{.Title}}</h1><div class="toolbar"><a href="/?sort=modified">最近修改</a><a href="/?sort=name">按名称</a></div><div class="grid">{{range .Apps}}<a class="card" href="/a/{{pathEscape .Slug}}/"><strong>{{.Name}}</strong> <span class="lock">{{if .Locked}}⚠ 已锁定{{else if .Protected}}🔒{{else}}公开{{end}}</span><p>{{.Description}}</p><small class="muted">{{.ModTime.Format "2006-01-02 15:04"}}</small></a>{{else}}<p class="muted">尚无可用应用。</p>{{end}}</div></main></body></html>{{end}}
{{define "login"}}{{template "base-head" .}}<div class="panel"><h1>{{.Name}}</h1><p>请输入密码继续访问。</p>{{if .Message}}<p class="error" role="alert">{{.Message}}</p>{{end}}{{if not .Locked}}<form method="post" action="/_auth/{{pathEscape .Slug}}"><input type="hidden" name="return" value="{{.Return}}"><label for="password">密码</label><input id="password" name="password" type="password" autocomplete="current-password" required autofocus><button type="submit">进入</button></form>{{end}}</div></main></body></html>{{end}}
{{define "directory"}}{{template "base-head" .}}<nav class="crumbs" aria-label="路径">{{range .Crumbs}}<a href="{{.URL}}">{{.Name}}</a><span>/</span>{{end}}</nav><ul class="items">{{range .Items}}<li><a href="{{.URL}}"><span>{{.Name}}</span><span class="muted">{{.Kind}} {{.Size}}</span></a></li>{{else}}<li class="card muted">此目录为空。</li>{{end}}</ul></main></body></html>{{end}}`
