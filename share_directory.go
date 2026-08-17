package main

import (
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

func shareDirectoryURL(token string, segments []string, directory bool) string {
	parts := []string{"", "_s", url.PathEscape(token), "_directory"}
	for _, segment := range segments {
		parts = append(parts, url.PathEscape(segment))
	}
	result := strings.Join(parts, "/")
	if directory && !strings.HasSuffix(result, "/") {
		result += "/"
	}
	return result
}

func shareDirectoryResourceURL(token, operation string, segments []string) string {
	parts := []string{"", "_s", url.PathEscape(token), operation}
	for _, segment := range segments {
		parts = append(parts, url.PathEscape(segment))
	}
	return strings.Join(parts, "/")
}

func (s *server) shareDirectoryRoute(w http.ResponseWriter, r *http.Request, share shareDefinition, token string, segments []string) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.NotFound(w, r)
		return
	}
	if len(segments) == 0 || segments[0] == "" {
		http.Redirect(w, r, shareDirectoryURL(token, nil, true), http.StatusSeeOther)
		return
	}
	relative := trimTrailingEmpty(segments[1:])
	for _, segment := range relative {
		if segment == "" || isPrivateName(segment) {
			http.NotFound(w, r)
			return
		}
	}
	root, rootInfo, err := resolveShareTarget(share.OwnerDir, share.Scope, share.Filename)
	if err != nil || !rootInfo.IsDir() || !s.directoryShareSafe(share.App, root, s.resolveDirectoryPolicy(share.App, ownerSegments(share.App, share.OwnerDir))) {
		http.NotFound(w, r)
		return
	}
	path, info, err := resolveSafePath(root, relative)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Cache-Control", "private, no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	switch segments[0] {
	case "_directory":
		if !info.IsDir() {
			http.NotFound(w, r)
			return
		}
		if !strings.HasSuffix(r.URL.EscapedPath(), "/") {
			http.Redirect(w, r, shareDirectoryURL(token, relative, true), http.StatusPermanentRedirect)
			return
		}
		s.shareDirectoryListing(w, r, token, path, relative, share.AllowDownload)
	case "_preview":
		if !info.Mode().IsRegular() {
			http.NotFound(w, r)
			return
		}
		kind, _ := previewFor(info.Name(), info)
		if kind == "none" {
			http.NotFound(w, r)
			return
		}
		if kind == "markdown" {
			s.serveMarkdown(w, r, share.App.Slug, append([]string{share.Filename}, relative...), path, info)
			return
		}
		if kind == "text" {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		}
		w.Header().Set("Content-Security-Policy", "sandbox; default-src 'none'; object-src 'none'; base-uri 'none'; frame-ancestors 'self'")
		s.serveFile(w, r, path, info, false)
	case "_download":
		if !info.Mode().IsRegular() || !share.AllowDownload {
			http.NotFound(w, r)
			return
		}
		s.serveDownload(w, r, path, info)
	case "_html":
		if !info.Mode().IsRegular() || !isHTMLName(info.Name()) {
			http.NotFound(w, r)
			return
		}
		s.shareDirectoryHTMLShell(w, r, token, relative, info, share.HTMLScriptsAllowed)
	case "_html-content":
		if !info.Mode().IsRegular() || !isHTMLName(info.Name()) {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Permissions-Policy", "accelerometer=(), camera=(), clipboard-read=(), clipboard-write=(), geolocation=(), microphone=(), payment=(), usb=()")
		csp := "sandbox; default-src 'none'; script-src 'none'; connect-src 'none'; img-src data: blob:; style-src 'unsafe-inline'; font-src 'none'; media-src 'none'; object-src 'none'; frame-src 'none'; form-action 'none'; base-uri 'none'; frame-ancestors 'self'"
		if share.HTMLScriptsAllowed {
			csp = "sandbox allow-scripts; default-src 'none'; script-src 'unsafe-inline'; connect-src 'none'; img-src data: blob:; style-src 'unsafe-inline'; font-src 'none'; media-src 'none'; object-src 'none'; frame-src 'none'; form-action 'none'; base-uri 'none'; frame-ancestors 'self'"
		}
		w.Header().Set("Content-Security-Policy", csp)
		s.serveHTMLContent(w, r, path, info)
	default:
		http.NotFound(w, r)
	}
}

func ownerSegments(app *application, owner string) []string {
	rel, err := filepath.Rel(app.Dir, owner)
	if err != nil || rel == "." {
		return nil
	}
	return strings.Split(rel, string(filepath.Separator))
}

func (s *server) shareDirectoryListing(w http.ResponseWriter, r *http.Request, token, dir string, relative []string, allowDownload bool) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	type entry struct{ name, href, download string }
	items := make([]entry, 0, len(entries))
	for _, item := range entries {
		if isPrivateName(item.Name()) || item.Type()&os.ModeSymlink != 0 {
			continue
		}
		info, err := item.Info()
		if err != nil || (!info.IsDir() && !info.Mode().IsRegular()) {
			continue
		}
		child := append(append([]string{}, relative...), item.Name())
		if info.IsDir() {
			items = append(items, entry{name: item.Name() + "/", href: shareDirectoryURL(token, child, true)})
			continue
		}
		kind, _ := previewFor(item.Name(), info)
		href := ""
		if isHTMLName(item.Name()) {
			href = shareDirectoryResourceURL(token, "_html", child)
		} else if kind != "none" {
			href = shareDirectoryResourceURL(token, "_preview", child)
		} else if allowDownload {
			href = shareDirectoryResourceURL(token, "_download", child)
		}
		download := ""
		if allowDownload && href != shareDirectoryResourceURL(token, "_download", child) {
			download = shareDirectoryResourceURL(token, "_download", child)
		}
		items = append(items, entry{name: item.Name(), href: href, download: download})
	}
	sort.Slice(items, func(i, j int) bool { return strings.ToLower(items[i].name) < strings.ToLower(items[j].name) })
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	setPageSecurityHeaders(w)
	if r.Method == http.MethodHead {
		return
	}
	_, _ = fmt.Fprint(w, "<!doctype html><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'><title>分享目录</title><h1>分享目录</h1><ul>")
	for _, item := range items {
		name := template.HTMLEscapeString(item.name)
		if item.href == "" {
			_, _ = fmt.Fprintf(w, "<li>%s</li>", name)
			continue
		}
		_, _ = fmt.Fprintf(w, "<li><a href='%s'>%s</a>", template.HTMLEscapeString(item.href), name)
		if item.download != "" {
			_, _ = fmt.Fprintf(w, " <a href='%s' download>下载</a>", template.HTMLEscapeString(item.download))
		}
		_, _ = fmt.Fprint(w, "</li>")
	}
	_, _ = fmt.Fprint(w, "</ul>")
}

func (s *server) shareDirectoryHTMLShell(w http.ResponseWriter, r *http.Request, token string, relative []string, info fs.FileInfo, scriptsAllowed bool) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; frame-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
	if r.Method == http.MethodHead {
		return
	}
	sandbox := ""
	if scriptsAllowed {
		sandbox = " allow-scripts"
	}
	content := shareDirectoryResourceURL(token, "_html-content", relative)
	preview := shareDirectoryResourceURL(token, "_preview", relative)
	_, _ = fmt.Fprintf(w, "<!doctype html><meta charset=utf-8><title>%s</title><p><a href='%s'>查看源码</a></p><iframe title='%s' sandbox='%s' src='%s' style='width:100%%;min-height:80vh;border:1px solid #bbb'></iframe>", template.HTMLEscapeString(info.Name()), template.HTMLEscapeString(preview), template.HTMLEscapeString(info.Name()), sandbox, template.HTMLEscapeString(content))
}
