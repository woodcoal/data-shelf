package main

import (
	"crypto/rand"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

type shareCreateRequest struct {
	Scope         string `json:"scope"`
	Path          string `json:"path"`
	Password      string `json:"password"`
	ExpiresAt     string `json:"expires_at"`
	AllowDownload bool   `json:"allow_download"`
}

// shareManagementItem is returned only to the authenticated owner of the
// directory.  The ID is an opaque configuration selector, not a credential;
// no password or password hash is ever returned.
type shareManagementItem struct {
	ID               string `json:"id"`
	Scope            string `json:"scope"`
	Path             string `json:"path"`
	State            string `json:"state"`
	RequiresPassword bool   `json:"requires_password"`
	ExpiresAt        string `json:"expires_at"`
	CanDownload      bool   `json:"can_download"`
	ShareURL         string `json:"share_url,omitempty"`
}

// manageShares keeps all mutating share configuration behind the same
// directory-scoped application session as creation.  The list and delete
// response deliberately use 404 when unauthorized so no capability metadata
// is revealed to an unauthenticated caller.
func (s *server) manageShares(w http.ResponseWriter, r *http.Request, slug string, ownerSegments []string) {
	if r.Method == http.MethodPost {
		s.createShare(w, r, slug, ownerSegments)
		return
	}
	app, ok := s.app(slug)
	if !ok {
		http.NotFound(w, r)
		return
	}
	policy := s.resolveDirectoryPolicy(app, ownerSegments)
	if !s.authorizedForShareCreation(r, app, policy) {
		http.NotFound(w, r)
		return
	}
	owner, ownerInfo, err := resolveSafePath(app.Dir, ownerSegments)
	if err != nil || !ownerInfo.IsDir() {
		http.NotFound(w, r)
		return
	}
	switch r.Method {
	case http.MethodGet:
		if r.URL.RawQuery != "" {
			http.NotFound(w, r)
			return
		}
		items, err := s.listManagedShares(app, owner, policy, time.Now())
		if err != nil {
			shareManagementFailure(w, http.StatusConflict)
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Cache-Control", "private, no-store")
		_ = json.NewEncoder(w).Encode(map[string]any{"shares": items})
	case http.MethodDelete:
		ids, ok := r.URL.Query()["id"]
		if !ok || len(ids) != 1 || !validShareID(ids[0]) {
			http.NotFound(w, r)
			return
		}
		if err := removeShareDefinition(owner, ids[0]); err != nil {
			shareManagementFailure(w, http.StatusConflict)
			return
		}
		// Share discovery reads .env for every request.  Once this atomic rewrite
		// completes, findShare no longer returns this token, so all old share
		// cookies are rejected before their session value is considered.
		w.Header().Set("Cache-Control", "private, no-store")
		w.WriteHeader(http.StatusNoContent)
	default:
		http.NotFound(w, r)
	}
}

func shareManagementFailure(w http.ResponseWriter, status int) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": "无法管理分享"})
}

func (s *server) listManagedShares(app *application, owner string, policy directoryPolicy, now time.Time) ([]shareManagementItem, error) {
	env, err := readDirectoryEnv(owner, owner == app.Dir)
	if err != nil {
		return nil, err
	}
	if env.doc.keyCount["SHARE_ENABLED"] != 1 || env.doc.values["SHARE_ENABLED"] != "true" {
		return []shareManagementItem{}, nil
	}
	type candidate struct {
		values map[string]string
		counts map[string]int
	}
	groups := make(map[string]*candidate)
	for key, value := range env.doc.values {
		parsed := parseShareKey(key)
		if parsed == (shareKey{}) {
			continue
		}
		group := groups[parsed.id]
		if group == nil {
			group = &candidate{values: make(map[string]string), counts: make(map[string]int)}
			groups[parsed.id] = group
		}
		group.values[parsed.field] = value
		group.counts[parsed.field] = env.doc.keyCount[key]
	}
	items := make([]shareManagementItem, 0, len(groups))
	for id, group := range groups {
		item := shareManagementItem{ID: id, State: "invalid"}
		item.Scope, item.Path = group.values["SCOPE"], group.values["PATH"]
		item.ExpiresAt = group.values["EXPIRES_AT"]
		item.CanDownload = group.values["ALLOW_DOWNLOAD"] == "true"
		if group.counts["ENABLED"] == 1 && group.values["ENABLED"] == "false" {
			item.State = "disabled"
			items = append(items, item)
			continue
		}
		fields := []string{"ENABLED", "SCOPE", "PATH", "TOKEN", "EXPIRES_AT", "PASSWORD", "ALLOW_DOWNLOAD"}
		valid := true
		for _, field := range fields {
			valid = valid && group.counts[field] == 1
		}
		if !valid || group.values["ENABLED"] != "true" || !validShareTarget(item.Scope, item.Path) || (group.values["ALLOW_DOWNLOAD"] != "true" && group.values["ALLOW_DOWNLOAD"] != "false") {
			items = append(items, item)
			continue
		}
		token, tokenErr := base64.RawURLEncoding.DecodeString(group.values["TOKEN"])
		expires, expiresErr := time.Parse(time.RFC3339, item.ExpiresAt)
		_, passwordErr := normalizeSharePassword(group.values["PASSWORD"])
		target, targetInfo, targetErr := resolveShareTarget(owner, item.Scope, item.Path)
		if tokenErr != nil || len(token) != 32 || base64.RawURLEncoding.EncodeToString(token) != group.values["TOKEN"] || expiresErr != nil || expires.After(now.Add(30*24*time.Hour)) || passwordErr != nil || targetErr != nil || (item.Scope == "file" && !targetInfo.Mode().IsRegular()) || (item.Scope == "directory" && (!targetInfo.IsDir() || !s.directoryShareSafe(app, target, policy))) {
			items = append(items, item)
			continue
		}
		item.RequiresPassword = true
		item.ExpiresAt = expires.UTC().Format(time.RFC3339)
		if expires.After(now) {
			item.State = "available"
			item.ShareURL = "/_s/" + group.values["TOKEN"] + "/"
		} else {
			item.State = "expired"
		}
		items = append(items, item)
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].Path != items[j].Path {
			return items[i].Path < items[j].Path
		}
		return items[i].ID < items[j].ID
	})
	return items, nil
}

// createShare accepts only a server-bound owner directory.  It deliberately
// does not accept an application name, local path, existing share ID, or token
// from the browser.
func (s *server) createShare(w http.ResponseWriter, r *http.Request, slug string, ownerSegments []string) {
	if r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	app, ok := s.app(slug)
	if !ok {
		http.NotFound(w, r)
		return
	}
	policy := s.resolveDirectoryPolicy(app, ownerSegments)
	if !s.authorizedForShareCreation(r, app, policy) {
		http.NotFound(w, r)
		return
	}
	owner, ownerInfo, err := resolveSafePath(app.Dir, ownerSegments)
	if err != nil || !ownerInfo.IsDir() {
		http.NotFound(w, r)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 8<<10)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	var input shareCreateRequest
	if err := decoder.Decode(&input); err != nil {
		s.shareCreateFailure(w, http.StatusBadRequest, "分享参数无效")
		return
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		s.shareCreateFailure(w, http.StatusBadRequest, "分享参数无效")
		return
	}
	if passwordErr := validatePlainPassword(input.Password); passwordErr != nil {
		s.shareCreateFailure(w, http.StatusBadRequest, sharePasswordError(input.Password))
		return
	}
	if !validShareTarget(input.Scope, input.Path) {
		s.shareCreateFailure(w, http.StatusBadRequest, "分享目标无效")
		return
	}
	expires, err := time.Parse(time.RFC3339, input.ExpiresAt)
	if err != nil || !expires.After(time.Now()) || expires.After(time.Now().Add(30*24*time.Hour)) {
		s.shareCreateFailure(w, http.StatusBadRequest, "分享有效期无效")
		return
	}
	target, targetInfo, err := resolveShareTarget(owner, input.Scope, input.Path)
	if err != nil || (input.Scope == "file" && !targetInfo.Mode().IsRegular()) || (input.Scope == "directory" && !targetInfo.IsDir()) {
		s.shareCreateFailure(w, http.StatusBadRequest, "分享目标无效")
		return
	}
	if input.Scope == "directory" && !s.directoryShareSafe(app, target, policy) {
		s.shareCreateFailure(w, http.StatusConflict, "该目录包含独立的密码边界，不能创建目录分享")
		return
	}
	password, err := hashPassword(input.Password)
	if err != nil {
		s.shareCreateFailure(w, http.StatusInternalServerError, "无法创建分享")
		return
	}
	token, err := newShareToken()
	if err != nil {
		s.shareCreateFailure(w, http.StatusInternalServerError, "无法创建分享")
		return
	}
	definition := shareDefinition{Token: token, Password: password, Scope: input.Scope, Filename: input.Path, Expires: expires, AllowDownload: input.AllowDownload}
	if err := appendShareDefinition(owner, &definition); err != nil {
		s.shareCreateFailure(w, http.StatusConflict, "无法保存分享设置")
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "private, no-store")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]string{"share_url": "/_s/" + token + "/"})
}

// validShareTarget accepts a direct child name, or the explicit "." marker
// for the already server-bound owner directory.  The marker cannot select a
// file or any ancestor or sibling path.
func validShareTarget(scope, path string) bool {
	if scope != "file" && scope != "directory" {
		return false
	}
	return scope == "directory" && path == "." || validShareTargetName(path)
}

func resolveShareTarget(owner, scope, path string) (string, os.FileInfo, error) {
	if scope == "directory" && path == "." {
		return resolveSafePath(owner, nil)
	}
	return resolveSafePath(owner, []string{path})
}

func (s *server) authorizedForShareCreation(r *http.Request, app *application, policy directoryPolicy) bool {
	if !policy.Protected || policy.Locked {
		return false
	}
	cookie, err := r.Cookie(s.sessions.cookieName(app.Slug))
	return err == nil && s.sessions.valid(cookie.Value, app.Slug, policy.Version)
}

func (s *server) shareCreateFailure(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": message})
}

func sharePasswordError(password string) string {
	if !utf8.ValidString(password) {
		return "分享密码不是有效文本"
	}
	count := utf8.RuneCountInString(password)
	if count < 6 {
		return "分享密码至少需要 6 位"
	}
	if count > 20 {
		return "分享密码不能超过 20 位"
	}
	return "分享密码包含不允许的字符"
}

func newShareToken() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func newShareID(existing map[string]string) (string, error) {
	for range 8 {
		raw := make([]byte, 8)
		if _, err := rand.Read(raw); err != nil {
			return "", err
		}
		id := "S" + strings.TrimRight(base32.StdEncoding.EncodeToString(raw), "=")
		if _, exists := existing[id]; !exists {
			return id, nil
		}
	}
	return "", errors.New("share id collision")
}

// appendShareDefinition preserves every unrelated line and uses the same
// compare-before-rename strategy as password migration.  A missing local .env
// is created with O_EXCL so inherited protection can safely gain local shares.
func appendShareDefinition(dir string, definition *shareDefinition) error {
	path := filepath.Join(dir, ".env")
	for attempt := 0; attempt < 2; attempt++ {
		info, err := os.Lstat(path)
		if errors.Is(err, os.ErrNotExist) {
			id, idErr := newShareID(nil)
			if idErr != nil {
				return idErr
			}
			definition.ID = id
			file, createErr := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
			if errors.Is(createErr, os.ErrExist) {
				continue
			}
			if createErr != nil {
				return createErr
			}
			content := []byte("SHARE_ENABLED='true'\n" + shareDefinitionLines(*definition))
			_, writeErr := file.Write(content)
			if writeErr == nil {
				writeErr = file.Sync()
			}
			if closeErr := file.Close(); writeErr == nil {
				writeErr = closeErr
			}
			if writeErr != nil {
				_ = os.Remove(path)
			}
			return writeErr
		}
		if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("invalid share configuration file")
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		doc, err := parseEnv(raw)
		if err != nil || doc.keyCount["SHARE_ENABLED"] > 1 || (doc.keyCount["SHARE_ENABLED"] == 1 && doc.values["SHARE_ENABLED"] != "true") {
			return errors.New("share creation is disabled")
		}
		id, err := newShareID(func() map[string]string {
			existing := make(map[string]string)
			for key := range doc.values {
				if parsed := parseShareKey(key); parsed != (shareKey{}) {
					existing[parsed.id] = ""
				}
			}
			return existing
		}())
		if err != nil {
			return err
		}
		definition.ID = id
		separator := ""
		if len(raw) > 0 && raw[len(raw)-1] != '\n' {
			separator = "\n"
		}
		updated := append(append([]byte{}, raw...), []byte(separator+func() string {
			if doc.keyCount["SHARE_ENABLED"] == 0 {
				return "SHARE_ENABLED='true'\n"
			}
			return ""
		}()+shareDefinitionLines(*definition))...)
		if len(updated) > maxEnvSize {
			return errors.New("share configuration exceeds size limit")
		}
		return replaceFileIfUnchanged(path, raw, updated, info.Mode().Perm())
	}
	return errors.New("share configuration changed")
}

// removeShareDefinition deletes exactly one complete SHARE_<ID>_* group while
// preserving unrelated configuration and comments.  The compare-before-rename
// write means a concurrent configuration change cannot be silently lost.
func removeShareDefinition(dir, id string) error {
	path := filepath.Join(dir, ".env")
	for attempt := 0; attempt < 2; attempt++ {
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("invalid share configuration file")
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		doc, err := parseEnv(raw)
		if err != nil {
			return err
		}
		removed := false
		lines := make([]string, 0, len(doc.lines))
		for _, line := range doc.lines {
			key, _, ok := strings.Cut(strings.TrimSpace(line), "=")
			if ok && parseShareKey(strings.TrimSpace(key)).id == id {
				removed = true
				continue
			}
			lines = append(lines, line)
		}
		if !removed {
			return errors.New("share definition is missing")
		}
		updated := []byte(strings.Join(lines, "\n"))
		if len(updated) != 0 {
			updated = append(updated, '\n')
		}
		if err := replaceFileIfUnchanged(path, raw, updated, info.Mode().Perm()); err == nil {
			return nil
		} else if err.Error() != "configuration changed during migration" {
			return err
		}
	}
	return errors.New("share configuration changed")
}

func shareDefinitionLines(definition shareDefinition) string {
	prefix := "SHARE_" + definition.ID + "_"
	return prefix + "ENABLED='true'\n" +
		prefix + "SCOPE='" + definition.Scope + "'\n" +
		prefix + "PATH='" + definition.Filename + "'\n" +
		prefix + "TOKEN='" + definition.Token + "'\n" +
		prefix + "EXPIRES_AT='" + definition.Expires.UTC().Format(time.RFC3339) + "'\n" +
		prefix + "PASSWORD='" + definition.Password + "'\n" +
		prefix + "ALLOW_DOWNLOAD='" + strings.ToLower(strconv.FormatBool(definition.AllowDownload)) + "'\n"
}
