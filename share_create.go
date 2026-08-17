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
	"strconv"
	"strings"
	"time"
)

type shareCreateRequest struct {
	Scope         string `json:"scope"`
	Path          string `json:"path"`
	Password      string `json:"password"`
	ExpiresAt     string `json:"expires_at"`
	AllowDownload bool   `json:"allow_download"`
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
		s.shareCreateFailure(w, http.StatusBadRequest)
		return
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		s.shareCreateFailure(w, http.StatusBadRequest)
		return
	}
	if (input.Scope != "file" && input.Scope != "directory") || !validShareTargetName(input.Path) || validatePlainPassword(input.Password) != nil {
		s.shareCreateFailure(w, http.StatusBadRequest)
		return
	}
	expires, err := time.Parse(time.RFC3339, input.ExpiresAt)
	if err != nil || !expires.After(time.Now()) || expires.After(time.Now().Add(30*24*time.Hour)) {
		s.shareCreateFailure(w, http.StatusBadRequest)
		return
	}
	target, targetInfo, err := resolveSafePath(owner, []string{input.Path})
	if err != nil || (input.Scope == "file" && !targetInfo.Mode().IsRegular()) || (input.Scope == "directory" && !targetInfo.IsDir()) {
		s.shareCreateFailure(w, http.StatusBadRequest)
		return
	}
	if input.Scope == "directory" && !s.directoryShareSafe(app, target, policy) {
		s.shareCreateFailure(w, http.StatusConflict)
		return
	}
	password, err := hashPassword(input.Password)
	if err != nil {
		s.shareCreateFailure(w, http.StatusInternalServerError)
		return
	}
	token, err := newShareToken()
	if err != nil {
		s.shareCreateFailure(w, http.StatusInternalServerError)
		return
	}
	definition := shareDefinition{Token: token, Password: password, Scope: input.Scope, Filename: input.Path, Expires: expires, AllowDownload: input.AllowDownload}
	if err := appendShareDefinition(owner, &definition); err != nil {
		s.shareCreateFailure(w, http.StatusConflict)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "private, no-store")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]string{"share_url": "/_s/" + token + "/"})
}

func (s *server) authorizedForShareCreation(r *http.Request, app *application, policy directoryPolicy) bool {
	if !policy.Protected || policy.Locked {
		return false
	}
	cookie, err := r.Cookie(s.sessions.cookieName(app.Slug))
	return err == nil && s.sessions.valid(cookie.Value, app.Slug, policy.Version)
}

func (s *server) shareCreateFailure(w http.ResponseWriter, status int) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": "无法创建分享"})
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
