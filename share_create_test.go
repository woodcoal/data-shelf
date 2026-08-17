package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func postShareCreate(t *testing.T, s *server, target string, payload shareCreateRequest, cookie *http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodPost, target, bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	if cookie != nil {
		r.AddCookie(cookie)
	}
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	return w
}

func TestShareCreationRequiresAuthorizedProtectedDirectoryAndPreservesConfig(t *testing.T) {
	s, slug := makeTestServer(t, true)
	appDir := s.apps[slug].Dir
	if err := os.WriteFile(filepath.Join(appDir, "report.txt"), []byte("report"), 0o644); err != nil {
		t.Fatal(err)
	}
	endpoint := appResourceURL(slug, "_shares", nil)
	payload := shareCreateRequest{Scope: "file", Path: "report.txt", Password: "分享访问密码123", ExpiresAt: time.Now().Add(24 * time.Hour).Format(time.RFC3339), AllowDownload: false}
	if w := postShareCreate(t, s, endpoint, payload, nil); w.Code != http.StatusNotFound || strings.Contains(w.Body.String(), payload.Password) {
		t.Fatalf("unauthorized creation=%d %q", w.Code, w.Body.String())
	}
	cookie := login(t, s, slug)
	page := request(t, s, http.MethodGet, appURL(slug, nil, true), nil, cookie)
	if page.Code != http.StatusOK || !strings.Contains(page.Body.String(), `data-share-create-url="`+endpoint+`"`) {
		t.Fatalf("authorized page=%d %q", page.Code, page.Body.String())
	}
	w := postShareCreate(t, s, endpoint, payload, cookie)
	if w.Code != http.StatusCreated || w.Header().Get("Cache-Control") != "private, no-store" {
		t.Fatalf("creation=%d headers=%v body=%q", w.Code, w.Header(), w.Body.String())
	}
	var response map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil || !strings.HasPrefix(response["share_url"], "/_s/") {
		t.Fatalf("response=%q err=%v", w.Body.String(), err)
	}
	raw, err := os.ReadFile(filepath.Join(appDir, ".env"))
	if err != nil {
		t.Fatal(err)
	}
	stored := string(raw)
	for _, want := range []string{"NAME='受保护资料'", "PASSWORD='" + protectedHash(t) + "'", "SHARE_ENABLED='true'", "SCOPE='file'", "PATH='report.txt'", "PASSWORD='hash:"} {
		if !strings.Contains(stored, want) {
			t.Errorf("configuration missing %q: %q", want, stored)
		}
	}
	if strings.Contains(stored, payload.Password) || strings.Contains(w.Body.String(), payload.Password) {
		t.Error("share password leaked")
	}
}

func TestDirectoryShareRejectsNestedPasswordBoundaryAndServesOnlyItsTree(t *testing.T) {
	s, slug := makeTestServer(t, true)
	appDir := s.apps[slug].Dir
	folder := filepath.Join(appDir, "folder")
	if err := os.MkdirAll(filepath.Join(folder, "nested"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(folder, "readme.txt"), []byte("inside"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(folder, "nested", "private.txt"), []byte("nested"), 0o644); err != nil {
		t.Fatal(err)
	}
	cookie := login(t, s, slug)
	endpoint := appResourceURL(slug, "_shares", nil)
	blockedPassword, err := hashPassword("更严格目录密码123")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(folder, "nested", ".env"), []byte("password='"+blockedPassword+"'\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	blocked := shareCreateRequest{Scope: "directory", Path: "folder", Password: "分享访问密码123", ExpiresAt: time.Now().Add(24 * time.Hour).Format(time.RFC3339), AllowDownload: false}
	w := postShareCreate(t, s, endpoint, blocked, cookie)
	if w.Code != http.StatusConflict || strings.Contains(w.Body.String(), blocked.Password) || strings.Contains(w.Body.String(), blocked.Path) || strings.Contains(w.Body.String(), blockedPassword) {
		t.Fatalf("nested boundary creation=%d body=%q", w.Code, w.Body.String())
	}
	if err := os.Remove(filepath.Join(folder, "nested", ".env")); err != nil {
		t.Fatal(err)
	}
	w = postShareCreate(t, s, endpoint, blocked, cookie)
	if w.Code != http.StatusCreated {
		t.Fatalf("directory creation=%d body=%q", w.Code, w.Body.String())
	}
	var created map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	shareURL := created["share_url"]
	token := strings.TrimSuffix(strings.TrimPrefix(shareURL, "/_s/"), "/")
	gate := request(t, s, http.MethodGet, shareURL, nil)
	if gate.Code != http.StatusOK || strings.Contains(gate.Body.String(), "folder") || strings.Contains(gate.Body.String(), blocked.Password) {
		t.Fatalf("share gate=%d %q", gate.Code, gate.Body.String())
	}
	form := "password=" + url.QueryEscape(blocked.Password)
	auth := httptest.NewRequest(http.MethodPost, "/_s/"+token+"/_auth", strings.NewReader(form))
	auth.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	auth.RemoteAddr = "127.0.0.1:43210"
	authResult := httptest.NewRecorder()
	s.ServeHTTP(authResult, auth)
	if authResult.Code != http.StatusSeeOther || authResult.Header().Get("Location") != shareDirectoryURL(token, nil, true) {
		t.Fatalf("share auth=%d location=%q", authResult.Code, authResult.Header().Get("Location"))
	}
	shareCookie := authResult.Result().Cookies()[0]
	listing := request(t, s, http.MethodGet, shareDirectoryURL(token, nil, true), nil, shareCookie)
	if listing.Code != http.StatusOK || !strings.Contains(listing.Body.String(), "readme.txt") || strings.Contains(listing.Body.String(), "secret.txt") {
		t.Fatalf("directory listing=%d %q", listing.Code, listing.Body.String())
	}
	preview := request(t, s, http.MethodGet, shareDirectoryResourceURL(token, "_preview", []string{"readme.txt"}), nil, shareCookie)
	if preview.Code != http.StatusOK || !strings.Contains(preview.Body.String(), "inside") {
		t.Fatalf("directory preview=%d %q", preview.Code, preview.Body.String())
	}
	if w := request(t, s, http.MethodGet, shareDirectoryResourceURL(token, "_download", []string{"readme.txt"}), nil, shareCookie); w.Code != http.StatusNotFound {
		t.Fatalf("download-disabled directory share=%d", w.Code)
	}
	if w := request(t, s, http.MethodGet, "/_s/"+token+"/_preview/%252e%252e/secret.txt", nil, shareCookie); w.Code != http.StatusNotFound {
		t.Fatalf("escaped parent path=%d", w.Code)
	}
}

func TestAuthorizedShareManagementListsAndRevokesShareSessions(t *testing.T) {
	s, slug := makeTestServer(t, true)
	appDir := s.apps[slug].Dir
	if err := os.WriteFile(filepath.Join(appDir, "report.txt"), []byte("report"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(appDir, "folder"), 0o755); err != nil {
		t.Fatal(err)
	}
	endpoint := appResourceURL(slug, "_shares", nil)
	ownerCookie := login(t, s, slug)
	fileShare := shareCreateRequest{Scope: "file", Path: "report.txt", Password: "分享访问密码123", ExpiresAt: time.Now().Add(24 * time.Hour).Format(time.RFC3339), AllowDownload: false}
	directoryShare := shareCreateRequest{Scope: "directory", Path: "folder", Password: "目录分享密码123", ExpiresAt: time.Now().Add(24 * time.Hour).Format(time.RFC3339), AllowDownload: true}
	created := postShareCreate(t, s, endpoint, fileShare, ownerCookie)
	if created.Code != http.StatusCreated {
		t.Fatalf("file creation=%d body=%q", created.Code, created.Body.String())
	}
	var createdBody map[string]string
	if err := json.Unmarshal(created.Body.Bytes(), &createdBody); err != nil {
		t.Fatal(err)
	}
	if created := postShareCreate(t, s, endpoint, directoryShare, ownerCookie); created.Code != http.StatusCreated {
		t.Fatalf("directory creation=%d body=%q", created.Code, created.Body.String())
	}

	if unauthorized := request(t, s, http.MethodGet, endpoint, nil); unauthorized.Code != http.StatusNotFound || strings.Contains(unauthorized.Body.String(), "report.txt") || strings.Contains(unauthorized.Body.String(), createdBody["share_url"]) {
		t.Fatalf("unauthorized list=%d body=%q", unauthorized.Code, unauthorized.Body.String())
	}
	listed := request(t, s, http.MethodGet, endpoint, nil, ownerCookie)
	if listed.Code != http.StatusOK || listed.Header().Get("Cache-Control") != "private, no-store" {
		t.Fatalf("list=%d headers=%v body=%q", listed.Code, listed.Header(), listed.Body.String())
	}
	var response struct {
		Shares []shareManagementItem `json:"shares"`
	}
	if err := json.Unmarshal(listed.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if len(response.Shares) != 2 {
		t.Fatalf("shares=%#v", response.Shares)
	}
	var fileItem shareManagementItem
	for _, item := range response.Shares {
		if item.Path == "report.txt" {
			fileItem = item
		}
		if item.RequiresPassword != true || item.State != "available" || item.ID == "" || item.ShareURL == "" {
			t.Errorf("invalid management item=%#v", item)
		}
	}
	if fileItem.ID == "" || fileItem.ShareURL != createdBody["share_url"] || fileItem.CanDownload {
		t.Fatalf("file item=%#v created=%#v", fileItem, createdBody)
	}

	token := strings.TrimSuffix(strings.TrimPrefix(fileItem.ShareURL, "/_s/"), "/")
	auth := httptest.NewRequest(http.MethodPost, "/_s/"+token+"/_auth", strings.NewReader("password="+url.QueryEscape(fileShare.Password)))
	auth.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	auth.RemoteAddr = "127.0.0.1:43210"
	authResult := httptest.NewRecorder()
	s.ServeHTTP(authResult, auth)
	if authResult.Code != http.StatusSeeOther {
		t.Fatalf("share auth=%d body=%q", authResult.Code, authResult.Body.String())
	}
	shareCookie := authResult.Result().Cookies()[0]
	if open := request(t, s, http.MethodGet, fileItem.ShareURL, nil, shareCookie); open.Code != http.StatusSeeOther {
		t.Fatalf("share before delete=%d", open.Code)
	}

	deleted := request(t, s, http.MethodDelete, endpoint+"?id="+url.QueryEscape(fileItem.ID), nil, ownerCookie)
	if deleted.Code != http.StatusNoContent || deleted.Header().Get("Cache-Control") != "private, no-store" {
		t.Fatalf("delete=%d headers=%v body=%q", deleted.Code, deleted.Header(), deleted.Body.String())
	}
	if open := request(t, s, http.MethodGet, fileItem.ShareURL, nil, shareCookie); open.Code != http.StatusNotFound {
		t.Fatalf("deleted share session remained valid: status=%d", open.Code)
	}
	raw, err := os.ReadFile(filepath.Join(appDir, ".env"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), token) || !strings.Contains(string(raw), "PATH='folder'") {
		t.Fatalf("configuration after delete=%q", raw)
	}
}

func TestShareManagementRejectsUnknownOrUnauthorizedDelete(t *testing.T) {
	s, slug := makeTestServer(t, true)
	endpoint := appResourceURL(slug, "_shares", nil)
	if w := request(t, s, http.MethodDelete, endpoint+"?id=SAMPLE", nil); w.Code != http.StatusNotFound {
		t.Fatalf("unauthorized delete=%d", w.Code)
	}
	if w := request(t, s, http.MethodDelete, endpoint+"?id=bad", nil, login(t, s, slug)); w.Code != http.StatusNotFound {
		t.Fatalf("bad id delete=%d", w.Code)
	}
	if w := request(t, s, http.MethodDelete, endpoint+"?id=SAMPLE", nil, login(t, s, slug)); w.Code != http.StatusConflict || strings.Contains(w.Body.String(), "SAMPLE") {
		t.Fatalf("missing definition delete=%d body=%q", w.Code, w.Body.String())
	}
}

func TestShareManagementShowsInvalidDefinitionWithoutCapability(t *testing.T) {
	s, slug := makeTestServer(t, true)
	appDir := s.apps[slug].Dir
	env := "NAME='受保护资料'\nPASSWORD='" + protectedHash(t) + "'\nSHARE_ENABLED='true'\nSHARE_BROKEN_ENABLED='true'\nSHARE_BROKEN_SCOPE='file'\nSHARE_BROKEN_PATH='missing.txt'\n"
	if err := os.WriteFile(filepath.Join(appDir, ".env"), []byte(env), 0o600); err != nil {
		t.Fatal(err)
	}
	endpoint := appResourceURL(slug, "_shares", nil)
	listed := request(t, s, http.MethodGet, endpoint, nil, login(t, s, slug))
	if listed.Code != http.StatusOK {
		t.Fatalf("list invalid=%d body=%q", listed.Code, listed.Body.String())
	}
	var response struct {
		Shares []shareManagementItem `json:"shares"`
	}
	if err := json.Unmarshal(listed.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if len(response.Shares) != 1 || response.Shares[0].ID != "BROKEN" || response.Shares[0].State != "invalid" || response.Shares[0].ShareURL != "" || response.Shares[0].RequiresPassword {
		t.Fatalf("invalid response=%#v", response.Shares)
	}
}
