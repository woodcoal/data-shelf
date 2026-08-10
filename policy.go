package main

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// directoryPolicy is recomputed for each request.  It deliberately has no
// long-lived authorization cache: an atomic .env replacement or a password
// rotation must invalidate the next request, not an eventually-consistent
// watcher notification.
type directoryPolicy struct {
	Title, Description string
	Password           string
	Protected, Locked  bool
	Boundary           string
	Version            [32]byte
}

type directoryEnv struct {
	title, description, password          string
	hasTitle, hasDescription, hasPassword bool
	doc                                   envDocument
	raw                                   []byte
}

func readDirectoryEnv(dir string, legacyAllowed bool) (directoryEnv, error) {
	path := filepath.Join(dir, ".env")
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return directoryEnv{}, nil
	}
	if err != nil {
		return directoryEnv{}, fmt.Errorf("inspect .env: %w", err)
	}
	if !info.Mode().IsRegular() {
		return directoryEnv{}, errors.New(".env is not a regular file")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return directoryEnv{}, fmt.Errorf("read .env: %w", err)
	}
	doc, err := parseEnv(raw)
	if err != nil {
		return directoryEnv{}, err
	}
	for _, key := range []string{"title", "description", "password", "NAME", "DESCRIPTION", "PASSWORD"} {
		if doc.keyCount[key] > 1 {
			return directoryEnv{}, fmt.Errorf("%s must appear at most once", key)
		}
	}
	usesOld := doc.keyCount["NAME"]+doc.keyCount["DESCRIPTION"]+doc.keyCount["PASSWORD"] > 0
	usesNew := doc.keyCount["title"]+doc.keyCount["description"]+doc.keyCount["password"] > 0
	if usesOld && (!legacyAllowed || usesNew) {
		return directoryEnv{}, errors.New("legacy and lower-case configuration cannot be mixed")
	}
	e := directoryEnv{doc: doc, raw: raw}
	if usesOld {
		e.title, e.description, e.password = doc.values["NAME"], doc.values["DESCRIPTION"], doc.values["PASSWORD"]
		e.hasTitle, e.hasDescription, e.hasPassword = doc.keyCount["NAME"] == 1, doc.keyCount["DESCRIPTION"] == 1, doc.keyCount["PASSWORD"] == 1
	} else {
		e.title, e.description, e.password = doc.values["title"], doc.values["description"], doc.values["password"]
		e.hasTitle, e.hasDescription, e.hasPassword = doc.keyCount["title"] == 1, doc.keyCount["description"] == 1, doc.keyCount["password"] == 1
	}
	if e.hasTitle && len(e.title) > 8<<10 || e.hasDescription && len(e.description) > 4<<10 {
		return directoryEnv{}, errors.New("directory text exceeds limit")
	}
	if e.hasPassword {
		if e.password == "" {
			return directoryEnv{}, errors.New("password is empty")
		}
		if strings.HasPrefix(e.password, "plain:") {
			if err := validatePlainPassword(strings.TrimPrefix(e.password, "plain:")); err != nil {
				return directoryEnv{}, err
			}
			hash, err := hashPassword(strings.TrimPrefix(e.password, "plain:"))
			if err != nil {
				return directoryEnv{}, err
			}
			key := "password"
			if usesOld {
				key = "PASSWORD"
			}
			updated, err := replaceDocumentPassword(doc, key, hash)
			if err != nil {
				return directoryEnv{}, err
			}
			if err := replaceFileIfUnchanged(path, raw, updated, info.Mode().Perm()); err != nil {
				return directoryEnv{}, fmt.Errorf("migrate password: %w", err)
			}
			return readDirectoryEnv(dir, legacyAllowed)
		} else if !strings.HasPrefix(e.password, "hash:") {
			return directoryEnv{}, errors.New("unknown password format")
		} else if _, err := decodePasswordHash(e.password); err != nil {
			return directoryEnv{}, err
		}
	}
	return e, nil
}

func verifyConfiguredPassword(encoded, supplied string) bool {
	if strings.HasPrefix(encoded, "plain:") {
		return subtleCompare(strings.TrimPrefix(encoded, "plain:"), supplied)
	}
	return verifyPassword(encoded, supplied)
}

func subtleCompare(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	var different byte
	for i := range a {
		different |= a[i] ^ b[i]
	}
	return different == 0
}

// resolveDirectoryPolicy folds root -> application -> requested directory.
// Any malformed ancestor locks its entire subtree.  Presentation fields are
// intentionally local, while password inheritance follows the nearest valid
// password boundary.
func (s *server) resolveDirectoryPolicy(app *application, segments []string) directoryPolicy {
	p := directoryPolicy{}
	chain := sha256.New()
	dirs := []string{s.root, app.Dir}
	current := app.Dir
	for _, segment := range segments {
		if segment == "" || isPrivateName(segment) {
			p.Locked, p.Protected = true, true
			return p
		}
		current = filepath.Join(current, segment)
		dirs = append(dirs, current)
	}
	var display directoryEnv
	for i, dir := range dirs {
		entry, err := readDirectoryEnv(dir, i <= 1)
		if err != nil {
			p.Locked, p.Protected = true, true
			return p
		}
		chain.Write(entry.raw)
		chain.Write([]byte{0})
		if i == len(dirs)-1 {
			display = entry
		}
		if entry.hasPassword {
			p.Password, p.Protected = entry.password, true
			if i == 0 {
				p.Boundary = "."
			} else if i == 1 {
				p.Boundary = ""
			} else {
				p.Boundary = strings.Join(segments[:i-1], "/")
			}
		}
	}
	// Legacy startup configuration is still accepted for one migration release.
	// It behaves exactly like a root boundary when no lower-case root password
	// has already defined one.
	if !p.Protected && s.global.Password != "" {
		p.Password, p.Protected, p.Boundary = s.global.Password, true, "."
	}
	if display.hasTitle && display.title != "" {
		p.Title = display.title
	} else if len(segments) > 0 {
		p.Title = segments[len(segments)-1]
	} else {
		p.Title = app.Slug
	}
	if display.hasDescription {
		p.Description = display.description
	}
	p.Version = sha256.Sum256(append(chain.Sum(nil), []byte(p.Boundary+"\x00"+p.Password)...))
	return p
}

type shareDefinition struct {
	ID, Token, Password string
	App                 *application
	OwnerDir, Filename  string
	Expires             time.Time
	AllowDownload       bool
	Version             [32]byte
}

func sharesFromEnv(app *application, owner string, policy directoryPolicy) ([]shareDefinition, error) {
	e, err := readDirectoryEnv(owner, owner == app.Dir)
	if err != nil {
		return nil, err
	}
	groups := map[string]map[string]string{}
	counts := map[string]map[string]int{}
	for key, value := range e.doc.values {
		if !strings.HasPrefix(key, "SHARE_") {
			continue
		}
		rest := strings.TrimPrefix(key, "SHARE_")
		at := strings.Index(rest, "_")
		id, field := rest[:at], rest[at+1:]
		if groups[id] == nil {
			groups[id], counts[id] = map[string]string{}, map[string]int{}
		}
		groups[id][field], counts[id][field] = value, e.doc.keyCount[key]
	}
	var result []shareDefinition
	for id, values := range groups {
		fields := []string{"ENABLED", "SCOPE", "PATH", "TOKEN", "EXPIRES_AT", "PASSWORD", "ALLOW_DOWNLOAD"}
		for _, field := range fields {
			if counts[id][field] != 1 {
				return nil, errors.New("incomplete share definition")
			}
		}
		if values["ENABLED"] != "true" {
			if values["ENABLED"] == "false" {
				continue
			}
			return nil, errors.New("invalid share enabled")
		}
		if values["SCOPE"] != "file" || strings.Contains(values["PATH"], "/") || isPrivateName(values["PATH"]) {
			return nil, errors.New("invalid share scope or path")
		}
		token, err := base64.RawURLEncoding.DecodeString(values["TOKEN"])
		if err != nil || len(token) != 32 {
			return nil, errors.New("invalid share token")
		}
		expires, err := time.Parse(time.RFC3339, values["EXPIRES_AT"])
		if err != nil || expires.Sub(time.Now()) > 30*24*time.Hour {
			return nil, errors.New("invalid share expiry")
		}
		if err := validateSharePassword(values["PASSWORD"]); err != nil {
			return nil, err
		}
		allow := values["ALLOW_DOWNLOAD"] == "true"
		if !allow && values["ALLOW_DOWNLOAD"] != "false" {
			return nil, errors.New("invalid share download flag")
		}
		path, info, err := resolveSafePath(owner, []string{values["PATH"]})
		if err != nil || !info.Mode().IsRegular() {
			return nil, errors.New("invalid share target")
		}
		identity := fmt.Sprintf("%s\x00%d\x00%d\x00%x", path, info.Size(), info.ModTime().UnixNano(), policy.Version)
		result = append(result, shareDefinition{ID: id, Token: values["TOKEN"], Password: values["PASSWORD"], App: app, OwnerDir: owner, Filename: values["PATH"], Expires: expires, AllowDownload: allow, Version: sha256.Sum256([]byte(identity))})
	}
	return result, nil
}

func validateSharePassword(value string) error {
	if strings.HasPrefix(value, "plain:") {
		return validatePlainPassword(strings.TrimPrefix(value, "plain:"))
	}
	if !strings.HasPrefix(value, "hash:") {
		return errors.New("invalid share password")
	}
	_, err := decodePasswordHash(value)
	return err
}

func (s *server) findShare(token string) (shareDefinition, bool) {
	decoded, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || len(decoded) != 32 {
		return shareDefinition{}, false
	}
	for _, app := range s.apps {
		var found *shareDefinition
		_ = filepath.WalkDir(app.Dir, func(path string, entry fs.DirEntry, err error) error {
			if err != nil || found != nil {
				return filepath.SkipDir
			}
			if entry.Type()&os.ModeSymlink != 0 || isPrivateName(entry.Name()) {
				if entry.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
			if !entry.IsDir() {
				return nil
			}
			rel, err := filepath.Rel(app.Dir, path)
			if err != nil {
				return filepath.SkipDir
			}
			segments := []string{}
			if rel != "." {
				segments = strings.Split(rel, string(filepath.Separator))
			}
			policy := s.resolveDirectoryPolicy(app, segments)
			if policy.Locked {
				return filepath.SkipDir
			}
			shares, err := sharesFromEnv(app, path, policy)
			if err != nil {
				return filepath.SkipDir
			}
			for _, share := range shares {
				if subtleCompare(share.Token, token) {
					item := share
					found = &item
					return filepath.SkipDir
				}
			}
			return nil
		})
		if found != nil {
			return *found, true
		}
	}
	return shareDefinition{}, false
}
