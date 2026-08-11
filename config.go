package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
)

const (
	maxEnvSize       = 64 << 10
	argonMemory      = 32 * 1024
	argonIterations  = 3
	argonParallelism = 1
	argonSaltLength  = 16
	argonKeyLength   = 32
)

var kdfGate = make(chan struct{}, 1)

type appConfig struct {
	Name        string
	Description string
	Password    string
	Protected   bool
	Locked      bool
	Version     [32]byte
}

// globalConfig is loaded once during startup. Its password is deliberately
// kept separate from application configuration: it only protects applications
// that do not have their own .env password.
type globalConfig struct {
	SiteTitle   string
	Description string
	Password    string
	Version     [32]byte
}

type envDocument struct {
	lines    []string
	values   map[string]string
	keyCount map[string]int
}

func loadAppConfig(appDir, fallbackName string) (appConfig, error) {
	envPath := filepath.Join(appDir, ".env")
	info, err := os.Lstat(envPath)
	if errors.Is(err, os.ErrNotExist) {
		return appConfig{Name: fallbackName}, nil
	}
	if err != nil {
		return lockedConfig(fallbackName), fmt.Errorf("inspect .env: %w", err)
	}
	if !info.Mode().IsRegular() {
		return lockedConfig(fallbackName), errors.New(".env is not a regular file")
	}

	original, err := os.ReadFile(envPath)
	if err != nil {
		return lockedConfig(fallbackName), fmt.Errorf("read .env: %w", err)
	}
	doc, err := parseEnv(original)
	if err != nil {
		return lockedConfig(fallbackName), err
	}
	cfg, err := configFromDocument(doc, fallbackName, original)
	if err != nil {
		return lockedConfigWithMetadata(doc, fallbackName), err
	}

	if !strings.HasPrefix(cfg.Password, "hash:") {
		plain := strings.TrimPrefix(cfg.Password, "plain:")
		if err := validatePlainPassword(plain); err != nil {
			return lockedConfigWithMetadata(doc, fallbackName), err
		}
		hash, err := hashPassword(plain)
		if err != nil {
			return lockedConfigWithMetadata(doc, fallbackName), fmt.Errorf("hash password: %w", err)
		}
		updated, err := replaceEnvPassword(doc, hash)
		if err != nil {
			return lockedConfigWithMetadata(doc, fallbackName), err
		}
		if err := replaceFileIfUnchanged(envPath, original, updated, info.Mode().Perm()); err != nil {
			return lockedConfigWithMetadata(doc, fallbackName), fmt.Errorf("migrate password: %w", err)
		}

		reloaded, err := os.ReadFile(envPath)
		if err != nil {
			return lockedConfigWithMetadata(doc, fallbackName), fmt.Errorf("verify migrated config: %w", err)
		}
		reloadedDoc, err := parseEnv(reloaded)
		if err != nil {
			return lockedConfigWithMetadata(doc, fallbackName), fmt.Errorf("verify migrated config: %w", err)
		}
		cfg, err = configFromDocument(reloadedDoc, fallbackName, reloaded)
		if err != nil || cfg.Password != hash {
			return lockedConfigWithMetadata(doc, fallbackName), errors.New("migrated config verification failed")
		}
	}

	if _, err := decodePasswordHash(cfg.Password); err != nil {
		return lockedConfigWithMetadata(doc, fallbackName), err
	}
	cfg.Protected = true
	return cfg, nil
}

func lockedConfig(fallbackName string) appConfig {
	return appConfig{Name: fallbackName, Protected: true, Locked: true}
}

func lockedConfigWithMetadata(doc envDocument, fallbackName string) appConfig {
	cfg := lockedConfig(fallbackName)
	if doc.keyCount["NAME"] == 1 && doc.values["NAME"] != "" {
		cfg.Name = doc.values["NAME"]
	}
	if doc.keyCount["DESCRIPTION"] == 1 {
		cfg.Description = doc.values["DESCRIPTION"]
	}
	return cfg
}

func configFromDocument(doc envDocument, fallbackName string, raw []byte) (appConfig, error) {
	if doc.keyCount["PASSWORD"] != 1 {
		return appConfig{}, errors.New("PASSWORD must appear exactly once")
	}
	password := doc.values["PASSWORD"]
	if password == "" {
		return appConfig{}, errors.New("PASSWORD is empty")
	}
	if !strings.HasPrefix(password, "hash:") && !strings.HasPrefix(password, "plain:") && strings.Contains(password, ":") {
		return appConfig{}, errors.New("unknown PASSWORD format")
	}
	name := fallbackName
	if doc.keyCount["NAME"] == 1 && doc.values["NAME"] != "" {
		name = doc.values["NAME"]
	}
	description := ""
	if doc.keyCount["DESCRIPTION"] == 1 {
		description = doc.values["DESCRIPTION"]
	}
	return appConfig{
		Name:        name,
		Description: description,
		Password:    password,
		Protected:   true,
		Version:     sha256.Sum256(raw),
	}, nil
}

// loadRootConfig reads the sole global configuration location: <data-root>/.env.
// A missing file is a valid public default; every malformed existing file stops
// startup so a typo can never make protected data public.
func loadRootConfig(root, defaultTitle string) (globalConfig, error) {
	cfg := globalConfig{SiteTitle: defaultTitle}
	path := filepath.Join(root, ".env")
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return cfg, nil
	}
	if err != nil {
		return globalConfig{}, fmt.Errorf("inspect global configuration: %w", err)
	}
	if !info.Mode().IsRegular() {
		return globalConfig{}, errors.New("global configuration must be a regular file")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return globalConfig{}, fmt.Errorf("read global configuration: %w", err)
	}
	doc, err := parseEnv(raw)
	if err != nil {
		return globalConfig{}, err
	}
	cfg, err = rootConfigFromDocument(doc, defaultTitle)
	if err != nil {
		return globalConfig{}, err
	}
	if cfg.Password == "" || strings.HasPrefix(cfg.Password, "hash:") {
		return cfg, nil
	}
	plain := strings.TrimPrefix(cfg.Password, "plain:")
	if err := validatePlainPassword(plain); err != nil {
		return globalConfig{}, err
	}
	hash, err := hashPassword(plain)
	if err != nil {
		return globalConfig{}, fmt.Errorf("hash global password: %w", err)
	}
	passwordKey := "PASSWORD"
	if doc.keyCount["password"] == 1 {
		passwordKey = "password"
	}
	updated, err := replaceDocumentPassword(doc, passwordKey, hash)
	if err != nil {
		return globalConfig{}, err
	}
	if err := replaceFileIfUnchanged(path, raw, updated, info.Mode().Perm()); err != nil {
		return globalConfig{}, fmt.Errorf("migrate global password: %w", err)
	}
	reloaded, err := os.ReadFile(path)
	if err != nil {
		return globalConfig{}, fmt.Errorf("verify global configuration migration: %w", err)
	}
	reloadedDoc, err := parseEnv(reloaded)
	if err != nil {
		return globalConfig{}, fmt.Errorf("verify global configuration migration: %w", err)
	}
	cfg, err = rootConfigFromDocument(reloadedDoc, defaultTitle)
	if err != nil || cfg.Password != hash {
		return globalConfig{}, errors.New("global password migration verification failed")
	}
	return cfg, nil
}

func rootConfigFromDocument(doc envDocument, defaultTitle string) (globalConfig, error) {
	for _, key := range []string{"NAME", "DESCRIPTION", "PASSWORD", "title", "description", "password"} {
		if doc.keyCount[key] > 1 {
			return globalConfig{}, fmt.Errorf("%s must appear at most once", key)
		}
	}
	usesOld := doc.keyCount["NAME"]+doc.keyCount["DESCRIPTION"]+doc.keyCount["PASSWORD"] > 0
	usesNew := doc.keyCount["title"]+doc.keyCount["description"]+doc.keyCount["password"] > 0
	if usesOld && usesNew {
		return globalConfig{}, errors.New("legacy and lower-case root configuration cannot be mixed")
	}
	titleKey, descriptionKey, passwordKey := "NAME", "DESCRIPTION", "PASSWORD"
	if usesNew {
		titleKey, descriptionKey, passwordKey = "title", "description", "password"
	}
	cfg := globalConfig{SiteTitle: defaultTitle}
	if doc.keyCount[titleKey] == 1 && doc.values[titleKey] != "" {
		cfg.SiteTitle = doc.values[titleKey]
	}
	if doc.keyCount[descriptionKey] == 1 {
		cfg.Description = doc.values[descriptionKey]
	}
	if doc.keyCount[passwordKey] == 1 {
		cfg.Password = doc.values[passwordKey]
		if cfg.Password == "" {
			return globalConfig{}, errors.New("PASSWORD is empty")
		}
		if !strings.HasPrefix(cfg.Password, "hash:") && !strings.HasPrefix(cfg.Password, "plain:") && strings.Contains(cfg.Password, ":") {
			return globalConfig{}, errors.New("unknown PASSWORD format")
		}
		if _, err := decodePasswordHash(cfg.Password); err != nil && strings.HasPrefix(cfg.Password, "hash:") {
			return globalConfig{}, err
		}
		cfg.Version = sha256.Sum256([]byte(cfg.Password))
	}
	return cfg, nil
}

func parseEnv(raw []byte) (envDocument, error) {
	if len(raw) > maxEnvSize {
		return envDocument{}, errors.New(".env exceeds 64 KiB")
	}
	if !utf8.Valid(raw) || bytes.IndexByte(raw, 0) >= 0 {
		return envDocument{}, errors.New(".env must be valid UTF-8 without NUL")
	}
	doc := envDocument{values: make(map[string]string), keyCount: make(map[string]int)}
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	scanner.Buffer(make([]byte, 1024), 64*1024)
	for scanner.Scan() {
		line := scanner.Text()
		doc.lines = append(doc.lines, line)
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		key, valueText, ok := strings.Cut(trimmed, "=")
		if !ok {
			return doc, errors.New("invalid .env line")
		}
		key = strings.TrimSpace(key)
		if !isSupportedEnvKey(key) {
			return doc, fmt.Errorf("unknown .env key %q", key)
		}
		value, err := parseEnvValue(strings.TrimSpace(valueText))
		if err != nil {
			return doc, fmt.Errorf("invalid %s value: %w", key, err)
		}
		doc.keyCount[key]++
		doc.values[key] = value
	}
	if err := scanner.Err(); err != nil {
		return doc, err
	}
	return doc, nil
}

func isSupportedEnvKey(key string) bool {
	return key == "NAME" || key == "DESCRIPTION" || key == "PASSWORD" ||
		key == "title" || key == "description" || key == "password" || key == "html_scripts" ||
		key == "SHARE_ENABLED" || parseShareKey(key) != (shareKey{})
}

type shareKey struct {
	id    string
	field string
}

func parseShareKey(key string) shareKey {
	if !strings.HasPrefix(key, "SHARE_") || key == "SHARE_ENABLED" {
		return shareKey{}
	}
	for _, field := range []string{"ENABLED", "SCOPE", "PATH", "TOKEN", "EXPIRES_AT", "PASSWORD", "ALLOW_DOWNLOAD"} {
		suffix := "_" + field
		if !strings.HasSuffix(key, suffix) {
			continue
		}
		id := strings.TrimSuffix(strings.TrimPrefix(key, "SHARE_"), suffix)
		if validShareID(id) {
			return shareKey{id: id, field: field}
		}
	}
	return shareKey{}
}

func validShareID(value string) bool {
	if len(value) == 0 || len(value) > 32 || strings.HasPrefix(value, "_") || strings.HasSuffix(value, "_") {
		return false
	}
	for _, char := range value {
		if char != '_' && (char < 'A' || char > 'Z') && (char < '0' || char > '9') {
			return false
		}
	}
	return true
}

// loadShareStatuses validates the narrow, direct-parent SHARE_* model before
// publishing UI capabilities for an already authorized directory render. Any
// I/O, syntax or policy error returns the closed default; credentials and
// target configuration never escape this function except through a complete
// ShareURL for a currently available share.
func loadShareStatuses(dir string, now time.Time) map[string]shareStatus {
	closed := make(map[string]shareStatus)
	path := filepath.Join(dir, ".env")
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return closed
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return closed
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return closed
	}
	doc, err := parseEnv(raw)
	if err != nil || doc.keyCount["SHARE_ENABLED"] > 1 || doc.values["SHARE_ENABLED"] != "true" {
		return closed
	}
	type candidate struct {
		values map[string]string
		counts map[string]int
	}
	groups := make(map[string]*candidate)
	for key, value := range doc.values {
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
		group.counts[parsed.field] = doc.keyCount[key]
	}
	for _, group := range groups {
		for _, field := range []string{"ENABLED", "SCOPE", "PATH", "TOKEN", "EXPIRES_AT", "PASSWORD", "ALLOW_DOWNLOAD"} {
			if group.counts[field] != 1 {
				return closed
			}
		}
		if group.values["ENABLED"] != "true" || group.values["SCOPE"] != "file" || !validShareTargetName(group.values["PATH"]) {
			return closed
		}
		token, err := base64.RawURLEncoding.DecodeString(group.values["TOKEN"])
		if err != nil || len(token) != 32 || base64.RawURLEncoding.EncodeToString(token) != group.values["TOKEN"] {
			return closed
		}
		if _, err := decodePasswordHash(group.values["PASSWORD"]); err != nil {
			return closed
		}
		expiresAt, err := time.Parse(time.RFC3339, group.values["EXPIRES_AT"])
		if err != nil || expiresAt.After(now.Add(30*24*time.Hour)) || group.values["ALLOW_DOWNLOAD"] != "true" && group.values["ALLOW_DOWNLOAD"] != "false" {
			return closed
		}
		state := "available"
		if !expiresAt.After(now) {
			state = "expired"
		}
		status := shareStatus{
			State: "" + state, RequiresPassword: true, ExpiresAt: expiresAt.Format(time.RFC3339), CanDownload: group.values["ALLOW_DOWNLOAD"] == "true",
		}
		if state == "available" {
			status.ShareURL = "/_s/" + url.PathEscape(group.values["TOKEN"]) + "/"
		}
		closed[group.values["PATH"]] = status
	}
	return closed
}

func validShareTargetName(name string) bool {
	return name != "" && name != "." && name != ".." && !isPrivateName(name) && !strings.ContainsAny(name, "/\\\x00")
}

func parseEnvValue(text string) (string, error) {
	if text == "" {
		return "", nil
	}
	if text[0] == '\'' {
		if len(text) < 2 || text[len(text)-1] != '\'' {
			return "", errors.New("unterminated single quote")
		}
		return text[1 : len(text)-1], nil
	}
	if text[0] == '"' {
		value, err := strconv.Unquote(text)
		if err != nil {
			return "", err
		}
		return value, nil
	}
	if strings.ContainsAny(text, "\r\n") {
		return "", errors.New("newline is not allowed")
	}
	return strings.TrimSpace(strings.SplitN(text, " #", 2)[0]), nil
}

func validatePlainPassword(password string) error {
	if !utf8.ValidString(password) {
		return errors.New("password is not valid UTF-8")
	}
	count := utf8.RuneCountInString(password)
	if count < 6 || count > 20 {
		return errors.New("password must contain 6 to 20 Unicode characters")
	}
	if strings.ContainsAny(password, "\x00\r\n") {
		return errors.New("password contains a forbidden character")
	}
	return nil
}

func replaceEnvPassword(doc envDocument, hash string) ([]byte, error) {
	return replaceDocumentPassword(doc, "PASSWORD", hash)
}

func replaceDocumentPassword(doc envDocument, keyName, hash string) ([]byte, error) {
	replaced := false
	for i, line := range doc.lines {
		trimmed := strings.TrimSpace(line)
		key, _, ok := strings.Cut(trimmed, "=")
		if ok && strings.TrimSpace(key) == keyName {
			if replaced {
				return nil, fmt.Errorf("duplicate %s", keyName)
			}
			doc.lines[i] = keyName + "='" + hash + "'"
			replaced = true
		}
	}
	if !replaced {
		return nil, fmt.Errorf("%s is missing", keyName)
	}
	return []byte(strings.Join(doc.lines, "\n") + "\n"), nil
}

func replaceFileIfUnchanged(path string, original, updated []byte, mode os.FileMode) error {
	current, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if !bytes.Equal(current, original) {
		return errors.New("configuration changed during migration")
	}
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".datashelf-env-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(updated); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	current, err = os.ReadFile(path)
	if err != nil {
		return err
	}
	if !bytes.Equal(current, original) {
		return errors.New("configuration changed during migration")
	}
	return os.Rename(tmpName, path)
}

func hashPassword(password string) (string, error) {
	salt := make([]byte, argonSaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	kdfGate <- struct{}{}
	key := argon2.IDKey([]byte(password), salt, argonIterations, argonMemory, argonParallelism, argonKeyLength)
	<-kdfGate
	return fmt.Sprintf("hash:v1:argon2id:m=%d,t=%d,p=%d$%s$%s",
		argonMemory, argonIterations, argonParallelism,
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(key)), nil
}

type passwordHash struct {
	memory      uint32
	iterations  uint32
	parallelism uint8
	salt        []byte
	key         []byte
}

func decodePasswordHash(encoded string) (passwordHash, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 3 {
		return passwordHash{}, errors.New("invalid password hash")
	}
	var memory, iterations uint32
	var parallelism uint8
	if _, err := fmt.Sscanf(parts[0], "hash:v1:argon2id:m=%d,t=%d,p=%d", &memory, &iterations, &parallelism); err != nil {
		return passwordHash{}, errors.New("invalid password hash parameters")
	}
	canonicalParameters := fmt.Sprintf("hash:v1:argon2id:m=%d,t=%d,p=%d", memory, iterations, parallelism)
	if parts[0] != canonicalParameters {
		return passwordHash{}, errors.New("invalid password hash parameters")
	}
	if memory != argonMemory || iterations != argonIterations || parallelism != argonParallelism {
		return passwordHash{}, errors.New("unsupported password hash parameters")
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[1])
	if err != nil || len(salt) != argonSaltLength {
		return passwordHash{}, errors.New("invalid password hash salt")
	}
	key, err := base64.RawStdEncoding.DecodeString(parts[2])
	if err != nil || len(key) != argonKeyLength {
		return passwordHash{}, errors.New("invalid password hash value")
	}
	return passwordHash{memory, iterations, parallelism, salt, key}, nil
}

func verifyPassword(encoded, password string) bool {
	parsed, err := decodePasswordHash(encoded)
	if err != nil {
		return false
	}
	kdfGate <- struct{}{}
	actual := argon2.IDKey([]byte(password), parsed.salt, parsed.iterations, parsed.memory, parsed.parallelism, uint32(len(parsed.key)))
	<-kdfGate
	return subtle.ConstantTimeCompare(actual, parsed.key) == 1
}

type configState struct {
	mu     sync.RWMutex
	config appConfig
}
