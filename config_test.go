package main

import (
	"crypto/sha256"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPlainPasswordMigratesAndVerifies(t *testing.T) {
	dir := t.TempDir()
	envPath := filepath.Join(dir, ".env")
	original := "NAME='资料'\nDESCRIPTION='说明'\nPASSWORD='plain:正确密码六位'\n"
	if err := os.WriteFile(envPath, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadAppConfig(dir, "fallback")
	if err != nil {
		t.Fatalf("loadAppConfig: %v", err)
	}
	if !cfg.Protected || cfg.Locked || !verifyPassword(cfg.Password, "正确密码六位") {
		t.Fatalf("unexpected migrated config: %+v", cfg)
	}
	updated, err := os.ReadFile(envPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(updated), "plain:") || !strings.Contains(string(updated), "hash:v1:argon2id:") {
		t.Fatalf("plaintext was not safely replaced: %s", updated)
	}
	if info, err := os.Stat(envPath); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("mode changed: info=%v err=%v", info, err)
	}
}

func TestRootAndChildConfigurationPasswordMatrix(t *testing.T) {
	root := t.TempDir()
	publicDir := filepath.Join(root, "公开")
	privateDir := filepath.Join(root, "私有")
	if err := os.MkdirAll(publicDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(privateDir, 0o755); err != nil {
		t.Fatal(err)
	}
	privateHash, err := hashPassword("私有密码六位")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(privateDir, ".env"), []byte("NAME='私有资料'\nPASSWORD='"+privateHash+"'\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	rootHash, err := hashPassword("根密码六位数")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".env"), []byte("NAME='资料架'\nPASSWORD='"+rootHash+"'\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	global, err := loadRootConfig(root, "DataShelf")
	if err != nil {
		t.Fatal(err)
	}
	if global.Version != sha256.Sum256([]byte(rootHash)) {
		t.Fatal("root password version was not derived from password only")
	}
	public, err := loadAppConfig(publicDir, "公开")
	if err != nil || public.Protected {
		t.Fatalf("public app=%+v err=%v", public, err)
	}
	private, err := loadAppConfig(privateDir, "私有")
	if err != nil || !private.Protected || !verifyPassword(private.Password, "私有密码六位") {
		t.Fatalf("private app=%+v err=%v", private, err)
	}
}

func TestRootConfigRejectsLinkedAndOversizedFiles(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target")
	if err := os.WriteFile(target, []byte("NAME='资料架'\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(root, ".env")); err != nil {
		t.Fatal(err)
	}
	if _, err := loadRootConfig(root, "DataShelf"); err == nil {
		t.Fatal("linked root .env was accepted")
	}
	if err := os.Remove(filepath.Join(root, ".env")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".env"), []byte(strings.Repeat("#", maxEnvSize+1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadRootConfig(root, "DataShelf"); err == nil {
		t.Fatal("oversized root .env was accepted")
	}
}

func TestInvalidConfigFailsClosedWithoutOverwrite(t *testing.T) {
	tests := []string{
		"NAME='x'\nPASSWORD='plain:短'\n",
		"NAME='x'\n",
		"PASSWORD=''\n",
		"PASSWORD='mystery:value'\n",
		"PASSWORD='plain:123456'\nPASSWORD='plain:654321'\n",
		"PASSWORD='hash:v1:argon2id:broken'\n",
	}
	for _, content := range tests {
		t.Run(strings.ReplaceAll(content, "\n", "_"), func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, ".env")
			if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			cfg, err := loadAppConfig(dir, "app")
			if err == nil || !cfg.Protected || !cfg.Locked {
				t.Fatalf("configuration did not fail closed: cfg=%+v err=%v", cfg, err)
			}
			after, readErr := os.ReadFile(path)
			if readErr != nil || string(after) != content {
				t.Fatalf("invalid config was overwritten: %q err=%v", after, readErr)
			}
		})
	}
}

func TestMissingEnvIsPublic(t *testing.T) {
	cfg, err := loadAppConfig(t.TempDir(), "public")
	if err != nil || cfg.Protected || cfg.Locked || cfg.Name != "public" {
		t.Fatalf("unexpected public config: %+v err=%v", cfg, err)
	}
}

func TestRootConfigLoadsAndMigratesPassword(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, ".env")
	original := "NAME='团队资料架'\nDESCRIPTION='资料说明'\nPASSWORD='plain:全局密码六位'\n"
	if err := os.WriteFile(configPath, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadRootConfig(dir, "fallback-title")
	if err != nil {
		t.Fatalf("loadRootConfig: %v", err)
	}
	if cfg.SiteTitle != "团队资料架" || cfg.Description != "资料说明" || !verifyPassword(cfg.Password, "全局密码六位") {
		t.Fatalf("unexpected global config: %+v", cfg)
	}
	updated, err := os.ReadFile(configPath)
	if err != nil || strings.Contains(string(updated), "plain:") || !strings.Contains(string(updated), "hash:v1:argon2id:") {
		t.Fatalf("global password was not migrated: %q err=%v", updated, err)
	}
}

func TestRootConfigFailureModesAndMissingDefault(t *testing.T) {
	dir := t.TempDir()
	cfg, err := loadRootConfig(dir, "default-title")
	if err != nil || cfg.SiteTitle != "default-title" || cfg.Password != "" {
		t.Fatalf("unexpected missing default config: %+v err=%v", cfg, err)
	}
	for _, content := range []string{
		"PASSWORD=''\n",
		"PASSWORD='plain:123456'\nPASSWORD='plain:654321'\n",
		"PASSWORD='mystery:value'\n",
		"UNSAFE_OPTION='x'\n",
	} {
		t.Run(strings.ReplaceAll(content, "\n", "_"), func(t *testing.T) {
			root := t.TempDir()
			path := filepath.Join(root, ".env")
			if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := loadRootConfig(root, "default-title"); err == nil {
				t.Fatalf("invalid global configuration was accepted: %q", content)
			}
		})
	}
}
