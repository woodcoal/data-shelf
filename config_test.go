package main

import (
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
