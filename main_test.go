package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolveDataRootUsesStartupDirectoryAndExplicitOverride(t *testing.T) {
	startup := t.TempDir()
	explicit := filepath.Join(startup, "资料")
	if err := os.Mkdir(explicit, 0o755); err != nil {
		t.Fatal(err)
	}
	if got, err := resolveDataRoot(startup, ""); err != nil || got != startup {
		t.Fatalf("default root=%q err=%v", got, err)
	}
	if got, err := resolveDataRoot(startup, "资料"); err != nil || got != explicit {
		t.Fatalf("relative explicit root=%q err=%v", got, err)
	}
	if got, err := resolveDataRoot(startup, explicit); err != nil || got != explicit {
		t.Fatalf("absolute explicit root=%q err=%v", got, err)
	}
}

func TestRejectLegacyConfiguration(t *testing.T) {
	startup := t.TempDir()
	if err := os.WriteFile(filepath.Join(startup, "datashelf.env"), []byte("GLOBAL_PASSWORD='ignored'\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := rejectLegacyConfig(startup); err == nil {
		t.Fatal("legacy datashelf.env was accepted")
	}
}
