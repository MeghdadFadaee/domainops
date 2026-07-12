package config

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestResolveOverrideAndEnsure(t *testing.T) {
	t.Setenv("HOME", "")
	root := filepath.Join(t.TempDir(), "state")
	p, err := Resolve(root)
	if err != nil {
		t.Fatal(err)
	}
	if p.Database != filepath.Join(root, "domainops.db") {
		t.Fatalf("unexpected database path: %s", p.Database)
	}
	if p.ConfigDir != filepath.Join(root, "config", "domainops") || p.CacheDir != filepath.Join(root, "cache", "domainops") {
		t.Fatalf("explicit data directory was not self-contained: config=%q cache=%q", p.ConfigDir, p.CacheDir)
	}
	if err := p.Ensure(); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(root)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o700 {
		t.Fatalf("data directory permissions = %o", info.Mode().Perm())
	}
	if _, err := os.Stat(p.ConfigDir); !os.IsNotExist(err) {
		t.Fatalf("unused config directory was created: %v", err)
	}
}

func TestResolveXDGDataWithoutHome(t *testing.T) {
	if runtime.GOOS == "darwin" {
		t.Skip("macOS uses its native Application Support default")
	}
	root := t.TempDir()
	t.Setenv("HOME", "")
	t.Setenv("XDG_DATA_HOME", root)
	p, err := Resolve("")
	if err != nil {
		t.Fatal(err)
	}
	if p.DataDir != filepath.Join(root, "domainops") {
		t.Fatalf("XDG data directory = %q", p.DataDir)
	}
}
