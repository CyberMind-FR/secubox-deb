package profile

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadProfile(t *testing.T) {
	dir := t.TempDir()
	content := `
name: test-profile
description: Test profile
packages:
  required:
    - secubox-core
    - secubox-hub
`
	path := filepath.Join(dir, "test.yaml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	p, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if p.Name != "test-profile" {
		t.Errorf("Name = %q, want %q", p.Name, "test-profile")
	}

	if len(p.Packages.Required) != 2 {
		t.Errorf("Packages.Required = %d, want 2", len(p.Packages.Required))
	}
}
