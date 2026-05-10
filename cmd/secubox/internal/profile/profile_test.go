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

func TestMergeProfiles(t *testing.T) {
	dir := t.TempDir()

	// Create base profile
	base := `
name: base
packages:
  required:
    - secubox-core
kernel:
  version: "6.6"
`
	basePath := filepath.Join(dir, "base.yaml")
	os.WriteFile(basePath, []byte(base), 0644)

	// Create child profile
	child := `
name: child
inherits: base
packages:
  required:
    - secubox-crowdsec
  excluded:
    - secubox-dpi
`
	childPath := filepath.Join(dir, "child.yaml")
	os.WriteFile(childPath, []byte(child), 0644)

	merger := NewMerger(dir)
	result, err := merger.Resolve("child")
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}

	// Should have both base and child packages
	if len(result.Packages.Required) != 2 {
		t.Errorf("Packages.Required = %v, want 2 items", result.Packages.Required)
	}

	// Should inherit kernel version
	if result.Kernel.Version != "6.6" {
		t.Errorf("Kernel.Version = %q, want %q", result.Kernel.Version, "6.6")
	}
}
