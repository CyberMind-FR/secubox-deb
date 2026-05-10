// cmd/secubox/internal/package/scanner_test.go
package pkgscan

import (
	"os"
	"path/filepath"
	"testing"
)

func TestScanPackages(t *testing.T) {
	dir := t.TempDir()

	// Create package structure
	pkgDir := filepath.Join(dir, "secubox-test", "debian")
	if err := os.MkdirAll(pkgDir, 0755); err != nil {
		t.Fatal(err)
	}

	content := `
name: secubox-test
category: security
description:
  en: Test package
requirements:
  min_ram: 256M
  arch:
    - arm64
    - amd64
tags:
  - security
  - essential
services:
  - secubox-test.service
ports:
  - 8080/tcp
`
	if err := os.WriteFile(filepath.Join(pkgDir, "secubox.yaml"), []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	scanner := NewScanner(dir)
	components, err := scanner.Scan()
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}

	if len(components) != 1 {
		t.Fatalf("Scan() returned %d components, want 1", len(components))
	}

	c := components["secubox-test"]
	if c.Name != "secubox-test" {
		t.Errorf("Name = %q, want %q", c.Name, "secubox-test")
	}
	if c.Category != "security" {
		t.Errorf("Category = %q, want %q", c.Category, "security")
	}
}

func TestSupportsArch(t *testing.T) {
	c := &Component{
		Requirements: Requirements{
			Arch: []string{"arm64", "amd64"},
		},
	}

	if !c.SupportsArch("arm64") {
		t.Error("SupportsArch(arm64) = false, want true")
	}
	if c.SupportsArch("riscv64") {
		t.Error("SupportsArch(riscv64) = true, want false")
	}
}

func TestSupportsArchEmpty(t *testing.T) {
	// Empty arch list means all archs supported
	c := &Component{}
	if !c.SupportsArch("arm64") {
		t.Error("SupportsArch(arm64) with no restriction = false, want true")
	}
}

func TestScanPackagesIgnoresNonSecuboxDirs(t *testing.T) {
	dir := t.TempDir()

	// Create a non-secubox directory that should be ignored
	otherDir := filepath.Join(dir, "other-package", "debian")
	if err := os.MkdirAll(otherDir, 0755); err != nil {
		t.Fatal(err)
	}

	content := `name: other-package
category: misc
`
	if err := os.WriteFile(filepath.Join(otherDir, "secubox.yaml"), []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	scanner := NewScanner(dir)
	components, err := scanner.Scan()
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}

	if len(components) != 0 {
		t.Errorf("Scan() returned %d components for non-secubox dir, want 0", len(components))
	}
}

func TestScanPackagesSkipsMissingYaml(t *testing.T) {
	dir := t.TempDir()

	// Create secubox package dir without secubox.yaml
	pkgDir := filepath.Join(dir, "secubox-nofile", "debian")
	if err := os.MkdirAll(pkgDir, 0755); err != nil {
		t.Fatal(err)
	}

	scanner := NewScanner(dir)
	components, err := scanner.Scan()
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}

	if len(components) != 0 {
		t.Errorf("Scan() returned %d components for pkg without yaml, want 0", len(components))
	}
}

func TestGetComponent(t *testing.T) {
	dir := t.TempDir()

	// Create package structure
	pkgDir := filepath.Join(dir, "secubox-specific", "debian")
	if err := os.MkdirAll(pkgDir, 0755); err != nil {
		t.Fatal(err)
	}

	content := `
name: secubox-specific
category: network
description:
  en: Specific package for testing GetComponent
  fr: Paquet specifique pour tester GetComponent
requirements:
  min_ram: 512M
  arch:
    - arm64
tags:
  - network
`
	if err := os.WriteFile(filepath.Join(pkgDir, "secubox.yaml"), []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	scanner := NewScanner(dir)
	c, err := scanner.GetComponent("secubox-specific")
	if err != nil {
		t.Fatalf("GetComponent() error = %v", err)
	}

	if c.Name != "secubox-specific" {
		t.Errorf("Name = %q, want %q", c.Name, "secubox-specific")
	}
	if c.Category != "network" {
		t.Errorf("Category = %q, want %q", c.Category, "network")
	}
	if c.Description["fr"] != "Paquet specifique pour tester GetComponent" {
		t.Errorf("Description[fr] = %q, want French translation", c.Description["fr"])
	}
}

func TestGetComponentNotFound(t *testing.T) {
	dir := t.TempDir()

	scanner := NewScanner(dir)
	_, err := scanner.GetComponent("secubox-nonexistent")
	if err == nil {
		t.Error("GetComponent() for nonexistent package should return error")
	}
}
