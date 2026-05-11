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
	if err := os.WriteFile(basePath, []byte(base), 0644); err != nil {
		t.Fatal(err)
	}

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
	if err := os.WriteFile(childPath, []byte(child), 0644); err != nil {
		t.Fatal(err)
	}

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

func TestCircularInheritance(t *testing.T) {
	dir := t.TempDir()

	a := `
name: a
inherits: b
packages:
  required:
    - pkg-a
`
	b := `
name: b
inherits: a
packages:
  required:
    - pkg-b
`
	if err := os.WriteFile(filepath.Join(dir, "a.yaml"), []byte(a), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "b.yaml"), []byte(b), 0644); err != nil {
		t.Fatal(err)
	}

	merger := NewMerger(dir)
	_, err := merger.Resolve("a")
	if err == nil {
		t.Error("expected error for circular inheritance, got nil")
	}
}

func TestMergeInheritedFields(t *testing.T) {
	dir := t.TempDir()

	// Create parent with various fields
	parent := `
name: parent
packages:
  required:
    - pkg-parent
  excluded:
    - pkg-excluded-parent
services:
  enable:
    - svc-parent
  disable:
    - svc-disable-parent
kernel:
  modules:
    enable:
      - mod-parent
constraints:
  min_ram: "512M"
  max_ram: "2G"
`
	if err := os.WriteFile(filepath.Join(dir, "parent.yaml"), []byte(parent), 0644); err != nil {
		t.Fatal(err)
	}

	// Create child that should inherit and extend
	child := `
name: child
inherits: parent
packages:
  required:
    - pkg-child
services:
  enable:
    - svc-child
kernel:
  modules:
    enable:
      - mod-child
constraints:
  min_ram: "1G"
`
	if err := os.WriteFile(filepath.Join(dir, "child.yaml"), []byte(child), 0644); err != nil {
		t.Fatal(err)
	}

	merger := NewMerger(dir)
	result, err := merger.Resolve("child")
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}

	// Check inherited Packages.Excluded
	if len(result.Packages.Excluded) != 1 || result.Packages.Excluded[0] != "pkg-excluded-parent" {
		t.Errorf("Packages.Excluded = %v, want [pkg-excluded-parent]", result.Packages.Excluded)
	}

	// Check inherited Services.Disable
	if len(result.Services.Disable) != 1 || result.Services.Disable[0] != "svc-disable-parent" {
		t.Errorf("Services.Disable = %v, want [svc-disable-parent]", result.Services.Disable)
	}

	// Check merged kernel modules
	if len(result.Kernel.Modules.Enable) != 2 {
		t.Errorf("Kernel.Modules.Enable = %v, want 2 items", result.Kernel.Modules.Enable)
	}

	// Check inherited Constraints.MaxRAM (parent only)
	if result.Constraints.MaxRAM != "2G" {
		t.Errorf("Constraints.MaxRAM = %q, want %q", result.Constraints.MaxRAM, "2G")
	}

	// Check overridden Constraints.MinRAM (child wins)
	if result.Constraints.MinRAM != "1G" {
		t.Errorf("Constraints.MinRAM = %q, want %q", result.Constraints.MinRAM, "1G")
	}
}

func TestLoadBoard(t *testing.T) {
	dir := t.TempDir()

	content := `
name: test-board
arch: arm64
tier: pro
soc: armada-7040

hardware:
  ram: 8G
  interfaces:
    wan: eth0
    lan:
      - eth1
      - eth2

boot:
  method: uboot
  kernel_image: Image
  dts: armada-7040-test
`
	boardDir := filepath.Join(dir, "test-board")
	if err := os.MkdirAll(boardDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(boardDir, "board.yaml"), []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	b, err := LoadBoard(boardDir)
	if err != nil {
		t.Fatalf("LoadBoard() error = %v", err)
	}

	if b.Name != "test-board" {
		t.Errorf("Name = %q, want %q", b.Name, "test-board")
	}
	if b.Arch != "arm64" {
		t.Errorf("Arch = %q, want %q", b.Arch, "arm64")
	}
	if b.Boot.Method != "uboot" {
		t.Errorf("Boot.Method = %q, want %q", b.Boot.Method, "uboot")
	}
}

func TestResolveWithArch(t *testing.T) {
	dir := t.TempDir()

	// Create base profile
	base := `
name: base
packages:
  required:
    - secubox-core
kernel:
  version: "6.6"
  modules:
    enable:
      - wireguard
sysctl:
  net.ipv4.ip_forward: 1
`
	if err := os.WriteFile(filepath.Join(dir, "base.yaml"), []byte(base), 0644); err != nil {
		t.Fatal(err)
	}

	// Create arch/arm64 profile
	archDir := filepath.Join(dir, "arch")
	if err := os.MkdirAll(archDir, 0755); err != nil {
		t.Fatal(err)
	}
	archProfile := `
name: arch-arm64
inherits: base
packages:
  required:
    - qemu-user-static
kernel:
  modules:
    enable:
      - cpufreq_dt
sysctl:
  vm.nr_hugepages: 64
`
	if err := os.WriteFile(filepath.Join(archDir, "arm64.yaml"), []byte(archProfile), 0644); err != nil {
		t.Fatal(err)
	}

	// Create tier profile
	tier := `
name: tier-pro
inherits: base
packages:
  required:
    - secubox-full
features:
  dpi: inline
`
	if err := os.WriteFile(filepath.Join(dir, "tier-pro.yaml"), []byte(tier), 0644); err != nil {
		t.Fatal(err)
	}

	merger := NewMerger(dir)
	result, err := merger.ResolveWithArch("tier-pro", "arm64")
	if err != nil {
		t.Fatalf("ResolveWithArch() error = %v", err)
	}

	// Should have base + arch + tier packages merged
	required := result.Packages.Required
	if !contains(required, "secubox-core") {
		t.Errorf("missing secubox-core from base")
	}
	if !contains(required, "qemu-user-static") {
		t.Errorf("missing qemu-user-static from arch/arm64")
	}
	if !contains(required, "secubox-full") {
		t.Errorf("missing secubox-full from tier-pro")
	}

	// Should have merged kernel modules
	modules := result.Kernel.Modules.Enable
	if !contains(modules, "wireguard") {
		t.Errorf("missing wireguard from base")
	}
	if !contains(modules, "cpufreq_dt") {
		t.Errorf("missing cpufreq_dt from arch/arm64")
	}

	// Should have merged sysctl (arch overrides base for same key)
	if result.Sysctl["net.ipv4.ip_forward"] != 1 {
		t.Errorf("sysctl net.ipv4.ip_forward = %v, want 1", result.Sysctl["net.ipv4.ip_forward"])
	}
	if result.Sysctl["vm.nr_hugepages"] != 64 {
		t.Errorf("sysctl vm.nr_hugepages = %v, want 64", result.Sysctl["vm.nr_hugepages"])
	}

	// Final name should be from tier
	if result.Name != "tier-pro" {
		t.Errorf("Name = %q, want tier-pro", result.Name)
	}
}

func TestResolveWithArch_NoArchProfile(t *testing.T) {
	dir := t.TempDir()

	// Create base profile
	base := `
name: base
packages:
  required:
    - secubox-core
`
	if err := os.WriteFile(filepath.Join(dir, "base.yaml"), []byte(base), 0644); err != nil {
		t.Fatal(err)
	}

	// Create tier profile (no arch/ directory)
	tier := `
name: tier-lite
inherits: base
packages:
  required:
    - secubox-crowdsec
`
	if err := os.WriteFile(filepath.Join(dir, "tier-lite.yaml"), []byte(tier), 0644); err != nil {
		t.Fatal(err)
	}

	merger := NewMerger(dir)
	result, err := merger.ResolveWithArch("tier-lite", "riscv64")
	if err != nil {
		t.Fatalf("ResolveWithArch() should succeed without arch profile, got error = %v", err)
	}

	// Should still merge base + tier
	if !contains(result.Packages.Required, "secubox-core") {
		t.Errorf("missing secubox-core from base")
	}
	if !contains(result.Packages.Required, "secubox-crowdsec") {
		t.Errorf("missing secubox-crowdsec from tier-lite")
	}
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func TestLoadTweaks(t *testing.T) {
	dir := t.TempDir()
	boardDir := filepath.Join(dir, "test-board")
	if err := os.MkdirAll(boardDir, 0755); err != nil {
		t.Fatal(err)
	}

	// Test missing tweaks.yaml returns empty Tweaks (valid)
	tw, err := LoadTweaks(boardDir)
	if err != nil {
		t.Fatalf("LoadTweaks() with missing file error = %v", err)
	}
	if tw == nil {
		t.Error("LoadTweaks() returned nil, want empty Tweaks")
	}

	// Test with actual tweaks.yaml
	content := `
kernel:
  modules:
    enable:
      - mvpp2
      - mvneta
    blacklist:
      - mv88e6xxx

sysctl:
  net.core.netdev_max_backlog: 5000

services:
  enable:
    - secubox-led
`
	if err := os.WriteFile(filepath.Join(boardDir, "tweaks.yaml"), []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	tw, err = LoadTweaks(boardDir)
	if err != nil {
		t.Fatalf("LoadTweaks() error = %v", err)
	}

	if len(tw.Kernel.Modules.Enable) != 2 {
		t.Errorf("Kernel.Modules.Enable = %v, want 2 items", tw.Kernel.Modules.Enable)
	}
	if len(tw.Kernel.Modules.Blacklist) != 1 {
		t.Errorf("Kernel.Modules.Blacklist = %v, want 1 item", tw.Kernel.Modules.Blacklist)
	}
	if len(tw.Services.Enable) != 1 || tw.Services.Enable[0] != "secubox-led" {
		t.Errorf("Services.Enable = %v, want [secubox-led]", tw.Services.Enable)
	}
}
