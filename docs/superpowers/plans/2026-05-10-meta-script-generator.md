<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Meta-Script Generator v2.0.0 Implementation Plan
1
> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a Go-based CLI tool (`secubox`) for profile-based image generation with OTA updates.

**Architecture:** Single Go binary with subcommands (gen, build, fetch, ota). Profiles defined in YAML with inheritance. Packages self-describe via debian/secubox.yaml. Build orchestrates debootstrap/partitioning via shell commands.

**Tech Stack:** Go 1.21+, cobra (CLI), viper (config), yaml.v3, promptui (wizard), goreleaser (releases)

---

## File Structure

```
cmd/secubox/
├── main.go                      # Entry point, root command
├── cmd/
│   ├── root.go                  # Root command setup, global flags
│   ├── gen.go                   # secubox gen command
│   ├── build.go                 # secubox build command
│   ├── fetch.go                 # secubox fetch command
│   ├── ota.go                   # secubox ota command
│   ├── info.go                  # secubox info command
│   └── config.go                # secubox config command
├── internal/
│   ├── profile/
│   │   ├── profile.go           # Profile struct and loader
│   │   ├── merger.go            # Profile inheritance resolver
│   │   └── profile_test.go      # Profile tests
│   ├── manifest/
│   │   ├── manifest.go          # Manifest struct and generator
│   │   ├── makefile.go          # Makefile generator
│   │   └── manifest_test.go     # Manifest tests
│   ├── package/
│   │   ├── scanner.go           # Scan debian/secubox.yaml files
│   │   ├── component.go         # Component struct
│   │   └── scanner_test.go      # Scanner tests
│   ├── hardware/
│   │   ├── detect.go            # Hardware detection (RAM, CPU, board)
│   │   └── detect_test.go       # Detection tests
│   ├── builder/
│   │   ├── builder.go           # Build orchestration
│   │   ├── stages.go            # Build stages (rootfs, partition, boot)
│   │   └── builder_test.go      # Builder tests
│   ├── ota/
│   │   ├── ota.go               # OTA logic
│   │   ├── partition.go         # A/B partition management
│   │   └── ota_test.go          # OTA tests
│   └── wizard/
│       ├── wizard.go            # Interactive wizard
│       └── wizard_test.go       # Wizard tests
├── go.mod
└── go.sum

profiles/
├── base.yaml
├── tier-lite.yaml
├── tier-standard.yaml
├── tier-pro.yaml
└── arch/
    ├── arm64.yaml
    └── amd64.yaml

board/mochabin/
├── board.yaml                   # NEW
└── tweaks.yaml                  # NEW

packages/secubox-core/debian/
└── secubox.yaml                 # NEW (example, replicated per package)
```

---

## Task 1: Initialize Go Module

**Files:**
- Create: `cmd/secubox/go.mod`
- Create: `cmd/secubox/main.go`
- Create: `cmd/secubox/cmd/root.go`

- [ ] **Step 1: Create Go module**

```bash
cd /home/reepost/CyberMindStudio/secubox-deb/secubox-deb
mkdir -p cmd/secubox
cd cmd/secubox
go mod init github.com/CyberMind-FR/secubox-deb/cmd/secubox
```

- [ ] **Step 2: Add dependencies**

```bash
go get github.com/spf13/cobra@v1.8.0
go get github.com/spf13/viper@v1.18.0
go get gopkg.in/yaml.v3@v3.0.1
go get github.com/manifoldco/promptui@v0.9.0
```

- [ ] **Step 3: Create main.go**

```go
// cmd/secubox/main.go
package main

import (
	"os"

	"github.com/CyberMind-FR/secubox-deb/cmd/secubox/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}
```

- [ ] **Step 4: Create root.go**

```go
// cmd/secubox/cmd/root.go
package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	cfgFile string
	verbose bool
	version = "2.8.0"
)

var rootCmd = &cobra.Command{
	Use:   "secubox",
	Short: "SecuBox Image Generator & Manager",
	Long: `SecuBox CLI tool for profile-based image generation,
building, fetching pre-built images, and OTA updates.

Version: ` + version,
}

func Execute() error {
	return rootCmd.Execute()
}

func init() {
	cobra.OnInitialize(initConfig)
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default: /etc/secubox/secubox.yaml)")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "verbose output")
}

func initConfig() {
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		viper.SetConfigName("secubox")
		viper.SetConfigType("yaml")
		viper.AddConfigPath("/etc/secubox")
		viper.AddConfigPath("$HOME/.secubox")
		viper.AddConfigPath(".")
	}
	viper.AutomaticEnv()
	if err := viper.ReadInConfig(); err == nil && verbose {
		fmt.Fprintln(os.Stderr, "Using config file:", viper.ConfigFileUsed())
	}
}
```

- [ ] **Step 5: Build and verify**

```bash
go build -o secubox .
./secubox --help
```

Expected output:
```
SecuBox CLI tool for profile-based image generation,
building, fetching pre-built images, and OTA updates.

Version: 2.8.0

Usage:
  secubox [command]

Flags:
      --config string   config file (default: /etc/secubox/secubox.yaml)
  -h, --help            help for secubox
  -v, --verbose         verbose output
```

- [ ] **Step 6: Commit**

```bash
git add cmd/secubox/
git commit -m "feat(secubox): initialize Go CLI with cobra

- Add go.mod with cobra, viper, yaml dependencies
- Create main.go entry point
- Create root command with version and config flags"
```

---

## Task 2: Profile Loader

**Files:**
- Create: `cmd/secubox/internal/profile/profile.go`
- Create: `cmd/secubox/internal/profile/profile_test.go`
- Create: `profiles/base.yaml`

- [ ] **Step 1: Write failing test for profile loading**

```go
// cmd/secubox/internal/profile/profile_test.go
package profile

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadProfile(t *testing.T) {
	// Create temp profile file
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
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd cmd/secubox
go test ./internal/profile/... -v
```

Expected: FAIL with "package profile is not in GOROOT"

- [ ] **Step 3: Write profile.go implementation**

```go
// cmd/secubox/internal/profile/profile.go
package profile

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Profile represents a SecuBox build profile
type Profile struct {
	Name        string      `yaml:"name"`
	Inherits    string      `yaml:"inherits,omitempty"`
	Description string      `yaml:"description"`
	Constraints Constraints `yaml:"constraints,omitempty"`
	Packages    Packages    `yaml:"packages,omitempty"`
	Kernel      Kernel      `yaml:"kernel,omitempty"`
	Services    Services    `yaml:"services,omitempty"`
	Sysctl      map[string]interface{} `yaml:"sysctl,omitempty"`
	Features    Features    `yaml:"features,omitempty"`
}

type Constraints struct {
	MinRAM string `yaml:"min_ram,omitempty"`
	MaxRAM string `yaml:"max_ram,omitempty"`
}

type Packages struct {
	Required []string `yaml:"required,omitempty"`
	Excluded []string `yaml:"excluded,omitempty"`
}

type Kernel struct {
	Version string        `yaml:"version,omitempty"`
	Modules KernelModules `yaml:"modules,omitempty"`
}

type KernelModules struct {
	Enable    []string `yaml:"enable,omitempty"`
	Blacklist []string `yaml:"blacklist,omitempty"`
}

type Services struct {
	Enable  []string `yaml:"enable,omitempty"`
	Disable []string `yaml:"disable,omitempty"`
}

type Features struct {
	DPI  interface{} `yaml:"dpi,omitempty"`  // bool or string (inline/mirror)
	LXC  bool        `yaml:"lxc,omitempty"`
	Swap string      `yaml:"swap,omitempty"`
}

// Load reads a profile from a YAML file
func Load(path string) (*Profile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read profile %s: %w", path, err)
	}

	var p Profile
	if err := yaml.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("parse profile %s: %w", path, err)
	}

	return &p, nil
}
```

- [ ] **Step 4: Run test to verify it passes**

```bash
go test ./internal/profile/... -v
```

Expected: PASS

- [ ] **Step 5: Create base.yaml profile**

```yaml
# profiles/base.yaml
version: "2.8.0"
name: base
description: Common SecuBox foundation

packages:
  required:
    - secubox-core
    - secubox-hub
    - secubox-portal
    - secubox-system
    - secubox-hardening

kernel:
  version: "6.6"
  modules:
    enable:
      - wireguard
      - nf_tables
      - nft_nat
      - nft_ct
      - nft_log
    blacklist: []

services:
  enable:
    - secubox-hub
    - nginx
    - nftables

sysctl:
  net.ipv4.ip_forward: 1
  net.ipv4.conf.all.rp_filter: 1
  kernel.randomize_va_space: 2
  kernel.kptr_restrict: 2
```

- [ ] **Step 6: Commit**

```bash
git add cmd/secubox/internal/profile/ profiles/base.yaml
git commit -m "feat(secubox): add profile loader with YAML parsing

- Define Profile struct with packages, kernel, services, features
- Implement Load() function for YAML files
- Add base.yaml with common SecuBox foundation
- Add unit tests for profile loading"
```

---

## Task 3: Profile Merger (Inheritance)

**Files:**
- Create: `cmd/secubox/internal/profile/merger.go`
- Modify: `cmd/secubox/internal/profile/profile_test.go`
- Create: `profiles/tier-lite.yaml`
- Create: `profiles/tier-pro.yaml`

- [ ] **Step 1: Write failing test for profile merging**

```go
// Add to cmd/secubox/internal/profile/profile_test.go

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
```

- [ ] **Step 2: Run test to verify it fails**

```bash
go test ./internal/profile/... -v -run TestMerge
```

Expected: FAIL with "undefined: NewMerger"

- [ ] **Step 3: Write merger.go implementation**

```go
// cmd/secubox/internal/profile/merger.go
package profile

import (
	"fmt"
	"path/filepath"
)

// Merger resolves profile inheritance
type Merger struct {
	profilesDir string
	cache       map[string]*Profile
}

// NewMerger creates a new profile merger
func NewMerger(profilesDir string) *Merger {
	return &Merger{
		profilesDir: profilesDir,
		cache:       make(map[string]*Profile),
	}
}

// Resolve loads a profile and merges all inherited profiles
func (m *Merger) Resolve(name string) (*Profile, error) {
	// Check cache
	if p, ok := m.cache[name]; ok {
		return p, nil
	}

	// Load profile
	path := filepath.Join(m.profilesDir, name+".yaml")
	p, err := Load(path)
	if err != nil {
		return nil, fmt.Errorf("load profile %s: %w", name, err)
	}

	// If no inheritance, return as-is
	if p.Inherits == "" {
		m.cache[name] = p
		return p, nil
	}

	// Resolve parent first
	parent, err := m.Resolve(p.Inherits)
	if err != nil {
		return nil, fmt.Errorf("resolve parent %s: %w", p.Inherits, err)
	}

	// Merge parent into child
	merged := m.merge(parent, p)
	m.cache[name] = merged
	return merged, nil
}

// merge combines parent and child profiles (child overrides parent)
func (m *Merger) merge(parent, child *Profile) *Profile {
	result := &Profile{
		Name:        child.Name,
		Description: child.Description,
	}

	// Merge packages (combine required, child excluded wins)
	result.Packages.Required = append([]string{}, parent.Packages.Required...)
	result.Packages.Required = append(result.Packages.Required, child.Packages.Required...)
	result.Packages.Required = unique(result.Packages.Required)
	result.Packages.Excluded = child.Packages.Excluded

	// Remove excluded packages from required
	result.Packages.Required = subtract(result.Packages.Required, result.Packages.Excluded)

	// Kernel: child overrides or inherits
	result.Kernel = parent.Kernel
	if child.Kernel.Version != "" {
		result.Kernel.Version = child.Kernel.Version
	}
	if len(child.Kernel.Modules.Enable) > 0 {
		result.Kernel.Modules.Enable = append(result.Kernel.Modules.Enable, child.Kernel.Modules.Enable...)
	}
	if len(child.Kernel.Modules.Blacklist) > 0 {
		result.Kernel.Modules.Blacklist = child.Kernel.Modules.Blacklist
	}

	// Services: merge
	result.Services.Enable = append(parent.Services.Enable, child.Services.Enable...)
	result.Services.Enable = unique(result.Services.Enable)
	result.Services.Disable = child.Services.Disable

	// Sysctl: merge maps
	result.Sysctl = make(map[string]interface{})
	for k, v := range parent.Sysctl {
		result.Sysctl[k] = v
	}
	for k, v := range child.Sysctl {
		result.Sysctl[k] = v
	}

	// Features: child overrides
	result.Features = parent.Features
	if child.Features.DPI != nil {
		result.Features.DPI = child.Features.DPI
	}
	if child.Features.Swap != "" {
		result.Features.Swap = child.Features.Swap
	}
	// LXC: explicit check since false is valid
	result.Features.LXC = child.Features.LXC || parent.Features.LXC

	// Constraints: child overrides
	result.Constraints = child.Constraints
	if result.Constraints.MinRAM == "" {
		result.Constraints.MinRAM = parent.Constraints.MinRAM
	}

	return result
}

// unique removes duplicates from a slice
func unique(s []string) []string {
	seen := make(map[string]bool)
	result := []string{}
	for _, v := range s {
		if !seen[v] {
			seen[v] = true
			result = append(result, v)
		}
	}
	return result
}

// subtract removes items in b from a
func subtract(a, b []string) []string {
	exclude := make(map[string]bool)
	for _, v := range b {
		exclude[v] = true
	}
	result := []string{}
	for _, v := range a {
		if !exclude[v] {
			result = append(result, v)
		}
	}
	return result
}
```

- [ ] **Step 4: Run test to verify it passes**

```bash
go test ./internal/profile/... -v
```

Expected: PASS

- [ ] **Step 5: Create tier profiles**

```yaml
# profiles/tier-lite.yaml
name: tier-lite
inherits: base
description: For 1-2GB RAM devices (ESPRESSObin)

constraints:
  min_ram: 1G
  max_ram: 2G

packages:
  required:
    - secubox-crowdsec
    - secubox-wireguard
    - secubox-netmodes
    - secubox-nac
  excluded:
    - secubox-dpi
    - secubox-ollama
    - secubox-jellyfin
    - secubox-matrix
    - secubox-nextcloud
    - secubox-gitea

features:
  dpi: false
  lxc: false
  swap: 512M
```

```yaml
# profiles/tier-standard.yaml
name: tier-standard
inherits: base
description: For 4GB RAM devices

constraints:
  min_ram: 4G
  max_ram: 8G

packages:
  required:
    - secubox-crowdsec
    - secubox-wireguard
    - secubox-netmodes
    - secubox-nac
    - secubox-dpi
    - secubox-qos
    - secubox-waf
    - secubox-haproxy
    - secubox-vhost

features:
  dpi: mirror
  lxc: true
  swap: 0
```

```yaml
# profiles/tier-pro.yaml
name: tier-pro
inherits: base
description: For 8GB+ RAM devices (MOCHAbin)

constraints:
  min_ram: 8G

packages:
  required:
    - secubox-full

features:
  dpi: inline
  lxc: true
  swap: 0
```

- [ ] **Step 6: Commit**

```bash
git add cmd/secubox/internal/profile/merger.go profiles/tier-*.yaml
git commit -m "feat(secubox): add profile inheritance merger

- Implement Merger with Resolve() for inheritance chain
- Merge packages, kernel, services, sysctl, features
- Add tier-lite, tier-standard, tier-pro profiles
- Handle excluded packages removal"
```

---

## Task 4: Board Configuration

**Files:**
- Create: `cmd/secubox/internal/profile/board.go`
- Create: `board/mochabin/board.yaml`
- Create: `board/mochabin/tweaks.yaml`

- [ ] **Step 1: Write failing test for board loading**

```go
// Add to cmd/secubox/internal/profile/profile_test.go

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
	os.MkdirAll(boardDir, 0755)
	os.WriteFile(filepath.Join(boardDir, "board.yaml"), []byte(content), 0644)

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
```

- [ ] **Step 2: Run test to verify it fails**

```bash
go test ./internal/profile/... -v -run TestLoadBoard
```

Expected: FAIL with "undefined: LoadBoard"

- [ ] **Step 3: Write board.go implementation**

```go
// cmd/secubox/internal/profile/board.go
package profile

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// Board represents a target hardware board
type Board struct {
	Name     string   `yaml:"name"`
	Arch     string   `yaml:"arch"`
	Tier     string   `yaml:"tier"`
	SOC      string   `yaml:"soc"`
	Hardware Hardware `yaml:"hardware"`
	Boot     Boot     `yaml:"boot"`
}

type Hardware struct {
	RAM        string     `yaml:"ram"`
	EMMC       string     `yaml:"emmc,omitempty"`
	Interfaces Interfaces `yaml:"interfaces"`
}

type Interfaces struct {
	WAN string   `yaml:"wan"`
	LAN []string `yaml:"lan"`
	SFP []string `yaml:"sfp,omitempty"`
}

type Boot struct {
	Method      string `yaml:"method"` // uboot, grub, rpi
	KernelImage string `yaml:"kernel_image"`
	DTS         string `yaml:"dts,omitempty"`
}

// Tweaks represents board-specific overrides
type Tweaks struct {
	Kernel   Kernel                 `yaml:"kernel,omitempty"`
	Sysctl   map[string]interface{} `yaml:"sysctl,omitempty"`
	Services Services               `yaml:"services,omitempty"`
}

// LoadBoard reads board configuration from a directory
func LoadBoard(boardDir string) (*Board, error) {
	path := filepath.Join(boardDir, "board.yaml")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read board.yaml: %w", err)
	}

	var b Board
	if err := yaml.Unmarshal(data, &b); err != nil {
		return nil, fmt.Errorf("parse board.yaml: %w", err)
	}

	return &b, nil
}

// LoadTweaks reads board-specific tweaks
func LoadTweaks(boardDir string) (*Tweaks, error) {
	path := filepath.Join(boardDir, "tweaks.yaml")
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &Tweaks{}, nil // No tweaks is valid
		}
		return nil, fmt.Errorf("read tweaks.yaml: %w", err)
	}

	var t Tweaks
	if err := yaml.Unmarshal(data, &t); err != nil {
		return nil, fmt.Errorf("parse tweaks.yaml: %w", err)
	}

	return &t, nil
}
```

- [ ] **Step 4: Run test to verify it passes**

```bash
go test ./internal/profile/... -v -run TestLoadBoard
```

Expected: PASS

- [ ] **Step 5: Create MOCHAbin board files**

```yaml
# board/mochabin/board.yaml
name: mochabin
arch: arm64
tier: pro
soc: armada-7040

hardware:
  ram: 4G-8G
  emmc: 8G
  interfaces:
    wan: eth0
    lan:
      - eth1
      - eth2
      - eth3
      - eth4
    sfp:
      - eth5
      - eth6

boot:
  method: uboot
  kernel_image: Image
  dts: armada-7040-mochabin
```

```yaml
# board/mochabin/tweaks.yaml
kernel:
  modules:
    enable:
      - mvpp2
      - mvneta
      - armada_thermal
    blacklist:
      - mv88e6xxx

sysctl:
  net.core.netdev_max_backlog: 5000
  net.core.rmem_max: 16777216
  net.core.wmem_max: 16777216

services:
  enable:
    - secubox-led
```

- [ ] **Step 6: Commit**

```bash
git add cmd/secubox/internal/profile/board.go board/mochabin/board.yaml board/mochabin/tweaks.yaml
git commit -m "feat(secubox): add board configuration loader

- Define Board struct with hardware, boot, interfaces
- Define Tweaks struct for board-specific overrides
- Add MOCHAbin board.yaml and tweaks.yaml
- Support missing tweaks.yaml (optional)"
```

---

## Task 5: Package Scanner

**Files:**
- Create: `cmd/secubox/internal/package/component.go`
- Create: `cmd/secubox/internal/package/scanner.go`
- Create: `cmd/secubox/internal/package/scanner_test.go`
- Create: `packages/secubox-core/debian/secubox.yaml`

- [ ] **Step 1: Write failing test for package scanning**

```go
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
	os.MkdirAll(pkgDir, 0755)

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
	os.WriteFile(filepath.Join(pkgDir, "secubox.yaml"), []byte(content), 0644)

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
```

- [ ] **Step 2: Run test to verify it fails**

```bash
go test ./internal/package/... -v
```

Expected: FAIL with "package pkgscan is not in GOROOT"

- [ ] **Step 3: Write component.go**

```go
// cmd/secubox/internal/package/component.go
package pkgscan

// Component represents a SecuBox package's metadata
type Component struct {
	Name         string            `yaml:"name"`
	Category     string            `yaml:"category"`
	Description  map[string]string `yaml:"description"`
	Requirements Requirements      `yaml:"requirements"`
	Tags         []string          `yaml:"tags"`
	Conflicts    []string          `yaml:"conflicts,omitempty"`
	Services     []string          `yaml:"services,omitempty"`
	Ports        []string          `yaml:"ports,omitempty"`
	Modes        map[string]Mode   `yaml:"modes,omitempty"`
}

type Requirements struct {
	MinRAM        string   `yaml:"min_ram,omitempty"`
	Arch          []string `yaml:"arch,omitempty"`
	Features      []string `yaml:"features,omitempty"`
	KernelModules []string `yaml:"kernel_modules,omitempty"`
}

type Mode struct {
	MinRAM      string `yaml:"min_ram,omitempty"`
	Description string `yaml:"description,omitempty"`
}

// SupportsArch checks if the component supports the given architecture
func (c *Component) SupportsArch(arch string) bool {
	if len(c.Requirements.Arch) == 0 {
		return true // No restriction means all archs
	}
	for _, a := range c.Requirements.Arch {
		if a == arch {
			return true
		}
	}
	return false
}
```

- [ ] **Step 4: Write scanner.go**

```go
// cmd/secubox/internal/package/scanner.go
package pkgscan

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// Scanner scans packages directory for secubox.yaml files
type Scanner struct {
	packagesDir string
}

// NewScanner creates a new package scanner
func NewScanner(packagesDir string) *Scanner {
	return &Scanner{packagesDir: packagesDir}
}

// Scan reads all debian/secubox.yaml files and returns components
func (s *Scanner) Scan() (map[string]*Component, error) {
	components := make(map[string]*Component)

	entries, err := os.ReadDir(s.packagesDir)
	if err != nil {
		return nil, fmt.Errorf("read packages dir: %w", err)
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		if !strings.HasPrefix(entry.Name(), "secubox-") {
			continue
		}

		metaPath := filepath.Join(s.packagesDir, entry.Name(), "debian", "secubox.yaml")
		if _, err := os.Stat(metaPath); os.IsNotExist(err) {
			continue // No secubox.yaml, skip
		}

		data, err := os.ReadFile(metaPath)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", metaPath, err)
		}

		var c Component
		if err := yaml.Unmarshal(data, &c); err != nil {
			return nil, fmt.Errorf("parse %s: %w", metaPath, err)
		}

		components[c.Name] = &c
	}

	return components, nil
}

// GetComponent returns a specific component by name
func (s *Scanner) GetComponent(name string) (*Component, error) {
	metaPath := filepath.Join(s.packagesDir, name, "debian", "secubox.yaml")
	data, err := os.ReadFile(metaPath)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", metaPath, err)
	}

	var c Component
	if err := yaml.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("parse %s: %w", metaPath, err)
	}

	return &c, nil
}
```

- [ ] **Step 5: Run test to verify it passes**

```bash
go test ./internal/package/... -v
```

Expected: PASS

- [ ] **Step 6: Create example secubox.yaml for secubox-core**

```yaml
# packages/secubox-core/debian/secubox.yaml
name: secubox-core
category: core
description:
  en: SecuBox core libraries and utilities
  fr: Bibliothèques et utilitaires SecuBox

requirements:
  min_ram: 128M
  arch:
    - arm64
    - amd64

tags:
  - core
  - essential
  - required

services:
  - secubox-core.service

ports: []
```

- [ ] **Step 7: Commit**

```bash
git add cmd/secubox/internal/package/ packages/secubox-core/debian/secubox.yaml
git commit -m "feat(secubox): add package scanner for debian/secubox.yaml

- Define Component struct with requirements, tags, modes
- Implement Scanner to find all secubox-* packages
- Add SupportsArch() helper method
- Create secubox-core/debian/secubox.yaml example"
```

---

## Task 6: Manifest Generator

**Files:**
- Create: `cmd/secubox/internal/manifest/manifest.go`
- Create: `cmd/secubox/internal/manifest/manifest_test.go`

- [ ] **Step 1: Write failing test for manifest generation**

```go
// cmd/secubox/internal/manifest/manifest_test.go
package manifest

import (
	"testing"

	"github.com/CyberMind-FR/secubox-deb/cmd/secubox/internal/profile"
)

func TestGenerate(t *testing.T) {
	p := &profile.Profile{
		Name: "test",
		Packages: profile.Packages{
			Required: []string{"secubox-core", "secubox-hub"},
		},
		Kernel: profile.Kernel{
			Version: "6.6",
		},
	}

	b := &profile.Board{
		Name: "mochabin",
		Arch: "arm64",
		Boot: profile.Boot{
			Method:      "uboot",
			KernelImage: "Image",
			DTS:         "armada-7040-mochabin",
		},
	}

	m := Generate(p, b, "2.8.0")

	if m.SecuboxVersion != "2.8.0" {
		t.Errorf("SecuboxVersion = %q, want %q", m.SecuboxVersion, "2.8.0")
	}
	if m.Board != "mochabin" {
		t.Errorf("Board = %q, want %q", m.Board, "mochabin")
	}
	if len(m.Packages) != 2 {
		t.Errorf("Packages = %d, want 2", len(m.Packages))
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
go test ./internal/manifest/... -v
```

Expected: FAIL with "undefined: Generate"

- [ ] **Step 3: Write manifest.go implementation**

```go
// cmd/secubox/internal/manifest/manifest.go
package manifest

import (
	"fmt"
	"time"

	"github.com/CyberMind-FR/secubox-deb/cmd/secubox/internal/profile"
	"gopkg.in/yaml.v3"
)

// Manifest represents the build manifest
type Manifest struct {
	SecuboxVersion string            `yaml:"secubox_version"`
	GeneratedAt    string            `yaml:"generated_at"`
	Board          string            `yaml:"board"`
	Tier           string            `yaml:"tier"`
	Arch           string            `yaml:"arch"`
	Packages       []string          `yaml:"packages"`
	Kernel         ManifestKernel    `yaml:"kernel"`
	Partitions     ManifestPartitions `yaml:"partitions"`
	Boot           ManifestBoot      `yaml:"boot"`
	Output         ManifestOutput    `yaml:"output"`
}

type ManifestKernel struct {
	Version string   `yaml:"version"`
	DTS     string   `yaml:"dts,omitempty"`
	Modules Modules  `yaml:"modules"`
}

type Modules struct {
	Enable    []string `yaml:"enable"`
	Blacklist []string `yaml:"blacklist"`
}

type ManifestPartitions struct {
	ESP  string `yaml:"esp"`
	Root string `yaml:"root"`
	Data string `yaml:"data"`
}

type ManifestBoot struct {
	Method      string `yaml:"method"`
	KernelImage string `yaml:"kernel_image,omitempty"`
}

type ManifestOutput struct {
	Formats   []string `yaml:"formats"`
	Checksums []string `yaml:"checksums"`
}

// Generate creates a manifest from profile and board
func Generate(p *profile.Profile, b *profile.Board, version string) *Manifest {
	m := &Manifest{
		SecuboxVersion: version,
		GeneratedAt:    time.Now().UTC().Format(time.RFC3339),
		Board:          b.Name,
		Tier:           p.Name,
		Arch:           b.Arch,
		Packages:       p.Packages.Required,
		Kernel: ManifestKernel{
			Version: p.Kernel.Version,
			DTS:     b.Boot.DTS,
			Modules: Modules{
				Enable:    p.Kernel.Modules.Enable,
				Blacklist: p.Kernel.Modules.Blacklist,
			},
		},
		Partitions: ManifestPartitions{
			ESP:  "256M",
			Root: "6G",
			Data: "2G",
		},
		Boot: ManifestBoot{
			Method:      b.Boot.Method,
			KernelImage: b.Boot.KernelImage,
		},
		Output: ManifestOutput{
			Formats:   []string{"img.gz", "img.xz"},
			Checksums: []string{"sha256", "sha512"},
		},
	}

	return m
}

// ToYAML serializes the manifest to YAML
func (m *Manifest) ToYAML() ([]byte, error) {
	header := "# Auto-generated by secubox gen v" + m.SecuboxVersion + "\n"
	header += "# Date: " + m.GeneratedAt + "\n"
	header += "# Do not edit manually - regenerate with: secubox gen\n\n"

	data, err := yaml.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("marshal manifest: %w", err)
	}

	return append([]byte(header), data...), nil
}
```

- [ ] **Step 4: Run test to verify it passes**

```bash
go test ./internal/manifest/... -v
```

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add cmd/secubox/internal/manifest/
git commit -m "feat(secubox): add manifest generator

- Define Manifest struct with kernel, partitions, boot, output
- Implement Generate() from Profile and Board
- Add ToYAML() for serialization with header comments"
```

---

## Task 7: Makefile Generator

**Files:**
- Create: `cmd/secubox/internal/manifest/makefile.go`
- Modify: `cmd/secubox/internal/manifest/manifest_test.go`

- [ ] **Step 1: Write failing test for Makefile generation**

```go
// Add to cmd/secubox/internal/manifest/manifest_test.go

func TestGenerateMakefile(t *testing.T) {
	m := &Manifest{
		SecuboxVersion: "2.8.0",
		Board:          "mochabin",
		Arch:           "arm64",
	}

	makefile := GenerateMakefile(m)

	if !strings.Contains(makefile, "VERSION := 2.8.0") {
		t.Error("Makefile missing VERSION")
	}
	if !strings.Contains(makefile, "BOARD := mochabin") {
		t.Error("Makefile missing BOARD")
	}
	if !strings.Contains(makefile, "image:") {
		t.Error("Makefile missing image target")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
go test ./internal/manifest/... -v -run TestGenerateMakefile
```

Expected: FAIL with "undefined: GenerateMakefile"

- [ ] **Step 3: Write makefile.go implementation**

```go
// cmd/secubox/internal/manifest/makefile.go
package manifest

import (
	"fmt"
	"strings"
)

// GenerateMakefile creates a Makefile from a manifest
func GenerateMakefile(m *Manifest) string {
	var sb strings.Builder

	// Header
	sb.WriteString(fmt.Sprintf(`# Auto-generated by secubox gen v%s
# Run: make image

MANIFEST := manifest.yaml
VERSION := %s
BOARD := %s
ARCH := %s
IMAGE_NAME := secubox-$(BOARD)-$(VERSION)

.PHONY: all image rootfs partition boot compress checksums clean

all: image

image: rootfs partition boot compress checksums
	@echo "✓ Build complete: $(IMAGE_NAME).img.gz"

rootfs:
	@echo "=== Building rootfs ==="
	secubox build --stage rootfs --manifest $(MANIFEST)

partition:
	@echo "=== Creating partitions ==="
	secubox build --stage partition --manifest $(MANIFEST)

boot:
	@echo "=== Installing bootloader ==="
	secubox build --stage boot --manifest $(MANIFEST)

compress:
	@echo "=== Compressing images ==="
`, m.SecuboxVersion, m.SecuboxVersion, m.Board, m.Arch))

	// Add compression commands based on output formats
	for _, format := range m.Output.Formats {
		switch format {
		case "img.gz":
			sb.WriteString("\tgzip -k $(IMAGE_NAME).img\n")
		case "img.xz":
			sb.WriteString("\txz -k $(IMAGE_NAME).img\n")
		}
	}

	// Checksums
	sb.WriteString(`
checksums:
	@echo "=== Generating checksums ==="
`)
	for _, sum := range m.Output.Checksums {
		sb.WriteString(fmt.Sprintf("\t%ssum $(IMAGE_NAME).img* > %sSUMS\n", sum, strings.ToUpper(sum)))
	}

	// Clean and additional targets
	sb.WriteString(`
clean:
	rm -rf rootfs/ *.img *.img.gz *.img.xz SHA*SUMS

# Platform-specific targets
.PHONY: vdi qcow2 iso

vdi: image
	qemu-img convert -f raw -O vdi $(IMAGE_NAME).img $(IMAGE_NAME).vdi

qcow2: image
	qemu-img convert -f raw -O qcow2 $(IMAGE_NAME).img $(IMAGE_NAME).qcow2

iso: rootfs
	secubox build --stage iso --manifest $(MANIFEST)
`)

	return sb.String()
}
```

- [ ] **Step 4: Run test to verify it passes**

```bash
go test ./internal/manifest/... -v
```

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add cmd/secubox/internal/manifest/makefile.go
git commit -m "feat(secubox): add Makefile generator

- Generate Makefile with image, rootfs, partition, boot stages
- Support configurable output formats (gz, xz)
- Support configurable checksums (sha256, sha512)
- Add vdi, qcow2, iso extra targets"
```

---

## Task 8: Gen Command

**Files:**
- Create: `cmd/secubox/cmd/gen.go`

- [ ] **Step 1: Write gen.go command**

```go
// cmd/secubox/cmd/gen.go
package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/CyberMind-FR/secubox-deb/cmd/secubox/internal/manifest"
	"github.com/CyberMind-FR/secubox-deb/cmd/secubox/internal/profile"
	"github.com/spf13/cobra"
)

var (
	genBoard   string
	genTier    string
	genEnable  []string
	genDisable []string
	genOut     string
	genAuto    bool
)

var genCmd = &cobra.Command{
	Use:   "gen",
	Short: "Generate manifest and Makefile",
	Long: `Generate a build manifest and Makefile for SecuBox image creation.

Examples:
  # Interactive wizard
  secubox gen

  # Specify board and tier
  secubox gen --board mochabin --tier tier-pro

  # Enable additional packages
  secubox gen --board mochabin --enable ollama,jellyfin

  # Auto-detect hardware
  secubox gen --auto`,
	RunE: runGen,
}

func init() {
	rootCmd.AddCommand(genCmd)
	genCmd.Flags().StringVarP(&genBoard, "board", "b", "", "target board (mochabin, espressobin-v7, rpi400, vm-x64)")
	genCmd.Flags().StringVarP(&genTier, "tier", "t", "", "profile tier (tier-lite, tier-standard, tier-pro)")
	genCmd.Flags().StringSliceVarP(&genEnable, "enable", "e", nil, "additional packages to enable")
	genCmd.Flags().StringSliceVarP(&genDisable, "disable", "d", nil, "packages to disable")
	genCmd.Flags().StringVarP(&genOut, "out", "o", ".", "output directory")
	genCmd.Flags().BoolVar(&genAuto, "auto", false, "auto-detect hardware")
}

func runGen(cmd *cobra.Command, args []string) error {
	// Find repo root (where profiles/ and board/ are)
	repoRoot, err := findRepoRoot()
	if err != nil {
		return fmt.Errorf("find repo root: %w", err)
	}

	// If no board specified and not auto, run wizard
	if genBoard == "" && !genAuto {
		return runWizard(repoRoot)
	}

	// Auto-detect hardware if requested
	if genAuto {
		detected, err := detectHardware()
		if err != nil {
			return fmt.Errorf("detect hardware: %w", err)
		}
		genBoard = detected.Board
		if genTier == "" {
			genTier = detected.Tier
		}
		fmt.Printf("Detected: board=%s, tier=%s\n", genBoard, genTier)
	}

	// Load board configuration
	boardDir := filepath.Join(repoRoot, "board", genBoard)
	board, err := profile.LoadBoard(boardDir)
	if err != nil {
		return fmt.Errorf("load board %s: %w", genBoard, err)
	}

	// Determine tier
	if genTier == "" {
		genTier = board.Tier
	}

	// Resolve profile with inheritance
	profilesDir := filepath.Join(repoRoot, "profiles")
	merger := profile.NewMerger(profilesDir)
	prof, err := merger.Resolve(genTier)
	if err != nil {
		return fmt.Errorf("resolve profile %s: %w", genTier, err)
	}

	// Apply board tweaks
	tweaks, err := profile.LoadTweaks(boardDir)
	if err != nil {
		return fmt.Errorf("load tweaks: %w", err)
	}
	applyTweaks(prof, tweaks)

	// Add/remove packages from CLI
	for _, pkg := range genEnable {
		prof.Packages.Required = append(prof.Packages.Required, "secubox-"+pkg)
	}
	for _, pkg := range genDisable {
		prof.Packages.Required = removePackage(prof.Packages.Required, "secubox-"+pkg)
	}

	// Generate manifest
	m := manifest.Generate(prof, board, version)

	// Write manifest.yaml
	manifestPath := filepath.Join(genOut, "manifest.yaml")
	manifestData, err := m.ToYAML()
	if err != nil {
		return fmt.Errorf("serialize manifest: %w", err)
	}
	if err := os.WriteFile(manifestPath, manifestData, 0644); err != nil {
		return fmt.Errorf("write manifest: %w", err)
	}
	fmt.Printf("✓ Generated: %s\n", manifestPath)

	// Write Makefile
	makefilePath := filepath.Join(genOut, "Makefile")
	makefileData := manifest.GenerateMakefile(m)
	if err := os.WriteFile(makefilePath, []byte(makefileData), 0644); err != nil {
		return fmt.Errorf("write Makefile: %w", err)
	}
	fmt.Printf("✓ Generated: %s\n", makefilePath)

	fmt.Printf("\nNext: cd %s && make image\n", genOut)
	return nil
}

func findRepoRoot() (string, error) {
	// Look for profiles/ directory
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}

	for {
		if _, err := os.Stat(filepath.Join(dir, "profiles")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("could not find repo root (no profiles/ directory)")
		}
		dir = parent
	}
}

func applyTweaks(p *profile.Profile, t *profile.Tweaks) {
	// Merge kernel modules
	p.Kernel.Modules.Enable = append(p.Kernel.Modules.Enable, t.Kernel.Modules.Enable...)
	p.Kernel.Modules.Blacklist = append(p.Kernel.Modules.Blacklist, t.Kernel.Modules.Blacklist...)

	// Merge sysctl
	for k, v := range t.Sysctl {
		p.Sysctl[k] = v
	}

	// Merge services
	p.Services.Enable = append(p.Services.Enable, t.Services.Enable...)
}

func removePackage(packages []string, pkg string) []string {
	result := []string{}
	for _, p := range packages {
		if p != pkg {
			result = append(result, p)
		}
	}
	return result
}

// Placeholder for hardware detection
type detectedHardware struct {
	Board string
	Tier  string
}

func detectHardware() (*detectedHardware, error) {
	// TODO: Implement actual hardware detection
	return nil, fmt.Errorf("hardware detection not implemented yet")
}

// Placeholder for wizard
func runWizard(repoRoot string) error {
	fmt.Println("Interactive wizard not implemented yet.")
	fmt.Println("Use: secubox gen --board <board> --tier <tier>")
	return nil
}
```

- [ ] **Step 2: Build and test**

```bash
cd cmd/secubox
go build -o secubox .
./secubox gen --help
```

Expected:
```
Generate a build manifest and Makefile for SecuBox image creation.
...
```

- [ ] **Step 3: Test with MOCHAbin**

```bash
cd /home/reepost/CyberMindStudio/secubox-deb/secubox-deb
./cmd/secubox/secubox gen --board mochabin --out /tmp/secubox-build
cat /tmp/secubox-build/manifest.yaml
cat /tmp/secubox-build/Makefile
```

- [ ] **Step 4: Commit**

```bash
git add cmd/secubox/cmd/gen.go
git commit -m "feat(secubox): add gen command for manifest generation

- Load board and profile configurations
- Resolve profile inheritance chain
- Apply board-specific tweaks
- Support --enable/--disable package flags
- Generate manifest.yaml and Makefile"
```

---

## Task 9: Interactive Wizard

**Files:**
- Create: `cmd/secubox/internal/wizard/wizard.go`
- Modify: `cmd/secubox/cmd/gen.go`

- [ ] **Step 1: Write wizard.go**

```go
// cmd/secubox/internal/wizard/wizard.go
package wizard

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/manifoldco/promptui"
)

// Options holds wizard results
type Options struct {
	Board   string
	Tier    string
	Enable  []string
	Formats []string
}

// Board represents a selectable board
type Board struct {
	Name        string
	Description string
	Tier        string
}

// Run executes the interactive wizard
func Run(repoRoot string) (*Options, error) {
	opts := &Options{}

	// Discover available boards
	boards, err := discoverBoards(repoRoot)
	if err != nil {
		return nil, fmt.Errorf("discover boards: %w", err)
	}

	// Select board
	boardItems := make([]string, len(boards))
	for i, b := range boards {
		boardItems[i] = fmt.Sprintf("%s (%s)", b.Name, b.Description)
	}

	boardPrompt := promptui.Select{
		Label: "Select target board",
		Items: boardItems,
	}
	boardIdx, _, err := boardPrompt.Run()
	if err != nil {
		return nil, err
	}
	opts.Board = boards[boardIdx].Name
	defaultTier := boards[boardIdx].Tier

	// Select tier
	tiers := []string{
		fmt.Sprintf("%s (recommended for %s)", defaultTier, opts.Board),
		"tier-lite",
		"tier-standard",
		"tier-pro",
	}

	tierPrompt := promptui.Select{
		Label: "Select tier",
		Items: tiers,
	}
	tierIdx, _, err := tierPrompt.Run()
	if err != nil {
		return nil, err
	}
	if tierIdx == 0 {
		opts.Tier = defaultTier
	} else {
		opts.Tier = tiers[tierIdx]
	}

	// Optional packages
	optionalPackages := []string{
		"ollama",
		"jellyfin",
		"homeassistant",
		"matrix",
		"nextcloud",
		"gitea",
	}

	enablePrompt := promptui.Select{
		Label: "Enable additional packages? (select 'Done' to finish)",
		Items: append([]string{"Done"}, optionalPackages...),
	}

	for {
		idx, _, err := enablePrompt.Run()
		if err != nil {
			return nil, err
		}
		if idx == 0 { // Done
			break
		}
		pkg := optionalPackages[idx-1]
		opts.Enable = append(opts.Enable, pkg)
		fmt.Printf("  + %s\n", pkg)
	}

	// Output formats
	formats := []string{"img.gz", "img.xz", "vdi", "qcow2"}
	formatPrompt := promptui.Select{
		Label: "Output formats (select 'Done' to finish)",
		Items: append([]string{"Done"}, formats...),
	}

	opts.Formats = []string{"img.gz"} // Default
	for {
		idx, _, err := formatPrompt.Run()
		if err != nil {
			return nil, err
		}
		if idx == 0 {
			break
		}
		format := formats[idx-1]
		opts.Formats = append(opts.Formats, format)
		fmt.Printf("  + %s\n", format)
	}

	return opts, nil
}

func discoverBoards(repoRoot string) ([]Board, error) {
	boardsDir := filepath.Join(repoRoot, "board")
	entries, err := os.ReadDir(boardsDir)
	if err != nil {
		return nil, err
	}

	boards := []Board{}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		// Read board.yaml if exists, otherwise use defaults
		name := entry.Name()
		desc := name
		tier := "tier-standard"

		boardYaml := filepath.Join(boardsDir, name, "board.yaml")
		if _, err := os.Stat(boardYaml); err == nil {
			// Could parse board.yaml here for description/tier
			// For now, use hardcoded descriptions
			switch name {
			case "mochabin":
				desc = "Armada 7040, 4-8GB RAM"
				tier = "tier-pro"
			case "espressobin-v7":
				desc = "Armada 3720, 1-2GB RAM"
				tier = "tier-lite"
			case "rpi400":
				desc = "Raspberry Pi 400"
				tier = "tier-standard"
			case "vm-x64":
				desc = "VirtualBox/QEMU x64"
				tier = "tier-standard"
			}
		}

		boards = append(boards, Board{
			Name:        name,
			Description: desc,
			Tier:        tier,
		})
	}

	return boards, nil
}
```

- [ ] **Step 2: Update gen.go to use wizard**

```go
// In cmd/secubox/cmd/gen.go, update the runWizard function:

func runWizard(repoRoot string) error {
	opts, err := wizard.Run(repoRoot)
	if err != nil {
		return fmt.Errorf("wizard: %w", err)
	}

	// Set global flags from wizard results
	genBoard = opts.Board
	genTier = opts.Tier
	genEnable = opts.Enable

	// Continue with normal generation
	return runGenWithOptions(repoRoot)
}

// Also add import:
// "github.com/CyberMind-FR/secubox-deb/cmd/secubox/internal/wizard"
```

- [ ] **Step 3: Build and test wizard**

```bash
cd cmd/secubox
go build -o secubox .
./secubox gen
```

Expected: Interactive prompts for board, tier, packages, formats

- [ ] **Step 4: Commit**

```bash
git add cmd/secubox/internal/wizard/ cmd/secubox/cmd/gen.go
git commit -m "feat(secubox): add interactive wizard for gen command

- Discover available boards from board/ directory
- Prompt for board, tier, optional packages, output formats
- Use promptui for terminal UI"
```

---

## Task 10: Info Command

**Files:**
- Create: `cmd/secubox/cmd/info.go`
- Create: `cmd/secubox/internal/hardware/detect.go`

- [ ] **Step 1: Write hardware detection**

```go
// cmd/secubox/internal/hardware/detect.go
package hardware

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
)

// Info holds detected hardware information
type Info struct {
	Board      string
	Arch       string
	CPUModel   string
	CPUCores   int
	RAMTotal   uint64 // bytes
	RAMTotalMB uint64
	DiskTotal  uint64 // bytes
}

// Detect gathers hardware information
func Detect() (*Info, error) {
	info := &Info{}

	// Detect architecture
	info.Arch = detectArch()

	// Detect CPU
	info.CPUModel, info.CPUCores = detectCPU()

	// Detect RAM
	info.RAMTotal = detectRAM()
	info.RAMTotalMB = info.RAMTotal / 1024 / 1024

	// Detect board (from device tree)
	info.Board = detectBoard()

	return info, nil
}

func detectArch() string {
	// Read from uname or /proc/cpuinfo
	data, err := os.ReadFile("/proc/cpuinfo")
	if err != nil {
		return "unknown"
	}

	content := string(data)
	if strings.Contains(content, "aarch64") || strings.Contains(content, "ARMv8") {
		return "arm64"
	}
	if strings.Contains(content, "x86_64") {
		return "amd64"
	}
	return "unknown"
}

func detectCPU() (string, int) {
	file, err := os.Open("/proc/cpuinfo")
	if err != nil {
		return "unknown", 0
	}
	defer file.Close()

	var model string
	cores := 0
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "model name") || strings.HasPrefix(line, "Model") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				model = strings.TrimSpace(parts[1])
			}
		}
		if strings.HasPrefix(line, "processor") {
			cores++
		}
	}

	return model, cores
}

func detectRAM() uint64 {
	file, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	re := regexp.MustCompile(`MemTotal:\s+(\d+)\s+kB`)

	for scanner.Scan() {
		matches := re.FindStringSubmatch(scanner.Text())
		if len(matches) == 2 {
			kb, _ := strconv.ParseUint(matches[1], 10, 64)
			return kb * 1024 // Convert to bytes
		}
	}
	return 0
}

func detectBoard() string {
	// Try device tree
	data, err := os.ReadFile("/proc/device-tree/model")
	if err == nil {
		model := strings.TrimSpace(strings.TrimRight(string(data), "\x00"))
		if strings.Contains(strings.ToLower(model), "mochabin") {
			return "mochabin"
		}
		if strings.Contains(strings.ToLower(model), "espressobin") {
			return "espressobin-v7"
		}
		if strings.Contains(strings.ToLower(model), "raspberry") {
			return "rpi400"
		}
	}

	// Try DMI (x86)
	data, err = os.ReadFile("/sys/class/dmi/id/product_name")
	if err == nil {
		product := strings.TrimSpace(string(data))
		if strings.Contains(strings.ToLower(product), "virtualbox") {
			return "vm-x64"
		}
	}

	return "unknown"
}

// SuggestTier suggests a tier based on RAM
func (i *Info) SuggestTier() string {
	ramGB := i.RAMTotalMB / 1024
	if ramGB >= 8 {
		return "tier-pro"
	}
	if ramGB >= 4 {
		return "tier-standard"
	}
	return "tier-lite"
}

// String returns a formatted string of hardware info
func (i *Info) String() string {
	return fmt.Sprintf(`Hardware Information:
  Board:     %s
  Arch:      %s
  CPU:       %s (%d cores)
  RAM:       %d MB
  Suggested: %s`,
		i.Board, i.Arch, i.CPUModel, i.CPUCores,
		i.RAMTotalMB, i.SuggestTier())
}
```

- [ ] **Step 2: Write info.go command**

```go
// cmd/secubox/cmd/info.go
package cmd

import (
	"fmt"

	"github.com/CyberMind-FR/secubox-deb/cmd/secubox/internal/hardware"
	"github.com/spf13/cobra"
)

var infoCmd = &cobra.Command{
	Use:   "info",
	Short: "Show system and hardware information",
	Long:  `Display detected hardware information and suggested build profile.`,
	RunE:  runInfo,
}

func init() {
	rootCmd.AddCommand(infoCmd)
}

func runInfo(cmd *cobra.Command, args []string) error {
	info, err := hardware.Detect()
	if err != nil {
		return fmt.Errorf("detect hardware: %w", err)
	}

	fmt.Println(info.String())
	return nil
}
```

- [ ] **Step 3: Build and test**

```bash
cd cmd/secubox
go build -o secubox .
./secubox info
```

Expected:
```
Hardware Information:
  Board:     vm-x64
  Arch:      amd64
  CPU:       Intel... (X cores)
  RAM:       XXXX MB
  Suggested: tier-standard
```

- [ ] **Step 4: Commit**

```bash
git add cmd/secubox/internal/hardware/ cmd/secubox/cmd/info.go
git commit -m "feat(secubox): add info command with hardware detection

- Detect arch, CPU, RAM from /proc
- Detect board from device tree or DMI
- Suggest tier based on RAM size"
```

---

## Remaining Tasks (Summary)

The following tasks follow the same TDD pattern:

### Task 11: Build Command
- Create `cmd/secubox/cmd/build.go`
- Implement stage orchestration (rootfs, partition, boot)
- Shell out to debootstrap, parted, mkfs

### Task 12: Fetch Command
- Create `cmd/secubox/cmd/fetch.go`
- Query GitHub releases API
- Download with progress bar
- Verify checksums

### Task 13: OTA Command
- Create `cmd/secubox/cmd/ota.go`
- Create `cmd/secubox/internal/ota/partition.go`
- Implement A/B partition detection
- Implement slot switching

### Task 14: Arch Profiles
- Create `profiles/arch/arm64.yaml`
- Create `profiles/arch/amd64.yaml`
- Update merger to include arch layer

### Task 15: Package secubox.yaml for All Packages
- Create `debian/secubox.yaml` for each package
- Script to generate from existing debian/control

### Task 16: APT Repository Setup
- Create `/srv/apt` structure on server
- Configure reprepro
- Add lintian pre-publish hook
- Create sync script to apt.secubox.in

### Task 17: CI Integration
- Add `.github/workflows/build-secubox-cli.yml`
- Build Go binary for linux-amd64, linux-arm64
- Publish to GitHub releases

---

## Success Criteria

- [ ] `secubox gen --board mochabin` produces valid manifest.yaml + Makefile
- [ ] `secubox gen` wizard works interactively
- [ ] `secubox info` detects hardware correctly
- [ ] Profile inheritance resolves base → arch → tier → board
- [ ] All 134 packages have debian/secubox.yaml
- [ ] apt.gk2.secubox.in serves arm64 + amd64 packages
- [ ] Lintian validation passes for all packages
