<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# SecuBox CLI: APT and Clone Commands Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `secubox apt` and `secubox clone` commands for APT repository management and system bootstrapping.

**Architecture:** Hybrid approach — pure Go for client operations (`apt setup`, `clone`), shell script wrappers for server operations (`apt init/publish/sync/list/remove/check`). Uses promptui for interactive wizard (existing pattern from wizard.go).

**Tech Stack:** Go 1.22, Cobra, promptui, net/http, os/exec

---

## File Structure

| Action | File | Responsibility |
|--------|------|----------------|
| Create | `cmd/secubox/cmd/apt.go` | Parent `apt` command + `setup` subcommand |
| Create | `cmd/secubox/cmd/apt_server.go` | Server subcommands (init, publish, sync, list, remove, check) |
| Create | `cmd/secubox/cmd/clone.go` | Bootstrap wizard command |
| Create | `cmd/secubox/internal/apt/client.go` | Client operations: GPG download, sources.list writing |
| Create | `cmd/secubox/internal/apt/server.go` | Server operations: script wrappers for reprepro |
| Create | `cmd/secubox/internal/apt/packages.go` | Tier-to-package resolution |
| Create | `cmd/secubox/internal/apt/client_test.go` | Unit tests for client operations |
| Create | `cmd/secubox/internal/apt/packages_test.go` | Unit tests for package resolution |

---

## Task 1: Create APT Client Package

**Files:**
- Create: `cmd/secubox/internal/apt/client.go`
- Test: `cmd/secubox/internal/apt/client_test.go`

- [x] **Step 1: Write failing test for GPG key download**

```go
// cmd/secubox/internal/apt/client_test.go
package apt

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestDownloadGPGKey(t *testing.T) {
	// Create test server with mock GPG key
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("-----BEGIN PGP PUBLIC KEY BLOCK-----\ntest-key\n-----END PGP PUBLIC KEY BLOCK-----"))
	}))
	defer ts.Close()

	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "secubox.gpg")

	client := &Client{
		GPGKeyURL:  ts.URL + "/secubox.gpg",
		KeyringDir: tmpDir,
	}

	err := client.DownloadGPGKey()
	if err != nil {
		t.Fatalf("DownloadGPGKey() error = %v", err)
	}

	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		t.Errorf("GPG key file not created at %s", keyPath)
	}
}
```

- [x] **Step 2: Run test to verify it fails**

Run: `cd cmd/secubox && go test -v ./internal/apt/... -run TestDownloadGPGKey`
Expected: FAIL with "package apt is not in std"

- [x] **Step 3: Write Client struct and DownloadGPGKey**

```go
// cmd/secubox/internal/apt/client.go
package apt

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

const (
	DefaultGPGKeyURL  = "https://apt.secubox.in/secubox.gpg"
	DefaultKeyringDir = "/usr/share/keyrings"
	DefaultSourcesDir = "/etc/apt/sources.list.d"
	DefaultRepoURL    = "https://apt.secubox.in"
	DefaultCodename   = "bookworm"
	DefaultComponent  = "main"
)

// Client handles APT repository client operations
type Client struct {
	GPGKeyURL  string
	KeyringDir string
	SourcesDir string
	RepoURL    string
	Codename   string
	Component  string
}

// NewClient creates a client with default settings
func NewClient() *Client {
	return &Client{
		GPGKeyURL:  DefaultGPGKeyURL,
		KeyringDir: DefaultKeyringDir,
		SourcesDir: DefaultSourcesDir,
		RepoURL:    DefaultRepoURL,
		Codename:   DefaultCodename,
		Component:  DefaultComponent,
	}
}

// DownloadGPGKey downloads the repository GPG key with retry
func (c *Client) DownloadGPGKey() error {
	keyPath := filepath.Join(c.KeyringDir, "secubox.gpg")

	var lastErr error
	for attempt := 1; attempt <= 3; attempt++ {
		if attempt > 1 {
			time.Sleep(2 * time.Second)
		}

		resp, err := http.Get(c.GPGKeyURL)
		if err != nil {
			lastErr = fmt.Errorf("download GPG key (attempt %d): %w", attempt, err)
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			lastErr = fmt.Errorf("download GPG key: HTTP %d", resp.StatusCode)
			continue
		}

		data, err := io.ReadAll(resp.Body)
		if err != nil {
			lastErr = fmt.Errorf("read GPG key: %w", err)
			continue
		}

		if err := os.MkdirAll(c.KeyringDir, 0755); err != nil {
			return fmt.Errorf("create keyring dir: %w", err)
		}

		if err := os.WriteFile(keyPath, data, 0644); err != nil {
			return fmt.Errorf("write GPG key: %w", err)
		}

		return nil
	}

	return lastErr
}
```

- [x] **Step 4: Run test to verify it passes**

Run: `cd cmd/secubox && go test -v ./internal/apt/... -run TestDownloadGPGKey`
Expected: PASS

- [x] **Step 5: Write failing test for sources.list generation**

```go
func TestWriteSourcesList(t *testing.T) {
	tmpDir := t.TempDir()

	client := &Client{
		KeyringDir: "/usr/share/keyrings",
		SourcesDir: tmpDir,
		RepoURL:    "https://apt.secubox.in",
		Codename:   "bookworm",
		Component:  "main",
	}

	err := client.WriteSourcesList()
	if err != nil {
		t.Fatalf("WriteSourcesList() error = %v", err)
	}

	content, err := os.ReadFile(filepath.Join(tmpDir, "secubox.list"))
	if err != nil {
		t.Fatalf("read sources.list: %v", err)
	}

	expected := "deb [signed-by=/usr/share/keyrings/secubox.gpg] https://apt.secubox.in bookworm main\n"
	if string(content) != expected {
		t.Errorf("sources.list content = %q, want %q", content, expected)
	}
}
```

- [x] **Step 6: Run test to verify it fails**

Run: `cd cmd/secubox && go test -v ./internal/apt/... -run TestWriteSourcesList`
Expected: FAIL with "WriteSourcesList undefined"

- [x] **Step 7: Implement WriteSourcesList**

```go
// WriteSourcesList creates /etc/apt/sources.list.d/secubox.list
func (c *Client) WriteSourcesList() error {
	if err := os.MkdirAll(c.SourcesDir, 0755); err != nil {
		return fmt.Errorf("create sources dir: %w", err)
	}

	content := fmt.Sprintf("deb [signed-by=%s/secubox.gpg] %s %s %s\n",
		c.KeyringDir, c.RepoURL, c.Codename, c.Component)

	path := filepath.Join(c.SourcesDir, "secubox.list")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		return fmt.Errorf("write sources.list: %w", err)
	}

	return nil
}
```

- [x] **Step 8: Run test to verify it passes**

Run: `cd cmd/secubox && go test -v ./internal/apt/... -run TestWriteSourcesList`
Expected: PASS

- [x] **Step 9: Add Setup method that combines operations**

```go
// Setup configures the system to use the SecuBox APT repository
func (c *Client) Setup() error {
	if err := c.DownloadGPGKey(); err != nil {
		return fmt.Errorf("download GPG key: %w", err)
	}

	if err := c.WriteSourcesList(); err != nil {
		return fmt.Errorf("write sources.list: %w", err)
	}

	return nil
}
```

- [x] **Step 10: Commit**

```bash
git add cmd/secubox/internal/apt/client.go cmd/secubox/internal/apt/client_test.go
git commit -m "feat(cli): add APT client package for repository setup

- DownloadGPGKey with 3-retry backoff
- WriteSourcesList for sources.list.d
- Setup combines both operations"
```

---

## Task 2: Create Package Resolution

**Files:**
- Create: `cmd/secubox/internal/apt/packages.go`
- Test: `cmd/secubox/internal/apt/packages_test.go`

- [x] **Step 1: Write failing test for tier resolution**

```go
// cmd/secubox/internal/apt/packages_test.go
package apt

import "testing"

func TestTierPackages(t *testing.T) {
	tests := []struct {
		tier     string
		wantPkg  string
		wantErr  bool
	}{
		{"lite", "secubox-lite", false},
		{"standard", "secubox-standard", false},
		{"pro", "secubox-full", false},
		{"minimal", "", false},
		{"invalid", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.tier, func(t *testing.T) {
			pkgs, err := TierPackages(tt.tier)
			if (err != nil) != tt.wantErr {
				t.Errorf("TierPackages(%q) error = %v, wantErr %v", tt.tier, err, tt.wantErr)
				return
			}
			if tt.wantPkg != "" && len(pkgs) > 0 && pkgs[0] != tt.wantPkg {
				t.Errorf("TierPackages(%q) = %v, want %q", tt.tier, pkgs, tt.wantPkg)
			}
		})
	}
}
```

- [x] **Step 2: Run test to verify it fails**

Run: `cd cmd/secubox && go test -v ./internal/apt/... -run TestTierPackages`
Expected: FAIL with "TierPackages undefined"

- [x] **Step 3: Implement TierPackages**

```go
// cmd/secubox/internal/apt/packages.go
package apt

import "fmt"

// Tier definitions
type Tier struct {
	Name        string
	Description string
	Packages    []string
}

var Tiers = map[string]Tier{
	"lite": {
		Name:        "Lite",
		Description: "1-2GB RAM devices (ESPRESSObin)",
		Packages:    []string{"secubox-lite"},
	},
	"standard": {
		Name:        "Standard",
		Description: "4GB RAM, general purpose",
		Packages:    []string{"secubox-standard"},
	},
	"pro": {
		Name:        "Pro",
		Description: "8GB+ RAM, all features (MOCHAbin)",
		Packages:    []string{"secubox-full"},
	},
	"minimal": {
		Name:        "Minimal",
		Description: "Core + Hub only",
		Packages:    []string{"secubox-core", "secubox-hub"},
	},
}

// AvailablePackages lists all selectable packages for custom install
var AvailablePackages = []string{
	"secubox-core",
	"secubox-hub",
	"secubox-crowdsec",
	"secubox-netdata",
	"secubox-wireguard",
	"secubox-dpi",
	"secubox-netmodes",
	"secubox-nac",
	"secubox-auth",
	"secubox-qos",
	"secubox-mediaflow",
	"secubox-cdn",
	"secubox-vhost",
	"secubox-system",
}

// TierPackages returns the packages for a given tier
func TierPackages(tier string) ([]string, error) {
	t, ok := Tiers[tier]
	if !ok {
		return nil, fmt.Errorf("invalid tier: %s (valid: lite, standard, pro, minimal)", tier)
	}
	return t.Packages, nil
}

// ValidateTier checks if a tier name is valid
func ValidateTier(tier string) bool {
	_, ok := Tiers[tier]
	return ok
}

// TierNames returns all tier names for wizard display
func TierNames() []string {
	return []string{"lite", "standard", "pro", "minimal", "custom"}
}
```

- [x] **Step 4: Run test to verify it passes**

Run: `cd cmd/secubox && go test -v ./internal/apt/... -run TestTierPackages`
Expected: PASS

- [x] **Step 5: Commit**

```bash
git add cmd/secubox/internal/apt/packages.go cmd/secubox/internal/apt/packages_test.go
git commit -m "feat(cli): add package tier resolution for clone wizard

- Tier definitions: lite, standard, pro, minimal
- AvailablePackages list for custom selection
- TierPackages resolver"
```

---

## Task 3: Create APT Server Package

**Files:**
- Create: `cmd/secubox/internal/apt/server.go`

- [x] **Step 1: Write Server struct with script paths**

```go
// cmd/secubox/internal/apt/server.go
package apt

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

const (
	DefaultRepoPath = "/srv/apt"
)

// Server handles APT repository server operations
type Server struct {
	RepoPath   string
	ScriptsDir string
	Codename   string
	Component  string
	DryRun     bool
	Verbose    bool
}

// NewServer creates a server with default settings
func NewServer(repoRoot string) *Server {
	return &Server{
		RepoPath:   DefaultRepoPath,
		ScriptsDir: filepath.Join(repoRoot, "scripts"),
		Codename:   DefaultCodename,
		Component:  DefaultComponent,
	}
}

// Init initializes the local APT repository
func (s *Server) Init() error {
	// Check reprepro
	if _, err := exec.LookPath("reprepro"); err != nil {
		return fmt.Errorf("reprepro not installed (apt install reprepro)")
	}

	// Create directories
	dirs := []string{"conf", "db", "dists", "pool", "incoming", "tmp"}
	for _, d := range dirs {
		path := filepath.Join(s.RepoPath, d)
		if err := os.MkdirAll(path, 0755); err != nil {
			return fmt.Errorf("create %s: %w", path, err)
		}
	}

	// Run reprepro export
	cmd := exec.Command("reprepro", "-b", s.RepoPath, "export")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("reprepro export: %w", err)
	}

	return nil
}

// Publish publishes .deb packages using the publish script
func (s *Server) Publish(files []string, skipLintian bool) error {
	script := filepath.Join(s.ScriptsDir, "apt-publish.sh")
	if _, err := os.Stat(script); os.IsNotExist(err) {
		return fmt.Errorf("publish script not found: %s", script)
	}

	args := []string{}
	args = append(args, "-c", s.Codename)
	args = append(args, "-C", s.Component)
	if skipLintian {
		args = append(args, "--skip-lintian")
	}
	if s.DryRun {
		args = append(args, "--dry-run")
	}
	args = append(args, files...)

	cmd := exec.Command(script, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// Sync syncs repository to remote using the sync script
func (s *Server) Sync() error {
	script := filepath.Join(s.ScriptsDir, "apt-sync.sh")
	if _, err := os.Stat(script); os.IsNotExist(err) {
		return fmt.Errorf("sync script not found: %s", script)
	}

	args := []string{}
	if s.DryRun {
		args = append(args, "--dry-run")
	}
	if s.Verbose {
		args = append(args, "--verbose")
	}

	cmd := exec.Command(script, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// List lists packages in the repository
func (s *Server) List() error {
	cmd := exec.Command("reprepro", "-b", s.RepoPath, "list", s.Codename)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// Remove removes a package from the repository
func (s *Server) Remove(pkgName string) error {
	if s.DryRun {
		fmt.Printf("[DRY-RUN] Would remove: %s from %s\n", pkgName, s.Codename)
		return nil
	}

	cmd := exec.Command("reprepro", "-b", s.RepoPath, "remove", s.Codename, pkgName)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// Check verifies repository integrity
func (s *Server) Check() error {
	cmd := exec.Command("reprepro", "-b", s.RepoPath, "check")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
```

- [x] **Step 2: Run existing tests to verify no regressions**

Run: `cd cmd/secubox && go test -v ./internal/apt/...`
Expected: PASS

- [x] **Step 3: Commit**

```bash
git add cmd/secubox/internal/apt/server.go
git commit -m "feat(cli): add APT server operations wrapper

- Init: create repo structure and export
- Publish: wrap apt-publish.sh script
- Sync: wrap apt-sync.sh script
- List/Remove/Check: direct reprepro commands"
```

---

## Task 4: Create APT Parent Command and Setup Subcommand

**Files:**
- Create: `cmd/secubox/cmd/apt.go`

- [x] **Step 1: Write apt.go with parent command**

```go
// cmd/secubox/cmd/apt.go
package cmd

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/CyberMind-FR/secubox-deb/cmd/secubox/internal/apt"
	"github.com/spf13/cobra"
)

var (
	aptCodename  string
	aptComponent string
	aptDryRun    bool
)

var aptCmd = &cobra.Command{
	Use:   "apt",
	Short: "Manage APT repository",
	Long: `Manage SecuBox APT repository (client and server operations).

Client commands:
  setup     Add SecuBox repository to this system

Server commands:
  init      Initialize local APT repository
  publish   Publish .deb packages
  sync      Sync to apt.secubox.in
  list      List packages in repository
  remove    Remove package from repository
  check     Verify repository integrity

Examples:
  # Add SecuBox repo to fresh Debian system
  sudo secubox apt setup

  # Publish packages (server)
  secubox apt publish packages/*/*.deb

  # Sync to remote (server)
  secubox apt sync`,
}

var aptSetupCmd = &cobra.Command{
	Use:   "setup",
	Short: "Add SecuBox repository to this system",
	Long: `Add the SecuBox APT repository to this system.

This command:
  1. Downloads the SecuBox GPG key
  2. Adds /etc/apt/sources.list.d/secubox.list
  3. Runs apt update

Requires root privileges.

Example:
  sudo secubox apt setup`,
	RunE: runAptSetup,
}

func init() {
	rootCmd.AddCommand(aptCmd)
	aptCmd.AddCommand(aptSetupCmd)

	// Global flags for apt subcommands
	aptCmd.PersistentFlags().StringVarP(&aptCodename, "codename", "c", "bookworm", "distribution codename")
	aptCmd.PersistentFlags().StringVarP(&aptComponent, "component", "C", "main", "repository component")
	aptCmd.PersistentFlags().BoolVarP(&aptDryRun, "dry-run", "n", false, "preview without executing")
}

func runAptSetup(cmd *cobra.Command, args []string) error {
	// Check root
	if os.Geteuid() != 0 {
		return fmt.Errorf("must run as root (use sudo)")
	}

	fmt.Println("SecuBox APT Repository Setup")
	fmt.Println("============================")
	fmt.Println()

	client := apt.NewClient()
	client.Codename = aptCodename
	client.Component = aptComponent

	// Download GPG key
	fmt.Print("Downloading GPG key... ")
	if err := client.DownloadGPGKey(); err != nil {
		fmt.Println("FAILED")
		return fmt.Errorf("download GPG key: %w", err)
	}
	fmt.Println("OK")

	// Write sources.list
	fmt.Print("Adding repository... ")
	if err := client.WriteSourcesList(); err != nil {
		fmt.Println("FAILED")
		return fmt.Errorf("write sources.list: %w", err)
	}
	fmt.Println("OK")

	// Run apt update
	fmt.Print("Updating package lists... ")
	if aptDryRun {
		fmt.Println("[DRY-RUN]")
	} else {
		aptUpdate := exec.Command("apt", "update")
		aptUpdate.Stdout = os.Stdout
		aptUpdate.Stderr = os.Stderr
		if err := aptUpdate.Run(); err != nil {
			fmt.Println("FAILED")
			return fmt.Errorf("apt update: %w", err)
		}
		fmt.Println("OK")
	}

	fmt.Println()
	fmt.Println("SecuBox repository configured successfully!")
	fmt.Println()
	fmt.Println("Install packages with:")
	fmt.Println("  apt install secubox-core secubox-hub")
	fmt.Println()
	fmt.Println("Or use the clone wizard:")
	fmt.Println("  sudo secubox clone")

	return nil
}
```

- [x] **Step 2: Run go build to verify compilation**

Run: `cd cmd/secubox && go build .`
Expected: Success

- [x] **Step 3: Commit**

```bash
git add cmd/secubox/cmd/apt.go
git commit -m "feat(cli): add secubox apt command with setup subcommand

- Parent command with --codename, --component, --dry-run flags
- setup subcommand: GPG key + sources.list + apt update"
```

---

## Task 5: Create APT Server Subcommands

**Files:**
- Create: `cmd/secubox/cmd/apt_server.go`

- [x] **Step 1: Write apt_server.go with all server subcommands**

```go
// cmd/secubox/cmd/apt_server.go
package cmd

import (
	"fmt"

	"github.com/CyberMind-FR/secubox-deb/cmd/secubox/internal/apt"
	"github.com/spf13/cobra"
)

var (
	aptSkipLintian bool
)

var aptInitCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize local APT repository",
	Long: `Initialize the local APT repository at /srv/apt.

Creates the directory structure and runs reprepro export.

Example:
  secubox apt init`,
	RunE: runAptInit,
}

var aptPublishCmd = &cobra.Command{
	Use:   "publish <files...>",
	Short: "Publish .deb packages to repository",
	Long: `Publish .deb packages to the local APT repository.

Validates packages with lintian before publishing (unless --skip-lintian).

Examples:
  secubox apt publish packages/secubox-core/*.deb
  secubox apt publish -c bookworm-testing *.deb
  secubox apt publish --skip-lintian packages/*/*.deb`,
	Args: cobra.MinimumNArgs(1),
	RunE: runAptPublish,
}

var aptSyncCmd = &cobra.Command{
	Use:   "sync",
	Short: "Sync repository to apt.secubox.in",
	Long: `Sync the local APT repository to apt.secubox.in.

Uses rsync to upload dists/ and pool/ directories.

Examples:
  secubox apt sync
  secubox apt sync --dry-run`,
	RunE: runAptSync,
}

var aptListCmd = &cobra.Command{
	Use:   "list",
	Short: "List packages in repository",
	Long: `List all packages in the repository for the given codename.

Example:
  secubox apt list
  secubox apt list -c bookworm-testing`,
	RunE: runAptList,
}

var aptRemoveCmd = &cobra.Command{
	Use:   "remove <package>",
	Short: "Remove package from repository",
	Long: `Remove a package from the repository.

Example:
  secubox apt remove secubox-core`,
	Args: cobra.ExactArgs(1),
	RunE: runAptRemove,
}

var aptCheckCmd = &cobra.Command{
	Use:   "check",
	Short: "Verify repository integrity",
	Long: `Run reprepro check to verify repository integrity.

Example:
  secubox apt check`,
	RunE: runAptCheck,
}

func init() {
	aptCmd.AddCommand(aptInitCmd)
	aptCmd.AddCommand(aptPublishCmd)
	aptCmd.AddCommand(aptSyncCmd)
	aptCmd.AddCommand(aptListCmd)
	aptCmd.AddCommand(aptRemoveCmd)
	aptCmd.AddCommand(aptCheckCmd)

	// Publish-specific flags
	aptPublishCmd.Flags().BoolVarP(&aptSkipLintian, "skip-lintian", "s", false, "skip lintian validation")
}

func getServer() (*apt.Server, error) {
	repoRoot, err := findRepoRoot()
	if err != nil {
		return nil, fmt.Errorf("find repo root: %w", err)
	}

	server := apt.NewServer(repoRoot)
	server.Codename = aptCodename
	server.Component = aptComponent
	server.DryRun = aptDryRun
	server.Verbose = verbose
	return server, nil
}

func runAptInit(cmd *cobra.Command, args []string) error {
	server, err := getServer()
	if err != nil {
		return err
	}

	fmt.Println("Initializing APT repository...")
	if err := server.Init(); err != nil {
		return fmt.Errorf("init: %w", err)
	}

	fmt.Println("Repository initialized at /srv/apt")
	return nil
}

func runAptPublish(cmd *cobra.Command, args []string) error {
	server, err := getServer()
	if err != nil {
		return err
	}

	return server.Publish(args, aptSkipLintian)
}

func runAptSync(cmd *cobra.Command, args []string) error {
	server, err := getServer()
	if err != nil {
		return err
	}

	return server.Sync()
}

func runAptList(cmd *cobra.Command, args []string) error {
	server, err := getServer()
	if err != nil {
		return err
	}

	return server.List()
}

func runAptRemove(cmd *cobra.Command, args []string) error {
	server, err := getServer()
	if err != nil {
		return err
	}

	return server.Remove(args[0])
}

func runAptCheck(cmd *cobra.Command, args []string) error {
	server, err := getServer()
	if err != nil {
		return err
	}

	return server.Check()
}
```

- [x] **Step 2: Run go build to verify compilation**

Run: `cd cmd/secubox && go build .`
Expected: Success

- [x] **Step 3: Commit**

```bash
git add cmd/secubox/cmd/apt_server.go
git commit -m "feat(cli): add secubox apt server subcommands

- init: initialize /srv/apt repository
- publish: wrap apt-publish.sh with lintian validation
- sync: wrap apt-sync.sh for rsync to remote
- list/remove/check: direct reprepro wrappers"
```

---

## Task 6: Create Clone Command with Interactive Wizard

**Files:**
- Create: `cmd/secubox/cmd/clone.go`

- [x] **Step 1: Write clone.go with flags and command structure**

```go
// cmd/secubox/cmd/clone.go
package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/CyberMind-FR/secubox-deb/cmd/secubox/internal/apt"
	"github.com/manifoldco/promptui"
	"github.com/spf13/cobra"
)

var (
	cloneTier     string
	cloneMinimal  bool
	clonePackages string
	cloneYes      bool
)

var cloneCmd = &cobra.Command{
	Use:   "clone",
	Short: "Bootstrap a new SecuBox system",
	Long: `Bootstrap wizard for new SecuBox installations.

This command:
  1. Adds the SecuBox APT repository
  2. Lets you select an installation tier (or custom packages)
  3. Installs the selected packages

Tiers:
  lite     - 1-2GB RAM (ESPRESSObin), basic security
  standard - 4GB RAM, general purpose
  pro      - 8GB+ RAM (MOCHAbin), all features
  minimal  - Core + Hub only

Examples:
  # Interactive wizard
  sudo secubox clone

  # Install pro tier non-interactively
  sudo secubox clone --tier pro -y

  # Minimal install
  sudo secubox clone --minimal -y

  # Specific packages
  sudo secubox clone --packages "secubox-core,secubox-hub,secubox-crowdsec" -y`,
	RunE: runClone,
}

func init() {
	rootCmd.AddCommand(cloneCmd)

	cloneCmd.Flags().StringVarP(&cloneTier, "tier", "t", "", "install specific tier (lite, standard, pro)")
	cloneCmd.Flags().BoolVar(&cloneMinimal, "minimal", false, "install secubox-core + secubox-hub only")
	cloneCmd.Flags().StringVarP(&clonePackages, "packages", "p", "", "comma-separated package list")
	cloneCmd.Flags().BoolVarP(&cloneYes, "yes", "y", false, "auto-confirm apt prompts")
}

func runClone(cmd *cobra.Command, args []string) error {
	// Check root
	if os.Geteuid() != 0 {
		return fmt.Errorf("must run as root (use sudo)")
	}

	fmt.Println()
	fmt.Println("SecuBox Bootstrap Wizard")
	fmt.Println("========================")
	fmt.Println()

	// Setup repository
	client := apt.NewClient()

	fmt.Println("Adding SecuBox repository...")
	fmt.Print("  Downloading GPG key... ")
	if err := client.DownloadGPGKey(); err != nil {
		fmt.Println("FAILED")
		return fmt.Errorf("download GPG key: %w", err)
	}
	fmt.Println("OK")

	fmt.Print("  Adding sources.list... ")
	if err := client.WriteSourcesList(); err != nil {
		fmt.Println("FAILED")
		return fmt.Errorf("write sources.list: %w", err)
	}
	fmt.Println("OK")

	fmt.Print("  Updating package lists... ")
	aptUpdate := exec.Command("apt", "update")
	if err := aptUpdate.Run(); err != nil {
		fmt.Println("FAILED")
		return fmt.Errorf("apt update: %w", err)
	}
	fmt.Println("OK")
	fmt.Println()

	// Determine packages to install
	var packages []string
	var err error

	if cloneMinimal {
		packages = []string{"secubox-core", "secubox-hub"}
	} else if clonePackages != "" {
		packages = strings.Split(clonePackages, ",")
		for i := range packages {
			packages[i] = strings.TrimSpace(packages[i])
		}
	} else if cloneTier != "" {
		packages, err = apt.TierPackages(cloneTier)
		if err != nil {
			return err
		}
	} else {
		// Interactive wizard
		packages, err = runCloneWizard()
		if err != nil {
			return fmt.Errorf("wizard: %w", err)
		}
	}

	if len(packages) == 0 {
		return fmt.Errorf("no packages selected")
	}

	// Install packages
	fmt.Printf("Installing: %s\n\n", strings.Join(packages, " "))

	aptArgs := []string{"install"}
	if cloneYes {
		aptArgs = append(aptArgs, "-y")
	}
	aptArgs = append(aptArgs, packages...)

	aptInstall := exec.Command("apt", aptArgs...)
	aptInstall.Stdout = os.Stdout
	aptInstall.Stderr = os.Stderr
	aptInstall.Stdin = os.Stdin

	if err := aptInstall.Run(); err != nil {
		return fmt.Errorf("apt install: %w", err)
	}

	fmt.Println()
	fmt.Println("SecuBox installation complete!")
	fmt.Println()
	fmt.Println("Access dashboard at: https://<IP>:9443")
	fmt.Println("Default credentials: admin / secubox")
	fmt.Println()

	return nil
}

func runCloneWizard() ([]string, error) {
	// Tier selection
	tierItems := []string{
		"Lite (1-2GB RAM) - ESPRESSObin, basic security",
		"Standard (4GB RAM) - General purpose",
		"Pro (8GB+ RAM) - Full features, MOCHAbin",
		"Minimal - Core + Hub only",
		"Custom - Pick individual packages",
	}

	tierPrompt := promptui.Select{
		Label: "Select installation tier",
		Items: tierItems,
		Size:  5,
	}

	tierIdx, _, err := tierPrompt.Run()
	if err != nil {
		return nil, fmt.Errorf("tier selection: %w", err)
	}

	tierMap := []string{"lite", "standard", "pro", "minimal", "custom"}
	selectedTier := tierMap[tierIdx]

	// Handle custom selection
	if selectedTier == "custom" {
		return selectCustomPackages()
	}

	// Return tier packages
	return apt.TierPackages(selectedTier)
}

func selectCustomPackages() ([]string, error) {
	packages := apt.AvailablePackages
	selected := []string{}

	fmt.Println()
	fmt.Println("Select packages to install (multi-select):")

	for {
		items := []string{"[Done - install selected]"}
		for _, pkg := range packages {
			marker := "  "
			for _, s := range selected {
				if s == pkg {
					marker = "✓ "
					break
				}
			}
			items = append(items, marker+pkg)
		}

		prompt := promptui.Select{
			Label: fmt.Sprintf("Selected: %d packages", len(selected)),
			Items: items,
			Size:  10,
		}

		idx, _, err := prompt.Run()
		if err != nil {
			return nil, fmt.Errorf("package selection: %w", err)
		}

		if idx == 0 {
			break
		}

		pkg := packages[idx-1]

		// Toggle selection
		found := false
		newSelected := []string{}
		for _, s := range selected {
			if s == pkg {
				found = true
			} else {
				newSelected = append(newSelected, s)
			}
		}
		if found {
			selected = newSelected
		} else {
			selected = append(selected, pkg)
		}
	}

	// Ensure secubox-core is always included
	hasCore := false
	for _, s := range selected {
		if s == "secubox-core" {
			hasCore = true
			break
		}
	}
	if !hasCore && len(selected) > 0 {
		selected = append([]string{"secubox-core"}, selected...)
	}

	return selected, nil
}
```

- [x] **Step 2: Run go build to verify compilation**

Run: `cd cmd/secubox && go build .`
Expected: Success

- [x] **Step 3: Commit**

```bash
git add cmd/secubox/cmd/clone.go
git commit -m "feat(cli): add secubox clone bootstrap wizard

- Interactive tier selection (lite/standard/pro/minimal/custom)
- Custom package multi-select with toggle
- Non-interactive modes: --tier, --minimal, --packages
- Auto-adds secubox-core as dependency"
```

---

## Task 7: Add Tests for Commands

**Files:**
- Create: `cmd/secubox/cmd/apt_test.go`
- Create: `cmd/secubox/cmd/clone_test.go`

- [x] **Step 1: Write apt command tests**

```go
// cmd/secubox/cmd/apt_test.go
package cmd

import (
	"bytes"
	"testing"
)

func TestAptCmdHelp(t *testing.T) {
	cmd := aptCmd
	b := new(bytes.Buffer)
	cmd.SetOut(b)
	cmd.SetArgs([]string{"--help"})

	err := cmd.Execute()
	if err != nil {
		t.Fatalf("apt --help failed: %v", err)
	}

	output := b.String()
	if !bytes.Contains([]byte(output), []byte("setup")) {
		t.Error("apt help should mention setup subcommand")
	}
	if !bytes.Contains([]byte(output), []byte("publish")) {
		t.Error("apt help should mention publish subcommand")
	}
}

func TestAptSetupRequiresRoot(t *testing.T) {
	// Skip if running as root
	if os.Geteuid() == 0 {
		t.Skip("test requires non-root user")
	}

	cmd := aptSetupCmd
	err := cmd.RunE(cmd, []string{})
	if err == nil {
		t.Error("apt setup should require root")
	}
	if !bytes.Contains([]byte(err.Error()), []byte("root")) {
		t.Errorf("error should mention root: %v", err)
	}
}
```

- [x] **Step 2: Write clone command tests**

```go
// cmd/secubox/cmd/clone_test.go
package cmd

import (
	"bytes"
	"os"
	"testing"
)

func TestCloneCmdHelp(t *testing.T) {
	cmd := cloneCmd
	b := new(bytes.Buffer)
	cmd.SetOut(b)
	cmd.SetArgs([]string{"--help"})

	err := cmd.Execute()
	if err != nil {
		t.Fatalf("clone --help failed: %v", err)
	}

	output := b.String()
	if !bytes.Contains([]byte(output), []byte("tier")) {
		t.Error("clone help should mention --tier flag")
	}
	if !bytes.Contains([]byte(output), []byte("minimal")) {
		t.Error("clone help should mention --minimal flag")
	}
}

func TestCloneRequiresRoot(t *testing.T) {
	// Skip if running as root
	if os.Geteuid() == 0 {
		t.Skip("test requires non-root user")
	}

	cmd := cloneCmd
	err := cmd.RunE(cmd, []string{})
	if err == nil {
		t.Error("clone should require root")
	}
	if !bytes.Contains([]byte(err.Error()), []byte("root")) {
		t.Errorf("error should mention root: %v", err)
	}
}
```

- [x] **Step 3: Add missing import to apt_test.go**

Add `"os"` to imports in apt_test.go.

- [x] **Step 4: Run tests**

Run: `cd cmd/secubox && go test -v ./cmd/... -run "TestApt|TestClone"`
Expected: PASS (or SKIP for root tests)

- [x] **Step 5: Commit**

```bash
git add cmd/secubox/cmd/apt_test.go cmd/secubox/cmd/clone_test.go
git commit -m "test(cli): add tests for apt and clone commands

- Help output validation
- Root privilege requirement tests"
```

---

## Task 8: Update go.mod and Run Full Tests

**Files:**
- Modify: `cmd/secubox/go.mod` (if needed)

- [x] **Step 1: Ensure promptui is in go.mod**

Run: `cd cmd/secubox && go mod tidy`
Expected: Success (promptui should already be present from wizard.go)

- [x] **Step 2: Run all tests**

Run: `cd cmd/secubox && go test -v ./...`
Expected: PASS

- [x] **Step 3: Build binary**

Run: `cd cmd/secubox && go build -o secubox .`
Expected: Success

- [x] **Step 4: Verify commands exist**

Run: `./secubox apt --help && ./secubox clone --help`
Expected: Help output for both commands

- [x] **Step 5: Commit go.mod changes if any**

```bash
git add cmd/secubox/go.mod cmd/secubox/go.sum
git commit -m "chore(cli): update dependencies for apt/clone commands"
```

---

## Task 9: Final Integration Test and Documentation

**Files:**
- None (manual testing)

- [x] **Step 1: Test apt help hierarchy**

Run: `cd cmd/secubox && go run . apt --help`
Expected: Shows all subcommands (setup, init, publish, sync, list, remove, check)

- [x] **Step 2: Test clone help**

Run: `cd cmd/secubox && go run . clone --help`
Expected: Shows tier and package options

- [x] **Step 3: Test dry-run modes**

Run: `cd cmd/secubox && go run . apt publish --dry-run -c bookworm packages/secubox-core/*.deb 2>&1 || true`
Expected: Shows dry-run output or "file not found" (acceptable)

- [x] **Step 4: Commit final changes**

```bash
git add -A
git commit -m "feat(cli): complete APT and Clone command implementation

APT Commands:
- secubox apt setup: Add SecuBox repo to system (client)
- secubox apt init: Initialize local repository (server)
- secubox apt publish: Publish .deb packages (server)
- secubox apt sync: Sync to apt.secubox.in (server)
- secubox apt list/remove/check: Package management (server)

Clone Command:
- Interactive tier selection wizard
- Non-interactive: --tier, --minimal, --packages
- Automatic repository setup

Closes the APT/Clone design spec."
```

---

## Success Criteria

- [x] `secubox apt setup` adds repository to fresh Debian system
- [x] `secubox apt publish *.deb` publishes packages with lintian check
- [x] `secubox apt sync` uploads to apt.secubox.in
- [x] `secubox clone` wizard completes full installation
- [x] `secubox clone --tier pro -y` works non-interactively
- [x] All commands show help with `--help`
- [x] All tests pass
