// cmd/secubox/internal/ota/ota.go
package ota

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// GitHub release configuration
const (
	GitHubOwner   = "CyberMind-FR"
	GitHubRepo    = "secubox-deb"
	GitHubAPIBase = "https://api.github.com"
)

// HTTP client with timeout
var httpClient = &http.Client{Timeout: 5 * time.Minute}

// UpdateType represents the type of update to perform
type UpdateType int

const (
	UpdatePackages UpdateType = iota // APT package updates only
	UpdateSystem                     // Kernel/boot update (A/B swap)
	UpdateAll                        // Full update (packages + system)
)

// UpdateStatus represents the status of an update check
type UpdateStatus struct {
	PackagesAvailable bool
	PackageCount      int
	PackageList       []string
	SystemAvailable   bool
	CurrentVersion    string
	LatestVersion     string
	ReleaseURL        string
	ReleaseNotes      string
}

// Options holds OTA operation configuration
type Options struct {
	DryRun    bool
	Verbose   bool
	Force     bool
	RepoURL   string // Custom APT repo URL
	Channel   string // Release channel (stable, beta, nightly)
}

// Manager handles OTA update operations
type Manager struct {
	opts    *Options
	version string // Current SecuBox version
}

// GitHubRelease represents a GitHub release
type GitHubRelease struct {
	TagName     string        `json:"tag_name"`
	Name        string        `json:"name"`
	Body        string        `json:"body"`
	PublishedAt string        `json:"published_at"`
	Assets      []GitHubAsset `json:"assets"`
	Prerelease  bool          `json:"prerelease"`
	Draft       bool          `json:"draft"`
	HTMLURL     string        `json:"html_url"`
}

// GitHubAsset represents a release asset
type GitHubAsset struct {
	Name               string `json:"name"`
	Size               int64  `json:"size"`
	BrowserDownloadURL string `json:"browser_download_url"`
	ContentType        string `json:"content_type"`
}

// NewManager creates a new OTA manager
func NewManager(version string, opts *Options) *Manager {
	if opts == nil {
		opts = &Options{}
	}
	if opts.Channel == "" {
		opts.Channel = "stable"
	}
	return &Manager{
		opts:    opts,
		version: version,
	}
}

// CheckUpdates checks for available updates
func (m *Manager) CheckUpdates() (*UpdateStatus, error) {
	status := &UpdateStatus{
		CurrentVersion: m.version,
	}

	// Check APT package updates
	pkgStatus, err := m.checkPackageUpdates()
	if err != nil {
		return nil, fmt.Errorf("check package updates: %w", err)
	}
	status.PackagesAvailable = pkgStatus.PackagesAvailable
	status.PackageCount = pkgStatus.PackageCount
	status.PackageList = pkgStatus.PackageList

	// Check system updates from GitHub releases
	sysStatus, err := m.checkSystemUpdates()
	if err != nil {
		// Don't fail completely if GitHub check fails
		if m.opts.Verbose {
			fmt.Fprintf(os.Stderr, "Warning: could not check GitHub releases: %v\n", err)
		}
	} else {
		status.SystemAvailable = sysStatus.SystemAvailable
		status.LatestVersion = sysStatus.LatestVersion
		status.ReleaseURL = sysStatus.ReleaseURL
		status.ReleaseNotes = sysStatus.ReleaseNotes
	}

	return status, nil
}

// checkPackageUpdates checks for APT package updates
func (m *Manager) checkPackageUpdates() (*UpdateStatus, error) {
	status := &UpdateStatus{}

	// Run apt-get update first
	if !m.opts.DryRun {
		cmd := exec.Command("apt-get", "update", "-qq")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			return nil, fmt.Errorf("apt-get update: %w", err)
		}
	}

	// Check for upgradable packages
	cmd := exec.Command("apt", "list", "--upgradable")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("apt list --upgradable: %w", err)
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "Listing") {
			continue
		}
		// Parse package name (format: "package/repo version arch [upgradable from: old]")
		parts := strings.Split(line, "/")
		if len(parts) > 0 {
			status.PackageList = append(status.PackageList, parts[0])
		}
	}

	status.PackageCount = len(status.PackageList)
	status.PackagesAvailable = status.PackageCount > 0

	return status, nil
}

// checkSystemUpdates checks GitHub releases for system updates
func (m *Manager) checkSystemUpdates() (*UpdateStatus, error) {
	status := &UpdateStatus{
		CurrentVersion: m.version,
	}

	release, err := m.getLatestRelease()
	if err != nil {
		return nil, err
	}

	status.LatestVersion = release.TagName
	status.ReleaseURL = release.HTMLURL
	status.ReleaseNotes = release.Body

	// Compare versions (simple string comparison for now)
	// Remove 'v' prefix if present
	current := strings.TrimPrefix(m.version, "v")
	latest := strings.TrimPrefix(release.TagName, "v")

	status.SystemAvailable = latest != current && !release.Prerelease

	return status, nil
}

// getLatestRelease fetches the latest release from GitHub
func (m *Manager) getLatestRelease() (*GitHubRelease, error) {
	url := fmt.Sprintf("%s/repos/%s/%s/releases/latest", GitHubAPIBase, GitHubOwner, GitHubRepo)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github.v3+json")
	req.Header.Set("User-Agent", "secubox-ota/"+m.version)

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("GitHub API error: %s - %s", resp.Status, string(body))
	}

	var release GitHubRelease
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return nil, fmt.Errorf("parse release: %w", err)
	}

	return &release, nil
}

// ApplyPackageUpdates applies APT package updates
func (m *Manager) ApplyPackageUpdates() error {
	if m.opts.Verbose {
		fmt.Println("Applying package updates...")
	}

	// Build apt-get upgrade command
	args := []string{"upgrade", "-y"}
	if m.opts.DryRun {
		args = append(args, "--dry-run")
	}

	cmd := exec.Command("apt-get", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = append(os.Environ(), "DEBIAN_FRONTEND=noninteractive")

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("apt-get upgrade: %w", err)
	}

	return nil
}

// ApplySystemUpdate applies a system update using A/B partition swap
func (m *Manager) ApplySystemUpdate() error {
	if m.opts.Verbose {
		fmt.Println("Applying system update...")
	}

	// Get current boot state
	state, err := GetBootState()
	if err != nil {
		return fmt.Errorf("get boot state: %w", err)
	}

	// Determine inactive slot
	inactiveSlot := state.ActiveSlot.Opposite()
	if m.opts.Verbose {
		fmt.Printf("Active slot: %s, Inactive slot: %s\n", state.ActiveSlot, inactiveSlot)
	}

	// Get latest release
	release, err := m.getLatestRelease()
	if err != nil {
		return fmt.Errorf("get latest release: %w", err)
	}

	// Find the appropriate update archive for our board
	board, err := detectBoard()
	if err != nil {
		return fmt.Errorf("detect board: %w", err)
	}

	// Find system update asset
	var updateAsset *GitHubAsset
	var checksumAsset *GitHubAsset
	for i := range release.Assets {
		asset := &release.Assets[i]
		if strings.Contains(asset.Name, board) && strings.HasSuffix(asset.Name, "-system.tar.gz") {
			updateAsset = asset
		}
		if strings.Contains(asset.Name, board) && strings.HasSuffix(asset.Name, "-system.tar.gz.sha256") {
			checksumAsset = asset
		}
	}

	if updateAsset == nil {
		return fmt.Errorf("no system update found for board %s in release %s", board, release.TagName)
	}

	if m.opts.DryRun {
		fmt.Printf("[DRY-RUN] Would download: %s\n", updateAsset.Name)
		fmt.Printf("[DRY-RUN] Would write to inactive slot: %s\n", inactiveSlot)
		fmt.Printf("[DRY-RUN] Would swap active to: %s, fallback to: %s\n", inactiveSlot, state.ActiveSlot)
		return nil
	}

	// Download update to temp directory
	tmpDir, err := os.MkdirTemp("", "secubox-ota-*")
	if err != nil {
		return fmt.Errorf("create temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	updatePath := filepath.Join(tmpDir, updateAsset.Name)
	if m.opts.Verbose {
		fmt.Printf("Downloading %s...\n", updateAsset.Name)
	}

	if err := downloadFile(updateAsset.BrowserDownloadURL, updatePath); err != nil {
		return fmt.Errorf("download update: %w", err)
	}

	// Verify checksum if available
	if checksumAsset != nil {
		if m.opts.Verbose {
			fmt.Println("Verifying checksum...")
		}
		if err := m.verifyChecksum(updatePath, checksumAsset); err != nil {
			return fmt.Errorf("verify checksum: %w", err)
		}
	}

	// Get inactive partition device
	inactiveDevice, err := GetPartitionDevice(inactiveSlot)
	if err != nil {
		return fmt.Errorf("get inactive device: %w", err)
	}

	// Mount inactive partition
	mountPoint := GetInactiveSlotMountPoint()
	if err := os.MkdirAll(mountPoint, 0755); err != nil {
		return fmt.Errorf("create mount point: %w", err)
	}

	if m.opts.Verbose {
		fmt.Printf("Mounting %s at %s...\n", inactiveDevice, mountPoint)
	}

	// Check if already mounted
	mounted, existingMount, _ := IsSlotMounted(inactiveSlot)
	if mounted {
		mountPoint = existingMount
	} else {
		cmd := exec.Command("mount", inactiveDevice, mountPoint)
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("mount inactive partition: %w", err)
		}
		defer func() {
			exec.Command("umount", mountPoint).Run()
		}()
	}

	// Extract update to inactive partition
	if m.opts.Verbose {
		fmt.Printf("Extracting update to %s...\n", mountPoint)
	}

	cmd := exec.Command("tar", "-xzf", updatePath, "-C", mountPoint)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("extract update: %w", err)
	}

	// Sync filesystem
	exec.Command("sync").Run()

	// Update boot control files
	if m.opts.Verbose {
		fmt.Println("Updating boot control...")
	}

	// Set new active slot to inactive (will become active after reboot)
	if err := SetFallbackSlot(state.ActiveSlot); err != nil {
		return fmt.Errorf("set fallback slot: %w", err)
	}

	if err := SetActiveSlot(inactiveSlot); err != nil {
		// Restore fallback
		SetFallbackSlot(state.FallbackSlot)
		return fmt.Errorf("set active slot: %w", err)
	}

	// Reset boot count
	if err := ResetBootCount(); err != nil {
		return fmt.Errorf("reset boot count: %w", err)
	}

	fmt.Printf("\nSystem update applied successfully!\n")
	fmt.Printf("New active slot: %s (will be active after reboot)\n", inactiveSlot)
	fmt.Printf("Fallback slot: %s\n", state.ActiveSlot)
	fmt.Printf("\nReboot to apply the update: sudo reboot\n")

	return nil
}

// Rollback performs a rollback to the fallback slot
func (m *Manager) Rollback() error {
	state, err := GetBootState()
	if err != nil {
		return fmt.Errorf("get boot state: %w", err)
	}

	if m.opts.Verbose {
		fmt.Printf("Current state:\n")
		fmt.Printf("  Active slot:   %s\n", state.ActiveSlot)
		fmt.Printf("  Fallback slot: %s\n", state.FallbackSlot)
		fmt.Printf("  Boot count:    %d\n", state.BootCount)
	}

	if m.opts.DryRun {
		fmt.Printf("[DRY-RUN] Would swap active to: %s, fallback to: %s\n", state.FallbackSlot, state.ActiveSlot)
		return nil
	}

	// Swap slots
	if err := SwapSlots(); err != nil {
		return fmt.Errorf("swap slots: %w", err)
	}

	newState, _ := GetBootState()
	fmt.Printf("\nRollback prepared:\n")
	fmt.Printf("  New active slot:   %s\n", newState.ActiveSlot)
	fmt.Printf("  New fallback slot: %s\n", newState.FallbackSlot)
	fmt.Printf("\nReboot to activate rollback: sudo reboot\n")

	return nil
}

// MarkBootSuccessful marks the current boot as successful (resets boot count)
func (m *Manager) MarkBootSuccessful() error {
	if m.opts.DryRun {
		fmt.Println("[DRY-RUN] Would reset boot count to 0")
		return nil
	}

	if err := ResetBootCount(); err != nil {
		return fmt.Errorf("reset boot count: %w", err)
	}

	if m.opts.Verbose {
		fmt.Println("Boot marked as successful, watchdog counter reset")
	}

	return nil
}

// GetStatus returns the current boot status
func (m *Manager) GetStatus() (*BootState, error) {
	return GetBootState()
}

// verifyChecksum verifies the SHA256 checksum of a downloaded file
func (m *Manager) verifyChecksum(filePath string, checksumAsset *GitHubAsset) error {
	// Download checksum file
	resp, err := httpClient.Get(checksumAsset.BrowserDownloadURL)
	if err != nil {
		return fmt.Errorf("download checksum: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("checksum download error: %s", resp.Status)
	}

	checksumData, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read checksum: %w", err)
	}

	// Parse expected checksum (format: "sha256sum  filename")
	expectedChecksum := strings.Fields(strings.TrimSpace(string(checksumData)))[0]

	// Calculate actual checksum
	f, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("open file: %w", err)
	}
	defer f.Close()

	hasher := sha256.New()
	if _, err := io.Copy(hasher, f); err != nil {
		return fmt.Errorf("calculate checksum: %w", err)
	}

	actualChecksum := hex.EncodeToString(hasher.Sum(nil))

	if !strings.EqualFold(actualChecksum, expectedChecksum) {
		return fmt.Errorf("checksum mismatch:\n  expected: %s\n  actual:   %s", expectedChecksum, actualChecksum)
	}

	return nil
}

// downloadFile downloads a file from URL to the destination path
func downloadFile(url, destPath string) error {
	out, err := os.Create(destPath)
	if err != nil {
		return fmt.Errorf("create file: %w", err)
	}
	defer out.Close()

	resp, err := httpClient.Get(url)
	if err != nil {
		return fmt.Errorf("download: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download error: %s", resp.Status)
	}

	_, err = io.Copy(out, resp.Body)
	if err != nil {
		return fmt.Errorf("write file: %w", err)
	}

	return nil
}

// detectBoard detects the current board type
func detectBoard() (string, error) {
	// Try reading from device-tree
	data, err := os.ReadFile("/sys/firmware/devicetree/base/model")
	if err == nil {
		model := strings.TrimRight(string(data), "\x00\n")
		model = strings.ToLower(model)

		if strings.Contains(model, "mochabin") {
			return "mochabin", nil
		}
		if strings.Contains(model, "espressobin") {
			if strings.Contains(model, "ultra") {
				return "espressobin-ultra", nil
			}
			return "espressobin-v7", nil
		}
		if strings.Contains(model, "raspberry") || strings.Contains(model, "rpi") {
			if strings.Contains(model, "400") {
				return "rpi400", nil
			}
		}
	}

	// Try reading from DMI for VMs
	product, err := os.ReadFile("/sys/class/dmi/id/product_name")
	if err == nil {
		productStr := strings.TrimSpace(string(product))
		if strings.Contains(strings.ToLower(productStr), "virtual") ||
			strings.Contains(strings.ToLower(productStr), "vmware") ||
			strings.Contains(strings.ToLower(productStr), "qemu") {
			// Check architecture
			arch, _ := exec.Command("uname", "-m").Output()
			if strings.Contains(string(arch), "aarch64") || strings.Contains(string(arch), "arm64") {
				return "vm-arm64", nil
			}
			return "vm-x64", nil
		}
	}

	// Default to detecting architecture
	arch, err := exec.Command("uname", "-m").Output()
	if err != nil {
		return "", fmt.Errorf("detect architecture: %w", err)
	}

	archStr := strings.TrimSpace(string(arch))
	if strings.Contains(archStr, "aarch64") || strings.Contains(archStr, "arm64") {
		return "vm-arm64", nil
	}

	return "vm-x64", nil
}

// GetCommands returns the shell commands that would be executed (for dry-run)
func (m *Manager) GetCommands(updateType UpdateType) []string {
	var cmds []string

	switch updateType {
	case UpdatePackages:
		cmds = append(cmds, "apt-get update -qq")
		cmds = append(cmds, "apt-get upgrade -y")

	case UpdateSystem:
		cmds = append(cmds, "# Download system update from GitHub releases")
		cmds = append(cmds, "# Verify SHA256 checksum")
		cmds = append(cmds, "# Mount inactive partition")
		cmds = append(cmds, "# Extract update tarball to inactive partition")
		cmds = append(cmds, "# Update boot control: active=<new>, fallback=<old>")
		cmds = append(cmds, "# Reset boot count")
		cmds = append(cmds, "# Reboot required")

	case UpdateAll:
		cmds = append(cmds, m.GetCommands(UpdatePackages)...)
		cmds = append(cmds, m.GetCommands(UpdateSystem)...)
	}

	return cmds
}
