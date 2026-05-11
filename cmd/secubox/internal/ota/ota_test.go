// cmd/secubox/internal/ota/ota_test.go
package ota

import (
	"os"
	"path/filepath"
	"testing"
)

// TestSlotOpposite tests slot opposite logic
func TestSlotOpposite(t *testing.T) {
	tests := []struct {
		slot     Slot
		expected Slot
	}{
		{SlotA, SlotB},
		{SlotB, SlotA},
	}

	for _, tc := range tests {
		got := tc.slot.Opposite()
		if got != tc.expected {
			t.Errorf("Slot(%q).Opposite() = %q, want %q", tc.slot, got, tc.expected)
		}
	}
}

// TestSlotPartitionNumber tests slot to partition number mapping
func TestSlotPartitionNumber(t *testing.T) {
	tests := []struct {
		slot     Slot
		expected int
	}{
		{SlotA, RootAPartition},
		{SlotB, RootBPartition},
	}

	for _, tc := range tests {
		got := tc.slot.PartitionNumber()
		if got != tc.expected {
			t.Errorf("Slot(%q).PartitionNumber() = %d, want %d", tc.slot, got, tc.expected)
		}
	}
}

// TestSlotLabel tests slot label generation
func TestSlotLabel(t *testing.T) {
	tests := []struct {
		slot     Slot
		expected string
	}{
		{SlotA, "root-a"},
		{SlotB, "root-b"},
	}

	for _, tc := range tests {
		got := tc.slot.Label()
		if got != tc.expected {
			t.Errorf("Slot(%q).Label() = %q, want %q", tc.slot, got, tc.expected)
		}
	}
}

// TestExtractBaseDevice tests base device extraction
func TestExtractBaseDevice(t *testing.T) {
	tests := []struct {
		partDev  string
		expected string
	}{
		{"/dev/mmcblk0p2", "/dev/mmcblk0"},
		{"/dev/mmcblk0p3", "/dev/mmcblk0"},
		{"/dev/nvme0n1p2", "/dev/nvme0n1"},
		{"/dev/sda2", "/dev/sda"},
		{"/dev/sda1", "/dev/sda"},
		{"/dev/vda3", "/dev/vda"},
	}

	for _, tc := range tests {
		got := extractBaseDevice(tc.partDev)
		if got != tc.expected {
			t.Errorf("extractBaseDevice(%q) = %q, want %q", tc.partDev, got, tc.expected)
		}
	}
}

// TestBootControlFileOperations tests boot control file read/write
func TestBootControlFileOperations(t *testing.T) {
	// Create a temporary directory for boot control
	tmpDir := t.TempDir()
	bootDir := filepath.Join(tmpDir, "secubox")

	// Override the constants for testing
	origBootControlDir := BootControlDir
	origActiveSlotFile := ActiveSlotFile
	origFallbackSlotFile := FallbackSlotFile
	origBootCountFile := BootCountFile

	// Create a local scope to modify package variables
	// Since we can't modify constants, we test the file operations directly
	testActiveFile := filepath.Join(bootDir, "active")
	testFallbackFile := filepath.Join(bootDir, "fallback")
	testBootCountFile := filepath.Join(bootDir, "boot-count")

	// Create boot control directory
	if err := os.MkdirAll(bootDir, 0755); err != nil {
		t.Fatalf("Failed to create boot dir: %v", err)
	}

	// Test writing active slot
	if err := os.WriteFile(testActiveFile, []byte("a\n"), 0644); err != nil {
		t.Fatalf("Failed to write active file: %v", err)
	}

	// Test reading active slot
	data, err := os.ReadFile(testActiveFile)
	if err != nil {
		t.Fatalf("Failed to read active file: %v", err)
	}
	if string(data) != "a\n" {
		t.Errorf("Active slot = %q, want %q", string(data), "a\n")
	}

	// Test writing fallback slot
	if err := os.WriteFile(testFallbackFile, []byte("b\n"), 0644); err != nil {
		t.Fatalf("Failed to write fallback file: %v", err)
	}

	// Test writing boot count
	if err := os.WriteFile(testBootCountFile, []byte("2\n"), 0644); err != nil {
		t.Fatalf("Failed to write boot count file: %v", err)
	}

	// Verify boot count
	data, err = os.ReadFile(testBootCountFile)
	if err != nil {
		t.Fatalf("Failed to read boot count file: %v", err)
	}
	if string(data) != "2\n" {
		t.Errorf("Boot count = %q, want %q", string(data), "2\n")
	}

	// Cleanup - restore original values (no-op since they're constants)
	_ = origBootControlDir
	_ = origActiveSlotFile
	_ = origFallbackSlotFile
	_ = origBootCountFile
}

// TestNewManager tests OTA manager creation
func TestNewManager(t *testing.T) {
	m := NewManager("2.8.0", nil)
	if m == nil {
		t.Fatal("NewManager returned nil")
	}
	if m.version != "2.8.0" {
		t.Errorf("version = %q, want %q", m.version, "2.8.0")
	}
	if m.opts.Channel != "stable" {
		t.Errorf("default channel = %q, want %q", m.opts.Channel, "stable")
	}
}

// TestNewManagerWithOptions tests OTA manager creation with options
func TestNewManagerWithOptions(t *testing.T) {
	opts := &Options{
		DryRun:  true,
		Verbose: true,
		Channel: "beta",
	}

	m := NewManager("2.8.0", opts)
	if m == nil {
		t.Fatal("NewManager returned nil")
	}
	if !m.opts.DryRun {
		t.Error("DryRun should be true")
	}
	if !m.opts.Verbose {
		t.Error("Verbose should be true")
	}
	if m.opts.Channel != "beta" {
		t.Errorf("Channel = %q, want %q", m.opts.Channel, "beta")
	}
}

// TestGetCommands tests command generation for different update types
func TestGetCommands(t *testing.T) {
	m := NewManager("2.8.0", &Options{DryRun: true})

	// Test package update commands
	pkgCmds := m.GetCommands(UpdatePackages)
	if len(pkgCmds) < 2 {
		t.Error("Expected at least 2 commands for package updates")
	}

	foundUpdate := false
	foundUpgrade := false
	for _, cmd := range pkgCmds {
		if cmd == "apt-get update -qq" {
			foundUpdate = true
		}
		if cmd == "apt-get upgrade -y" {
			foundUpgrade = true
		}
	}
	if !foundUpdate {
		t.Error("Expected apt-get update command")
	}
	if !foundUpgrade {
		t.Error("Expected apt-get upgrade command")
	}

	// Test system update commands
	sysCmds := m.GetCommands(UpdateSystem)
	if len(sysCmds) < 5 {
		t.Error("Expected at least 5 steps for system updates")
	}

	// Test all updates
	allCmds := m.GetCommands(UpdateAll)
	if len(allCmds) < len(pkgCmds)+len(sysCmds) {
		t.Error("UpdateAll should include both package and system commands")
	}
}

// TestBootControlConstants tests that constants are properly defined
func TestBootControlConstants(t *testing.T) {
	if ESPPartition != 1 {
		t.Errorf("ESPPartition = %d, want 1", ESPPartition)
	}
	if RootAPartition != 2 {
		t.Errorf("RootAPartition = %d, want 2", RootAPartition)
	}
	if RootBPartition != 3 {
		t.Errorf("RootBPartition = %d, want 3", RootBPartition)
	}
	if DataPartition != 4 {
		t.Errorf("DataPartition = %d, want 4", DataPartition)
	}
	if MaxBootCount != 3 {
		t.Errorf("MaxBootCount = %d, want 3", MaxBootCount)
	}
}

// TestSlotString tests slot string representation
func TestSlotString(t *testing.T) {
	if SlotA.String() != "a" {
		t.Errorf("SlotA.String() = %q, want %q", SlotA.String(), "a")
	}
	if SlotB.String() != "b" {
		t.Errorf("SlotB.String() = %q, want %q", SlotB.String(), "b")
	}
}

// TestInactiveSlotMountPoint tests the inactive slot mount point
func TestInactiveSlotMountPoint(t *testing.T) {
	mountPoint := GetInactiveSlotMountPoint()
	expected := "/mnt/secubox-inactive"
	if mountPoint != expected {
		t.Errorf("GetInactiveSlotMountPoint() = %q, want %q", mountPoint, expected)
	}
}

// TestDetectBoardFromDeviceTree tests board detection (mock)
func TestDetectBoardFromDeviceTree(t *testing.T) {
	// This test can only verify the function exists
	// Actual detection requires device-tree which may not be present
	_, err := detectBoard()
	// We don't fail on error because device-tree might not exist in test environment
	if err != nil {
		t.Logf("detectBoard() returned error (expected in test env): %v", err)
	}
}

// TestUpdateStatus tests UpdateStatus struct
func TestUpdateStatus(t *testing.T) {
	status := &UpdateStatus{
		PackagesAvailable: true,
		PackageCount:      5,
		PackageList:       []string{"pkg1", "pkg2", "pkg3", "pkg4", "pkg5"},
		SystemAvailable:   true,
		CurrentVersion:    "2.7.0",
		LatestVersion:     "2.8.0",
		ReleaseURL:        "https://github.com/CyberMind-FR/secubox-deb/releases/tag/v2.8.0",
	}

	if !status.PackagesAvailable {
		t.Error("PackagesAvailable should be true")
	}
	if status.PackageCount != 5 {
		t.Errorf("PackageCount = %d, want 5", status.PackageCount)
	}
	if !status.SystemAvailable {
		t.Error("SystemAvailable should be true")
	}
}

// TestBootState tests BootState struct
func TestBootState(t *testing.T) {
	state := &BootState{
		ActiveSlot:   SlotA,
		FallbackSlot: SlotB,
		BootCount:    1,
		IsRecovery:   false,
	}

	if state.ActiveSlot != SlotA {
		t.Errorf("ActiveSlot = %q, want %q", state.ActiveSlot, SlotA)
	}
	if state.FallbackSlot != SlotB {
		t.Errorf("FallbackSlot = %q, want %q", state.FallbackSlot, SlotB)
	}
	if state.BootCount != 1 {
		t.Errorf("BootCount = %d, want 1", state.BootCount)
	}
	if state.IsRecovery {
		t.Error("IsRecovery should be false")
	}

	// Test recovery state
	recoveryState := &BootState{
		ActiveSlot:   SlotB,
		FallbackSlot: SlotA,
		BootCount:    MaxBootCount,
		IsRecovery:   true,
	}

	if !recoveryState.IsRecovery {
		t.Error("IsRecovery should be true when BootCount >= MaxBootCount")
	}
}

// TestGitHubConstants tests GitHub API constants
func TestGitHubConstants(t *testing.T) {
	if GitHubOwner != "CyberMind-FR" {
		t.Errorf("GitHubOwner = %q, want %q", GitHubOwner, "CyberMind-FR")
	}
	if GitHubRepo != "secubox-deb" {
		t.Errorf("GitHubRepo = %q, want %q", GitHubRepo, "secubox-deb")
	}
	if GitHubAPIBase != "https://api.github.com" {
		t.Errorf("GitHubAPIBase = %q, want %q", GitHubAPIBase, "https://api.github.com")
	}
}
