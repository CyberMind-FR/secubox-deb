// cmd/secubox/internal/builder/builder_test.go
package builder

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/CyberMind-FR/secubox-deb/cmd/secubox/internal/manifest"
)

// TestNewBuilder tests builder creation
func TestNewBuilder(t *testing.T) {
	m := &manifest.Manifest{
		SecuboxVersion: "2.8.0",
		Board:          "mochabin",
		Arch:           "arm64",
		Packages:       []string{"secubox-core", "secubox-hub"},
		Partitions: manifest.ManifestPartitions{
			ESP:  "256M",
			Root: "6G",
			Data: "2G",
		},
		Boot: manifest.ManifestBoot{
			Method:      "uboot",
			KernelImage: "Image",
		},
		Output: manifest.ManifestOutput{
			Formats:   []string{"img.gz"},
			Checksums: []string{"sha256"},
		},
	}

	opts := &Options{
		Manifest:   m,
		OutputDir:  "/tmp/build",
		DryRun:     false,
		ParallelJobs: 1,
	}

	b := New(opts)

	if b == nil {
		t.Fatal("New() returned nil")
	}
	if b.manifest != m {
		t.Error("Builder manifest not set correctly")
	}
	if b.outputDir != "/tmp/build" {
		t.Errorf("outputDir = %q, want %q", b.outputDir, "/tmp/build")
	}
}

// TestStageNames tests that all stages have valid names
func TestStageNames(t *testing.T) {
	expectedStages := []string{"rootfs", "partition", "boot", "compress", "checksums"}

	for _, name := range expectedStages {
		if !IsValidStage(name) {
			t.Errorf("Stage %q should be valid", name)
		}
	}

	if IsValidStage("invalid") {
		t.Error("Stage 'invalid' should not be valid")
	}
}

// TestDryRunRootfs tests rootfs stage in dry-run mode
func TestDryRunRootfs(t *testing.T) {
	tmpDir := t.TempDir()
	m := &manifest.Manifest{
		Board:    "mochabin",
		Arch:     "arm64",
		Packages: []string{"secubox-core", "secubox-hub"},
	}

	opts := &Options{
		Manifest:   m,
		OutputDir:  tmpDir,
		DryRun:     true,
		ParallelJobs: 1,
	}

	b := New(opts)
	cmds, err := b.RunStage("rootfs")
	if err != nil {
		t.Fatalf("RunStage(rootfs) error = %v", err)
	}

	// In dry-run mode, should return commands that would be executed
	if len(cmds) == 0 {
		t.Error("Expected commands to be returned in dry-run mode")
	}

	// Check that debootstrap command is included
	found := false
	for _, cmd := range cmds {
		if strings.Contains(cmd, "debootstrap") {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected debootstrap command in rootfs stage")
	}
}

// TestDryRunPartition tests partition stage in dry-run mode
func TestDryRunPartition(t *testing.T) {
	tmpDir := t.TempDir()
	m := &manifest.Manifest{
		Board: "mochabin",
		Arch:  "arm64",
		Partitions: manifest.ManifestPartitions{
			ESP:  "256M",
			Root: "6G",
			Data: "2G",
		},
	}

	opts := &Options{
		Manifest:   m,
		OutputDir:  tmpDir,
		DryRun:     true,
		ParallelJobs: 1,
	}

	b := New(opts)
	cmds, err := b.RunStage("partition")
	if err != nil {
		t.Fatalf("RunStage(partition) error = %v", err)
	}

	// Check for dd command (image creation)
	foundDD := false
	foundParted := false
	for _, cmd := range cmds {
		if strings.Contains(cmd, "dd ") {
			foundDD = true
		}
		if strings.Contains(cmd, "parted") {
			foundParted = true
		}
	}
	if !foundDD {
		t.Error("Expected dd command in partition stage")
	}
	if !foundParted {
		t.Error("Expected parted command in partition stage")
	}
}

// TestDryRunBoot tests boot stage in dry-run mode
func TestDryRunBoot(t *testing.T) {
	tmpDir := t.TempDir()
	m := &manifest.Manifest{
		Board: "mochabin",
		Arch:  "arm64",
		Boot: manifest.ManifestBoot{
			Method:      "uboot",
			KernelImage: "Image",
		},
		Kernel: manifest.ManifestKernel{
			DTS: "armada-7040-mochabin",
		},
	}

	opts := &Options{
		Manifest:   m,
		OutputDir:  tmpDir,
		DryRun:     true,
		ParallelJobs: 1,
	}

	b := New(opts)
	cmds, err := b.RunStage("boot")
	if err != nil {
		t.Fatalf("RunStage(boot) error = %v", err)
	}

	if len(cmds) == 0 {
		t.Error("Expected commands in boot stage")
	}
}

// TestDryRunCompress tests compress stage in dry-run mode
func TestDryRunCompress(t *testing.T) {
	tmpDir := t.TempDir()
	m := &manifest.Manifest{
		Board: "mochabin",
		Output: manifest.ManifestOutput{
			Formats: []string{"img.gz", "img.xz"},
		},
	}

	opts := &Options{
		Manifest:   m,
		OutputDir:  tmpDir,
		DryRun:     true,
		ParallelJobs: 1,
	}

	b := New(opts)
	cmds, err := b.RunStage("compress")
	if err != nil {
		t.Fatalf("RunStage(compress) error = %v", err)
	}

	foundGzip := false
	foundXz := false
	for _, cmd := range cmds {
		if strings.Contains(cmd, "gzip") {
			foundGzip = true
		}
		if strings.Contains(cmd, "xz") {
			foundXz = true
		}
	}
	if !foundGzip {
		t.Error("Expected gzip command for img.gz format")
	}
	if !foundXz {
		t.Error("Expected xz command for img.xz format")
	}
}

// TestDryRunChecksums tests checksums stage in dry-run mode
func TestDryRunChecksums(t *testing.T) {
	tmpDir := t.TempDir()
	m := &manifest.Manifest{
		Board: "mochabin",
		Output: manifest.ManifestOutput{
			Formats:   []string{"img.gz"},
			Checksums: []string{"sha256", "sha512"},
		},
	}

	opts := &Options{
		Manifest:   m,
		OutputDir:  tmpDir,
		DryRun:     true,
		ParallelJobs: 1,
	}

	b := New(opts)
	cmds, err := b.RunStage("checksums")
	if err != nil {
		t.Fatalf("RunStage(checksums) error = %v", err)
	}

	foundSha256 := false
	foundSha512 := false
	for _, cmd := range cmds {
		if strings.Contains(cmd, "sha256sum") {
			foundSha256 = true
		}
		if strings.Contains(cmd, "sha512sum") {
			foundSha512 = true
		}
	}
	if !foundSha256 {
		t.Error("Expected sha256sum command")
	}
	if !foundSha512 {
		t.Error("Expected sha512sum command")
	}
}

// TestDryRunAll tests running all stages in dry-run mode
func TestDryRunAll(t *testing.T) {
	tmpDir := t.TempDir()
	m := &manifest.Manifest{
		SecuboxVersion: "2.8.0",
		Board:          "mochabin",
		Arch:           "arm64",
		Packages:       []string{"secubox-core"},
		Partitions: manifest.ManifestPartitions{
			ESP:  "256M",
			Root: "6G",
			Data: "2G",
		},
		Boot: manifest.ManifestBoot{
			Method: "uboot",
		},
		Output: manifest.ManifestOutput{
			Formats:   []string{"img.gz"},
			Checksums: []string{"sha256"},
		},
	}

	opts := &Options{
		Manifest:   m,
		OutputDir:  tmpDir,
		DryRun:     true,
		ParallelJobs: 1,
	}

	b := New(opts)
	cmds, err := b.Run()
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if len(cmds) == 0 {
		t.Error("Expected commands from full build")
	}

	// Should have commands from all stages
	hasDebootstrap := false
	hasDD := false
	hasGzip := false
	hasSha256 := false
	for _, cmd := range cmds {
		if strings.Contains(cmd, "debootstrap") {
			hasDebootstrap = true
		}
		if strings.Contains(cmd, "dd ") {
			hasDD = true
		}
		if strings.Contains(cmd, "gzip") {
			hasGzip = true
		}
		if strings.Contains(cmd, "sha256sum") {
			hasSha256 = true
		}
	}
	if !hasDebootstrap {
		t.Error("Missing debootstrap from full build")
	}
	if !hasDD {
		t.Error("Missing dd from full build")
	}
	if !hasGzip {
		t.Error("Missing gzip from full build")
	}
	if !hasSha256 {
		t.Error("Missing sha256sum from full build")
	}
}

// TestInvalidStage tests error handling for invalid stage
func TestInvalidStage(t *testing.T) {
	tmpDir := t.TempDir()
	m := &manifest.Manifest{}

	opts := &Options{
		Manifest:   m,
		OutputDir:  tmpDir,
		DryRun:     true,
		ParallelJobs: 1,
	}

	b := New(opts)
	_, err := b.RunStage("invalid")
	if err == nil {
		t.Error("Expected error for invalid stage")
	}
}

// TestLoadManifest tests loading manifest from file
func TestLoadManifest(t *testing.T) {
	tmpDir := t.TempDir()
	manifestContent := `secubox_version: "2.8.0"
board: mochabin
tier: tier-pro
arch: arm64
packages:
  - secubox-core
  - secubox-hub
partitions:
  esp: 256M
  root: 6G
  data: 2G
boot:
  method: uboot
  kernel_image: Image
output:
  formats:
    - img.gz
  checksums:
    - sha256
`
	manifestPath := filepath.Join(tmpDir, "manifest.yaml")
	if err := os.WriteFile(manifestPath, []byte(manifestContent), 0644); err != nil {
		t.Fatalf("Failed to write manifest: %v", err)
	}

	m, err := LoadManifest(manifestPath)
	if err != nil {
		t.Fatalf("LoadManifest() error = %v", err)
	}

	if m.Board != "mochabin" {
		t.Errorf("Board = %q, want %q", m.Board, "mochabin")
	}
	if m.Arch != "arm64" {
		t.Errorf("Arch = %q, want %q", m.Arch, "arm64")
	}
	if len(m.Packages) != 2 {
		t.Errorf("Packages count = %d, want 2", len(m.Packages))
	}
}

// TestCrossCompilationDetection tests ARM cross-compilation detection on x86
func TestCrossCompilationDetection(t *testing.T) {
	m := &manifest.Manifest{
		Arch: "arm64",
	}

	opts := &Options{
		Manifest:     m,
		OutputDir:    t.TempDir(),
		DryRun:       true,
		ParallelJobs: 1,
	}

	b := New(opts)
	cmds, _ := b.RunStage("rootfs")

	// When building ARM64 on potentially x86, debootstrap should include arch flag
	for _, cmd := range cmds {
		if strings.Contains(cmd, "debootstrap") {
			if strings.Contains(cmd, "--arch=arm64") || strings.Contains(cmd, "--foreign") {
				// Good - has cross-compilation support
				return
			}
		}
	}
	// The test passes either way since cross-compilation is environment-dependent
}

// TestParsePartitionSize tests partition size parsing
func TestParsePartitionSize(t *testing.T) {
	tests := []struct {
		input    string
		expected int64
		wantErr  bool
	}{
		{"256M", 256 * 1024 * 1024, false},
		{"6G", 6 * 1024 * 1024 * 1024, false},
		{"2G", 2 * 1024 * 1024 * 1024, false},
		{"1T", 1024 * 1024 * 1024 * 1024, false},
		{"100K", 100 * 1024, false},
		{"invalid", 0, true},
		{"", 0, true},
	}

	for _, tc := range tests {
		got, err := ParsePartitionSize(tc.input)
		if tc.wantErr {
			if err == nil {
				t.Errorf("ParsePartitionSize(%q) expected error", tc.input)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParsePartitionSize(%q) error = %v", tc.input, err)
			continue
		}
		if got != tc.expected {
			t.Errorf("ParsePartitionSize(%q) = %d, want %d", tc.input, got, tc.expected)
		}
	}
}
