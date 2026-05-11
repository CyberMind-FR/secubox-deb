// cmd/secubox/internal/builder/builder.go
package builder

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/CyberMind-FR/secubox-deb/cmd/secubox/internal/manifest"
	"gopkg.in/yaml.v3"
)

// ValidStages lists all valid build stages in order
var ValidStages = []string{"rootfs", "partition", "boot", "compress", "checksums"}

// Package-level compiled regex for partition size parsing
var partitionSizeRe = regexp.MustCompile(`^(\d+)([KMGT])$`)

// Options holds builder configuration
type Options struct {
	Manifest     *manifest.Manifest
	OutputDir    string
	DryRun       bool
	ParallelJobs int
	Verbose      bool
}

// Builder orchestrates the build process
type Builder struct {
	manifest     *manifest.Manifest
	outputDir    string
	dryRun       bool
	parallelJobs int
	verbose      bool
}

// New creates a new Builder instance
func New(opts *Options) *Builder {
	jobs := opts.ParallelJobs
	if jobs < 1 {
		jobs = 1
	}

	return &Builder{
		manifest:     opts.Manifest,
		outputDir:    opts.OutputDir,
		dryRun:       opts.DryRun,
		parallelJobs: jobs,
		verbose:      opts.Verbose,
	}
}

// IsValidStage checks if a stage name is valid
func IsValidStage(name string) bool {
	for _, s := range ValidStages {
		if s == name {
			return true
		}
	}
	return false
}

// LoadManifest loads a manifest from a YAML file
func LoadManifest(path string) (*manifest.Manifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read manifest file: %w", err)
	}

	var m manifest.Manifest
	if err := yaml.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("parse manifest YAML: %w", err)
	}

	return &m, nil
}

// ParsePartitionSize parses human-readable partition sizes (e.g., "256M", "6G")
func ParsePartitionSize(size string) (int64, error) {
	if size == "" {
		return 0, fmt.Errorf("empty size string")
	}

	matches := partitionSizeRe.FindStringSubmatch(strings.ToUpper(size))
	if len(matches) != 3 {
		return 0, fmt.Errorf("invalid size format: %s", size)
	}

	value, err := strconv.ParseInt(matches[1], 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parse size value: %w", err)
	}

	multipliers := map[string]int64{
		"K": 1024,
		"M": 1024 * 1024,
		"G": 1024 * 1024 * 1024,
		"T": 1024 * 1024 * 1024 * 1024,
	}

	multiplier, ok := multipliers[matches[2]]
	if !ok {
		return 0, fmt.Errorf("unknown size suffix: %s", matches[2])
	}

	return value * multiplier, nil
}

// Run executes all build stages in order
func (b *Builder) Run() ([]string, error) {
	var allCmds []string

	for _, stage := range ValidStages {
		cmds, err := b.RunStage(stage)
		if err != nil {
			return allCmds, fmt.Errorf("stage %s: %w", stage, err)
		}
		allCmds = append(allCmds, cmds...)
	}

	return allCmds, nil
}

// RunStage executes a specific build stage
func (b *Builder) RunStage(stage string) ([]string, error) {
	if !IsValidStage(stage) {
		return nil, fmt.Errorf("invalid stage: %s (valid: %v)", stage, ValidStages)
	}

	var cmds []string
	var err error

	switch stage {
	case "rootfs":
		cmds, err = b.stageRootfs()
	case "partition":
		cmds, err = b.stagePartition()
	case "boot":
		cmds, err = b.stageBoot()
	case "compress":
		cmds, err = b.stageCompress()
	case "checksums":
		cmds, err = b.stageChecksums()
	default:
		return nil, fmt.Errorf("unimplemented stage: %s", stage)
	}

	if err != nil {
		return cmds, err
	}

	// If not dry-run, execute the commands
	if !b.dryRun {
		for _, cmd := range cmds {
			if b.verbose {
				fmt.Printf("+ %s\n", cmd)
			}
			if err := b.execCommand(cmd); err != nil {
				return cmds, fmt.Errorf("execute command: %w", err)
			}
		}
	}

	return cmds, nil
}

// execCommand executes a shell command with error handling
func (b *Builder) execCommand(cmd string) error {
	// Wrap command with 'set -e' for fail-fast behavior
	wrappedCmd := fmt.Sprintf("set -e\n%s", cmd)
	c := exec.Command("sh", "-c", wrappedCmd)
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr
	return c.Run()
}

// imagePath returns the path to the build image
func (b *Builder) imagePath() string {
	return filepath.Join(b.outputDir, fmt.Sprintf("secubox-%s.img", b.manifest.Board))
}

// rootfsPath returns the path to the rootfs directory
func (b *Builder) rootfsPath() string {
	return filepath.Join(b.outputDir, "rootfs")
}

// needsCrossCompile checks if cross-compilation is needed for ARM on x86
func (b *Builder) needsCrossCompile() bool {
	// Check if we're building ARM on a non-ARM host
	if b.manifest.Arch == "arm64" || b.manifest.Arch == "armhf" {
		// Check host architecture
		hostArch := os.Getenv("HOSTTYPE")
		if hostArch == "" {
			// Try to detect from uname
			out, err := exec.Command("uname", "-m").Output()
			if err == nil {
				hostArch = strings.TrimSpace(string(out))
			}
		}
		// If host is x86, we need cross-compilation
		if hostArch == "x86_64" || hostArch == "i686" || hostArch == "i386" {
			return true
		}
	}
	return false
}
