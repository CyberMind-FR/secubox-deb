// cmd/secubox/cmd/build.go
package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/CyberMind-FR/secubox-deb/cmd/secubox/internal/builder"
	"github.com/spf13/cobra"
)

var (
	buildManifest string
	buildStage    string
	buildDryRun   bool
	buildJobs     int
	buildOutput   string
)

var buildCmd = &cobra.Command{
	Use:   "build",
	Short: "Build SecuBox image from manifest",
	Long: `Build a SecuBox disk image from a manifest.yaml file.

The build process runs through multiple stages:
  1. rootfs    - Create root filesystem with debootstrap
  2. partition - Create disk image with GPT partitions
  3. boot      - Install bootloader (U-Boot/GRUB)
  4. compress  - Compress image (gzip/xz)
  5. checksums - Generate checksums (SHA256/SHA512)

Examples:
  # Build from manifest in current directory
  secubox build

  # Build from specific manifest
  secubox build --manifest /path/to/manifest.yaml

  # Run only the rootfs stage
  secubox build --stage rootfs

  # Show what would be done (dry-run)
  secubox build --dry-run

  # Build with 4 parallel jobs
  secubox build -j 4

Note: Building requires root privileges for debootstrap, losetup, and mount operations.
Use: sudo secubox build`,
	RunE: runBuild,
}

func init() {
	rootCmd.AddCommand(buildCmd)
	buildCmd.Flags().StringVarP(&buildManifest, "manifest", "m", "", "path to manifest.yaml (default: ./manifest.yaml)")
	buildCmd.Flags().StringVarP(&buildStage, "stage", "s", "", "run only specific stage (rootfs, partition, boot, compress, checksums)")
	buildCmd.Flags().BoolVar(&buildDryRun, "dry-run", false, "show commands without executing")
	buildCmd.Flags().IntVarP(&buildJobs, "jobs", "j", 1, "number of parallel jobs for compression")
	buildCmd.Flags().StringVarP(&buildOutput, "output", "o", "./build", "output directory for build artifacts")
}

func runBuild(cmd *cobra.Command, args []string) error {
	// Find manifest file
	manifestPath := buildManifest
	if manifestPath == "" {
		// Look for manifest.yaml in current directory
		cwd, err := os.Getwd()
		if err != nil {
			return fmt.Errorf("get working directory: %w", err)
		}
		manifestPath = filepath.Join(cwd, "manifest.yaml")
	}

	// Check manifest exists
	if _, err := os.Stat(manifestPath); os.IsNotExist(err) {
		return fmt.Errorf("manifest not found: %s\nRun 'secubox gen' first to create a manifest", manifestPath)
	}

	// Load manifest
	m, err := builder.LoadManifest(manifestPath)
	if err != nil {
		return fmt.Errorf("load manifest: %w", err)
	}

	// Validate stage if specified
	if buildStage != "" && !builder.IsValidStage(buildStage) {
		return fmt.Errorf("invalid stage: %s\nValid stages: %s", buildStage, strings.Join(builder.ValidStages, ", "))
	}

	// Resolve output directory
	outputDir := buildOutput
	if !filepath.IsAbs(outputDir) {
		cwd, err := os.Getwd()
		if err != nil {
			return fmt.Errorf("get working directory for output: %w", err)
		}
		outputDir = filepath.Join(cwd, outputDir)
	}

	// Create builder
	opts := &builder.Options{
		Manifest:     m,
		OutputDir:    outputDir,
		DryRun:       buildDryRun,
		ParallelJobs: buildJobs,
		Verbose:      verbose,
	}
	b := builder.New(opts)

	// Print build info
	fmt.Printf("SecuBox Build\n")
	fmt.Printf("  Board:    %s\n", m.Board)
	fmt.Printf("  Arch:     %s\n", m.Arch)
	fmt.Printf("  Tier:     %s\n", m.Tier)
	fmt.Printf("  Packages: %d\n", len(m.Packages))
	fmt.Printf("  Output:   %s\n", outputDir)
	if buildDryRun {
		fmt.Printf("  Mode:     DRY-RUN\n")
	}
	fmt.Println()

	// Create output directory if not dry-run
	if !buildDryRun {
		if err := os.MkdirAll(outputDir, 0755); err != nil {
			return fmt.Errorf("create output directory: %w", err)
		}
	}

	// Run build
	var cmds []string
	if buildStage != "" {
		// Run single stage
		fmt.Printf("Running stage: %s\n", buildStage)
		cmds, err = b.RunStage(buildStage)
	} else {
		// Run all stages
		fmt.Printf("Running all stages: %s\n", strings.Join(builder.ValidStages, " -> "))
		cmds, err = b.Run()
	}

	// In dry-run mode, print commands
	if buildDryRun {
		fmt.Println("\n--- Commands that would be executed ---")
		for i, c := range cmds {
			fmt.Printf("[%d] %s\n", i+1, c)
		}
		fmt.Println("--- End of commands ---")
		return nil
	}

	if err != nil {
		return fmt.Errorf("build failed: %w", err)
	}

	fmt.Printf("\nBuild complete!\n")
	fmt.Printf("Image: %s/secubox-%s.img\n", outputDir, m.Board)

	return nil
}
