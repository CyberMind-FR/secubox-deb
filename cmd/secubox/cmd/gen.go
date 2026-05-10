// cmd/secubox/cmd/gen.go
package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/CyberMind-FR/secubox-deb/cmd/secubox/internal/manifest"
	"github.com/CyberMind-FR/secubox-deb/cmd/secubox/internal/profile"
	"github.com/CyberMind-FR/secubox-deb/cmd/secubox/internal/wizard"
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

	// Write output files
	return writeOutput(m)
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

	// Initialize sysctl map if nil
	if p.Sysctl == nil {
		p.Sysctl = make(map[string]interface{})
	}

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

// writeOutput writes the manifest and Makefile to the output directory
func writeOutput(m *manifest.Manifest) error {
	// Create output directory if needed
	if err := os.MkdirAll(genOut, 0755); err != nil {
		return fmt.Errorf("create output directory: %w", err)
	}

	// Write manifest.yaml
	manifestPath := filepath.Join(genOut, "manifest.yaml")
	manifestData, err := m.ToYAML()
	if err != nil {
		return fmt.Errorf("serialize manifest: %w", err)
	}
	if err := os.WriteFile(manifestPath, manifestData, 0644); err != nil {
		return fmt.Errorf("write manifest: %w", err)
	}
	fmt.Printf("Generated: %s\n", manifestPath)

	// Write Makefile
	makefilePath := filepath.Join(genOut, "Makefile")
	makefileData := manifest.GenerateMakefile(m)
	if err := os.WriteFile(makefilePath, []byte(makefileData), 0644); err != nil {
		return fmt.Errorf("write Makefile: %w", err)
	}
	fmt.Printf("Generated: %s\n", makefilePath)

	fmt.Printf("\nNext: cd %s && make image\n", genOut)
	return nil
}

// runWizard launches the interactive wizard for configuration
func runWizard(repoRoot string) error {
	opts, err := wizard.Run(repoRoot)
	if err != nil {
		return fmt.Errorf("wizard: %w", err)
	}

	// Set global flags from wizard results
	genBoard = opts.Board
	genTier = opts.Tier
	genEnable = opts.Enable

	// Load board configuration
	boardDir := filepath.Join(repoRoot, "board", genBoard)
	board, err := profile.LoadBoard(boardDir)
	if err != nil {
		return fmt.Errorf("load board %s: %w", genBoard, err)
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

	// Add packages from wizard
	for _, pkg := range genEnable {
		prof.Packages.Required = append(prof.Packages.Required, "secubox-"+pkg)
	}

	// Generate manifest
	m := manifest.Generate(prof, board, version)

	// Update formats from wizard if specified
	if len(opts.Formats) > 0 {
		m.Output.Formats = opts.Formats
	}

	// Write output files
	return writeOutput(m)
}
