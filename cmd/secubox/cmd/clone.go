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
