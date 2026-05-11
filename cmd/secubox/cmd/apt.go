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
