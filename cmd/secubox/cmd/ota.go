// cmd/secubox/cmd/ota.go
package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/CyberMind-FR/secubox-deb/cmd/secubox/internal/ota"
	"github.com/spf13/cobra"
)

var (
	otaCheck    bool
	otaPackages bool
	otaSystem   bool
	otaAll      bool
	otaRollback bool
	otaDryRun   bool
	otaForce    bool
	otaChannel  string
	otaMarkOK   bool
	otaStatus   bool
)

var otaCmd = &cobra.Command{
	Use:   "ota",
	Short: "Over-The-Air updates with A/B partition support",
	Long: `Manage OTA updates for SecuBox using A/B partition scheme.

SecuBox uses an A/B partition layout for safe, rollback-capable updates:

  Partition Layout:
    1: ESP        256M   FAT32    /boot/efi
    2: root-a     6G     ext4     /           (active)
    3: root-b     6G     ext4     (inactive)
    4: data       rest   ext4     /srv        (persistent)

  Boot Control:
    /boot/efi/secubox/active       ← Contains "a" or "b"
    /boot/efi/secubox/fallback     ← Previous working slot
    /boot/efi/secubox/boot-count   ← Rollback after 3 failed boots

Examples:
  # Check for available updates
  secubox ota --check

  # Apply package updates only (no reboot needed)
  secubox ota --packages

  # Apply system update (kernel, dtb, bootloader) - requires reboot
  secubox ota --system

  # Full update (packages + system)
  secubox ota --all

  # Rollback to previous version
  secubox ota --rollback

  # Show current boot status
  secubox ota --status

  # Show what would be done (dry-run)
  secubox ota --all --dry-run

Note: System updates require root privileges.
Use: sudo secubox ota --system`,
	RunE: runOTA,
}

func init() {
	rootCmd.AddCommand(otaCmd)

	// Update actions
	otaCmd.Flags().BoolVar(&otaCheck, "check", false, "check for available updates")
	otaCmd.Flags().BoolVar(&otaPackages, "packages", false, "apply APT package updates (no reboot)")
	otaCmd.Flags().BoolVar(&otaSystem, "system", false, "apply kernel/boot update (A/B swap, requires reboot)")
	otaCmd.Flags().BoolVar(&otaAll, "all", false, "full update (packages + system)")
	otaCmd.Flags().BoolVar(&otaRollback, "rollback", false, "rollback to previous version")

	// Options
	otaCmd.Flags().BoolVar(&otaDryRun, "dry-run", false, "show what would be done without executing")
	otaCmd.Flags().BoolVarP(&otaForce, "force", "f", false, "force update even if no updates available")
	otaCmd.Flags().StringVar(&otaChannel, "channel", "stable", "release channel (stable, beta, nightly)")

	// Status and housekeeping
	otaCmd.Flags().BoolVar(&otaStatus, "status", false, "show current boot status")
	otaCmd.Flags().BoolVar(&otaMarkOK, "mark-ok", false, "mark current boot as successful (reset watchdog)")
}

func runOTA(cmd *cobra.Command, args []string) error {
	// Create OTA manager
	opts := &ota.Options{
		DryRun:  otaDryRun,
		Verbose: verbose,
		Force:   otaForce,
		Channel: otaChannel,
	}
	mgr := ota.NewManager(version, opts)

	// Count how many actions were requested
	actionCount := 0
	if otaCheck {
		actionCount++
	}
	if otaPackages {
		actionCount++
	}
	if otaSystem {
		actionCount++
	}
	if otaAll {
		actionCount++
	}
	if otaRollback {
		actionCount++
	}
	if otaStatus {
		actionCount++
	}
	if otaMarkOK {
		actionCount++
	}

	// If no action specified, show help
	if actionCount == 0 {
		return cmd.Help()
	}

	// Prevent conflicting actions
	if actionCount > 1 && !otaDryRun {
		// Allow --status with other flags for info
		if !otaStatus && !otaMarkOK {
			return fmt.Errorf("please specify only one action at a time")
		}
	}

	// Handle status display
	if otaStatus {
		return showStatus(mgr)
	}

	// Handle mark-ok
	if otaMarkOK {
		fmt.Println("Marking boot as successful...")
		if err := mgr.MarkBootSuccessful(); err != nil {
			return fmt.Errorf("mark boot successful: %w", err)
		}
		fmt.Println("Boot marked as successful, watchdog counter reset")
		return nil
	}

	// Handle check
	if otaCheck {
		return checkUpdates(mgr)
	}

	// Handle rollback
	if otaRollback {
		return performRollback(mgr)
	}

	// Handle updates
	if otaPackages || otaAll {
		if err := applyPackageUpdates(mgr); err != nil {
			return err
		}
	}

	if otaSystem || otaAll {
		if err := applySystemUpdate(mgr); err != nil {
			return err
		}
	}

	return nil
}

func showStatus(mgr *ota.Manager) error {
	state, err := mgr.GetStatus()
	if err != nil {
		return fmt.Errorf("get status: %w", err)
	}

	fmt.Printf("SecuBox OTA Status\n")
	fmt.Printf("==================\n\n")

	fmt.Printf("Boot State:\n")
	fmt.Printf("  Active slot:   %s (partition %d: %s)\n",
		strings.ToUpper(string(state.ActiveSlot)),
		state.ActiveSlot.PartitionNumber(),
		state.ActiveSlot.Label())
	fmt.Printf("  Fallback slot: %s (partition %d: %s)\n",
		strings.ToUpper(string(state.FallbackSlot)),
		state.FallbackSlot.PartitionNumber(),
		state.FallbackSlot.Label())
	fmt.Printf("  Boot count:    %d/%d\n", state.BootCount, ota.MaxBootCount)

	if state.IsRecovery {
		fmt.Printf("\n  WARNING: Boot count at maximum!\n")
		fmt.Printf("  System will auto-rollback on next failure.\n")
	}

	// Check if boot control exists
	if !ota.BootControlExists() {
		fmt.Printf("\n  NOTE: Boot control files not found.\n")
		fmt.Printf("  A/B partition updates may not be available.\n")
	}

	return nil
}

func checkUpdates(mgr *ota.Manager) error {
	fmt.Printf("SecuBox Update Check\n")
	fmt.Printf("====================\n\n")

	fmt.Printf("Checking for updates...\n\n")

	status, err := mgr.CheckUpdates()
	if err != nil {
		return fmt.Errorf("check updates: %w", err)
	}

	// Package updates
	fmt.Printf("Package Updates:\n")
	if status.PackagesAvailable {
		fmt.Printf("  Status:  %d packages available\n", status.PackageCount)
		if verbose && len(status.PackageList) > 0 {
			fmt.Printf("  Packages:\n")
			for _, pkg := range status.PackageList {
				fmt.Printf("    - %s\n", pkg)
			}
		}
		fmt.Printf("  Action:  secubox ota --packages\n")
	} else {
		fmt.Printf("  Status:  Up to date\n")
	}

	fmt.Println()

	// System updates
	fmt.Printf("System Updates:\n")
	fmt.Printf("  Current: %s\n", status.CurrentVersion)
	if status.SystemAvailable {
		fmt.Printf("  Latest:  %s\n", status.LatestVersion)
		fmt.Printf("  Status:  Update available\n")
		fmt.Printf("  Action:  secubox ota --system\n")
		if verbose && status.ReleaseURL != "" {
			fmt.Printf("  Release: %s\n", status.ReleaseURL)
		}
	} else {
		fmt.Printf("  Status:  Up to date\n")
	}

	fmt.Println()

	// Summary
	if status.PackagesAvailable || status.SystemAvailable {
		fmt.Printf("Summary: Updates are available\n")
		fmt.Printf("  Full update: secubox ota --all\n")
	} else {
		fmt.Printf("Summary: System is up to date\n")
	}

	return nil
}

func performRollback(mgr *ota.Manager) error {
	fmt.Printf("SecuBox Rollback\n")
	fmt.Printf("================\n\n")

	state, err := mgr.GetStatus()
	if err != nil {
		return fmt.Errorf("get status: %w", err)
	}

	fmt.Printf("Current state:\n")
	fmt.Printf("  Active slot:   %s\n", strings.ToUpper(string(state.ActiveSlot)))
	fmt.Printf("  Fallback slot: %s\n", strings.ToUpper(string(state.FallbackSlot)))
	fmt.Println()

	if otaDryRun {
		fmt.Printf("[DRY-RUN] Would swap:\n")
		fmt.Printf("  New active slot:   %s\n", strings.ToUpper(string(state.FallbackSlot)))
		fmt.Printf("  New fallback slot: %s\n", strings.ToUpper(string(state.ActiveSlot)))
		return nil
	}

	// Confirm rollback
	fmt.Printf("This will swap active and fallback slots.\n")
	fmt.Printf("After reboot, the system will boot from slot %s.\n\n", strings.ToUpper(string(state.FallbackSlot)))

	if !otaForce {
		fmt.Printf("Proceed with rollback? [y/N]: ")
		var response string
		fmt.Scanln(&response)
		if response != "y" && response != "Y" {
			fmt.Println("Rollback cancelled")
			return nil
		}
	}

	if err := mgr.Rollback(); err != nil {
		return fmt.Errorf("rollback: %w", err)
	}

	return nil
}

func applyPackageUpdates(mgr *ota.Manager) error {
	fmt.Printf("SecuBox Package Update\n")
	fmt.Printf("======================\n\n")

	if otaDryRun {
		fmt.Printf("[DRY-RUN] Commands that would be executed:\n")
		cmds := mgr.GetCommands(ota.UpdatePackages)
		for i, cmd := range cmds {
			fmt.Printf("  [%d] %s\n", i+1, cmd)
		}
		return nil
	}

	// Check for root privileges
	if os.Geteuid() != 0 {
		return fmt.Errorf("package updates require root privileges\nRun: sudo secubox ota --packages")
	}

	fmt.Println("Updating package lists...")
	fmt.Println()

	if err := mgr.ApplyPackageUpdates(); err != nil {
		return fmt.Errorf("apply package updates: %w", err)
	}

	fmt.Println()
	fmt.Println("Package updates complete!")
	return nil
}

func applySystemUpdate(mgr *ota.Manager) error {
	fmt.Printf("SecuBox System Update\n")
	fmt.Printf("=====================\n\n")

	if otaDryRun {
		fmt.Printf("[DRY-RUN] Steps that would be performed:\n")
		cmds := mgr.GetCommands(ota.UpdateSystem)
		for i, cmd := range cmds {
			fmt.Printf("  [%d] %s\n", i+1, cmd)
		}
		return nil
	}

	// Check for root privileges
	if os.Geteuid() != 0 {
		return fmt.Errorf("system updates require root privileges\nRun: sudo secubox ota --system")
	}

	// Check if A/B partitions are available
	if !ota.BootControlExists() {
		fmt.Printf("Warning: Boot control not initialized.\n")
		fmt.Printf("Initializing boot control files...\n\n")
		if err := ota.InitBootControl(); err != nil {
			return fmt.Errorf("initialize boot control: %w", err)
		}
	}

	state, err := mgr.GetStatus()
	if err != nil {
		return fmt.Errorf("get boot state: %w", err)
	}

	fmt.Printf("Current boot state:\n")
	fmt.Printf("  Active slot:   %s\n", strings.ToUpper(string(state.ActiveSlot)))
	fmt.Printf("  Fallback slot: %s\n", strings.ToUpper(string(state.FallbackSlot)))
	fmt.Printf("  Target slot:   %s (inactive)\n\n", strings.ToUpper(string(state.ActiveSlot.Opposite())))

	if !otaForce {
		fmt.Printf("This will write the update to the inactive partition.\n")
		fmt.Printf("A reboot will be required to activate the update.\n\n")
		fmt.Printf("Proceed with system update? [y/N]: ")
		var response string
		fmt.Scanln(&response)
		if response != "y" && response != "Y" {
			fmt.Println("Update cancelled")
			return nil
		}
	}

	fmt.Println()

	if err := mgr.ApplySystemUpdate(); err != nil {
		return fmt.Errorf("apply system update: %w", err)
	}

	return nil
}
