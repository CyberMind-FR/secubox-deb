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
