// cmd/secubox/cmd/info.go
package cmd

import (
	"encoding/json"
	"fmt"

	"github.com/CyberMind-FR/secubox-deb/cmd/secubox/internal/hardware"
	"github.com/spf13/cobra"
)

var (
	infoJSON bool
)

var infoCmd = &cobra.Command{
	Use:   "info",
	Short: "Show system and hardware information",
	Long: `Display detected hardware information and suggested build profile.

This command detects:
  - Board type (from device tree or DMI)
  - CPU architecture and model
  - RAM size
  - Suggested tier based on resources

Examples:
  # Show hardware info
  secubox info

  # Output as JSON
  secubox info --json`,
	RunE: runInfo,
}

func init() {
	rootCmd.AddCommand(infoCmd)
	infoCmd.Flags().BoolVar(&infoJSON, "json", false, "output as JSON")
}

func runInfo(cmd *cobra.Command, args []string) error {
	info, err := hardware.Detect()
	if err != nil {
		return fmt.Errorf("detect hardware: %w", err)
	}

	if infoJSON {
		// JSON output for scripting
		output := map[string]interface{}{
			"board":         info.Board,
			"arch":          info.Arch,
			"cpu_model":     info.CPUModel,
			"cpu_cores":     info.CPUCores,
			"ram_total_mb":  info.RAMTotalMB,
			"suggested_tier": info.SuggestTier(),
		}
		data, err := json.MarshalIndent(output, "", "  ")
		if err != nil {
			return fmt.Errorf("marshal JSON: %w", err)
		}
		fmt.Println(string(data))
		return nil
	}

	fmt.Println(info.String())
	return nil
}
