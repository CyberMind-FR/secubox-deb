// cmd/secubox/cmd/root.go
package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	cfgFile   string
	verbose   bool
	version   = "2.8.0"
	buildTime = "unknown"
	commit    = "unknown"
)

// SetVersionInfo sets build-time version information
func SetVersionInfo(v, bt, c string) {
	if v != "" {
		version = v
	}
	if bt != "" {
		buildTime = bt
	}
	if c != "" {
		commit = c
	}
}

var rootCmd = &cobra.Command{
	Use:   "secubox",
	Short: "SecuBox Image Generator & Manager",
	Long: `SecuBox CLI tool for profile-based image generation,
building, fetching pre-built images, and OTA updates.`,
	Version: version,
}

func Execute() error {
	return rootCmd.Execute()
}

func init() {
	cobra.OnInitialize(initConfig)
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default: /etc/secubox/secubox.yaml)")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "verbose output")

	// Set version template
	rootCmd.SetVersionTemplate(fmt.Sprintf("secubox version %s\nBuild: %s\nCommit: %s\n", version, buildTime, commit))
}

func initConfig() {
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		viper.SetConfigName("secubox")
		viper.SetConfigType("yaml")
		viper.AddConfigPath("/etc/secubox")
		viper.AddConfigPath("$HOME/.secubox")
		viper.AddConfigPath(".")
	}
	viper.AutomaticEnv()
	if err := viper.ReadInConfig(); err == nil && verbose {
		fmt.Fprintln(os.Stderr, "Using config file:", viper.ConfigFileUsed())
	}
}
