// cmd/secubox/cmd/root.go
package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	cfgFile string
	verbose bool
	version = "2.8.0"
)

var rootCmd = &cobra.Command{
	Use:   "secubox",
	Short: "SecuBox Image Generator & Manager",
	Long: `SecuBox CLI tool for profile-based image generation,
building, fetching pre-built images, and OTA updates.

Version: ` + version,
}

func Execute() error {
	return rootCmd.Execute()
}

func init() {
	cobra.OnInitialize(initConfig)
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default: /etc/secubox/secubox.yaml)")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "verbose output")
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
