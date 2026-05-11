// cmd/secubox/main.go
package main

import (
	"os"

	"github.com/CyberMind-FR/secubox-deb/cmd/secubox/cmd"
)

// Build-time variables (set via -ldflags)
var (
	Version   = "dev"
	BuildTime = "unknown"
	Commit    = "unknown"
)

func main() {
	// Pass version info to cmd package
	cmd.SetVersionInfo(Version, BuildTime, Commit)

	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}
