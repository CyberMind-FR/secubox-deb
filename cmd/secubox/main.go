// cmd/secubox/main.go
package main

import (
	"os"

	"github.com/CyberMind-FR/secubox-deb/cmd/secubox/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}
