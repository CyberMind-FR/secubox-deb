// cmd/secubox/cmd/apt_test.go
package cmd

import (
	"bytes"
	"os"
	"testing"
)

func TestAptCmdHelp(t *testing.T) {
	cmd := rootCmd
	b := new(bytes.Buffer)
	cmd.SetOut(b)
	cmd.SetArgs([]string{"apt", "--help"})

	// Execute() returns nil when --help is used
	cmd.Execute()

	output := b.String()
	if !bytes.Contains([]byte(output), []byte("setup")) {
		t.Error("apt help should mention setup subcommand")
	}
	if !bytes.Contains([]byte(output), []byte("publish")) {
		t.Error("apt help should mention publish subcommand")
	}
}

func TestAptSetupRequiresRoot(t *testing.T) {
	// Skip if running as root
	if os.Geteuid() == 0 {
		t.Skip("test requires non-root user")
	}

	cmd := aptSetupCmd
	err := cmd.RunE(cmd, []string{})
	if err == nil {
		t.Error("apt setup should require root")
	}
	if !bytes.Contains([]byte(err.Error()), []byte("root")) {
		t.Errorf("error should mention root: %v", err)
	}
}
