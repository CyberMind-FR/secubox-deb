// cmd/secubox/cmd/clone_test.go
package cmd

import (
	"bytes"
	"os"
	"testing"
)

func TestCloneCmdHelp(t *testing.T) {
	cmd := rootCmd
	b := new(bytes.Buffer)
	cmd.SetOut(b)
	cmd.SetArgs([]string{"clone", "--help"})

	// Execute() returns nil when --help is used
	cmd.Execute()

	output := b.String()
	if !bytes.Contains([]byte(output), []byte("tier")) {
		t.Error("clone help should mention --tier flag")
	}
	if !bytes.Contains([]byte(output), []byte("minimal")) {
		t.Error("clone help should mention --minimal flag")
	}
}

func TestCloneRequiresRoot(t *testing.T) {
	// Skip if running as root
	if os.Geteuid() == 0 {
		t.Skip("test requires non-root user")
	}

	cmd := cloneCmd
	err := cmd.RunE(cmd, []string{})
	if err == nil {
		t.Error("clone should require root")
	}
	if !bytes.Contains([]byte(err.Error()), []byte("root")) {
		t.Errorf("error should mention root: %v", err)
	}
}
