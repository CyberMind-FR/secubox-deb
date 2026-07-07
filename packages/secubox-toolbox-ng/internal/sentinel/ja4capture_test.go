// SPDX-License-Identifier: LicenseRef-CMSD-1.0
package sentinel

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestJA4CaptureDedupAndDisabled(t *testing.T) {
	// disabled (empty path) → nil, and Observe is a safe no-op
	var off *JA4Capture = NewJA4Capture("")
	off.Observe("h", "j") // must not panic

	p := filepath.Join(t.TempDir(), "ja4.tsv")
	c := NewJA4Capture(p)
	if c == nil {
		t.Fatal("expected a capture")
	}
	c.Observe("news.example", "t13d_browserfp")
	c.Observe("news.example", "t13d_browserfp") // dup → not written twice
	c.Observe("cdn.example", "t13d_browserfp")
	c.Observe("x", "") // empty ja4 → skipped
	c.Observe("", "y") // empty host → skipped
	b, _ := os.ReadFile(p)
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if len(lines) != 2 {
		t.Fatalf("want 2 unique lines, got %d: %q", len(lines), string(b))
	}
	if !strings.Contains(string(b), "news.example\tt13d_browserfp") {
		t.Errorf("missing host<TAB>ja4 line: %q", string(b))
	}
}
