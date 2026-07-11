package sentinel

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func writeLines(t *testing.T, path string, lines ...string) {
	t.Helper()
	body := ""
	for _, l := range lines {
		body += l + "\n"
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestC2AllowSuffixAndLan(t *testing.T) {
	dir := t.TempDir()
	allow := filepath.Join(dir, "c2-allow.txt")
	box := filepath.Join(dir, "haproxy-routes.json")
	writeLines(t, allow, "mail.example.com", "# comment", "", "monitoring.example.org")
	os.WriteFile(box, []byte(`{"admin.gk2.secubox.in":["127.0.0.1",9080],"dash.gk2.secubox.in":["127.0.0.1",9081]}`), 0o644)

	a := NewC2Allow(allow, box)
	cases := []struct {
		host string
		want bool
	}{
		{"mail.example.com", true},        // exact allow
		{"imap.mail.example.com", true},   // subdomain of allow entry
		{"monitoring.example.org", true},  // second allow entry
		{"admin.gk2.secubox.in", true},    // box vhost (haproxy key)
		{"api.dash.gk2.secubox.in", true}, // subdomain of box vhost
		{"192.168.1.50", true},            // RFC1918 literal
		{"127.0.0.1", true},               // loopback literal
		{"10.10.0.2", true},               // RFC1918 literal
		{"evil-c2-xyz.example", false},    // unknown → not allowed
		{"", true},                        // empty host → treat as allowed (never learn a blank)
	}
	for _, c := range cases {
		if got := a.Allowed(c.host); got != c.want {
			t.Errorf("Allowed(%q)=%v want %v", c.host, got, c.want)
		}
	}
}

func TestC2AllowFailSafeMissingFiles(t *testing.T) {
	a := NewC2Allow("/nonexistent/allow.txt", "/nonexistent/box.json")
	if !a.Allowed("192.168.0.1") {
		t.Error("RFC1918 must be allowed even with no files")
	}
	if a.Allowed("evil.example") {
		t.Error("unknown host must not be allowed when files are missing")
	}
}

func TestC2AllowAddAppends(t *testing.T) {
	dir := t.TempDir()
	allow := filepath.Join(dir, "c2-allow.txt")
	writeLines(t, allow, "seed.example")
	a := NewC2Allow(allow, "")
	if err := a.Add("newfp.example"); err != nil {
		t.Fatal(err)
	}
	a.Reload()
	if !a.Allowed("newfp.example") {
		t.Error("added host must be allowed after Add+Reload")
	}
	if !a.Allowed("seed.example") {
		t.Error("seed host must remain allowed")
	}
}

func TestC2AllowAddRejectsInjection(t *testing.T) {
	dir := t.TempDir()
	allow := filepath.Join(dir, "c2-allow.txt")
	writeLines(t, allow, "seed.example")
	a := NewC2Allow(allow, "")
	a.Add("good.com\nevil.com")
	a.Reload()
	if a.Allowed("evil.com") {
		t.Error("newline-injected second host must not be added")
	}
}

func TestC2AllowAddRejectsBareTLD(t *testing.T) {
	dir := t.TempDir()
	allow := filepath.Join(dir, "c2-allow.txt")
	writeLines(t, allow, "seed.example")
	a := NewC2Allow(allow, "")

	if err := a.Add("com"); err != nil {
		t.Fatal(err)
	}
	if err := a.Add("localhost"); err != nil {
		t.Fatal(err)
	}
	a.Reload()

	if a.Allowed("anything.com") {
		t.Error("bare TLD 'com' must not have been added — it would blind-match the entire TLD")
	}
	if a.Allowed("evil.localhost") {
		t.Error("bare single-label 'localhost' must not have been added")
	}
	// existing dotted entry still works
	if !a.Allowed("seed.example") {
		t.Error("seed host must remain allowed after rejected bare-TLD Adds")
	}
}

func TestC2AllowAddConcurrent(t *testing.T) {
	dir := t.TempDir()
	allow := filepath.Join(dir, "c2-allow.txt")
	writeLines(t, allow, "seed.example")
	a := NewC2Allow(allow, "")
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(n int) { defer wg.Done(); a.Add(fmt.Sprintf("h%d.example", n)) }(i)
	}
	wg.Wait()
	a.Reload()
	for i := 0; i < 20; i++ {
		if !a.Allowed(fmt.Sprintf("h%d.example", i)) {
			t.Errorf("concurrent Add lost h%d.example", i)
		}
	}
}

func TestAtomicWriteFileRelativePathAndNoLeak(t *testing.T) {
	dir := t.TempDir()
	// relative path (no slash) must still write correctly next to CWD-safe temp
	p := filepath.Join(dir, "sub.json")
	if err := atomicWriteFile(p, []byte("x"), 0o640); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(p); string(b) != "x" {
		t.Error("atomicWriteFile did not write content")
	}
	// rename onto an existing directory fails → temp must be cleaned up
	d := filepath.Join(dir, "adir")
	os.Mkdir(d, 0o755)
	_ = atomicWriteFile(d, []byte("y"), 0o640) // rename file→dir fails
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".c2tmp-") {
			t.Errorf("leaked temp file %s after failed rename", e.Name())
		}
	}
}
