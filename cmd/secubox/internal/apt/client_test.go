package apt

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestDownloadGPGKey(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("-----BEGIN PGP PUBLIC KEY BLOCK-----\ntest-key\n-----END PGP PUBLIC KEY BLOCK-----"))
	}))
	defer ts.Close()

	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "secubox.gpg")

	client := &Client{
		GPGKeyURL:  ts.URL + "/secubox.gpg",
		KeyringDir: tmpDir,
	}

	err := client.DownloadGPGKey()
	if err != nil {
		t.Fatalf("DownloadGPGKey() error = %v", err)
	}

	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		t.Errorf("GPG key file not created at %s", keyPath)
	}
}

func TestDownloadGPGKey_HTTPError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	tmpDir := t.TempDir()

	client := &Client{
		GPGKeyURL:  ts.URL + "/nonexistent.gpg",
		KeyringDir: tmpDir,
	}

	err := client.DownloadGPGKey()
	if err == nil {
		t.Error("DownloadGPGKey() should fail on HTTP 404")
	}
}

func TestDownloadGPGKey_VerifyContent(t *testing.T) {
	expectedContent := "-----BEGIN PGP PUBLIC KEY BLOCK-----\ntest-key\n-----END PGP PUBLIC KEY BLOCK-----"
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(expectedContent))
	}))
	defer ts.Close()

	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "secubox.gpg")

	client := &Client{
		GPGKeyURL:  ts.URL + "/secubox.gpg",
		KeyringDir: tmpDir,
	}

	err := client.DownloadGPGKey()
	if err != nil {
		t.Fatalf("DownloadGPGKey() error = %v", err)
	}

	content, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("failed to read key file: %v", err)
	}

	if string(content) != expectedContent {
		t.Errorf("key content = %q, want %q", content, expectedContent)
	}
}

func TestWriteSourcesList(t *testing.T) {
	tmpDir := t.TempDir()

	client := &Client{
		KeyringDir: "/usr/share/keyrings",
		SourcesDir: tmpDir,
		RepoURL:    "https://apt.secubox.in",
		Codename:   "bookworm",
		Component:  "main",
	}

	err := client.WriteSourcesList()
	if err != nil {
		t.Fatalf("WriteSourcesList() error = %v", err)
	}

	content, err := os.ReadFile(filepath.Join(tmpDir, "secubox.list"))
	if err != nil {
		t.Fatalf("read sources.list: %v", err)
	}

	expected := "deb [signed-by=/usr/share/keyrings/secubox.gpg] https://apt.secubox.in bookworm main\n"
	if string(content) != expected {
		t.Errorf("sources.list content = %q, want %q", content, expected)
	}
}

func TestNewClient(t *testing.T) {
	client := NewClient()

	if client.GPGKeyURL != DefaultGPGKeyURL {
		t.Errorf("GPGKeyURL = %q, want %q", client.GPGKeyURL, DefaultGPGKeyURL)
	}
	if client.KeyringDir != DefaultKeyringDir {
		t.Errorf("KeyringDir = %q, want %q", client.KeyringDir, DefaultKeyringDir)
	}
	if client.SourcesDir != DefaultSourcesDir {
		t.Errorf("SourcesDir = %q, want %q", client.SourcesDir, DefaultSourcesDir)
	}
	if client.RepoURL != DefaultRepoURL {
		t.Errorf("RepoURL = %q, want %q", client.RepoURL, DefaultRepoURL)
	}
	if client.Codename != DefaultCodename {
		t.Errorf("Codename = %q, want %q", client.Codename, DefaultCodename)
	}
	if client.Component != DefaultComponent {
		t.Errorf("Component = %q, want %q", client.Component, DefaultComponent)
	}
}

func TestSetup(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("-----BEGIN PGP PUBLIC KEY BLOCK-----\ntest-key\n-----END PGP PUBLIC KEY BLOCK-----"))
	}))
	defer ts.Close()

	tmpDir := t.TempDir()
	tmpSourcesDir := filepath.Join(tmpDir, "sources")
	tmpKeyringDir := filepath.Join(tmpDir, "keyring")

	client := &Client{
		GPGKeyURL:  ts.URL + "/secubox.gpg",
		KeyringDir: tmpKeyringDir,
		SourcesDir: tmpSourcesDir,
		RepoURL:    "https://apt.secubox.in",
		Codename:   "bookworm",
		Component:  "main",
	}

	err := client.Setup()
	if err != nil {
		t.Fatalf("Setup() error = %v", err)
	}

	// Verify GPG key was downloaded
	keyPath := filepath.Join(tmpKeyringDir, "secubox.gpg")
	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		t.Errorf("GPG key file not created at %s", keyPath)
	}

	// Verify sources.list was written
	sourcesPath := filepath.Join(tmpSourcesDir, "secubox.list")
	if _, err := os.Stat(sourcesPath); os.IsNotExist(err) {
		t.Errorf("sources.list file not created at %s", sourcesPath)
	}
}
