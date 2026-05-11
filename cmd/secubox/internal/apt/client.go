/*
SecuBox-Deb :: APT Client
CyberMind — https://cybermind.fr
Author: Gérald Kerma <gandalf@gk2.net>
License: Proprietary / ANSSI CSPN candidate
*/

package apt

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

const (
	DefaultGPGKeyURL  = "https://apt.secubox.in/secubox.gpg"
	DefaultKeyringDir = "/usr/share/keyrings"
	DefaultSourcesDir = "/etc/apt/sources.list.d"
	DefaultRepoURL    = "https://apt.secubox.in"
	DefaultCodename   = "bookworm"
	DefaultComponent  = "main"
)

// Client manages APT repository configuration
type Client struct {
	GPGKeyURL  string
	KeyringDir string
	SourcesDir string
	RepoURL    string
	Codename   string
	Component  string
}

// NewClient creates a new APT client with default configuration
func NewClient() *Client {
	return &Client{
		GPGKeyURL:  DefaultGPGKeyURL,
		KeyringDir: DefaultKeyringDir,
		SourcesDir: DefaultSourcesDir,
		RepoURL:    DefaultRepoURL,
		Codename:   DefaultCodename,
		Component:  DefaultComponent,
	}
}

// DownloadGPGKey downloads the SecuBox GPG signing key
func (c *Client) DownloadGPGKey() error {
	keyPath := filepath.Join(c.KeyringDir, "secubox.gpg")

	var lastErr error
	for attempt := 1; attempt <= 3; attempt++ {
		if attempt > 1 {
			time.Sleep(2 * time.Second)
		}

		resp, err := http.Get(c.GPGKeyURL)
		if err != nil {
			lastErr = fmt.Errorf("download GPG key (attempt %d): %w", attempt, err)
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			lastErr = fmt.Errorf("download GPG key: HTTP %d", resp.StatusCode)
			continue
		}

		data, err := io.ReadAll(resp.Body)
		if err != nil {
			lastErr = fmt.Errorf("read GPG key: %w", err)
			continue
		}

		if err := os.MkdirAll(c.KeyringDir, 0755); err != nil {
			return fmt.Errorf("create keyring dir: %w", err)
		}

		if err := os.WriteFile(keyPath, data, 0644); err != nil {
			return fmt.Errorf("write GPG key: %w", err)
		}

		return nil
	}

	return lastErr
}

// WriteSourcesList writes the APT sources.list configuration
func (c *Client) WriteSourcesList() error {
	if err := os.MkdirAll(c.SourcesDir, 0755); err != nil {
		return fmt.Errorf("create sources dir: %w", err)
	}

	content := fmt.Sprintf("deb [signed-by=%s/secubox.gpg] %s %s %s\n",
		c.KeyringDir, c.RepoURL, c.Codename, c.Component)

	path := filepath.Join(c.SourcesDir, "secubox.list")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		return fmt.Errorf("write sources.list: %w", err)
	}

	return nil
}

// Setup performs complete APT repository setup
func (c *Client) Setup() error {
	if err := c.DownloadGPGKey(); err != nil {
		return fmt.Errorf("download GPG key: %w", err)
	}

	if err := c.WriteSourcesList(); err != nil {
		return fmt.Errorf("write sources.list: %w", err)
	}

	return nil
}
