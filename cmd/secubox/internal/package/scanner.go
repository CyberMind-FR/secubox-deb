// cmd/secubox/internal/package/scanner.go
package pkgscan

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// Scanner scans packages directory for debian/secubox.yaml files
type Scanner struct {
	packagesDir string
}

// NewScanner creates a new package scanner for the given packages directory
func NewScanner(packagesDir string) *Scanner {
	return &Scanner{packagesDir: packagesDir}
}

// Scan reads all debian/secubox.yaml files from secubox-* directories
// and returns a map of component name to Component
func (s *Scanner) Scan() (map[string]*Component, error) {
	components := make(map[string]*Component)

	entries, err := os.ReadDir(s.packagesDir)
	if err != nil {
		return nil, fmt.Errorf("read packages dir: %w", err)
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		// Only scan directories starting with "secubox-"
		if !strings.HasPrefix(entry.Name(), "secubox-") {
			continue
		}

		metaPath := filepath.Join(s.packagesDir, entry.Name(), "debian", "secubox.yaml")
		if _, err := os.Stat(metaPath); os.IsNotExist(err) {
			continue // No secubox.yaml, skip this package
		}

		data, err := os.ReadFile(metaPath)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", metaPath, err)
		}

		var c Component
		if err := yaml.Unmarshal(data, &c); err != nil {
			return nil, fmt.Errorf("parse %s: %w", metaPath, err)
		}

		components[c.Name] = &c
	}

	return components, nil
}

// GetComponent returns a specific component by package name
func (s *Scanner) GetComponent(name string) (*Component, error) {
	metaPath := filepath.Join(s.packagesDir, name, "debian", "secubox.yaml")
	data, err := os.ReadFile(metaPath)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", metaPath, err)
	}

	var c Component
	if err := yaml.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("parse %s: %w", metaPath, err)
	}

	return &c, nil
}
