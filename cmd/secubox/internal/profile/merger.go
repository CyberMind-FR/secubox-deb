// cmd/secubox/internal/profile/merger.go
package profile

import (
	"fmt"
	"path/filepath"
)

// Merger resolves profile inheritance
type Merger struct {
	profilesDir string
	cache       map[string]*Profile
}

// NewMerger creates a new profile merger
func NewMerger(profilesDir string) *Merger {
	return &Merger{
		profilesDir: profilesDir,
		cache:       make(map[string]*Profile),
	}
}

// Resolve loads a profile and merges all inherited profiles
func (m *Merger) Resolve(name string) (*Profile, error) {
	// Check cache
	if p, ok := m.cache[name]; ok {
		return p, nil
	}

	// Load profile
	path := filepath.Join(m.profilesDir, name+".yaml")
	p, err := Load(path)
	if err != nil {
		return nil, fmt.Errorf("load profile %s: %w", name, err)
	}

	// If no inheritance, return as-is
	if p.Inherits == "" {
		m.cache[name] = p
		return p, nil
	}

	// Resolve parent first
	parent, err := m.Resolve(p.Inherits)
	if err != nil {
		return nil, fmt.Errorf("resolve parent %s: %w", p.Inherits, err)
	}

	// Merge parent into child
	merged := m.merge(parent, p)
	m.cache[name] = merged
	return merged, nil
}

// merge combines parent and child profiles (child overrides parent)
func (m *Merger) merge(parent, child *Profile) *Profile {
	result := &Profile{
		Name:        child.Name,
		Description: child.Description,
	}

	// Merge packages (combine required, child excluded wins)
	result.Packages.Required = append([]string{}, parent.Packages.Required...)
	result.Packages.Required = append(result.Packages.Required, child.Packages.Required...)
	result.Packages.Required = unique(result.Packages.Required)
	result.Packages.Excluded = child.Packages.Excluded

	// Remove excluded packages from required
	result.Packages.Required = subtract(result.Packages.Required, result.Packages.Excluded)

	// Kernel: child overrides or inherits
	result.Kernel = parent.Kernel
	if child.Kernel.Version != "" {
		result.Kernel.Version = child.Kernel.Version
	}
	if len(child.Kernel.Modules.Enable) > 0 {
		result.Kernel.Modules.Enable = append(result.Kernel.Modules.Enable, child.Kernel.Modules.Enable...)
	}
	if len(child.Kernel.Modules.Blacklist) > 0 {
		result.Kernel.Modules.Blacklist = child.Kernel.Modules.Blacklist
	}

	// Services: merge
	result.Services.Enable = append(parent.Services.Enable, child.Services.Enable...)
	result.Services.Enable = unique(result.Services.Enable)
	result.Services.Disable = child.Services.Disable

	// Sysctl: merge maps
	result.Sysctl = make(map[string]interface{})
	for k, v := range parent.Sysctl {
		result.Sysctl[k] = v
	}
	for k, v := range child.Sysctl {
		result.Sysctl[k] = v
	}

	// Features: child overrides
	result.Features = parent.Features
	if child.Features.DPI != nil {
		result.Features.DPI = child.Features.DPI
	}
	if child.Features.Swap != "" {
		result.Features.Swap = child.Features.Swap
	}
	// LXC: explicit check since false is valid
	result.Features.LXC = child.Features.LXC || parent.Features.LXC

	// Constraints: child overrides
	result.Constraints = child.Constraints
	if result.Constraints.MinRAM == "" {
		result.Constraints.MinRAM = parent.Constraints.MinRAM
	}

	return result
}

// unique removes duplicates from a slice
func unique(s []string) []string {
	seen := make(map[string]bool)
	result := []string{}
	for _, v := range s {
		if !seen[v] {
			seen[v] = true
			result = append(result, v)
		}
	}
	return result
}

// subtract removes items in b from a
func subtract(a, b []string) []string {
	exclude := make(map[string]bool)
	for _, v := range b {
		exclude[v] = true
	}
	result := []string{}
	for _, v := range a {
		if !exclude[v] {
			result = append(result, v)
		}
	}
	return result
}
