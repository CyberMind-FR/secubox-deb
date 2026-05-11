// cmd/secubox/internal/profile/merger.go
package profile

import (
	"fmt"
	"os"
	"path/filepath"
)

// Merger resolves profile inheritance chains.
//
// Merge semantics:
// - Packages.Required: union of parent + child, then subtract excluded
// - Packages.Excluded: union of parent + child
// - Kernel.Version: child overrides if set
// - Kernel.Modules.Enable: union of parent + child
// - Kernel.Modules.Blacklist: union of parent + child
// - Services.Enable: union of parent + child
// - Services.Disable: union of parent + child
// - Sysctl: merged map, child overrides parent keys
// - Features: child overrides parent for each field if set
// - Constraints: field-by-field merge, child overrides if set
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

// Resolve loads a profile and merges all inherited profiles.
// Returns error if circular inheritance is detected.
func (m *Merger) Resolve(name string) (*Profile, error) {
	return m.resolveWithPath(name, make(map[string]bool))
}

// ResolveWithArch resolves a tier profile with architecture layer inserted.
// Chain: base → arch/<arch> → tier → (optional tweaks)
// This is the recommended method for full profile resolution.
func (m *Merger) ResolveWithArch(tierName, arch string) (*Profile, error) {
	// First resolve base
	base, err := m.Resolve("base")
	if err != nil {
		return nil, fmt.Errorf("resolve base: %w", err)
	}

	// Check if arch profile exists
	archProfilePath := filepath.Join(m.profilesDir, "arch", arch+".yaml")
	var archProfile *Profile
	if _, statErr := os.Stat(archProfilePath); statErr == nil {
		// Load arch profile directly (don't follow its inherits, we already have base)
		archProfile, err = Load(archProfilePath)
		if err != nil {
			return nil, fmt.Errorf("load arch profile %s: %w", arch, err)
		}
	}

	// Load tier profile directly (don't follow its inherits, we build chain manually)
	tierProfilePath := filepath.Join(m.profilesDir, tierName+".yaml")
	tierProfile, err := Load(tierProfilePath)
	if err != nil {
		return nil, fmt.Errorf("load tier profile %s: %w", tierName, err)
	}

	// Build merge chain: base → arch → tier
	result := base
	if archProfile != nil {
		result = m.merge(result, archProfile)
	}
	result = m.merge(result, tierProfile)

	// Set final name/description from tier
	result.Name = tierProfile.Name
	result.Description = tierProfile.Description

	return result, nil
}

// resolveWithPath resolves with cycle detection via visited map
func (m *Merger) resolveWithPath(name string, visited map[string]bool) (*Profile, error) {
	// Check for circular inheritance
	if visited[name] {
		return nil, fmt.Errorf("circular inheritance detected: %s", name)
	}
	visited[name] = true

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

	// Resolve parent first (with visited map for cycle detection)
	parent, err := m.resolveWithPath(p.Inherits, visited)
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

	// Merge packages (combine required, union excluded)
	result.Packages.Required = append([]string{}, parent.Packages.Required...)
	result.Packages.Required = append(result.Packages.Required, child.Packages.Required...)
	result.Packages.Required = unique(result.Packages.Required)

	// Merge excluded from both parent and child
	result.Packages.Excluded = append([]string{}, parent.Packages.Excluded...)
	result.Packages.Excluded = append(result.Packages.Excluded, child.Packages.Excluded...)
	result.Packages.Excluded = unique(result.Packages.Excluded)

	// Remove excluded packages from required
	result.Packages.Required = subtract(result.Packages.Required, result.Packages.Excluded)

	// Kernel: merge carefully with nil checks
	result.Kernel.Version = parent.Kernel.Version
	if child.Kernel.Version != "" {
		result.Kernel.Version = child.Kernel.Version
	}

	// Initialize Modules.Enable before appending to avoid nil dereference
	result.Kernel.Modules.Enable = append([]string{}, parent.Kernel.Modules.Enable...)
	result.Kernel.Modules.Enable = append(result.Kernel.Modules.Enable, child.Kernel.Modules.Enable...)
	result.Kernel.Modules.Enable = unique(result.Kernel.Modules.Enable)

	// Merge Blacklist as well
	result.Kernel.Modules.Blacklist = append([]string{}, parent.Kernel.Modules.Blacklist...)
	result.Kernel.Modules.Blacklist = append(result.Kernel.Modules.Blacklist, child.Kernel.Modules.Blacklist...)
	result.Kernel.Modules.Blacklist = unique(result.Kernel.Modules.Blacklist)

	// Services: merge both enable and disable
	result.Services.Enable = append([]string{}, parent.Services.Enable...)
	result.Services.Enable = append(result.Services.Enable, child.Services.Enable...)
	result.Services.Enable = unique(result.Services.Enable)

	result.Services.Disable = append([]string{}, parent.Services.Disable...)
	result.Services.Disable = append(result.Services.Disable, child.Services.Disable...)
	result.Services.Disable = unique(result.Services.Disable)

	// Sysctl: merge maps
	result.Sysctl = make(map[string]interface{})
	for k, v := range parent.Sysctl {
		result.Sysctl[k] = v
	}
	for k, v := range child.Sysctl {
		result.Sysctl[k] = v
	}

	// Features: child overrides parent for each field
	// Note: DPI is interface{}, so nil check works for explicit nil but not for
	// distinguishing "not set" from "set to false". Current behavior: child nil = use parent.
	result.Features = parent.Features
	if child.Features.DPI != nil {
		result.Features.DPI = child.Features.DPI
	}
	if child.Features.Swap != "" {
		result.Features.Swap = child.Features.Swap
	}
	// LXC: true if either parent or child enables it
	result.Features.LXC = child.Features.LXC || parent.Features.LXC

	// Constraints: field-by-field merge
	result.Constraints.MinRAM = parent.Constraints.MinRAM
	if child.Constraints.MinRAM != "" {
		result.Constraints.MinRAM = child.Constraints.MinRAM
	}
	result.Constraints.MaxRAM = parent.Constraints.MaxRAM
	if child.Constraints.MaxRAM != "" {
		result.Constraints.MaxRAM = child.Constraints.MaxRAM
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
