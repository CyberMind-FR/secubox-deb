// cmd/secubox/internal/profile/profile.go
package profile

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Profile represents a SecuBox image profile configuration
type Profile struct {
	Name        string                 `yaml:"name"`
	Inherits    string                 `yaml:"inherits,omitempty"`
	Description string                 `yaml:"description"`
	Constraints Constraints            `yaml:"constraints,omitempty"`
	Packages    Packages               `yaml:"packages,omitempty"`
	Kernel      Kernel                 `yaml:"kernel,omitempty"`
	Services    Services               `yaml:"services,omitempty"`
	Sysctl      map[string]interface{} `yaml:"sysctl,omitempty"`
	Features    Features               `yaml:"features,omitempty"`
}

// Constraints defines hardware requirements for the profile
type Constraints struct {
	MinRAM string `yaml:"min_ram,omitempty"`
	MaxRAM string `yaml:"max_ram,omitempty"`
}

// Packages defines required and excluded packages
type Packages struct {
	Required []string `yaml:"required,omitempty"`
	Excluded []string `yaml:"excluded,omitempty"`
}

// Kernel defines kernel version and module configuration
type Kernel struct {
	Version string        `yaml:"version,omitempty"`
	Modules KernelModules `yaml:"modules,omitempty"`
}

// KernelModules defines modules to enable or blacklist
type KernelModules struct {
	Enable    []string `yaml:"enable,omitempty"`
	Blacklist []string `yaml:"blacklist,omitempty"`
}

// Services defines systemd services to enable or disable
type Services struct {
	Enable  []string `yaml:"enable,omitempty"`
	Disable []string `yaml:"disable,omitempty"`
}

// Features defines optional feature flags
type Features struct {
	DPI  interface{} `yaml:"dpi,omitempty"`
	LXC  bool        `yaml:"lxc,omitempty"`
	Swap string      `yaml:"swap,omitempty"`
}

// Load reads and parses a profile YAML file
func Load(path string) (*Profile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read profile %s: %w", path, err)
	}

	var p Profile
	if err := yaml.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("parse profile %s: %w", path, err)
	}

	return &p, nil
}
