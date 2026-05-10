// cmd/secubox/internal/package/component.go
package pkgscan

// Component represents a SecuBox package's metadata from debian/secubox.yaml
type Component struct {
	Name         string            `yaml:"name"`
	Category     string            `yaml:"category"`
	Description  map[string]string `yaml:"description"`
	Requirements Requirements      `yaml:"requirements"`
	Tags         []string          `yaml:"tags"`
	Conflicts    []string          `yaml:"conflicts,omitempty"`
	Services     []string          `yaml:"services,omitempty"`
	Ports        []string          `yaml:"ports,omitempty"`
	Modes        map[string]Mode   `yaml:"modes,omitempty"`
}

// Requirements defines hardware and system requirements for the package
type Requirements struct {
	MinRAM        string   `yaml:"min_ram,omitempty"`
	Arch          []string `yaml:"arch,omitempty"`
	Features      []string `yaml:"features,omitempty"`
	KernelModules []string `yaml:"kernel_modules,omitempty"`
}

// Mode defines a specific operational mode for the package
type Mode struct {
	MinRAM      string `yaml:"min_ram,omitempty"`
	Description string `yaml:"description,omitempty"`
}

// SupportsArch checks if the component supports the given architecture.
// If no architecture restrictions are defined, all architectures are supported.
func (c *Component) SupportsArch(arch string) bool {
	if len(c.Requirements.Arch) == 0 {
		return true // No restriction means all archs supported
	}
	for _, a := range c.Requirements.Arch {
		if a == arch {
			return true
		}
	}
	return false
}
