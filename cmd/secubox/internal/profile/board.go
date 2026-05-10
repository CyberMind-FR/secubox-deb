// cmd/secubox/internal/profile/board.go
package profile

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// Board represents a target hardware board
type Board struct {
	Name     string   `yaml:"name"`
	Arch     string   `yaml:"arch"`
	Tier     string   `yaml:"tier"`
	SOC      string   `yaml:"soc"`
	Hardware Hardware `yaml:"hardware"`
	Boot     Boot     `yaml:"boot"`
}

// Hardware defines the board's hardware specifications
type Hardware struct {
	RAM        string     `yaml:"ram"`
	EMMC       string     `yaml:"emmc,omitempty"`
	Interfaces Interfaces `yaml:"interfaces"`
}

// Interfaces defines network interface configuration
type Interfaces struct {
	WAN string   `yaml:"wan"`
	LAN []string `yaml:"lan"`
	SFP []string `yaml:"sfp,omitempty"`
}

// Boot defines boot configuration
type Boot struct {
	Method      string `yaml:"method"` // uboot, grub, rpi
	KernelImage string `yaml:"kernel_image"`
	DTS         string `yaml:"dts,omitempty"`
}

// Tweaks represents board-specific overrides
type Tweaks struct {
	Kernel   Kernel                 `yaml:"kernel,omitempty"`
	Sysctl   map[string]interface{} `yaml:"sysctl,omitempty"`
	Services Services               `yaml:"services,omitempty"`
}

// LoadBoard reads board configuration from a directory
func LoadBoard(boardDir string) (*Board, error) {
	path := filepath.Join(boardDir, "board.yaml")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read board.yaml: %w", err)
	}

	var b Board
	if err := yaml.Unmarshal(data, &b); err != nil {
		return nil, fmt.Errorf("parse board.yaml: %w", err)
	}

	return &b, nil
}

// LoadTweaks reads board-specific tweaks
func LoadTweaks(boardDir string) (*Tweaks, error) {
	path := filepath.Join(boardDir, "tweaks.yaml")
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &Tweaks{}, nil // No tweaks is valid
		}
		return nil, fmt.Errorf("read tweaks.yaml: %w", err)
	}

	var t Tweaks
	if err := yaml.Unmarshal(data, &t); err != nil {
		return nil, fmt.Errorf("parse tweaks.yaml: %w", err)
	}

	return &t, nil
}
