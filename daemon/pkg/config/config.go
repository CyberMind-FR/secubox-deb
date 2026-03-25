// Package config handles YAML configuration loading and validation
// CyberMind — SecuBox-Deb — 2026
package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Config is the main secuboxd configuration structure
type Config struct {
	Node      NodeConfig      `yaml:"node"`
	Mesh      MeshConfig      `yaml:"mesh"`
	Tailscale TailscaleConfig `yaml:"tailscale"`
	Telemetry TelemetryConfig `yaml:"telemetry"`
	ZKP       ZKPConfig       `yaml:"zkp"`
}

// NodeConfig defines the local node settings
type NodeConfig struct {
	Role    string `yaml:"role"`    // edge | relay | air-gapped
	DID     string `yaml:"did"`     // did:plc:...
	Keypair string `yaml:"keypair"` // path to keypair file
}

// MeshConfig defines mesh network settings
type MeshConfig struct {
	Transport      string `yaml:"transport"`       // wireguard
	Subnet         string `yaml:"subnet"`          // 10.42.0.0/16
	MDNSService    string `yaml:"mdns_service"`    // _secubox._udp
	BeaconInterval int    `yaml:"beacon_interval"` // seconds
	PeerTimeout    int    `yaml:"peer_timeout"`    // seconds
}

// TailscaleConfig defines Tailscale integration
type TailscaleConfig struct {
	Enabled bool   `yaml:"enabled"`
	AuthKey string `yaml:"authkey"` // path to authkey file
}

// TelemetryConfig defines telemetry settings
type TelemetryConfig struct {
	Interval    int    `yaml:"interval"`     // seconds
	C3BoxSocket string `yaml:"c3box_socket"` // unix socket path
	DB          string `yaml:"db"`           // sqlite db path
}

// ZKPConfig defines ZKP Hamiltonian settings
type ZKPConfig struct {
	Enabled          bool   `yaml:"enabled"`
	RotationHours    int    `yaml:"rotation_hours"`
	HamiltonianGraph string `yaml:"hamiltonian_graph"` // path to graph JSON
}

// Load reads and parses configuration from a YAML file
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	cfg := &Config{}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("config validation failed: %w", err)
	}

	// Apply defaults
	cfg.applyDefaults()

	return cfg, nil
}

// Validate checks configuration values
func (c *Config) Validate() error {
	// Validate node role
	validRoles := map[string]bool{"edge": true, "relay": true, "air-gapped": true}
	if !validRoles[c.Node.Role] {
		return fmt.Errorf("invalid node role: %s (must be edge|relay|air-gapped)", c.Node.Role)
	}

	// Validate DID format
	if c.Node.DID != "" && len(c.Node.DID) < 10 {
		return fmt.Errorf("invalid DID format: %s", c.Node.DID)
	}

	// Validate mesh transport
	if c.Mesh.Transport != "" && c.Mesh.Transport != "wireguard" {
		return fmt.Errorf("unsupported mesh transport: %s (only wireguard supported)", c.Mesh.Transport)
	}

	return nil
}

// applyDefaults sets default values for unset fields
func (c *Config) applyDefaults() {
	if c.Node.Role == "" {
		c.Node.Role = "edge"
	}
	if c.Mesh.Transport == "" {
		c.Mesh.Transport = "wireguard"
	}
	if c.Mesh.Subnet == "" {
		c.Mesh.Subnet = "10.42.0.0/16"
	}
	if c.Mesh.MDNSService == "" {
		c.Mesh.MDNSService = "_secubox._udp"
	}
	if c.Mesh.BeaconInterval == 0 {
		c.Mesh.BeaconInterval = 30
	}
	if c.Mesh.PeerTimeout == 0 {
		c.Mesh.PeerTimeout = 120
	}
	if c.Telemetry.Interval == 0 {
		c.Telemetry.Interval = 60
	}
	if c.Telemetry.DB == "" {
		c.Telemetry.DB = "/var/lib/secuboxd/telemetry.db"
	}
	if c.ZKP.RotationHours == 0 {
		c.ZKP.RotationHours = 24
	}
}
