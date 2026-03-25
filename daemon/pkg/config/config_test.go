package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadConfig(t *testing.T) {
	// Create temp config file
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "test.yaml")

	configData := `
node:
  role: edge
  did: "did:plc:test123"
  keypair: /etc/secubox/node.key
mesh:
  transport: wireguard
  subnet: 10.42.0.0/16
  mdns_service: _secubox._udp
  beacon_interval: 30
  peer_timeout: 120
telemetry:
  interval: 60
  db: /var/lib/secuboxd/telemetry.db
zkp:
  enabled: true
  rotation_hours: 24
`

	if err := os.WriteFile(configPath, []byte(configData), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(configPath)
	if err != nil {
		t.Fatalf("failed to load config: %v", err)
	}

	if cfg.Node.Role != "edge" {
		t.Errorf("expected role 'edge', got '%s'", cfg.Node.Role)
	}

	if cfg.Node.DID != "did:plc:test123" {
		t.Errorf("expected DID 'did:plc:test123', got '%s'", cfg.Node.DID)
	}

	if cfg.Mesh.Subnet != "10.42.0.0/16" {
		t.Errorf("expected subnet '10.42.0.0/16', got '%s'", cfg.Mesh.Subnet)
	}

	if cfg.Mesh.BeaconInterval != 30 {
		t.Errorf("expected beacon_interval 30, got %d", cfg.Mesh.BeaconInterval)
	}
}

func TestConfigValidation(t *testing.T) {
	tests := []struct {
		name    string
		config  Config
		wantErr bool
	}{
		{
			name: "valid edge role",
			config: Config{
				Node: NodeConfig{Role: "edge"},
			},
			wantErr: false,
		},
		{
			name: "valid relay role",
			config: Config{
				Node: NodeConfig{Role: "relay"},
			},
			wantErr: false,
		},
		{
			name: "valid air-gapped role",
			config: Config{
				Node: NodeConfig{Role: "air-gapped"},
			},
			wantErr: false,
		},
		{
			name: "invalid role",
			config: Config{
				Node: NodeConfig{Role: "invalid"},
			},
			wantErr: true,
		},
		{
			name: "invalid transport",
			config: Config{
				Node: NodeConfig{Role: "edge"},
				Mesh: MeshConfig{Transport: "openvpn"},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestApplyDefaults(t *testing.T) {
	cfg := &Config{}
	cfg.applyDefaults()

	if cfg.Node.Role != "edge" {
		t.Errorf("expected default role 'edge', got '%s'", cfg.Node.Role)
	}

	if cfg.Mesh.Transport != "wireguard" {
		t.Errorf("expected default transport 'wireguard', got '%s'", cfg.Mesh.Transport)
	}

	if cfg.Mesh.BeaconInterval != 30 {
		t.Errorf("expected default beacon_interval 30, got %d", cfg.Mesh.BeaconInterval)
	}

	if cfg.Telemetry.Interval != 60 {
		t.Errorf("expected default telemetry interval 60, got %d", cfg.Telemetry.Interval)
	}

	if cfg.ZKP.RotationHours != 24 {
		t.Errorf("expected default rotation_hours 24, got %d", cfg.ZKP.RotationHours)
	}
}
