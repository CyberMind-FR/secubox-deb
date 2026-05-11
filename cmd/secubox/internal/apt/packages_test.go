package apt

import "testing"

func TestTierPackages(t *testing.T) {
	tests := []struct {
		tier     string
		wantPkg  string
		wantErr  bool
	}{
		{"lite", "secubox-lite", false},
		{"standard", "secubox-standard", false},
		{"pro", "secubox-full", false},
		{"minimal", "secubox-core", false},
		{"invalid", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.tier, func(t *testing.T) {
			pkgs, err := TierPackages(tt.tier)
			if (err != nil) != tt.wantErr {
				t.Errorf("TierPackages(%q) error = %v, wantErr %v", tt.tier, err, tt.wantErr)
				return
			}
			if tt.wantPkg != "" && len(pkgs) > 0 && pkgs[0] != tt.wantPkg {
				t.Errorf("TierPackages(%q)[0] = %v, want %q", tt.tier, pkgs[0], tt.wantPkg)
			}
		})
	}
}

func TestValidateTier(t *testing.T) {
	tests := []struct {
		tier string
		want bool
	}{
		{"lite", true},
		{"standard", true},
		{"pro", true},
		{"minimal", true},
		{"custom", false},
		{"invalid", false},
	}

	for _, tt := range tests {
		t.Run(tt.tier, func(t *testing.T) {
			if got := ValidateTier(tt.tier); got != tt.want {
				t.Errorf("ValidateTier(%q) = %v, want %v", tt.tier, got, tt.want)
			}
		})
	}
}

func TestTierNames(t *testing.T) {
	names := TierNames()
	expected := []string{"lite", "standard", "pro", "minimal", "custom"}

	if len(names) != len(expected) {
		t.Errorf("TierNames() len = %d, want %d", len(names), len(expected))
	}

	for i, name := range expected {
		if names[i] != name {
			t.Errorf("TierNames()[%d] = %q, want %q", i, names[i], name)
		}
	}
}

func TestAvailablePackages(t *testing.T) {
	if len(AvailablePackages) != 14 {
		t.Errorf("AvailablePackages len = %d, want 14", len(AvailablePackages))
	}

	// Verify secubox-core is first
	if AvailablePackages[0] != "secubox-core" {
		t.Errorf("AvailablePackages[0] = %q, want secubox-core", AvailablePackages[0])
	}
}
