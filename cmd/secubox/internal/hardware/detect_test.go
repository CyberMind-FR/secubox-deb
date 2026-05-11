package hardware

import (
	"testing"
)

func TestDetect(t *testing.T) {
	info, err := Detect()
	if err != nil {
		t.Fatalf("Detect() error = %v", err)
	}

	if info == nil {
		t.Fatal("Detect() returned nil")
	}

	// Arch should always be detected
	if info.Arch == "" {
		t.Error("Arch should not be empty")
	}

	// CPUCores should be at least 1
	if info.CPUCores < 1 {
		t.Errorf("CPUCores = %d, want >= 1", info.CPUCores)
	}
}

func TestSuggestTier(t *testing.T) {
	tests := []struct {
		name       string
		ramTotalMB uint64
		want       string
	}{
		{"lite - 1GB", 1024, "tier-lite"},
		{"lite - 2GB", 2048, "tier-lite"},
		{"standard - 4GB", 4096, "tier-standard"},
		{"standard - 6GB", 6144, "tier-standard"},
		{"pro - 8GB", 8192, "tier-pro"},
		{"pro - 16GB", 16384, "tier-pro"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info := &Info{RAMTotalMB: tt.ramTotalMB}
			got := info.SuggestTier()
			if got != tt.want {
				t.Errorf("SuggestTier() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestInfoString(t *testing.T) {
	info := &Info{
		Board:      "mochabin",
		Arch:       "arm64",
		CPUModel:   "Test CPU",
		CPUCores:   4,
		RAMTotalMB: 8192,
	}

	s := info.String()
	if s == "" {
		t.Error("String() returned empty string")
	}

	// Check that key information is present
	if !contains(s, "mochabin") {
		t.Error("String() should contain board name")
	}
	if !contains(s, "arm64") {
		t.Error("String() should contain arch")
	}
	if !contains(s, "8192") {
		t.Error("String() should contain RAM")
	}
}

func TestIdentifyBoardFromModel(t *testing.T) {
	tests := []struct {
		model string
		want  string
	}{
		{"GlobalScale MOCHAbin", "mochabin"},
		{"Globalscale ESPRESSObin", "espressobin-v7"},
		{"ESPRESSObin Ultra", "espressobin-ultra"},
		{"Raspberry Pi 4 Model B", "rpi4"},
		{"Raspberry Pi 5", "rpi5"},
		{"Raspberry Pi 400", "rpi400"},
		{"Marvell Armada 7040", "mochabin"},
		{"Marvell Armada 3720", "espressobin-v7"},
		{"Unknown Board", ""},
	}

	for _, tt := range tests {
		t.Run(tt.model, func(t *testing.T) {
			got := identifyBoardFromModel(tt.model)
			if got != tt.want {
				t.Errorf("identifyBoardFromModel(%q) = %q, want %q", tt.model, got, tt.want)
			}
		})
	}
}

func TestIdentifyBoardFromCompatible(t *testing.T) {
	tests := []struct {
		compatible string
		want       string
	}{
		{"globalscale,mochabin", "mochabin"},
		{"globalscale,espressobin", "espressobin-v7"},
		{"raspberrypi,4-model-b", "rpi4"},
		{"raspberrypi,400", "rpi400"},
		{"unknown,board", ""},
	}

	for _, tt := range tests {
		t.Run(tt.compatible, func(t *testing.T) {
			got := identifyBoardFromCompatible(tt.compatible)
			if got != tt.want {
				t.Errorf("identifyBoardFromCompatible(%q) = %q, want %q", tt.compatible, got, tt.want)
			}
		})
	}
}

func TestIdentifyBoardFromDMI(t *testing.T) {
	tests := []struct {
		product string
		want    string
	}{
		{"VirtualBox", "vm-x64"},
		{"VMware Virtual Machine", "vm-x64"},
		{"QEMU KVM", "vm-x64"},
		{"Dell PowerEdge", ""},
	}

	for _, tt := range tests {
		t.Run(tt.product, func(t *testing.T) {
			got := identifyBoardFromDMI(tt.product)
			if got != tt.want {
				t.Errorf("identifyBoardFromDMI(%q) = %q, want %q", tt.product, got, tt.want)
			}
		})
	}
}

// Helper function
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsSubstr(s, substr))
}

func containsSubstr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
