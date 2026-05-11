package apt

import "fmt"

// Tier definitions
type Tier struct {
	Name        string
	Description string
	Packages    []string
}

var Tiers = map[string]Tier{
	"lite": {
		Name:        "Lite",
		Description: "1-2GB RAM devices (ESPRESSObin)",
		Packages:    []string{"secubox-lite"},
	},
	"standard": {
		Name:        "Standard",
		Description: "4GB RAM, general purpose",
		Packages:    []string{"secubox-standard"},
	},
	"pro": {
		Name:        "Pro",
		Description: "8GB+ RAM, all features (MOCHAbin)",
		Packages:    []string{"secubox-full"},
	},
	"minimal": {
		Name:        "Minimal",
		Description: "Core + Hub only",
		Packages:    []string{"secubox-core", "secubox-hub"},
	},
}

// AvailablePackages lists all selectable packages for custom install
var AvailablePackages = []string{
	"secubox-core",
	"secubox-hub",
	"secubox-crowdsec",
	"secubox-netdata",
	"secubox-wireguard",
	"secubox-dpi",
	"secubox-netmodes",
	"secubox-nac",
	"secubox-auth",
	"secubox-qos",
	"secubox-mediaflow",
	"secubox-cdn",
	"secubox-vhost",
	"secubox-system",
}

// TierPackages returns the packages for a given tier
func TierPackages(tier string) ([]string, error) {
	t, ok := Tiers[tier]
	if !ok {
		return nil, fmt.Errorf("invalid tier: %s (valid: lite, standard, pro, minimal)", tier)
	}
	return t.Packages, nil
}

// ValidateTier checks if a tier name is valid
func ValidateTier(tier string) bool {
	_, ok := Tiers[tier]
	return ok
}

// TierNames returns all tier names for wizard display
func TierNames() []string {
	return []string{"lite", "standard", "pro", "minimal", "custom"}
}
