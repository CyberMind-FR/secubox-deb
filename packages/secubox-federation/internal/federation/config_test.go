package federation

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func ecrit(t *testing.T, s string) string {
	p := filepath.Join(t.TempDir(), "federation.yaml")
	os.WriteFile(p, []byte(s), 0o644)
	return p
}

func TestSansFichierLaBoxEstAutonome(t *testing.T) {
	c, err := Charge(filepath.Join(t.TempDir(), "absent.yaml"))
	if err != nil || c.Role != "member" || c.Federation.URL != "" {
		t.Fatalf("%+v %v", c, err)
	}
}

func TestLeTableauDuCahierDesCharges(t *testing.T) {
	c, _ := Charge(ecrit(t, "tier: pro\n"))
	cas := map[string]time.Duration{"community": 24 * time.Hour, "standard": 6 * time.Hour, "pro": 5 * time.Minute, "premium": 0}
	for tier, attendu := range cas {
		if got := time.Duration(c.Intervalle(tier, "waf")); got != attendu {
			t.Errorf("%s : waf %v, attendu %v", tier, got, attendu)
		}
	}
	if ch := c.Tiers["premium"].Channels; len(ch) != 3 || ch[2] != "alpha" {
		t.Errorf("premium : %v", ch)
	}
	if c.Tiers["community"].Rights["waf_pro"] {
		t.Error("community a waf_pro")
	}
}

func TestUneSurchargeLocaleNePeutPasAllerPlusVite(t *testing.T) {
	c, err := Charge(ecrit(t, "tier: community\nsync:\n  waf: 5m\n  appstore: 48h\n"))
	if err != nil {
		t.Fatal(err)
	}
	if got := time.Duration(c.Intervalle("community", "waf")); got != 24*time.Hour {
		t.Errorf("waf community forcé à %v : plus vite que le tier", got)
	}
	if got := time.Duration(c.Intervalle("community", "appstore")); got != 48*time.Hour {
		t.Errorf("appstore : %v, la box doit pouvoir aller MOINS vite", got)
	}
}

func TestLesTiersSeSurchargent(t *testing.T) {
	c, err := Charge(ecrit(t, "tier: pro\ntiers:\n  pro:\n    sync:\n      waf: 1m\n"))
	if err != nil {
		t.Fatal(err)
	}
	if got := time.Duration(c.Intervalle("pro", "waf")); got != time.Minute {
		t.Errorf("waf pro : %v", got)
	}
	if len(c.Tiers["pro"].Channels) != 2 {
		t.Error("la surcharge a effacé les canaux du tier")
	}
}

func TestErreursDeConfiguration(t *testing.T) {
	for _, s := range []string{"tier: gold\n", "role: maitre\n", "tier: pro\nsync:\n  waf: vite\n", "tier: pro\ninconnu: 1\n"} {
		if _, err := Charge(ecrit(t, s)); err == nil {
			t.Errorf("accepté : %q", s)
		}
	}
}
