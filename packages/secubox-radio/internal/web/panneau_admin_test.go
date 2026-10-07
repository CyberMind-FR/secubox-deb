package web

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// Le panneau d'administration appelle chaque fonction qu'il utilise, et propose le geste « moins souvent ».
func TestLePanneauAdminNAppellePasDeFonctionInexistante(t *testing.T) {
	b, err := os.ReadFile("../../www/radio/radio-admin.js")
	if err != nil {
		t.Fatal(err)
	}
	js := string(b)
	// une fonction appelée au premier niveau d'un then() qui n'est définie nulle part interrompt tout le rafraîchissement (« Écartés » ne s'affichait plus)
	defs := map[string]bool{}
	for _, m := range regexp.MustCompile(`function\s+([A-Za-z_$][\w$]*)\s*\(`).FindAllStringSubmatch(js, -1) {
		defs[m[1]] = true
	}
	for _, m := range regexp.MustCompile(`(?m)^\s+(rend[A-Z]\w*)\(`).FindAllStringSubmatch(js, -1) {
		if !defs[m[1]] {
			t.Errorf("%s est appelée mais jamais définie", m[1])
		}
	}
}

func TestLePanneauAdminPropose_MoinsSouvent(t *testing.T) {
	b, _ := os.ReadFile("../../www/radio/radio-admin.js")
	js := string(b)
	for _, attendu := range []string{"function boutonBas(", "'/bas'", "Moins souvent", "Rang normal", "p.proba"} {
		if !strings.Contains(js, attendu) {
			t.Errorf("manque %q", attendu)
		}
	}
}
