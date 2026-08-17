package web

import (
	"strings"
	"testing"
)

func avecOrigines(t *testing.T, o []string) {
	t.Helper()
	ConfigurerFiches(o)
	t.Cleanup(func() { ConfigurerFiches(nil) })
}

func TestSeulsNosServicesDeviennentUneFiche(t *testing.T) {
	avecOrigines(t, []string{"https://radio.gk2.secubox.in", "https://peertube.gk2.secubox.in/"})

	nos := string(Render("https://radio.gk2.secubox.in/piste/3"))
	if !strings.Contains(nos, `class="fiche-sbx"`) {
		t.Fatalf("un lien vers notre radio n'est pas devenu une fiche : %s", nos)
	}
	if !strings.Contains(nos, ">radio<") {
		t.Errorf("le service n'est pas nomme : %s", nos)
	}

	for _, etranger := range []string{
		"https://exemple.tld/x",
		// Suffixe trompeur : sans separateur, il passerait pour notre radio.
		"https://radio.gk2.secubox.in.mal.tld/x",
		"http://radio.gk2.secubox.in/x", // pas https
	} {
		out := string(Render(etranger))
		if strings.Contains(out, "fiche-sbx") {
			t.Errorf("USURPATION : %s est devenu une fiche : %s", etranger, out)
		}
	}
}

// Le lien doit rester un lien : si le service est absent, le membre garde une
// adresse cliquable.
func TestLaFicheResteUnLien(t *testing.T) {
	avecOrigines(t, []string{"https://radio.gk2.secubox.in"})
	out := string(Render("https://radio.gk2.secubox.in/piste/3"))
	if !strings.Contains(out, `href="https://radio.gk2.secubox.in/piste/3"`) {
		t.Fatalf("l'adresse a disparu : %s", out)
	}
}

// Sans configuration, rien ne change : une autre installation n'a pas nos
// vhosts, et transformer des liens au hasard serait pire que de ne rien faire.
func TestSansConfigurationRienNeChange(t *testing.T) {
	ConfigurerFiches(nil)
	out := string(Render("https://radio.gk2.secubox.in/piste/3"))
	if strings.Contains(out, "fiche-sbx") {
		t.Fatalf("fiche produite sans configuration : %s", out)
	}
}

// Le rendu ne doit JAMAIS rendre executable ce qu'un membre ecrit.
func TestUneFicheNInjectePas(t *testing.T) {
	avecOrigines(t, []string{"https://radio.gk2.secubox.in"})
	out := string(Render(`[<img src=x onerror=alert(1)>](https://radio.gk2.secubox.in/x)`))
	if strings.Contains(out, "onerror=alert") && !strings.Contains(out, "&lt;img") {
		t.Fatalf("INJECTION : %s", out)
	}
	if strings.Contains(out, "<script") {
		t.Fatalf("script injecte : %s", out)
	}
}
