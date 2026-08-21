package web

import (
	"strings"
	"testing"
)

// UNE CARTE MONTRE UNE PHRASE, PAS LE BROUILLON D'UNE PASSERELLE. Les billets
// importés recopient le titre en tête, collent un chemin de média nu, un pied
// « Discuter ce billet… » et un lien markdown. L'aperçu du carrousel affichait
// tout cela tel quel (#1114) : un chemin /media/… et un « [Voir chez… » tronqué
// au lieu d'un résumé. resumeDeCorps doit tout retirer et ne garder que le fond.
func TestResumeDeCorpsNettoieLeBrouillonDePasserelle(t *testing.T) {
	corps := "ANIBAL-AMIOT.FR/COM/NET\n" +
		"gk2 — ANIBAL-AMIOT.FR\n" +
		"/media/01KZYAJYGJDAJP1SKHMT5529PC.jpg\n" +
		"Discuter ce billet sur le BBS\n\n" +
		"[Voir chez billets](http://billets/b/anibal)"
	got := resumeDeCorps(corps, "ANIBAL-AMIOT.FR/COM/NET")

	for _, indesirable := range []string{"/media/", "Discuter ce billet", "[Voir chez", "]("} {
		if strings.Contains(got, indesirable) {
			t.Errorf("l'aperçu contient encore %q : %q", indesirable, got)
		}
	}
	if !strings.Contains(got, "gk2 — ANIBAL-AMIOT.FR") {
		t.Errorf("le contenu utile a disparu : %q", got)
	}
	if strings.HasPrefix(strings.ToUpper(got), "ANIBAL-AMIOT.FR/COM/NET") {
		t.Errorf("la ligne-titre répétée n'a pas été retirée : %q", got)
	}
}

// UN LIEN MARKDOWN GARDE SON TEXTE, PERD SA SYNTAXE : sur une carte on lit le
// libellé, pas la parenthèse d'URL.
func TestResumeDeCorpsDeplieLesLiensMarkdown(t *testing.T) {
	got := resumeDeCorps("voir [le site](https://example.org) pour la suite", "")
	if !strings.Contains(got, "le site") || strings.Contains(got, "https://") || strings.Contains(got, "](") {
		t.Errorf("lien markdown mal déplié : %q", got)
	}
}
