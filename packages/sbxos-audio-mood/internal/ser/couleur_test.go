// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package ser

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// CE TEST GARDE UNE LISTE QUE PERSONNE NE TIENT (#1331).
//
// La table des teintes vit dans `webui/src/lib/couleur.ts`, en TypeScript,
// loin d'ici. Rien dans le compilateur Go ni dans celui de Svelte ne relie les
// deux : ajouter un état dans `Etats` ci-contre et oublier sa teinte donne une
// lampe qui reste blanche pour cette émotion-là. Pas d'erreur, pas de
// message — juste une émotion qui n'éclaire jamais, et qu'on ne remarquera
// qu'en la ressentant devant la lampe.
//
// C'est exactement la forme de panne qui s'est répétée trois fois dans ce
// dépôt (la table de routes sbxwaf, le frame-src du Hall, un test CSP périmé) :
// une liste tenue à la main, dont la divergence est silencieuse. On la relie
// donc par un test plutôt que par de la discipline.
func TestChaqueEtatAUneTeinteDansLeWebui(t *testing.T) {
	src := lireCouleurTS(t)
	// On lit les clés du littéral TEINTES, et elles seules : le fichier
	// contient d'autres couleurs (le neutre, les bornes) qu'un `grep` naïf
	// prendrait pour des états.
	bloc := extraitBloc(t, src, "const TEINTES: Record<string, string> = {")
	cles := regexp.MustCompile(`(?m)^\s*([A-Za-z_][A-Za-z0-9_]*)\s*:`)
	vues := map[string]bool{}
	for _, m := range cles.FindAllStringSubmatch(bloc, -1) {
		vues[m[1]] = true
	}
	for _, e := range Etats {
		if !vues[e] {
			t.Errorf("l'état %q n'a pas de teinte dans couleur.ts : la lampe "+
				"restera blanche pour cette émotion, sans le dire", e)
		}
	}
	// Et l'inverse : une teinte pour un état qui n'existe plus est du code
	// mort qui donne l'illusion d'une couverture complète.
	for c := range vues {
		if !contient(Etats, c) {
			t.Errorf("couleur.ts donne une teinte à %q, qui n'est pas un état connu", c)
		}
	}
}

// TestLIndetermineNAPasDeTeinte : la règle du module, gardée par un test.
//
// « Ne jamais présenter les émotions comme des certitudes » se traduit ici par
// une absence : l'indéterminé ne doit PAS avoir de couleur. Lui en donner une,
// même pâle, ferait dire à la lampe quelque chose que la mesure n'a pas dit.
func TestLIndetermineNAPasDeTeinte(t *testing.T) {
	bloc := extraitBloc(t, lireCouleurTS(t), "const TEINTES: Record<string, string> = {")
	if strings.Contains(bloc, Indetermine+":") {
		t.Fatalf("l'indéterminé a reçu une teinte : une absence de mesure "+
			"deviendrait une couleur affirmée au mur (état %q)", Indetermine)
	}
}

func lireCouleurTS(t *testing.T) string {
	t.Helper()
	chemin := filepath.Join("..", "..", "webui", "src", "lib", "couleur.ts")
	b, err := os.ReadFile(chemin)
	if err != nil {
		t.Fatalf("couleur.ts illisible (%s) : %v", chemin, err)
	}
	return string(b)
}

// extraitBloc rend le contenu entre l'en-tête donné et l'accolade fermante de
// début de ligne qui lui correspond.
func extraitBloc(t *testing.T, src, entete string) string {
	t.Helper()
	i := strings.Index(src, entete)
	if i < 0 {
		t.Fatalf("bloc introuvable dans couleur.ts : %q", entete)
	}
	reste := src[i+len(entete):]
	j := strings.Index(reste, "\n}")
	if j < 0 {
		t.Fatalf("bloc %q non refermé", entete)
	}
	return reste[:j]
}

func contient(l []string, v string) bool {
	for _, x := range l {
		if x == v {
			return true
		}
	}
	return false
}
