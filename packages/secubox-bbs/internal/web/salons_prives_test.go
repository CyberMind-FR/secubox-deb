// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
package web

import (
	"os"
	"strings"
	"testing"
)

// LE MUR, PAS SEULEMENT LA PORTE. Le magasin sait dire qui a acces ; encore
// faut-il que l'affichage le consomme. Tant qu'il ne le faisait pas, un salon
// ferme restait visible dans le rail — la serrure posee sur une porte ouverte.
func TestLeFiltreDesSalonsPrivesEstBienPoseDansBase(t *testing.T) {
	src, err := assets.ReadFile("templates/sysop.html")
	if err != nil {
		t.Fatalf("lecture du gabarit : %v", err)
	}
	texte := string(src)
	for _, attendu := range []string{
		"/mod/salon-prive",  // fermer ou rouvrir
		"/mod/salon-membre", // convier, retirer
		"/mod/salon-invite", // emettre un lien
		"{{$.V.CSRF}}",      // dans une boucle, le jeton se prend a la racine
	} {
		if !strings.Contains(texte, attendu) {
			t.Errorf("la console des salons prives ne contient pas %q", attendu)
		}
	}
}

// UN 403 CONFIRMERAIT L'EXISTENCE DU SALON. Pour qui n'y a pas acces, un salon
// prive ne doit pas exister du tout : le handler doit donc s'appuyer sur la
// liste filtree, et tomber sur un 404 par construction plutot que sur un refus
// explicite.
func TestLAccesDirectRepondIntrouvableEtNonInterdit(t *testing.T) {
	// On lit la source du paquet : les tests s'executent dans son repertoire.
	brut, err := os.ReadFile("routes.go")
	if err != nil {
		t.Skipf("source indisponible : %v", err)
	}
	src := string(brut)
	if !strings.Contains(src, "SalonsCachesPour") {
		t.Fatal("le filtre n'est pas applique a la construction de page")
	}
	// Le handler de salon ne doit jamais rendre un 403 : il cherche dans la
	// liste deja filtree, et `NotFound` fait le reste.
	i := strings.Index(src, "func (s *Server) salon(")
	if i < 0 {
		t.Fatal("handler de salon introuvable")
	}
	corps := src[i:]
	if j := strings.Index(corps, "\nfunc "); j > 0 {
		corps = corps[:j]
	}
	if strings.Contains(corps, "StatusForbidden") {
		t.Error("le salon repond 403 : l'existence du salon prive fuit")
	}
	if !strings.Contains(corps, "NotFound") {
		t.Error("le salon ne rend pas 404 quand la categorie est absente")
	}
}
