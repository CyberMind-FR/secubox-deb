// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// See LICENCE-CMSD-1.0.md for terms.

package main

import (
	"path/filepath"
	"os"
	"testing"
)

func TestListeBlancheAdressesEtPrefixes(t *testing.T) {
	lb, err := NewListeBlanche("203.0.113.7, 198.51.100.0/24")
	if err != nil {
		t.Fatalf("chargement : %v", err)
	}
	for _, ip := range []string{"203.0.113.7", "198.51.100.42"} {
		if !lb.Contient(ip) {
			t.Errorf("%s devrait etre exemptee", ip)
		}
	}
	if lb.Contient("203.0.113.8") {
		t.Error("203.0.113.8 n'est pas dans la liste")
	}
}

// Le prive est TOUJOURS exempte : sans cela, le premier echec d'un client LAN
// mal configure bannirait un poste de la maison.
func TestPriveToujoursExempte(t *testing.T) {
	lb, _ := NewListeBlanche("")
	for _, ip := range []string{"192.168.1.10", "10.100.0.40", "127.0.0.1", "172.16.5.1", "169.254.1.1"} {
		if !lb.Contient(ip) {
			t.Errorf("%s doit etre exemptee sans avoir a l'ecrire", ip)
		}
	}
}

func TestListeBlancheRefuseUneEntreeInvalide(t *testing.T) {
	if _, err := NewListeBlanche("pas-une-adresse"); err == nil {
		t.Error("une entree invalide doit etre refusee au chargement, pas ignoree en silence")
	}
	if _, err := NewListeBlanche("10.0.0.0/99"); err == nil {
		t.Error("un prefixe invalide doit etre refuse")
	}
}

// Un fichier absent n'est pas une erreur : l'operateur doit pouvoir le creer
// apres coup.
func TestFichierAbsentTolere(t *testing.T) {
	lb, _ := NewListeBlanche("")
	if err := lb.ChargeFichier(filepath.Join(t.TempDir(), "nulle-part")); err != nil {
		t.Fatalf("un fichier absent ne doit pas echouer : %v", err)
	}
}

func TestFichierAvecCommentaires(t *testing.T) {
	d := t.TempDir()
	f := filepath.Join(d, "liste")
	os.WriteFile(f, []byte("# bureau\n203.0.113.7\n\n# agence\n198.51.100.0/24\n"), 0o644)
	lb, _ := NewListeBlanche("")
	if err := lb.ChargeFichier(f); err != nil {
		t.Fatalf("chargement : %v", err)
	}
	if !lb.Contient("198.51.100.9") || !lb.Contient("203.0.113.7") {
		t.Error("les entrees du fichier doivent etre prises en compte")
	}
	if lb.Taille() != 2 {
		t.Errorf("taille %d, attendu 2 (les commentaires ne comptent pas)", lb.Taille())
	}
}

func TestAnalyseLeurres(t *testing.T) {
	l, err := AnalyseLeurres("3389:rdp, 5900")
	if err != nil {
		t.Fatalf("analyse : %v", err)
	}
	if len(l) != 2 || l[0].Service != "rdp" || l[1].Service != "vnc" {
		t.Fatalf("obtenu %+v — le second doit etre nomme depuis la liste connue", l)
	}
	if _, err := AnalyseLeurres("99999:trop"); err == nil {
		t.Error("un port hors bornes doit etre refuse")
	}
	def, _ := AnalyseLeurres("defaut")
	if len(def) != len(LeurresConnus) {
		t.Error("« defaut » doit rendre la liste connue")
	}
}
