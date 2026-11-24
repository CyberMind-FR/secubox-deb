// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package reseau

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const catalogueLivre = `# commentaire
[classes]
proxy_loue = [212238, 62874, 55286, 18779, 203020, 207990, 203061, 50131]
hebergeur = [20473, 14061,
  16509, 14618, # fin
  15169]

scanner_recherche = [211298, 398324]
mobile_partage = [14593]
relais_vie_privee = [13335]
acces = []
cdn = []
`

func TestLireCatalogue(t *testing.T) {
	m, err := LireCatalogue(strings.NewReader(catalogueLivre))
	if err != nil {
		t.Fatal(err)
	}
	if m[212238] != "proxy_loue" || m[13335] != "relais_vie_privee" ||
		m[15169] != "hebergeur" || m[14618] != "hebergeur" {
		t.Fatalf("catalogue mal lu : %v", m)
	}
	if _, err := LireCatalogue(strings.NewReader("[classes]\nbidon = [1]\n")); err == nil {
		t.Error("classe inconnue acceptée")
	}
	if _, err := LireCatalogue(strings.NewReader("[classes]\ncdn = [abc]\n")); err == nil {
		t.Error("ASN non numérique accepté")
	}
	if _, err := LireCatalogue(strings.NewReader("[classes]\ncdn = [1,\n")); err == nil {
		t.Error("tableau non fermé accepté")
	}
}

func TestSurchargeOperateur(t *testing.T) {
	d := t.TempDir()
	livre := filepath.Join(d, "livre.toml")
	op := filepath.Join(d, "op.toml")
	if err := os.WriteFile(livre, []byte(catalogueLivre), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(op, []byte("[classes]\nacces = [20473]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	a := Ouvrir("", livre, op, filepath.Join(d, "absent.toml"))
	defer a.Close()
	if got := a.classes[20473]; got != ClasseAcces {
		t.Errorf("20473 = %q, attendu acces", got)
	}
	if got := a.classes[14061]; got != ClasseHebergeur {
		t.Errorf("14061 = %q, attendu hebergeur", got)
	}
}

func TestClasserSansBase(t *testing.T) {
	a := Ouvrir("/inexistant")
	defer a.Close()
	if got := a.Classer("8.8.8.8"); got != (Info{Classe: "inconnu"}) {
		t.Errorf("got %+v", got)
	}
	var n *Annuaire
	if got := n.Classer("8.8.8.8"); got != (Info{Classe: "inconnu"}) {
		t.Errorf("nil : got %+v", got)
	}
	n.Recharger()
	n.Close()
}

func TestClasserAdressesSpeciales(t *testing.T) {
	a := Ouvrir("")
	for _, ip := range []string{"local", "", "pas-une-ip", "10.0.0.1", "::1"} {
		if got := a.Classer(ip); got != (Info{Classe: "inconnu"}) {
			t.Errorf("%q : got %+v", ip, got)
		}
	}
}

func TestRechargerBaseTronquee(t *testing.T) {
	// Aucune base de test (GeoLite2-ASN-Test.mmdb) n'est embarquée dans le
	// vendor de maxminddb-golang, et rien ne doit être téléchargé : test
	// sauté tant qu'un fichier de test n'est pas fourni.
	t.Skip("pas de base mmdb de test dans vendor/ ; à activer avec un testdata/GeoLite2-ASN-Test.mmdb")
}

func TestMasquerCompte(t *testing.T) {
	cas := map[string]string{
		"gerald@gk2.net": "ger…",
		"abc":            "…",
		"ab":             "…",
		"":               "…",
		"éèàù":           "éèà…",
	}
	for in, want := range cas {
		if got := MasquerCompte(in); got != want {
			t.Errorf("MasquerCompte(%q) = %q, attendu %q", in, got, want)
		}
	}
}

// baseFausse remplace le lecteur mmdb (#3919).
type baseFausse struct{ ferme bool }

func (b *baseFausse) Lookup(ip net.IP, res any) error {
	e := res.(*enregistrementASN)
	e.ASN, e.Org = 15169, "GOOGLE"
	return nil
}
func (b *baseFausse) Close() error { b.ferme = true; return nil }

func TestRechargerGardeAncienneBase(t *testing.T) {
	ancienne := &baseFausse{}
	defer func(o func(string) (baseASN, error)) { ouvrirBase = o }(ouvrirBase)
	ouvrirBase = func(string) (baseASN, error) { return ancienne, nil }
	a := Ouvrir("/fausse.mmdb")
	if got := a.Classer("8.8.8.8"); got.ASN != 15169 {
		t.Fatalf("avant rechargement : %+v", got)
	}
	ouvrirBase = func(string) (baseASN, error) { return nil, errors.New("tronquée") }
	a.Recharger()
	if got := a.Classer("8.8.8.8"); got.ASN != 15169 || got.Org != "GOOGLE" {
		t.Errorf("l'ancienne base doit rester : %+v", got)
	}
	if ancienne.ferme {
		t.Error("l'ancienne base ne doit pas être fermée sur échec")
	}
}
