// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package modele

import (
	"context"
	"errors"
	"testing"
)

type fausse struct {
	nom    string
	params map[string]any
	err    error
}

func (f fausse) Nom() string { return f.nom }
func (f fausse) Lire(context.Context) (map[string]any, error) {
	return f.params, f.err
}

func TestAplatirFusionneEtIgnoreLesErreurs(t *testing.T) {
	plat := Aplatir([]Resultat{
		{Chemin: "A.", Params: map[string]any{"A.x": 1, "A.y": 2}},
		{Chemin: "B.", Params: map[string]any{"B.z": "v"}},
		{Chemin: "C.", Erreur: "chemin inconnu"},
	})
	if len(plat) != 3 || plat["A.x"] != 1 || plat["B.z"] != "v" {
		t.Fatalf("aplatissement inattendu : %v", plat)
	}
}

func TestGetExactPrefixeEtInconnu(t *testing.T) {
	m := NouveauModele(fausse{nom: "f", params: map[string]any{"D.a": 1, "D.b.c": 2, "E.z": 3}})
	r := m.Get(context.Background(), []string{"D.", "D.a", "X.y"})
	if len(r[0].Params) != 2 || r[1].Params["D.a"] != 1 || r[2].Erreur != "chemin inconnu" {
		t.Fatalf("résultats inattendus : %+v", r)
	}
}

func TestGetSourceEnErreurNeCacheRien(t *testing.T) {
	m := NouveauModele(
		fausse{nom: "ok", params: map[string]any{"D.a": 1}},
		fausse{nom: "ko", err: errors.New("boum")},
	)
	r := m.Get(context.Background(), []string{"D.", "Z.q"})
	if r[0].Params["D.a"] != 1 || r[1].Erreur == "" {
		t.Fatalf("résultats inattendus : %+v", r)
	}
}

func TestGetPrefixeSignaleLesSourcesEnEchec(t *testing.T) {
	m := NouveauModele(
		fausse{nom: "ok", params: map[string]any{"D.a": 1}},
		fausse{nom: "systemd", err: errors.New("délai")},
		fausse{nom: "mem", err: errors.New("boum")},
	)
	r := m.Get(context.Background(), []string{"D.", "D.a", "Z."})
	if r[0].Params["D.a"] != 1 || len(r[0].Echecs) != 2 || r[0].Echecs[0] != "mem" || r[0].Echecs[1] != "systemd" {
		t.Fatalf("préfixe : échecs non signalés ou triés : %+v", r[0])
	}
	if len(r[1].Echecs) != 0 {
		t.Fatalf("chemin exact trouvé : pas d'échec à signaler : %+v", r[1])
	}
	if r[2].Erreur == "" || len(r[2].Echecs) != 0 {
		t.Fatalf("rien trouvé : err seul : %+v", r[2])
	}
	if plat := Aplatir(r); plat["D.a"] != 1 {
		t.Fatalf("aplatir inchangé : %v", plat)
	}
}

func TestGetSansEchecNeSignaleRien(t *testing.T) {
	m := NouveauModele(fausse{nom: "ok", params: map[string]any{"D.a": 1}})
	if r := m.Get(context.Background(), []string{"D."}); r[0].Echecs != nil {
		t.Fatalf("échecs inattendus : %+v", r[0])
	}
}
