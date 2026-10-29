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

// comptee : source déclarante qui compte ses lectures.
type comptee struct {
	nom      string
	chemins  []string
	params   map[string]any
	lectures *int
}

func (c comptee) Nom() string       { return c.nom }
func (c comptee) Chemins() []string { return c.chemins }
func (c comptee) Lire(context.Context) (map[string]any, error) {
	*c.lectures++
	return c.params, nil
}

// M3 : un Get ne lit que les sources dont les chemins annoncés recoupent la demande (systemctl, dpkg/status et
// /proc/net/tcp* ne sont plus relus pour un UpTime) ; une source qui n'annonce rien est toujours lue.
func TestGetNeLitQueLesSourcesConcernees(t *testing.T) {
	var nSys, nSvc, nNue int
	sys := comptee{"systeme", []string{"Device.DeviceInfo.UpTime", "Device.DeviceInfo.ProcessStatus.Process.{i}.PID"},
		map[string]any{"Device.DeviceInfo.UpTime": 5, "Device.DeviceInfo.ProcessStatus.Process.1.PID": 1}, &nSys}
	svc := comptee{"systemd", []string{"Device.X_SECUBOX_Services.FailedNumberOfEntries", "Device.X_SECUBOX_Services.{i}.Name"},
		map[string]any{"Device.X_SECUBOX_Services.FailedNumberOfEntries": 0, "Device.X_SECUBOX_Services.3.Name": "a"}, &nSvc}
	nue := fausse{nom: "nue", params: map[string]any{"Device.Nu": 1}}
	compteNue := &nNue
	m := NouveauModele(sys, svc, compteurSansChemins{nue, compteNue})
	for _, c := range []struct {
		chemins       []string
		sys, svc, nue int
	}{
		{[]string{"Device.DeviceInfo.UpTime"}, 1, 0, 1},
		{[]string{"Device.X_SECUBOX_Services.3.Name"}, 0, 1, 1},
		{[]string{"Device.X_SECUBOX_Services.3."}, 0, 1, 1},
		{[]string{"Device.X_SECUBOX_Services."}, 0, 1, 1},
		{[]string{"Device.DeviceInfo.ProcessStatus.Process.2."}, 1, 0, 1},
		{[]string{"Device.DeviceInfo.UpTime."}, 0, 0, 1}, // préfixe sous une feuille : rien à lire
		{[]string{"Device.Rien"}, 0, 0, 1},
		{[]string{"Device."}, 1, 1, 1},
		{[]string{"Device.DeviceInfo.UpTime", "Device.X_SECUBOX_Services.FailedNumberOfEntries"}, 1, 1, 1},
	} {
		nSys, nSvc, nNue = 0, 0, 0
		res := m.Get(context.Background(), c.chemins)
		if nSys != c.sys || nSvc != c.svc || nNue != c.nue {
			t.Errorf("%v : lectures systeme=%d systemd=%d nue=%d, attendu %d %d %d", c.chemins, nSys, nSvc, nNue, c.sys, c.svc, c.nue)
		}
		if len(res) != len(c.chemins) {
			t.Errorf("%v : %d résultats", c.chemins, len(res))
		}
	}
	if r := m.Get(context.Background(), []string{"Device.X_SECUBOX_Services.3.Name"}); r[0].Params["Device.X_SECUBOX_Services.3.Name"] != "a" {
		t.Errorf("valeur perdue : %+v", r)
	}
	if r := m.Get(context.Background(), []string{"Device.Rien"}); r[0].Erreur != "chemin inconnu" {
		t.Errorf("chemin inconnu : %+v", r)
	}
}

// compteurSansChemins : source sans Declarant (toujours lue), qui compte ses lectures.
type compteurSansChemins struct {
	f fausse
	n *int
}

func (c compteurSansChemins) Nom() string { return c.f.nom }
func (c compteurSansChemins) Lire(ctx context.Context) (map[string]any, error) {
	*c.n++
	return c.f.Lire(ctx)
}
