// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package main

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/CyberMind-FR/secubox-deb/secubox-toolbox-ng/internal/actor/envelope"
	"github.com/CyberMind-FR/secubox-deb/secubox-toolbox-ng/internal/actor/graph"
)

const now0 = int64(1_700_000_000)

func ev(ago int64, ip, sensor, regle, pays string, sev int) envelope.Envelope {
	return envelope.Envelope{Timestamp: now0 - ago, SrcIP: ip, Sensor: sensor, RuleID: regle, GeoCountry: pays, Severity: sev}
}

func TestApercuTopPaysEtActivite(t *testing.T) {
	evs := []envelope.Envelope{ // du plus récent au plus ancien, comme Store.Recent
		ev(60, "203.0.113.1", "waf", "sqli", "RU", 90),
		ev(120, "203.0.113.2", "dpi", "scan", "RU", 40),
		ev(3*3600+10, "203.0.113.3", "waf", "lfi", "US", 70),
		ev(30*3600, "203.0.113.4", "waf", "lfi", "CN", 70), // hors des 24 h : compte pour les pays, pas pour l'activité
	}
	a := apercu(evs, nil, now0)
	if len(a.TopPays) != 3 || a.TopPays[0].Code != "RU" || a.TopPays[0].N != 2 {
		t.Fatalf("top pays: %+v", a.TopPays)
	}
	if len(a.Activite24h) != 24 {
		t.Fatalf("24 compartiments, obtenu %d", len(a.Activite24h))
	}
	total := 0
	for _, n := range a.Activite24h {
		total += n
	}
	if total != 3 || a.Activite24h[23] != 2 {
		t.Fatalf("activité: %v (l'heure en cours est le dernier compartiment)", a.Activite24h)
	}
}

func TestApercuRattacheLesEvenementsAuxActeursSansExposerLesIP(t *testing.T) {
	acteurs := []*graph.Actor{{ID: "ACT-0040", IPs: []string{"203.0.113.1"}}}
	a := apercu([]envelope.Envelope{ev(60, "203.0.113.1", "waf", "sqli", "RU", 90), ev(90, "198.51.100.9", "dpi", "scan", "FR", 20)}, acteurs, now0)
	if len(a.Recents) != 2 || a.Recents[0].Acteur != "ACT-0040" || a.Recents[0].Module != "waf" || a.Recents[0].Score != 90 || a.Recents[0].Type != "sqli" {
		t.Fatalf("récents: %+v", a.Recents)
	}
	if a.Recents[1].Acteur != "" {
		t.Fatalf("un événement sans acteur reste sans acteur: %+v", a.Recents[1])
	}
	b, _ := json.Marshal(a)
	for _, ip := range []string{"203.0.113.1", "198.51.100.9"} {
		if strings.Contains(string(b), ip) {
			t.Fatalf("aucune adresse IP dans l'aperçu : %s", b)
		}
	}
}

func TestApercuTechniquesParActeur(t *testing.T) {
	acteurs := []*graph.Actor{{ID: "ACT-1", IPs: []string{"203.0.113.1"}}}
	evs := []envelope.Envelope{ev(1, "203.0.113.1", "waf", "sqli", "", 90), ev(2, "203.0.113.1", "waf", "sqli", "", 90), ev(3, "203.0.113.1", "dpi", "scan", "", 40)}
	a := apercu(evs, acteurs, now0)
	tech := a.Techniques["ACT-1"]
	if len(tech) != 2 || tech[0].Nom != "sqli" || tech[0].N != 2 {
		t.Fatalf("techniques: %+v", tech)
	}
}

func TestApercuPlafonneLesRecents(t *testing.T) {
	var evs []envelope.Envelope
	for i := 0; i < 50; i++ {
		evs = append(evs, ev(int64(i), "203.0.113.1", "waf", "x", "", 10))
	}
	if n := len(apercu(evs, nil, now0).Recents); n != 8 {
		t.Fatalf("8 derniers événements au plus, obtenu %d", n)
	}
}

func TestApercuActiviteParActeur(t *testing.T) {
	acteurs := []*graph.Actor{{ID: "ACT-1", IPs: []string{"203.0.113.1"}}}
	a := apercu([]envelope.Envelope{ev(60, "203.0.113.1", "waf", "x", "", 1), ev(7200+5, "203.0.113.1", "waf", "x", "", 1), ev(60, "198.51.100.9", "waf", "x", "", 1)}, acteurs, now0)
	h := a.ActiviteActeurs["ACT-1"]
	if len(h) != 24 || h[23] != 1 || h[21] != 1 {
		t.Fatalf("activité acteur: %v", h)
	}
	if _, ok := a.ActiviteActeurs[""]; ok {
		t.Fatal("pas de compartiment pour les événements sans acteur")
	}
}

// L'aperçu relit des milliers d'événements : il est mis en cache quelques dizaines de secondes (la carte du Hall l'appelle toutes les minutes
// depuis plusieurs navigateurs, sur une box déjà chargée).
func TestApercuEstMisEnCache(t *testing.T) {
	s := serveur(t)
	appel := func() Apercu {
		w := httptest.NewRecorder()
		s.handleApercu(w, httptest.NewRequest("GET", "/overview", nil))
		var a Apercu
		if err := json.Unmarshal(w.Body.Bytes(), &a); err != nil {
			t.Fatal(err)
		}
		return a
	}
	if err := s.store.Ingest(&envelope.Envelope{EventID: "e1", Timestamp: time.Now().Unix(), Sensor: "waf", SrcIP: "203.0.113.1", Severity: 10}); err != nil {
		t.Fatal(err)
	}
	a1 := appel()
	if err := s.store.Ingest(&envelope.Envelope{EventID: "e2", Timestamp: time.Now().Unix(), Sensor: "waf", SrcIP: "203.0.113.2", Severity: 10}); err != nil {
		t.Fatal(err)
	}
	a2 := appel()
	if a1.Echantillon != 1 || a2.Echantillon != 1 {
		t.Fatalf("le second appel doit servir le cache : %d puis %d événements", a1.Echantillon, a2.Echantillon)
	}
	s.apercuT.perime()
	if a3 := appel(); a3.Echantillon != 1 {
		t.Fatalf("périmé, l'aperçu courant doit être servi tel quel (double tampon) : %d", a3.Echantillon)
	}
	attendre(t, func() bool { return appel().Echantillon == 2 }, "le nouvel aperçu n'a jamais été publié")
}

// /stats relit et décode TOUTES les 24 dernières heures d'événements à chaque appel : la carte du Hall, la page d'administration et
// la couche Renseignement l'appellent toutes en parallèle. Sur gk2 (RAM saturée) cela relisait le disque à 23 Mo/s en continu et
// faisait expirer l'API. Même règle que l'aperçu : un calcul à la fois, gardé quelques dizaines de secondes.
func TestStatsEstMisEnCache(t *testing.T) {
	s := serveur(t)
	appel := func() float64 {
		w := httptest.NewRecorder()
		s.handleStats(w, httptest.NewRequest("GET", "/stats", nil))
		var m map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &m); err != nil {
			t.Fatal(err)
		}
		return m["events_24h"].(float64)
	}
	if err := s.store.Ingest(&envelope.Envelope{EventID: "s1", Timestamp: time.Now().Unix(), Sensor: "waf", SrcIP: "203.0.113.1", Severity: 10}); err != nil {
		t.Fatal(err)
	}
	n1 := appel()
	if err := s.store.Ingest(&envelope.Envelope{EventID: "s2", Timestamp: time.Now().Unix(), Sensor: "waf", SrcIP: "203.0.113.2", Severity: 10}); err != nil {
		t.Fatal(err)
	}
	if n2 := appel(); n1 != 1 || n2 != 1 {
		t.Fatalf("le second appel doit servir le cache : %v puis %v événements", n1, n2)
	}
	s.statsT.perime()
	if n3 := appel(); n3 != 1 {
		t.Fatalf("périmées, les stats courantes doivent être servies telles quelles (double tampon) : %v", n3)
	}
	attendre(t, func() bool { return appel() == 2 }, "les nouvelles stats n'ont jamais été publiées")
}

// attendre sonde une condition que le renouvellement en arrière-plan doit finir par rendre vraie.
func attendre(t *testing.T, ok func() bool, msg string) {
	t.Helper()
	for i := 0; i < 300; i++ {
		if ok() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal(msg)
}
