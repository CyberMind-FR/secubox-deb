// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"
)

// #3936 : les compteurs d'activité regardent le graphe, ils n'y touchent pas. Empreinte de la
// corrélation (acteurs, campagnes, mesures, propositions) d'un flux fixe, relevée AVANT l'ajout des
// compteurs (commit 30d48269f) : elle doit rester la même, octet pour octet, en direct, après
// consolidation et au rejeu. La modifier = décision du propriétaire.
const empreinteCorrelation3936 = "80aeb56eda5743525e4e3be1f6633e3ce4df525b7cfa74a7783bb0521657a178"

func TestCorrelationInchangee3936(t *testing.T) {
	const t0 = int64(1_788_000_000)
	s := serveur(t)
	for _, e := range fluxAvecASN(t0, true) {
		if err := s.store.Ingest(e); err != nil {
			t.Fatal(err)
		}
		s.correlate(e)
	}
	h := sha256.New()
	ecrire := func(s *Server) {
		b, err := json.Marshal(decisionDe(t, s, t0))
		if err != nil {
			t.Fatal(err)
		}
		h.Write(b)
	}
	ecrire(s)
	s.graph.Consolider(map[string]bool{"a.exemple.test": true, "b.exemple.test": true})
	ecrire(s)
	r := serveur(t)
	r.store = s.store
	r.rebuild()
	ecrire(r)
	if got := hex.EncodeToString(h.Sum(nil)); got != empreinteCorrelation3936 {
		t.Errorf("corrélation modifiée : %s", got)
	}
}
