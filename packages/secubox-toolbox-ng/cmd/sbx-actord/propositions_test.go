// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/CyberMind-FR/secubox-deb/secubox-toolbox-ng/internal/actor/graph"
)

func acteur(id string, ips []string, v graph.Vector) *graph.Actor {
	return &graph.Actor{ID: id, IPs: ips, Vector: v, Bans: 4, Priority: 80}
}

// Un acteur dont le composite atteint DENY est proposé, avec ses IP et la preuve de son calcul ; les autres ne le sont jamais.
func TestPropositionsNeGardentQueLesActeursDeLaCategorieDeny(t *testing.T) {
	fort := acteur("ACT-1", []string{"203.0.113.5", "203.0.113.6"}, graph.Vector{Severity: 95, Knowledge: 80, Intent: 90, Confidence: 95})
	faible := acteur("ACT-2", []string{"203.0.113.9"}, graph.Vector{Severity: 75, Confidence: 93})
	incertain := acteur("ACT-3", []string{"203.0.113.10"}, graph.Vector{Severity: 100, Knowledge: 100, Intent: 100, Confidence: 10})
	p := propositionsDepuis([]*graph.Actor{fort, faible, incertain}, true)
	if len(p) != 1 || p[0].Actor != "ACT-1" {
		t.Fatalf("seul ACT-1 doit être proposé, obtenu %+v", p)
	}
	if p[0].Mode != "DENY" && p[0].Mode != "QUARANTINE" {
		t.Fatalf("mode %q", p[0].Mode)
	}
	if len(p[0].IPs) != 2 || p[0].TTLs <= 0 || p[0].Raison == "" {
		t.Fatalf("proposition incomplète: %+v", p[0])
	}
}

func TestFichierDePropositionsEstAtomiqueEtDatee(t *testing.T) {
	chemin := filepath.Join(t.TempDir(), "p.json")
	prop := []Proposition{{Actor: "ACT-1", Mode: "DENY", IPs: []string{"203.0.113.5"}, TTLs: 3600, Raison: "x"}}
	now := time.Unix(1_700_000_000, 0)
	if err := ecrirePropositions(chemin, prop, true, now); err != nil {
		t.Fatal(err)
	}
	var f FichierPropositions
	b, _ := os.ReadFile(chemin)
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	if f.GenereLe != now.Unix() || !f.Shadow || len(f.Propositions) != 1 {
		t.Fatalf("fichier: %+v", f)
	}
	st, _ := os.Stat(chemin)
	if st.Mode().Perm() != 0o640 {
		t.Fatalf("droits %v", st.Mode().Perm())
	}
}
