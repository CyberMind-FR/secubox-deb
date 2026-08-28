// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// See LICENCE-CMSD-1.0.md for terms.

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestThreatLog_NegativeSpaceAnnotation — le journal de menaces étiquette une
// sonde de reconnaissance et LAISSE VIERGE une attaque à charge utile (#1240).
// Vérifie aussi que le champ reste absent (omitempty) quand il n'y a pas de
// signal, pour ne pas polluer les enregistrements existants.
func TestThreatLog_NegativeSpaceAnnotation(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "waf-threats.log")
	tl := NewThreatLog(p)

	tl.Record(ThreatRecord{Path: "/.git/HEAD", Category: "scanners", Action: "detect"})
	tl.Record(ThreatRecord{Path: "/admin.bak", Category: "honeypot", Action: "warning"})
	tl.Record(ThreatRecord{Path: "/api?id=1' OR 1=1", Category: "sqli", Action: "banned"})

	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("lecture du journal : %v", err)
	}
	lignes := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(lignes) != 3 {
		t.Fatalf("attendu 3 lignes, obtenu %d", len(lignes))
	}

	var e0, e1, e2 struct {
		Category      string `json:"category"`
		NegativeSpace string `json:"negative_space"`
	}
	_ = json.Unmarshal([]byte(lignes[0]), &e0)
	_ = json.Unmarshal([]byte(lignes[1]), &e1)
	_ = json.Unmarshal([]byte(lignes[2]), &e2)

	if e0.NegativeSpace != pathHighValueProbe {
		t.Errorf("/.git/HEAD : negative_space=%q, attendu %q", e0.NegativeSpace, pathHighValueProbe)
	}
	if e1.NegativeSpace != pathKnownNegative {
		t.Errorf("/admin.bak : negative_space=%q, attendu %q", e1.NegativeSpace, pathKnownNegative)
	}
	// Attaque à charge utile : PAS d'étiquette negative_space (champ absent).
	if e2.NegativeSpace != "" {
		t.Errorf("sqli : negative_space=%q, attendu vide (omitempty)", e2.NegativeSpace)
	}
	if strings.Contains(lignes[2], "negative_space") {
		t.Errorf("sqli : le champ negative_space ne doit pas apparaître dans le JSON : %s", lignes[2])
	}
}
