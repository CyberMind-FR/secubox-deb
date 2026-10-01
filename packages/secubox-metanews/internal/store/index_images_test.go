// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package store

import (
	"strings"
	"testing"
)

// Le relais d'images interroge la base à CHAQUE image (#1835) : les deux
// recherches d'ImageConnue doivent passer par un index, jamais par un SCAN de
// table (54 653 articles relus par image sur gk2).
func TestImageConnueParIndex(t *testing.T) {
	s := ouvrir(t)
	for _, q := range []string{
		`SELECT 1 FROM article WHERE image=? LIMIT 1`,
		`SELECT 1 FROM topic WHERE vignette=? LIMIT 1`,
	} {
		rows, err := s.db.Query(`EXPLAIN QUERY PLAN `+q, "https://exemple.org/a.jpg")
		if err != nil {
			t.Fatalf("%s : %v", q, err)
		}
		var plan []string
		for rows.Next() {
			var id, parent, inutile int
			var detail string
			if err := rows.Scan(&id, &parent, &inutile, &detail); err != nil {
				t.Fatal(err)
			}
			plan = append(plan, detail)
		}
		rows.Close()
		tout := strings.Join(plan, " | ")
		if !strings.Contains(tout, "USING") || strings.HasPrefix(tout, "SCAN") {
			t.Fatalf("%s : plan sans index : %s", q, tout)
		}
	}
}

func TestImageConnueRepondToujours(t *testing.T) {
	s := ouvrir(t)
	if s.ImageConnue("") || s.ImageConnue("https://inconnue.example/x.png") {
		t.Fatal("une image inconnue ne doit pas être relayée")
	}
}
