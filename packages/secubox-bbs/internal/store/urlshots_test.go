// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
package store

import "testing"

// TestMigrationUrlshotsCreeLaTable prouve que la migration 0023 crée bien la
// table urlshots — une insertion minimale (colonnes par défaut) doit réussir.
func TestMigrationUrlshotsCreeLaTable(t *testing.T) {
	s := ouvre(t)
	if _, err := s.db.Exec(`INSERT INTO urlshots(cle,url) VALUES('abc','https://x')`); err != nil {
		t.Fatalf("table urlshots absente : %v", err)
	}
}
