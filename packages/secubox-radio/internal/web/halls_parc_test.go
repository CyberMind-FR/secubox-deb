// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package web

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestHallsDuParcNeGardeQueDesOrigines(t *testing.T) {
	f := filepath.Join(t.TempDir(), "origines.txt")
	os.WriteFile(f, []byte("https://hall.gk3.secubox.in\nhttps://x.y; script-src *\n*.secubox.in\nhttp://hall.z.in\n"), 0o644)
	ancien := fichierHallsParc
	fichierHallsParc = f
	defer func() { fichierHallsParc = ancien; hallsParc.lu = time.Time{} }()
	hallsParc.lu = time.Time{}
	if got := hallsDuParc(); got != " https://hall.gk3.secubox.in" {
		t.Fatalf("hallsDuParc() = %q", got)
	}
	fichierHallsParc = filepath.Join(t.TempDir(), "absent")
	hallsParc.lu = time.Time{}
	if got := hallsDuParc(); got != "" {
		t.Fatalf("fichier absent : %q", got)
	}
}
