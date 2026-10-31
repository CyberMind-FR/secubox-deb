// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package evidence

import (
	"path/filepath"
	"testing"
)

// #3320 : un lot ajoute en une transaction reste une chaine verifiable, et
// s'enchaine avec un ajout unitaire.
func TestAppendLotChaine(t *testing.T) {
	l := ouvre(t, filepath.Join(t.TempDir(), "e.db"))
	if _, err := l.Append(sample()[0]); err != nil {
		t.Fatal(err)
	}
	out, err := l.AppendLot(sample()[1:])
	if err != nil || len(out) != len(sample())-1 {
		t.Fatalf("lot : %d, %v", len(out), err)
	}
	if out[0].PrevHash == GenesisHash || out[1].PrevHash != out[0].Hash {
		t.Fatal("chainage du lot rompu")
	}
	ok, corrompu, err := l.Verify() // corrompu = -1 : aucun maillon rompu
	if err != nil || !ok || corrompu != -1 {
		t.Fatalf("verify : ok=%v corrompu=%d err=%v", ok, corrompu, err)
	}
	if n, _ := l.Count(); n != len(sample()) {
		t.Fatalf("count = %d", n)
	}
}
