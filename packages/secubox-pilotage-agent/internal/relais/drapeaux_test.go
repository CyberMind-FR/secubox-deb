// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package relais

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

// TestEcheanceDans (R-L5-21 I1) : drapeau root `support-ouvert` / `proprietaire` contenant une échéance (secondes
// epoch). Valide seulement si dossier et fichier passent les MÊMES contrôles que les mains liées et si l'échéance
// n'est pas dépassée ; tout le reste ⇒ faux (lecture).
func TestEcheanceDans(t *testing.T) {
	maintenant := time.Unix(1_800_000_000, 0)
	futur := strconv.FormatInt(maintenant.Unix()+600, 10)
	cas := []struct {
		nom    string
		poser  func(d string) uint32
		valide bool
	}{
		{"absent", func(d string) uint32 { return uid0Test }, false},
		{"valide", func(d string) uint32 {
			os.WriteFile(filepath.Join(d, "support-ouvert"), []byte(futur+"\n"), 0o644)
			return uid0Test
		}, true},
		{"échu", func(d string) uint32 {
			os.WriteFile(filepath.Join(d, "support-ouvert"), []byte(strconv.FormatInt(maintenant.Unix(), 10)), 0o644)
			return uid0Test
		}, false},
		{"illisible", func(d string) uint32 {
			os.WriteFile(filepath.Join(d, "support-ouvert"), []byte("demain"), 0o644)
			return uid0Test
		}, false},
		{"vide", func(d string) uint32 { os.WriteFile(filepath.Join(d, "support-ouvert"), nil, 0o644); return uid0Test }, false},
		{"trop long", func(d string) uint32 {
			os.WriteFile(filepath.Join(d, "support-ouvert"), []byte(futur+string(make([]byte, 100))), 0o644)
			return uid0Test
		}, false},
		{"non root", func(d string) uint32 {
			os.WriteFile(filepath.Join(d, "support-ouvert"), []byte(futur), 0o644)
			return uid0Test + 1
		}, false},
		{"droits larges", func(d string) uint32 {
			f := filepath.Join(d, "support-ouvert")
			os.WriteFile(f, []byte(futur), 0o644)
			os.Chmod(f, 0o666)
			return uid0Test
		}, false},
		{"lien", func(d string) uint32 {
			c := filepath.Join(filepath.Dir(d), "ailleurs")
			os.WriteFile(c, []byte(futur), 0o644)
			os.Symlink(c, filepath.Join(d, "support-ouvert"))
			return uid0Test
		}, false},
		{"dossier ouvert à tous", func(d string) uint32 {
			os.WriteFile(filepath.Join(d, "support-ouvert"), []byte(futur), 0o644)
			os.Chmod(d, 0o777)
			return uid0Test
		}, false},
		{"pas un fichier", func(d string) uint32 { os.Mkdir(filepath.Join(d, "support-ouvert"), 0o755); return uid0Test }, false},
	}
	for _, c := range cas {
		t.Run(c.nom, func(t *testing.T) {
			d := filepath.Join(t.TempDir(), "etc-secubox-pilotage")
			os.Mkdir(d, 0o755)
			uid := c.poser(d)
			if got := EcheanceDans(d, "support-ouvert", uid, maintenant); got != c.valide {
				t.Fatalf("%s : %v attendu", c.nom, c.valide)
			}
		})
	}
	if EcheanceDans(filepath.Join(t.TempDir(), "absent"), "support-ouvert", uid0Test, maintenant) {
		t.Fatal("dossier absent : faux attendu")
	}
}
