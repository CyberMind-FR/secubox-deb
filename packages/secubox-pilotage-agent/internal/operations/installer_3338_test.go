// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package operations

import (
	"reflect"
	"strings"
	"testing"
)

// TestTraduireInstaller (#3338) : Device.X_SECUBOX_Packages.Installer() {paquet} → `installer <paquet>`, un paquet
// SecuBox et rien d'autre (le ctl revérifie le motif et la présence au dépôt).
func TestTraduireInstaller(t *testing.T) {
	argv, err := Traduire(CmdInstaller, map[string]any{"paquet": "secubox-jellyfin"})
	if err != nil || !reflect.DeepEqual(argv, []string{"installer", "secubox-jellyfin"}) {
		t.Fatalf("argv %v, err %v", argv, err)
	}
	for _, args := range []map[string]any{
		nil,
		{"paquet": "nginx"},
		{"paquet": "secubox-Jelly"},
		{"paquet": "secubox-a;reboot"},
		{"paquet": "secubox-" + strings.Repeat("a", 49)},
		{"paquet": 3.0},
		{"paquet": "secubox-jellyfin", "version": "1.0"},
	} {
		if argv, err := Traduire(CmdInstaller, args); err == nil {
			t.Fatalf("%v accepté : %v", args, argv)
		}
	}
}
