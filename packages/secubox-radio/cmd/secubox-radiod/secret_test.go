// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
package main

import (
	"os"
	"path/filepath"
	"testing"
)

// La crédence de systemd d'abord, l'ancien fichier sinon (Coffre P3, #1367).
func TestCheminSecretCredenceDAbord(t *testing.T) {
	d := t.TempDir()
	ancien := "/etc/secubox/secrets/radio-sysop"
	if got := cheminSecret("", ancien); got != ancien {
		t.Fatalf("sans CREDENTIALS_DIRECTORY : %q", got)
	}
	if got := cheminSecret(d, ancien); got != ancien {
		t.Fatalf("crédence absente : %q", got)
	}
	if err := os.WriteFile(filepath.Join(d, "radio-sysop"), []byte("s3cr3t\n"), 0o400); err != nil {
		t.Fatal(err)
	}
	if got := cheminSecret(d, ancien); got != filepath.Join(d, "radio-sysop") {
		t.Fatalf("crédence présente : %q", got)
	}
	secretSysop = ""
	chargeSecret(cheminSecret(d, ancien))
	if secretSysop != "s3cr3t" {
		t.Fatalf("secret chargé : %q", secretSysop)
	}
}
