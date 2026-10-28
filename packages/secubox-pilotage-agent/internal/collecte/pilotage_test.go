// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package collecte

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestPilotageMainsLiees(t *testing.T) {
	s := NouvelleSourcePilotage(gk5, "0.1.0")
	p := lireTout(t, s)
	if p["Device.X_SECUBOX_Pilotage.MainsLiees"] != true || p["Device.X_SECUBOX_Pilotage.AgentVersion"] != "0.1.0" ||
		p["Device.X_SECUBOX_Pilotage.Profil"] != "passerelle" {
		t.Errorf("pilotage = %v", p)
	}
	verifierChemins(t, s, p)

	vide := t.TempDir()
	p = lireTout(t, NouvelleSourcePilotage(vide, "0.1.0"))
	if p["Device.X_SECUBOX_Pilotage.MainsLiees"] != false || p["Device.X_SECUBOX_Pilotage.Profil"] != "" {
		t.Errorf("sans fichiers : %v", p)
	}
}

func pilotageAvecProfil(t *testing.T, prep func(chemin string)) map[string]any {
	t.Helper()
	r := t.TempDir()
	d := filepath.Join(r, "var/lib/secubox/profiles")
	if err := os.MkdirAll(d, 0o755); err != nil {
		t.Fatal(err)
	}
	prep(filepath.Join(d, "actif"))
	fini := make(chan map[string]any, 1)
	go func() { p, _ := NouvelleSourcePilotage(r, "0.1.0").Lire(context.Background()); fini <- p }()
	select {
	case p := <-fini:
		return p
	case <-time.After(2 * time.Second):
		t.Fatal("Lire bloque")
		return nil
	}
}

func TestPilotageProfilFifoNeBloquePas(t *testing.T) {
	p := pilotageAvecProfil(t, func(c string) {
		if err := syscall.Mkfifo(c, 0o600); err != nil {
			t.Skip(err)
		}
	})
	if p["Device.X_SECUBOX_Pilotage.Profil"] != "" {
		t.Errorf("profil = %v", p)
	}
}

func TestPilotageProfilGrosFichierIgnore(t *testing.T) {
	p := pilotageAvecProfil(t, func(c string) {
		os.WriteFile(c, []byte(strings.Repeat("a", 1<<20)), 0o600)
	})
	if p["Device.X_SECUBOX_Pilotage.Profil"] != "" {
		t.Error("un profil trop long ne doit pas être publié")
	}
}

func TestPilotageProfilInvalideIgnore(t *testing.T) {
	for _, v := range []string{"Passerelle", "a b", "../x", "pro\x00fil", ""} {
		p := pilotageAvecProfil(t, func(c string) { os.WriteFile(c, []byte(v+"\n"), 0o600) })
		if p["Device.X_SECUBOX_Pilotage.Profil"] != "" {
			t.Errorf("%q publié", v)
		}
	}
}
