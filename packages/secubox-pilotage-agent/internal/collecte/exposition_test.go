// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package collecte

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestExpositionNomsEtPorts(t *testing.T) {
	s := NouvelleSourceExposition(gk5)
	p := lireTout(t, s)
	noms, _ := p["Device.X_SECUBOX_Exposure.Names"].([]string)
	if !reflect.DeepEqual(noms, []string{"admin.gk5.secubox.in", "hub.gk5.secubox.in"}) {
		t.Errorf("noms = %v", noms)
	}
	ports, _ := p["Device.X_SECUBOX_Exposure.Ports"].([]int)
	if !reflect.DeepEqual(ports, []int{80, 443, 9080}) {
		t.Errorf("ports = %v", ports)
	}
	verifierChemins(t, s, p)
}

func TestExpositionIgnoreLesDirectivesVoisines(t *testing.T) {
	p := lireTout(t, NouvelleSourceExposition(gk5))
	for _, n := range p["Device.X_SECUBOX_Exposure.Names"].([]string) {
		if n == "128" || n == "off" {
			t.Errorf("nom parasite : %s", n)
		}
	}
}

func TestExpositionFifoEtGrosFichierBornes(t *testing.T) {
	r := t.TempDir()
	d := filepath.Join(r, "etc/nginx/sites-enabled")
	os.MkdirAll(d, 0o755)
	os.MkdirAll(filepath.Join(r, "proc/net"), 0o755)
	os.WriteFile(filepath.Join(r, "proc/net/tcp"), nil, 0o600)
	if err := syscall.Mkfifo(filepath.Join(d, "a-fifo"), 0o600); err != nil {
		t.Skip(err)
	}
	gros := filepath.Join(t.TempDir(), "gros")
	os.WriteFile(gros, []byte(strings.Repeat("server_name x.example;\n", 100000)+"server_name apres.example;\n"), 0o600)
	os.Symlink(gros, filepath.Join(d, "b-gros"))
	fini := make(chan map[string]any, 1)
	go func() { p, _ := NouvelleSourceExposition(r).Lire(context.Background()); fini <- p }()
	select {
	case p := <-fini:
		for _, n := range p["Device.X_SECUBOX_Exposure.Names"].([]string) {
			if n == "apres.example" {
				t.Error("la lecture n'est pas bornée")
			}
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Lire bloque")
	}
}
