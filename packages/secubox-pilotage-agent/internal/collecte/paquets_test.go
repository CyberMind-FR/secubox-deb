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
	"testing"
)

func TestPaquetsNeGardeQueSecuboxInstalles(t *testing.T) {
	s := NouvelleSourcePaquets(gk5)
	p := lireTout(t, s)
	n := 0
	for k, v := range p {
		if strings.HasSuffix(k, ".Name") {
			n++
			if !strings.HasPrefix(v.(string), "secubox-") || v == "secubox-retire" || v == "secubox-casse" {
				t.Errorf("paquet indésirable : %v", v)
			}
		}
	}
	if n != 24 {
		t.Errorf("%d paquets, attendu 24", n)
	}
	if p["Device.DeviceInfo.SoftwareVersion"] != "1.0.0-1~trixie1" {
		t.Errorf("SoftwareVersion = %v", p["Device.DeviceInfo.SoftwareVersion"])
	}
	verifierChemins(t, s, p)
}

func TestPaquetsSansStatusEnErreur(t *testing.T) {
	if _, err := NouvelleSourcePaquets(t.TempDir()).Lire(context.Background()); err == nil {
		t.Error("une erreur est attendue")
	}
}

func TestPaquetsStropheTronqueeNonPubliee(t *testing.T) {
	r := t.TempDir()
	os.MkdirAll(filepath.Join(r, "var/lib/dpkg"), 0o755)
	b := "Package: secubox-b\nStatus: install ok installed\nVersion: 2.3.4-1\n"
	// Le plafond coupe la ligne « Version: 2. » de secubox-b.
	coupe := len(b) - len("3.4-1\n")
	entete := "Package: zz\nStatus: install ok installed\nDescription: "
	remplissage := plafondDpkg - coupe - len(entete) - len("\n\n")
	contenu := entete + strings.Repeat("y", remplissage) + "\n\n" + b
	os.WriteFile(filepath.Join(r, "var/lib/dpkg/status"), []byte(contenu), 0o600)
	p, err := NouvelleSourcePaquets(r).Lire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range p {
		if v == "secubox-b" || v == "2." {
			t.Errorf("strophe tronquée publiée : %s = %v", k, v)
		}
	}
}
