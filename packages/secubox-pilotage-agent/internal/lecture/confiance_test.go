// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package lecture

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// moi : le propriétaire des fichiers créés par le test (root:root en production).
func moi() Proprietaire { return Proprietaire{UID: uint32(os.Getuid()), GID: uint32(os.Getgid())} }

// arbre crée racine/etc/secubox/<nom> avec le contenu et le mode exacts (l'umask ne compte pas).
func arbre(t *testing.T, nom, contenu string, mode os.FileMode) (racine, rel string) {
	t.Helper()
	racine = t.TempDir()
	d := filepath.Join(racine, "etc/secubox")
	if err := os.MkdirAll(d, 0o755); err != nil {
		t.Fatal(err)
	}
	f := filepath.Join(d, nom)
	if err := os.WriteFile(f, []byte(contenu), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(f, mode); err != nil {
		t.Fatal(err)
	}
	return racine, "etc/secubox/" + nom
}

func TestLireDeConfianceFichierFiable(t *testing.T) {
	racine, rel := arbre(t, "a.env", "PILOTAGE_MAITRE=10.10.0.1\n", 0o644)
	b, err := LireDeConfiance(racine, rel, 1024, moi())
	if err != nil || string(b) != "PILOTAGE_MAITRE=10.10.0.1\n" {
		t.Fatalf("%q, %v", b, err)
	}
	if err := PresentDeConfiance(racine, rel, moi()); err != nil {
		t.Fatalf("présent et fiable : %v", err)
	}
}

func TestLireDeConfianceAbsentEstErrNotExist(t *testing.T) {
	racine := t.TempDir()
	for _, rel := range []string{"etc/secubox/absent.env", "etc/absent/x"} {
		if _, err := LireDeConfiance(racine, rel, 1024, moi()); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("%s : %v, attendu fs.ErrNotExist", rel, err)
		}
	}
}

func TestLireDeConfianceRefuseInscriptibleParLeGroupeOuLesAutres(t *testing.T) {
	for _, mode := range []os.FileMode{0o664, 0o646, 0o666} {
		racine, rel := arbre(t, "a.env", "X=1\n", mode)
		if _, err := LireDeConfiance(racine, rel, 1024, moi()); err == nil || errors.Is(err, fs.ErrNotExist) {
			t.Errorf("mode %o accepté (%v)", mode, err)
		}
	}
}

func TestLireDeConfianceRefuseUnAutreProprietaire(t *testing.T) {
	racine, rel := arbre(t, "a.env", "X=1\n", 0o644)
	autre := moi()
	autre.UID++
	if _, err := LireDeConfiance(racine, rel, 1024, autre); err == nil || !strings.Contains(err.Error(), "propriétaire") {
		t.Errorf("propriétaire inattendu accepté : %v", err)
	}
	autre = moi()
	autre.GID++
	if _, err := LireDeConfiance(racine, rel, 1024, autre); err == nil {
		t.Error("groupe inattendu accepté")
	}
}

func TestLireDeConfianceNeSuitAucunLien(t *testing.T) {
	// le fichier lui-même est un lien
	racine, rel := arbre(t, "vrai.env", "X=1\n", 0o644)
	lien := filepath.Join(racine, "etc/secubox/a.env")
	if err := os.Symlink(filepath.Join(racine, rel), lien); err != nil {
		t.Fatal(err)
	}
	if _, err := LireDeConfiance(racine, "etc/secubox/a.env", 1024, moi()); err == nil || errors.Is(err, fs.ErrNotExist) {
		t.Errorf("lien final suivi : %v", err)
	}
	// un dossier intermédiaire est un lien (cas de /etc/secubox/pilotage → /etc/secubox/secrets)
	cible := filepath.Join(racine, "cible")
	if err := os.MkdirAll(cible, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cible, "mains-liees"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(cible, filepath.Join(racine, "etc/secubox/pilotage")); err != nil {
		t.Fatal(err)
	}
	if err := PresentDeConfiance(racine, "etc/secubox/pilotage/mains-liees", moi()); err == nil || errors.Is(err, fs.ErrNotExist) {
		t.Errorf("dossier intermédiaire en lien suivi : %v", err)
	}
}

func TestLireDeConfianceRefuseLienPhysiqueMultiple(t *testing.T) {
	racine, rel := arbre(t, "a.env", "X=1\n", 0o644)
	if err := os.Link(filepath.Join(racine, rel), filepath.Join(racine, "etc/secubox/b.env")); err != nil {
		t.Skip(err)
	}
	if _, err := LireDeConfiance(racine, rel, 1024, moi()); err == nil {
		t.Error("un fichier à deux liens physiques est accepté")
	}
}

func TestLireDeConfianceRefuseFifoSansBloquerEtRepertoire(t *testing.T) {
	racine, _ := arbre(t, "a.env", "", 0o644)
	fifo := filepath.Join(racine, "etc/secubox/fifo")
	if err := syscall.Mkfifo(fifo, 0o644); err != nil {
		t.Skip(err)
	}
	fini := make(chan error, 1)
	go func() { _, err := LireDeConfiance(racine, "etc/secubox/fifo", 1024, moi()); fini <- err }()
	select {
	case err := <-fini:
		if err == nil {
			t.Error("une FIFO est acceptée")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("bloque sur une FIFO")
	}
	if _, err := LireDeConfiance(racine, "etc/secubox", 1024, moi()); err == nil {
		t.Error("un répertoire est accepté")
	}
}

func TestLireDeConfianceRefuseTropLongEtCheminInvalide(t *testing.T) {
	racine, rel := arbre(t, "a.env", strings.Repeat("a", 2000), 0o644)
	if _, err := LireDeConfiance(racine, rel, 1024, moi()); err == nil {
		t.Error("un fichier plus long que le plafond est accepté (il serait coupé au milieu d'une valeur)")
	}
	for _, mauvais := range []string{"", "etc/../etc/secubox/a.env", "etc//secubox/a.env", "./etc/secubox/a.env"} {
		if _, err := LireDeConfiance(racine, mauvais, 1024, moi()); err == nil {
			t.Errorf("chemin %q accepté", mauvais)
		}
	}
}
