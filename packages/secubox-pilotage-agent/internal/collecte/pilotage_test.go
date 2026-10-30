// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package collecte

import (
	"bytes"
	"context"
	"log"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/CyberMind-FR/secubox-deb/secubox-pilotage-agent/internal/lecture"
)

// sourcePilotageDe : la source, avec le propriétaire du test en guise de root:root.
func sourcePilotageDe(racine, version string) *pilotage {
	s := NouvelleSourcePilotage(racine, version).(*pilotage)
	s.proprio = lecture.Proprietaire{UID: uint32(os.Getuid()), GID: uint32(os.Getgid())}
	return s
}

// racineMainsLiees copie le drapeau du jeu gk5 avec un mode exact (l'umask de la copie de travail ne compte pas).
func racineMainsLiees(t *testing.T, mode os.FileMode) string {
	t.Helper()
	r := t.TempDir()
	d := filepath.Join(r, "etc/secubox/pilotage")
	if err := os.MkdirAll(d, 0o755); err != nil {
		t.Fatal(err)
	}
	f := filepath.Join(d, "mains-liees")
	if err := os.WriteFile(f, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(f, mode); err != nil {
		t.Fatal(err)
	}
	return r
}

func journalCollecte(t *testing.T) *bytes.Buffer {
	t.Helper()
	var b bytes.Buffer
	log.SetOutput(&b)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	return &b
}

func TestPilotageMainsLiees(t *testing.T) {
	s := sourcePilotageDe(gk5, "0.1.0")
	os.Chmod(filepath.Join(gk5, "etc/secubox/pilotage/mains-liees"), 0o644) // mode de git, quel que soit l'umask de la copie de travail
	p := lireTout(t, s)
	if p["Device.X_SECUBOX_Pilotage.MainsLiees"] != true || p["Device.X_SECUBOX_Pilotage.AgentVersion"] != "0.1.0" ||
		p["Device.X_SECUBOX_Pilotage.Profil"] != "passerelle" {
		t.Errorf("pilotage = %v", p)
	}
	verifierChemins(t, s, p)

	vide := t.TempDir()
	p = lireTout(t, sourcePilotageDe(vide, "0.1.0"))
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
	go func() { p, _ := sourcePilotageDe(r, "0.1.0").Lire(context.Background()); fini <- p }()
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

// R36 : le drapeau n'est cru que root:root, sans droit d'écriture groupe/autres, sans lien ; sinon faux et une ligne de journal.
func TestPilotageMainsLieesNonFiablesIgnorees(t *testing.T) {
	cas := map[string]func(t *testing.T) string{
		"inscriptible par le groupe":  func(t *testing.T) string { return racineMainsLiees(t, 0o664) },
		"inscriptible par les autres": func(t *testing.T) string { return racineMainsLiees(t, 0o646) },
		"drapeau en lien": func(t *testing.T) string {
			r := racineMainsLiees(t, 0o644)
			f := filepath.Join(r, "etc/secubox/pilotage/mains-liees")
			os.Rename(f, filepath.Join(r, "vrai"))
			if err := os.Symlink(filepath.Join(r, "vrai"), f); err != nil {
				t.Fatal(err)
			}
			return r
		},
		"dossier en lien": func(t *testing.T) string {
			r := racineMainsLiees(t, 0o644)
			d := filepath.Join(r, "etc/secubox/pilotage")
			os.Rename(d, filepath.Join(r, "ailleurs"))
			if err := os.Symlink(filepath.Join(r, "ailleurs"), d); err != nil {
				t.Fatal(err)
			}
			return r
		},
	}
	for nom, prep := range cas {
		t.Run(nom, func(t *testing.T) {
			r := prep(t)
			j := journalCollecte(t)
			s := sourcePilotageDe(r, "0.1.0")
			for i := 0; i < 3; i++ {
				if p := lireTout(t, s); p["Device.X_SECUBOX_Pilotage.MainsLiees"] != false {
					t.Fatalf("drapeau non fiable cru : %v", p)
				}
			}
			if n := strings.Count(j.String(), "mains liées ignoré"); n != 1 {
				t.Fatalf("%d ligne(s) de journal sur trois lectures, attendu 1 : %q", n, j.String())
			}
		})
	}
	// un autre propriétaire que celui exigé
	r := racineMainsLiees(t, 0o644)
	s := sourcePilotageDe(r, "0.1.0")
	s.proprio.UID++
	journalCollecte(t)
	if p := lireTout(t, s); p["Device.X_SECUBOX_Pilotage.MainsLiees"] != false {
		t.Fatalf("propriétaire inattendu cru : %v", p)
	}
	// production : root:root exigé
	if NouvelleSourcePilotage(r, "x").(*pilotage).proprio != lecture.Root {
		t.Fatal("la source de production doit exiger root:root")
	}
}

// L5 tâche 7, R-L5-34 : « distante » seulement quand l'allègement a RÉUSSI (marqueur root posé par secubox-profilectl
// après nginx -t, ôté au retour) ; le nom du profil seul ne suffit pas (un allègement défait garde l'admin locale).
func TestPilotageInterfaceSelonLAllegement(t *testing.T) {
	r := t.TempDir()
	s := sourcePilotageDe(r, "0.1.0")
	p, _ := s.Lire(context.Background())
	if p["Device.X_SECUBOX_Pilotage.Interface"] != "locale" {
		t.Errorf("sans marqueur : %v", p["Device.X_SECUBOX_Pilotage.Interface"])
	}
	d := filepath.Join(r, "var/lib/secubox-profiles/allegement")
	os.MkdirAll(d, 0o755)
	os.WriteFile(filepath.Join(d, "actif"), nil, 0o644)
	p, _ = s.Lire(context.Background())
	if p["Device.X_SECUBOX_Pilotage.Interface"] != "distante" {
		t.Errorf("avec marqueur : %v", p["Device.X_SECUBOX_Pilotage.Interface"])
	}
	os.Chmod(filepath.Join(d, "actif"), 0o666) // inscriptible par tous : non fiable
	p, _ = s.Lire(context.Background())
	if p["Device.X_SECUBOX_Pilotage.Interface"] != "locale" {
		t.Errorf("marqueur non fiable accepté")
	}
}

// R-L5-34 tour 2 : marqueur en lien symbolique ou d'un autre propriétaire ⇒ « locale ».
func TestPilotageMarqueurLienOuEtrangerRefuse(t *testing.T) {
	r := t.TempDir()
	d := filepath.Join(r, "var/lib/secubox-profiles/allegement")
	os.MkdirAll(d, 0o755)
	vrai := filepath.Join(r, "ailleurs")
	os.WriteFile(vrai, nil, 0o644)
	os.Symlink(vrai, filepath.Join(d, "actif"))
	s := sourcePilotageDe(r, "0.1.0")
	if p, _ := s.Lire(context.Background()); p["Device.X_SECUBOX_Pilotage.Interface"] != "locale" {
		t.Errorf("marqueur en lien accepté")
	}
	os.Remove(filepath.Join(d, "actif"))
	os.WriteFile(filepath.Join(d, "actif"), nil, 0o644)
	if p, _ := s.Lire(context.Background()); p["Device.X_SECUBOX_Pilotage.Interface"] != "distante" {
		t.Fatalf("marqueur valide refusé")
	}
	s.proprio = lecture.Proprietaire{UID: uint32(os.Getuid()) + 1, GID: uint32(os.Getgid())}
	if p, _ := s.Lire(context.Background()); p["Device.X_SECUBOX_Pilotage.Interface"] != "locale" {
		t.Errorf("marqueur d'un autre propriétaire accepté")
	}
}
