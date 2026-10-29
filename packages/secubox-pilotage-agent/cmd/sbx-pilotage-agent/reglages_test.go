// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package main

import (
	"bytes"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/CyberMind-FR/secubox-deb/secubox-pilotage-agent/internal/lecture"
)

func moi() lecture.Proprietaire {
	return lecture.Proprietaire{UID: uint32(os.Getuid()), GID: uint32(os.Getgid())}
}

// journal capte la sortie de log le temps du test.
func journal(t *testing.T) *bytes.Buffer {
	t.Helper()
	var b bytes.Buffer
	log.SetOutput(&b)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	return &b
}

func fichierEnv(t *testing.T, contenu string, mode os.FileMode) string {
	t.Helper()
	racine := t.TempDir()
	d := filepath.Join(racine, "etc/secubox")
	if err := os.MkdirAll(d, 0o755); err != nil {
		t.Fatal(err)
	}
	f := filepath.Join(d, "pilotage-agent.env")
	if err := os.WriteFile(f, []byte(contenu), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(f, mode); err != nil {
		t.Fatal(err)
	}
	return racine
}

const envExemple = "# commentaire\n\nPILOTAGE_MAITRE=10.10.0.1:8472\nPILOTAGE_RELEVE_INTERVALLE_S = \"45\"\nPILOTAGE_SWAP_SEUIL_PCT='70'\nPATH=/tmp/piege\nLD_PRELOAD=/tmp/x.so\nligne sans egal\n"

func TestReglagesFiablesAppliques(t *testing.T) {
	racine := fichierEnv(t, envExemple, 0o644)
	poses := map[string]string{}
	j := journal(t)
	chargerReglages(racine, moi(), func(k, v string) error { poses[k] = v; return nil })
	if poses["PILOTAGE_MAITRE"] != "10.10.0.1:8472" || poses["PILOTAGE_RELEVE_INTERVALLE_S"] != "45" || poses["PILOTAGE_SWAP_SEUIL_PCT"] != "70" {
		t.Fatalf("réglages : %v", poses)
	}
	if _, ok := poses["PATH"]; ok || len(poses) != 3 {
		t.Fatalf("seules les clés PILOTAGE_* connues sont posées : %v", poses)
	}
	if !strings.Contains(j.String(), "LD_PRELOAD") {
		t.Errorf("clé inconnue non journalisée : %q", j.String())
	}
}

func TestReglagesNonFiablesIgnoresAvecUneLigneDeJournal(t *testing.T) {
	for nom, prep := range map[string]func(t *testing.T) string{
		"inscriptible par le groupe":  func(t *testing.T) string { return fichierEnv(t, envExemple, 0o664) },
		"inscriptible par les autres": func(t *testing.T) string { return fichierEnv(t, envExemple, 0o646) },
		"lien vers un fichier fiable": func(t *testing.T) string {
			r := fichierEnv(t, envExemple, 0o644)
			env := filepath.Join(r, "etc/secubox/pilotage-agent.env")
			vrai := filepath.Join(r, "vrai.env")
			if err := os.Rename(env, vrai); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(vrai, env); err != nil {
				t.Fatal(err)
			}
			return r
		},
	} {
		t.Run(nom, func(t *testing.T) {
			racine := prep(t)
			j := journal(t)
			poses := map[string]string{}
			chargerReglages(racine, moi(), func(k, v string) error { poses[k] = v; return nil })
			if len(poses) != 0 {
				t.Fatalf("réglages non fiables appliqués : %v", poses)
			}
			if n := strings.Count(j.String(), "ignoré"); n != 1 {
				t.Fatalf("%d ligne(s) « ignoré » au journal, attendu 1 : %q", n, j.String())
			}
		})
	}
}

func TestReglagesProprietaireAutreIgnores(t *testing.T) {
	racine := fichierEnv(t, envExemple, 0o644)
	autre := moi()
	autre.UID++
	poses := map[string]string{}
	j := journal(t)
	chargerReglages(racine, autre, func(k, v string) error { poses[k] = v; return nil })
	if len(poses) != 0 || !strings.Contains(j.String(), "propriétaire") {
		t.Fatalf("poses %v, journal %q", poses, j.String())
	}
}

func TestReglagesAbsentsSilencieux(t *testing.T) {
	j := journal(t)
	poses := map[string]string{}
	chargerReglages(t.TempDir(), moi(), func(k, v string) error { poses[k] = v; return nil })
	if len(poses) != 0 || j.Len() != 0 {
		t.Fatalf("poses %v, journal %q", poses, j.String())
	}
}
