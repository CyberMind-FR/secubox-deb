// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package web

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/CyberMind-FR/secubox-deb/secubox-bbs/internal/store"
)

// deposeSnapshotDeTest ecrit un faux PNG dans le cache, au chemin attendu par
// servirUrlshot (<base>/<cle>/screenshot.png), en pointant urlshotBase vers un
// repertoire temporaire — restaure a la fin du test pour ne pas contaminer les
// suivants (variable de PAQUET, pas de test).
func deposeSnapshotDeTest(t *testing.T, cle string, contenu []byte) {
	t.Helper()
	avant := urlshotBase
	base := t.TempDir()
	urlshotBase = base
	t.Cleanup(func() { urlshotBase = avant })
	dir := filepath.Join(base, cle)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "screenshot.png"), contenu, 0o640); err != nil {
		t.Fatal(err)
	}
}

// TestUrlshotSertLePlaceholderQuandPasDeSnapshot prouve que l'absence de
// fichier en cache produit quand meme une reponse PNG 200 — jamais un
// 404/500 qui casserait le chargement de l'<img> sur la carte.
func TestUrlshotSertLePlaceholderQuandPasDeSnapshot(t *testing.T) {
	srv, s := banc(t)
	cle := store.CleUrlshot("https://x.example/a")
	if err := s.EnfileUrlshot(cle, "https://x.example/a", "public"); err != nil {
		t.Fatal(err)
	}
	w := demande(t, srv, "GET", "/urlshot/"+cle, "", nil) // anonyme
	if w.Code != 200 || w.Header().Get("Content-Type") != "image/png" {
		t.Fatalf("placeholder attendu : code=%d ct=%q", w.Code, w.Header().Get("Content-Type"))
	}
	if w.Body.Len() == 0 {
		t.Fatal("corps vide")
	}
}

// TestUrlshotLocalRefuseAnonyme prouve que c'est la VISIBILITE, pas
// l'absence de fichier, qui protege : un vrai PNG est present en cache mais
// un anonyme sur une cle LOCAL ne doit jamais le recevoir (miroir /f/ #1114).
func TestUrlshotLocalRefuseAnonyme(t *testing.T) {
	srv, s := banc(t)
	cle := store.CleUrlshot("https://x.example/b")
	if err := s.EnfileUrlshot(cle, "https://x.example/b", "local"); err != nil {
		t.Fatal(err)
	}
	secret := []byte("\x89PNG-secret-snapshot-local")
	deposeSnapshotDeTest(t, cle, secret)

	w := demande(t, srv, "GET", "/urlshot/"+cle, "", nil) // anonyme
	if bytes.Contains(w.Body.Bytes(), secret) {
		t.Fatal("snapshot d'un post LOCAL servi a un anonyme")
	}
	if w.Code != 200 || w.Header().Get("Content-Type") != "image/png" {
		t.Fatalf("placeholder attendu malgre tout : code=%d ct=%q", w.Code, w.Header().Get("Content-Type"))
	}
}

// TestUrlshotLocalServiAuMembreConnecte prouve le pendant positif de la garde
// ci-dessus : un membre connecte, lui, recoit bien le snapshot d'une cle
// LOCAL — sinon la garde masquerait aussi le contenu a ses ayants droit.
func TestUrlshotLocalServiAuMembreConnecte(t *testing.T) {
	srv, s := banc(t)
	uid, err := s.CreateUser("gk2", "Gandalf", store.RoleSysop)
	if err != nil {
		t.Fatal(err)
	}
	jeton, _ := s.NewSession(uid, "", "")
	cle := store.CleUrlshot("https://x.example/c")
	if err := s.EnfileUrlshot(cle, "https://x.example/c", "local"); err != nil {
		t.Fatal(err)
	}
	contenu := []byte("\x89PNG-vrai-contenu")
	deposeSnapshotDeTest(t, cle, contenu)

	w := demande(t, srv, "GET", "/urlshot/"+cle, jeton, nil)
	if w.Code != 200 {
		t.Fatalf("code %d pour un membre connecte", w.Code)
	}
	if !bytes.Equal(w.Body.Bytes(), contenu) {
		t.Fatal("le membre connecte ne recoit pas le vrai snapshot")
	}
}

// TestUrlshotCleInvalideEst404 prouve que la cle est validee par motif AVANT
// tout acces disque — une traversee de chemin ne doit jamais atteindre
// filepath.Join.
func TestUrlshotCleInvalideEst404(t *testing.T) {
	srv, _ := banc(t)
	for _, chemin := range []string{
		"/urlshot/../etc/passwd",
		"/urlshot/" + string(make([]byte, 0)), // cle vide
		"/urlshot/pas-32-hexa",
		"/urlshot/" + "0123456789abcdef0123456789abcdeF", // majuscule refusee
	} {
		w := demande(t, srv, "GET", chemin, "", nil)
		if w.Code == 200 {
			t.Errorf("cle invalide acceptee (%q) : code %d", chemin, w.Code)
		}
	}
}
