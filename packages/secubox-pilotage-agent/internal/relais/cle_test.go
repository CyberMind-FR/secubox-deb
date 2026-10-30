// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package relais

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCleCreeeUneFoisPuisRelue(t *testing.T) {
	d := t.TempDir()
	if err := os.Chmod(d, 0o700); err != nil {
		t.Fatal(err)
	}
	chemin := filepath.Join(d, "relais.key")
	cle, err := CreerOuChargerCle(chemin)
	if err != nil {
		t.Fatal(err)
	}
	st, err := os.Lstat(chemin)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 || !st.Mode().IsRegular() {
		t.Fatalf("mode %v", st.Mode())
	}
	brut, _ := os.ReadFile(chemin)
	bloc, _ := pem.Decode(brut)
	if bloc == nil || bloc.Type != "PRIVATE KEY" {
		t.Fatalf("PEM PKCS#8 attendu : %q", brut)
	}
	if _, err := x509.ParsePKCS8PrivateKey(bloc.Bytes); err != nil {
		t.Fatal(err)
	}
	encore, err := CreerOuChargerCle(chemin)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(cle, encore) {
		t.Fatal("la clé a changé à la seconde lecture")
	}
	entrees, _ := os.ReadDir(d)
	if len(entrees) != 1 {
		t.Fatalf("fichiers temporaires laissés : %v", entrees)
	}
	pub := PEMPublique(cle)
	bp, _ := pem.Decode(pub)
	if bp == nil || bp.Type != "PUBLIC KEY" {
		t.Fatalf("PEM SPKI attendu : %q", pub)
	}
	k, err := x509.ParsePKIXPublicKey(bp.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if !k.(ed25519.PublicKey).Equal(cle.Public()) {
		t.Fatal("clé publique différente")
	}
}

func TestCleDouteuseRefusee(t *testing.T) {
	d := t.TempDir()
	if err := os.Chmod(d, 0o700); err != nil {
		t.Fatal(err)
	}
	chemin := filepath.Join(d, "relais.key")
	cle, err := CreerOuChargerCle(chemin)
	if err != nil {
		t.Fatal(err)
	}
	_ = cle
	// Lisible par le groupe : refusée, jamais réparée en silence.
	if err := os.Chmod(chemin, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := ChargerCle(chemin); err == nil {
		t.Fatal("clé 0640 acceptée")
	}
	if err := os.Chmod(chemin, 0o600); err != nil {
		t.Fatal(err)
	}
	// Un lien symbolique n'est jamais suivi.
	lien := filepath.Join(d, "lien.key")
	if err := os.Symlink(chemin, lien); err != nil {
		t.Fatal(err)
	}
	if _, err := ChargerCle(lien); err == nil {
		t.Fatal("lien suivi")
	}
	if _, err := CreerOuChargerCle(lien); err == nil {
		t.Fatal("lien suivi à la création")
	}
	// Contenu qui n'est pas une clé Ed25519 PKCS#8.
	autre := filepath.Join(d, "autre.key")
	if err := os.WriteFile(autre, []byte("-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ChargerCle(autre); err == nil {
		t.Fatal("clé illisible acceptée")
	}
	// Dossier ouvert aux autres : on ne crée rien dedans.
	ouvert := filepath.Join(d, "ouvert")
	if err := os.Mkdir(ouvert, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(ouvert, 0o777); err != nil {
		t.Fatal(err)
	}
	if _, err := CreerOuChargerCle(filepath.Join(ouvert, "relais.key")); err == nil {
		t.Fatal("clé créée dans un dossier ouvert à tous")
	}
}

func TestClePubliqueConcordante(t *testing.T) {
	d := t.TempDir()
	if err := os.Chmod(d, 0o700); err != nil {
		t.Fatal(err)
	}
	cle, err := CreerOuChargerCle(filepath.Join(d, "relais.key"))
	if err != nil {
		t.Fatal(err)
	}
	pub := filepath.Join(d, "relais.pub")
	if err := os.WriteFile(pub, PEMPublique(cle), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := VerifierClePublique(pub, cle, uint32(os.Getuid())); err != nil {
		t.Fatal(err)
	}
	if err := VerifierClePublique(pub, cle, uint32(os.Getuid())+1); err == nil {
		t.Fatal("propriétaire non vérifié")
	}
	_, autre, _ := ed25519.GenerateKey(nil)
	if err := VerifierClePublique(pub, autre, uint32(os.Getuid())); err == nil {
		t.Fatal("clé publique d'une autre clé acceptée")
	}
	if err := os.Chmod(pub, 0o666); err != nil {
		t.Fatal(err)
	}
	if err := VerifierClePublique(pub, cle, uint32(os.Getuid())); err == nil {
		t.Fatal("clé publique inscriptible par tous acceptée")
	}
}

// vecteurPython : le jeton frappé par ce code, vérifié par le vrai vérificateur Python
// (common/secubox_core/tests/test_relais_vecteur_3126.py).
type vecteurPython struct {
	PubPEM string `json:"pub_pem"`
	Jeton  string `json:"jeton"`
	Box    string `json:"box"`
	Cible  string `json:"cible"`
	Iat    int64  `json:"iat"`
}

const cheminVecteur = "testdata/vecteur-python.json"

func vecteur(t *testing.T, iat time.Time, acteur string) vecteurPython {
	t.Helper()
	graine := bytes.Repeat([]byte{0x5b}, ed25519.SeedSize)
	cle := ed25519.NewKeyFromSeed(graine)
	a, m, err := Normaliser(acteur, "GK2")
	if err != nil {
		t.Fatal(err)
	}
	j, err := Frapper(cle, "gk5", "demo", a, m, "admin", iat)
	if err != nil {
		t.Fatal(err)
	}
	return vecteurPython{PubPEM: string(PEMPublique(cle)), Jeton: j, Box: "gk5", Cible: "demo", Iat: iat.Unix()}
}

// TestVecteurFige : le vecteur versionné est bien ce que frappe ce code (Ed25519 est déterministe).
// SBX_VECTEUR_ECRIRE=1 le réécrit.
func TestVecteurFige(t *testing.T) {
	v := vecteur(t, time.Unix(1_800_000_000, 0), "Gerald")
	attendu, _ := json.MarshalIndent(v, "", "  ")
	attendu = append(attendu, '\n')
	if os.Getenv("SBX_VECTEUR_ECRIRE") == "1" {
		if err := os.WriteFile(cheminVecteur, attendu, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	brut, err := os.ReadFile(cheminVecteur)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(brut, attendu) {
		t.Fatalf("vecteur versionné périmé :\n%s\nattendu :\n%s", brut, attendu)
	}
}

// TestVecteurVivant : un jeton frappé MAINTENANT, écrit là où le test Python le demande (SBX_VECTEUR_SORTIE).
func TestVecteurVivant(t *testing.T) {
	sortie := os.Getenv("SBX_VECTEUR_SORTIE")
	if sortie == "" {
		t.Skip("SBX_VECTEUR_SORTIE absent : lancé par le test Python seulement")
	}
	v := vecteur(t, time.Now(), "Gerald")
	b, _ := json.Marshal(v)
	if err := os.WriteFile(sortie, b, 0o600); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(v.Jeton, "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.") {
		t.Fatalf("en-tête %q", v.Jeton)
	}
}
