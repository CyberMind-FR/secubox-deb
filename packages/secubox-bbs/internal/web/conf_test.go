package web

import (
	"os"
	"path/filepath"
	"testing"
)

func ecris(t *testing.T, contenu string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "secubox.conf")
	if err := os.WriteFile(p, []byte(contenu), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLeSecretEstLuDansLaSectionApi(t *testing.T) {
	p := ecris(t, "# entete\n[core]\nnom = \"gk2\"\n\n[api]\nport = 8080\njwt_secret  = \"abcdef123\"\n")
	if got := SecretDepuisConf(p); got != "abcdef123" {
		t.Errorf("secret lu : %q", got)
	}
}

func TestUneCleDeMemeNomHorsApiEstIgnoree(t *testing.T) {
	// Un fichier peut porter un `jwt_secret` dans une autre section — celui
	// d'un module tiers, par exemple. Le prendre pour celui du core ferait
	// signer avec la mauvaise clef, et l'echec serait incomprehensible.
	p := ecris(t, "[autre]\njwt_secret = \"le-mauvais\"\n\n[api]\njwt_secret = \"le-bon\"\n")
	if got := SecretDepuisConf(p); got != "le-bon" {
		t.Errorf("secret lu : %q", got)
	}
}

func TestUnFichierAbsentDonneUnSecretVide(t *testing.T) {
	// Vide, donc API fermee. L'appelant ne doit jamais interpreter ce vide
	// comme « pas d'authentification requise ».
	if got := SecretDepuisConf("/n/existe/pas.conf"); got != "" {
		t.Errorf("secret invente : %q", got)
	}
}

func TestUnCommentaireEnFinDeLigneNEstPasDansLeSecret(t *testing.T) {
	p := ecris(t, "[api]\njwt_secret = \"abc123\" # genere le 2026-01-01\n")
	if got := SecretDepuisConf(p); got != "abc123" {
		t.Errorf("secret lu : %q", got)
	}
}

func TestUneCleAbsenteDonneUnSecretVide(t *testing.T) {
	p := ecris(t, "[api]\nport = 8080\n")
	if got := SecretDepuisConf(p); got != "" {
		t.Errorf("secret invente : %q", got)
	}
}
