// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// See LICENCE-CMSD-1.0.md for terms.

package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Le format reel de la box : une table postfix vmailbox.
func fichierComptes(t *testing.T, contenu string) string {
	t.Helper()
	f := filepath.Join(t.TempDir(), "vmailbox")
	if err := os.WriteFile(f, []byte(contenu), 0o644); err != nil {
		t.Fatal(err)
	}
	return f
}

func TestFormatVmailboxEtFormeLocale(t *testing.T) {
	c, err := NewComptes([]string{fichierComptes(t, "gk2@secubox.in\tsecubox.in/gk2/\n")})
	if err != nil {
		t.Fatalf("chargement : %v", err)
	}
	if !c.Charge() {
		t.Fatal("la liste doit etre consideree chargee")
	}
	// Les journaux montrent les deux formes : « sasl_username=gk2@secubox.in »
	// comme « sasl_username=gk2 ».
	for _, existe := range []string{"gk2@secubox.in", "gk2", "GK2@SECUBOX.IN"} {
		if c.Inexistant(existe) {
			t.Errorf("%s est un compte reel, il ne doit pas etre signale inexistant", existe)
		}
	}
	// Les cibles reellement observees dans les campagnes.
	for _, absent := range []string{"gerald@gk2.net", "gerard", "gege@gk2.net", "s4wlume"} {
		if !c.Inexistant(absent) {
			t.Errorf("%s n'existe pas sur la box, il doit etre signale", absent)
		}
	}
}

// SANS liste, aucune certitude : mieux vaut rester patient que bannir un
// utilisateur reel sur une liste qu'on n'a pas su lire.
func TestSansListeAucuneCertitude(t *testing.T) {
	c, err := NewComptes([]string{filepath.Join(t.TempDir(), "absent")})
	if err != nil {
		t.Fatalf("un fichier absent ne doit pas echouer : %v", err)
	}
	if c.Charge() {
		t.Fatal("une liste vide ne doit pas etre consideree chargee")
	}
	if c.Inexistant("nimportequi@example.com") {
		t.Fatal("sans liste, on ne conclut rien")
	}
}

func TestCommentairesEtLignesVides(t *testing.T) {
	c, _ := NewComptes([]string{fichierComptes(t,
		"# boites virtuelles\n\ngk2@secubox.in\tsecubox.in/gk2/\n   \n# fin\n")})
	if c.Taille() != 2 { // l'adresse + sa partie locale
		t.Fatalf("taille %d, attendu 2 (adresse + forme locale)", c.Taille())
	}
}

func TestCibleVideNeConclutRien(t *testing.T) {
	c, _ := NewComptes([]string{fichierComptes(t, "gk2@secubox.in\n")})
	if c.Inexistant("") {
		t.Fatal("une ligne sans compte vise ne doit rien declencher")
	}
}

// Bout en bout : le cas qui a motive la fonctionnalite. Une SEULE tentative
// sur un compte inexistant, depuis une adresse jamais revue — le compteur ne
// verrait rien, la liste des comptes tranche.
func TestCompteInexistantBannitDesLaPremiereTentative(t *testing.T) {
	b, fx := banneurTest(t)
	j, chemin := journalTest(t)
	lb, _ := NewListeBlanche("")
	comptes, _ := NewComptes([]string{fichierComptes(t, "gk2@secubox.in\tsecubox.in/gk2/\n")})

	ctx, annule := context.WithCancel(context.Background())
	signaux := make(chan Signal, 2)
	signaux <- Signal{IP: "203.0.113.77", Service: "smtp", Categorie: "auth_smtp:sasl_failed",
		Severite: "high", Detail: "SASL refusee", Cible: "gerald@gk2.net"}
	// Seuils volontairement inatteignables : seule la liste peut declencher.
	go traite(ctx, signaux, NewCompteur(time.Hour, 999, time.Hour),
		NewCampagnes(time.Hour, 999), comptes, b, j, lb, false)
	time.Sleep(100 * time.Millisecond)
	annule()

	if len(fx.bannies) != 1 || fx.bannies[0] != "203.0.113.77" {
		t.Fatalf("une tentative sur un compte inexistant doit bannir aussitot, obtenu %v", fx.bannies)
	}
	if l := lignesJournal(t, chemin); len(l) != 1 || l[0]["action"] != "banned" {
		t.Fatalf("journal attendu banned, obtenu %v", l)
	}
}

// Le miroir : un echec sur le compte REEL reste patient, pour ne pas bannir
// son proprietaire qui se trompe.
func TestCompteReelResteTraiteAvecPatience(t *testing.T) {
	b, fx := banneurTest(t)
	j, _ := journalTest(t)
	lb, _ := NewListeBlanche("")
	comptes, _ := NewComptes([]string{fichierComptes(t, "gk2@secubox.in\tsecubox.in/gk2/\n")})

	ctx, annule := context.WithCancel(context.Background())
	signaux := make(chan Signal, 2)
	signaux <- Signal{IP: "203.0.113.78", Service: "smtp", Categorie: "auth_smtp:sasl_failed",
		Severite: "high", Detail: "SASL refusee", Cible: "gk2@secubox.in"}
	go traite(ctx, signaux, NewCompteur(time.Hour, 999, time.Hour),
		NewCampagnes(time.Hour, 999), comptes, b, j, lb, false)
	time.Sleep(100 * time.Millisecond)
	annule()

	if len(fx.bannies) != 0 {
		t.Fatalf("un echec sur le compte reel ne doit pas bannir aussitot, obtenu %v", fx.bannies)
	}
}

// Le format REEL de dovecot sur gk2 : passwd-file. Sans decoupage sur « : »,
// on prendrait l'empreinte du mot de passe pour un nom de compte — et TOUTES
// les cibles paraitraient inexistantes, y compris les vraies.
func TestFormatPasswdFileDovecot(t *testing.T) {
	c, err := NewComptes([]string{fichierComptes(t,
		"gk2@secubox.in:{SHA512-CRYPT}$6$abcd$efgh:5000:5000::/var/vmail/secubox.in/gk2::\n"+
			"mastodon@secubox.in:{SHA512-CRYPT}$6$ijkl$mnop:5000:5000::/var/vmail::\n")})
	if err != nil {
		t.Fatalf("chargement : %v", err)
	}
	for _, existe := range []string{"gk2@secubox.in", "gk2", "mastodon@secubox.in", "mastodon"} {
		if c.Inexistant(existe) {
			t.Errorf("%s est un compte reel", existe)
		}
	}
	if !c.Inexistant("gerald@gk2.net") {
		t.Error("gerald@gk2.net n'existe pas et doit etre signale")
	}
	// La garde qui compte : l'empreinte ne doit jamais devenir un nom de compte.
	if !c.Inexistant("{sha512-crypt}$6$abcd$efgh") {
		t.Error("une empreinte ne doit pas etre enregistree comme compte")
	}
}
