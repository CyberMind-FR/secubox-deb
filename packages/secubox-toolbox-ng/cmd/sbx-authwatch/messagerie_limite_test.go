// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package main

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"strings"
	"testing"
	"time"
)

var t0Mail = time.Date(2026, 11, 24, 12, 0, 0, 0, time.Local)

// Une ligne par (adresse, leurre) et par minute, portant le total ; rien n'est
// perdu des compteurs.
func TestLigneParAdresseEtLeurre(t *testing.T) {
	j, chemin := journalTest(t)
	l := j.mail
	for i := 0; i < 50; i++ {
		l.Detecte(j, sigMail("imap", "203.0.113.1", "secret-dans-le-mauvais-champ"), t0Mail.Add(time.Duration(i)*time.Second))
	}
	l.Detecte(j, sigMail("pop3", "203.0.113.1", ""), t0Mail)
	l.Detecte(j, sigMail("imap", "203.0.113.2", ""), t0Mail)
	if n := len(lignesJournal(t, chemin)); n != 3 {
		t.Fatalf("%d lignes, attendu 3", n)
	}
	for _, p := range l.paquets {
		if strings.Contains(p.sig.Cible, "secret") {
			t.Fatal("un nom inconnu ne doit pas attendre en mémoire")
		}
	}
	l.Vide(j, t0Mail.Add(59*time.Second), false)
	if n := len(lignesJournal(t, chemin)); n != 3 {
		t.Fatal("la minute n'est pas écoulée")
	}
	l.Vide(j, t0Mail.Add(61*time.Second), false)
	lg := lignesJournal(t, chemin)
	if len(lg) != 4 || !strings.HasSuffix(lg[3]["rule_id"].(string), "/49") {
		t.Fatalf("total des suivantes attendu : %v", lg)
	}
	e := l.Etat(t0Mail.Add(2 * time.Minute))
	if e["imap"] != (CompteMail{Tentatives: 51, Lignes: 3}) || e["pop3"].Tentatives != 1 {
		t.Fatalf("%+v", e)
	}
	l.Vide(j, t0Mail.Add(5*time.Minute), false)
	if len(l.paquets) != 0 {
		t.Fatal("paquets écrits à oublier")
	}
	if len(l.Etat(t0Mail.Add(24*time.Hour))) != 0 {
		t.Fatal("compteurs du jour")
	}
}

// Plafond commun : 60 lignes par minute, l'excédent attend, une ligne de résumé.
func TestPlafondCommunDeLignes(t *testing.T) {
	var sortie bytes.Buffer
	log.SetOutput(&sortie)
	defer log.SetOutput(os.Stderr)
	j, chemin := journalTest(t)
	l := j.mail
	for i := 0; i < 200; i++ {
		l.Detecte(j, sigMail("submission", fmt.Sprintf("203.0.113.%d", i), ""), t0Mail)
	}
	if n := len(lignesJournal(t, chemin)); n != mailLignesMax {
		t.Fatalf("%d lignes", n)
	}
	for s := 10; s < 60; s += 10 {
		l.Vide(j, t0Mail.Add(time.Duration(s)*time.Second), false)
	}
	if n := len(lignesJournal(t, chemin)); n != mailLignesMax || sortie.Len() != 0 {
		t.Fatalf("%d lignes, %q", n, sortie.String())
	}
	for m := 1; m <= 3; m++ {
		l.Vide(j, t0Mail.Add(time.Duration(m)*61*time.Second), false)
		attendu := mailLignesMax * (m + 1)
		if attendu > 200 {
			attendu = 200
		}
		if n := len(lignesJournal(t, chemin)); n != attendu {
			t.Fatalf("minute %d : %d lignes, attendu %d", m, n, attendu)
		}
	}
	if n := strings.Count(sortie.String(), "140 tentative(s) sans ligne propre"); n != 1 || strings.Count(sortie.String(), "\n") != 1 {
		t.Fatalf("un seul résumé attendu : %q", sortie.String())
	}
	if e := l.Etat(t0Mail.Add(4 * time.Minute)); e["submission"] != (CompteMail{Tentatives: 200, Lignes: 200}) {
		t.Fatalf("%+v", e)
	}
}

func TestTablePleineComptee(t *testing.T) {
	var sortie bytes.Buffer
	log.SetOutput(&sortie)
	defer log.SetOutput(os.Stderr)
	j, _ := journalTest(t)
	l := j.mail
	for i := 0; i < mailPaquetsMax+10; i++ {
		l.Detecte(j, sigMail("imap", fmt.Sprintf("8.0.%d.%d", i>>8, i&255), ""), t0Mail)
	}
	e := l.Etat(t0Mail)["imap"]
	if len(l.paquets) != mailPaquetsMax || e.Tentatives != mailPaquetsMax+10 || e.SansDetail != 10 {
		t.Fatalf("%d %+v", len(l.paquets), e)
	}
}

// Ban : une fois par adresse et par leurre dans la minute, hors du plafond commun.
func TestBanUneLigneParMinute(t *testing.T) {
	l := NewLimiteMail()
	s := sigMail("submission", "203.0.113.9", "x")
	if !l.Bannit(s, t0Mail) || l.Bannit(s, t0Mail.Add(30*time.Second)) || !l.Bannit(s, t0Mail.Add(61*time.Second)) {
		t.Fatal("une ligne de ban par minute")
	}
	if e := l.Etat(t0Mail)["submission"]; e.Tentatives != 3 || e.Bans != 2 {
		t.Fatalf("%+v", e)
	}
	l.lignes = mailLignesMax
	if !l.Bannit(sigMail("submission", "203.0.113.10", "x"), t0Mail) {
		t.Fatal("un ban n'attend jamais le plafond des lignes")
	}
	bans, lignes, _ := decide(t, comptesReels(t), nil, modesBannir, sigMail("imap", "203.0.113.11", "gk2@secubox.in"),
		sigMail("imap", "203.0.113.11", "inconnu"), sigMail("imap", "203.0.113.11", "autre"))
	if len(bans) != 1 || len(lignes) != 2 || lignes[1]["action"] != "banned" {
		t.Fatalf("une ligne detect ne retarde pas le ban : %v %v", bans, lignes)
	}
}

// À l'arrêt, ce qui attend est écrit dans le plafond.
func TestArretEcritLesPaquets(t *testing.T) {
	j, chemin := journalTest(t)
	for i := 0; i < 5; i++ {
		j.mail.Detecte(j, sigMail("imap", "203.0.113.1", ""), t0Mail)
	}
	j.mail.Vide(j, t0Mail.Add(time.Second), true)
	if lg := lignesJournal(t, chemin); len(lg) != 2 || !strings.HasSuffix(lg[1]["rule_id"].(string), "/4") {
		t.Fatalf("%v", lg)
	}
}
