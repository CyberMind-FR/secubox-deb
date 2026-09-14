// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>

package main

import (
	"net"
	"strings"
	"testing"
	"time"
)

// duo rend les deux bouts d'une connexion en mémoire.
func duo(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	a, b := net.Pipe()
	t.Cleanup(func() { _ = a.Close(); _ = b.Close() })
	return a, b
}

func TestBanniere_LeServeurParleEnPremierEtLeClientRepond(t *testing.T) {
	// C'est tout l'intérêt du régime : l'annonce déclenche la première trame du
	// client, et c'est ELLE qui décrit l'outil.
	srv, cli := duo(t)
	go func() {
		lu := make([]byte, 64)
		n, _ := cli.Read(lu)
		if !strings.HasPrefix(string(lu[:n]), "SSH-2.0-") {
			t.Errorf("bannière inattendue : %q", lu[:n])
		}
		_, _ = cli.Write([]byte("SSH-2.0-Go\r\n"))
	}()
	extrait, n := Echange(srv, "ssh")
	if n == 0 || !strings.Contains(extrait, "SSH-2.0-Go") {
		t.Fatalf("trame client non capturée : %q (%d o)", extrait, n)
	}
}

func TestBanniere_SansBanniereConnueOnNEnInventePas(t *testing.T) {
	// Fabriquer une fausse poignée binaire ne tromperait personne et nous
	// obligerait à imiter un protocole — ce qu'on refuse.
	srv, cli := duo(t)
	go func() {
		lu := make([]byte, 16)
		_ = cli.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		if n, _ := cli.Read(lu); n > 0 {
			t.Errorf("une bannière a été envoyée pour un service sans annonce : %q", lu[:n])
		}
		_, _ = cli.Write([]byte{0x16, 0x03, 0x01, 0x00})
	}()
	extrait, n := Echange(srv, "rdp")
	if n == 0 {
		t.Fatal("la trame client n'a pas été capturée")
	}
	if !strings.Contains(extrait, "16030100") {
		t.Errorf("l'hexadécimal de tête manque : %q", extrait)
	}
}

func TestBanniere_UnClientMuetNeBloquePas(t *testing.T) {
	// Un balayeur qui ouvre et se tait ne doit pas immobiliser le leurre.
	srv, _ := duo(t)
	debut := time.Now()
	_, n := Echange(srv, "vnc")
	if n != 0 {
		t.Errorf("des octets ont été lus d'un client muet : %d", n)
	}
	if d := time.Since(debut); d > banniereEcheance+2*time.Second {
		t.Errorf("échéance non appliquée : %s", d)
	}
}

func TestBanniere_LaTrameEstAssainieAvantLeJournal(t *testing.T) {
	// Des octets bruts dans un journal, c'est un attaquant qui y écrit :
	// une fin de ligne suffirait à fabriquer une fausse entrée.
	brut := []byte("GET / HTTP/1.1\r\nX: \x00\x1b[31mrouge\n")
	got := resumeTrame(brut)
	for _, interdit := range []string{"\n", "\r", "\x00", "\x1b"} {
		if strings.Contains(got, interdit) {
			t.Errorf("octet de contrôle %q laissé dans %q", interdit, got)
		}
	}
	if !strings.Contains(got, "GET / HTTP/1.1") {
		t.Errorf("la partie lisible a été perdue : %q", got)
	}
}

func TestBanniere_LaLectureEstBornee(t *testing.T) {
	srv, cli := duo(t)
	go func() {
		lu := make([]byte, 64)
		_, _ = cli.Read(lu)
		_, _ = cli.Write(make([]byte, 64<<10)) // 64 Kio
	}()
	_, n := Echange(srv, "ssh")
	if n > banniereLectureMax {
		t.Fatalf("%d octets lus, plafond %d", n, banniereLectureMax)
	}
}
