// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const scriptDore = `add table ip secubox_leurres_mail
delete table ip secubox_leurres_mail
table ip secubox_leurres_mail {
	set actifs {
		type inet_service
		flags timeout
		elements = { 25 timeout 90s, 465 timeout 90s, 587 timeout 90s, 993 timeout 90s, 995 timeout 90s }
	}
	chain redirection {
		type nat hook prerouting priority -120; policy accept;
		iifname != { "br-lxc", "lo" } ip saddr != { 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16 } fib daddr type local tcp dport @actifs redirect to :tcp dport map { 25 : 18025, 465 : 18465, 587 : 18587, 993 : 18993, 995 : 18995 }
	}
	chain entree {
		type filter hook input priority -20; policy accept;
		tcp dport { 18025, 18465, 18587, 18993, 18995 } ct status & dnat != dnat drop
	}
}
`

func TestScriptBascule(t *testing.T) {
	if s := scriptBascule(LeurresMailRelais, 90*time.Second); s != scriptDore {
		t.Fatalf("script :\n%s", s)
	}
	// Seul NOTRE nom de table, aucun vidage.
	for _, s := range []string{scriptDore, scriptRetrait} {
		if strings.Contains(s, "flush") || strings.Count(s, "table ip ") != strings.Count(s, "table ip secubox_leurres_mail") {
			t.Fatalf("touche à autre chose : %s", s)
		}
	}
}

// Chargé pour de vrai dans un espace de noms réseau jetable, en UN argument comme
// le fait authwatch, deux fois de suite, puis retiré. Sauté sans nft ni unshare.
func TestScriptBasculeChargeParNft(t *testing.T) {
	if exec.Command("unshare", "-rn", "nft", "list", "ruleset").Run() != nil {
		t.Skip("nft ou unshare -rn indisponible")
	}
	s := scriptBascule(LeurresMailRelais, 90*time.Second)
	out, err := exec.Command("unshare", "-rn", "sh", "-ec",
		`nft "$1"; nft "$1"; nft list table ip secubox_leurres_mail; nft "$2"; nft "$2"; test -z "$(nft list tables)"`,
		"sh", s, scriptRetrait).CombinedOutput()
	if err != nil {
		t.Fatalf("%v : %s", err, out)
	}
	if !strings.Contains(string(out), "expires") || !strings.Contains(string(out), "redirect to") {
		t.Fatalf("jeu chargé inattendu : %s", out)
	}
}

type basculeFausse struct {
	debout          bool
	marche          error
	scripts         []string
	refus           bool
	ouverts, fermes int
}

func basculeTest(f *basculeFausse, ports []LeurreMail) *BasculeMail {
	return &BasculeMail{
		intervalle: 30 * time.Second,
		sonder:     func(context.Context) bool { return f.debout },
		etat:       func() error { return f.marche },
		nft: func(_ context.Context, s string) error {
			if f.refus {
				return errors.New("refus")
			}
			f.scripts = append(f.scripts, s)
			return nil
		},
		ouvrir: func(context.Context) ([]LeurreMail, func()) {
			f.ouverts++
			return ports, func() { f.fermes++ }
		},
	}
}

func TestMachineAEtats(t *testing.T) {
	f := &basculeFausse{debout: true}
	b := basculeTest(f, LeurresMailRelais)
	ctx := context.Background()
	b.tour(ctx)
	f.debout = false
	b.tour(ctx)
	if b.actif || len(f.scripts) != 0 {
		t.Fatal("une seule sonde ratée ne bascule pas")
	}
	f.debout = true
	b.tour(ctx)
	f.debout = false
	b.tour(ctx)
	if b.actif {
		t.Fatal("deux échecs NON consécutifs ne basculent pas")
	}
	b.tour(ctx)
	if !b.actif || len(f.scripts) != 1 || f.scripts[0] != scriptDore {
		t.Fatalf("deux échecs d'affilée basculent : %v", f.scripts)
	}
	b.tour(ctx)
	if len(f.scripts) != 2 || f.scripts[1] != scriptDore || f.ouverts != 1 {
		t.Fatal("battement : le script entier est reposé, sans rouvrir les ports")
	}
	f.debout = true
	b.tour(ctx)
	if b.actif || f.scripts[2] != scriptRetrait || f.fermes != 1 {
		t.Fatal("une sonde réussie retire aussitôt, puis ferme les ports")
	}
	b.tour(ctx)
	if len(f.scripts) != 3 {
		t.Fatal("rien à retirer, rien à exécuter")
	}
}

func TestRetraitRefuseRetente(t *testing.T) {
	f := &basculeFausse{}
	b := basculeTest(f, LeurresMailRelais)
	ctx := context.Background()
	b.tour(ctx)
	b.tour(ctx)
	f.debout, f.refus = true, true
	b.tour(ctx)
	if !b.actif || f.fermes != 0 {
		t.Fatal("retrait refusé : leurres gardés ouverts, nouvelle tentative au tour suivant")
	}
	f.refus = false
	b.tour(ctx)
	if b.actif || f.fermes != 1 {
		t.Fatal("retrait au tour suivant")
	}
}

func TestPoseRefuseeRefermeLesPorts(t *testing.T) {
	f := &basculeFausse{refus: true}
	b := basculeTest(f, LeurresMailRelais)
	for i := 0; i < 3; i++ {
		b.tour(context.Background())
	}
	if b.actif || f.ouverts != 2 || f.fermes != 2 {
		t.Fatalf("%+v actif=%v", f, b.actif)
	}
	f.refus = false
	b = basculeTest(f, nil) // aucun port local libre : rien n'est redirigé
	f.scripts = nil
	b.tour(context.Background())
	b.tour(context.Background())
	if b.actif || len(f.scripts) != 0 {
		t.Fatal("sans leurre ouvert, pas de redirection")
	}
}

func TestArretRetireEtNInterpretePasLaCoupure(t *testing.T) {
	f := &basculeFausse{}
	b := basculeTest(f, LeurresMailRelais)
	b.intervalle = 10 * time.Millisecond
	ctx, fin := context.WithCancel(context.Background())
	arret := make(chan struct{})
	go func() { b.Boucle(ctx); close(arret) }()
	for limite := time.Now().Add(2 * time.Second); time.Now().Before(limite); time.Sleep(5 * time.Millisecond) {
		b.mu.Lock()
		a := b.actif
		b.mu.Unlock()
		if a {
			break
		}
	}
	fin()
	<-arret
	if b.actif || f.scripts[0] != scriptRetrait || f.scripts[len(f.scripts)-1] != scriptRetrait || f.fermes != 1 {
		t.Fatalf("arrêt : table retirée ; scripts %d", len(f.scripts))
	}
	// Contexte déjà annulé : la sonde ratée ne compte pas.
	b.tour(ctx)
	if b.echecs > sondeEchecsPour || b.actif {
		t.Fatal("coupure prise pour un arrêt du conteneur")
	}
}

func TestNewBasculeMailValide(t *testing.T) {
	b, _ := banneurTest(t)
	m := NewServeurMail(nil, nil)
	for _, c := range []struct {
		adr, nom string
		d        time.Duration
		ok       bool
	}{{"10.100.0.10", "mail", 30 * time.Second, true}, {"1.2.3.4", "mail", 30 * time.Second, false}, {"mail", "mail", 30 * time.Second, false},
		{"fd00::1", "mail", 30 * time.Second, false}, {"10.100.0.10", "mail", time.Second, false}, {"10.100.0.10", "mail", time.Hour, false},
		{"10.100.0.10", "../mail", 30 * time.Second, false}, {"10.100.0.10", "*", 30 * time.Second, false}} {
		if _, err := NewBasculeMail(c.adr, c.nom, nil, c.d, b, m); (err == nil) != c.ok {
			t.Errorf("%s %s : %v", c.adr, c.d, err)
		}
	}
}

func TestSondePort(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	if !sondePort(context.Background(), "127.0.0.1", port) {
		t.Error("port ouvert")
	}
	ln.Close()
	if sondePort(context.Background(), "127.0.0.1", port) {
		t.Error("port fermé")
	}
}

// Relais : écoute IPv4 seulement, port déjà pris = non redirigé.
func TestRelaisCedeUnPortPris(t *testing.T) {
	ln, err := net.Listen("tcp4", ":18465")
	if err != nil {
		t.Skip("18465 déjà pris")
	}
	defer ln.Close()
	m := NewServeurMail(make(chan Signal, 1), nil)
	ouverts, fermer := m.Relais(context.Background())
	defer fermer()
	for _, l := range ouverts {
		if l.Port == 465 {
			t.Fatal("465 ne doit pas être redirigé")
		}
	}
	if c, err := net.DialTimeout("tcp6", "[::1]:18025", time.Second); err == nil {
		c.Close()
		t.Fatal("écoute IPv6 ouverte")
	}
}

func TestEtatMailReserve(t *testing.T) {
	f := &basculeFausse{}
	b := basculeTest(f, LeurresMailRelais)
	m := NewServeurMail(nil, nil)
	m.paniques = 2
	l := NewLimiteMail()
	l.Detecte(NewJournalMenaces(""), sigMail("imap", "203.0.113.2", "x"), time.Now())
	m.tls.Note("imaps", "203.0.113.1", time.Now())
	chemin := filepath.Join(t.TempDir(), "leurres-mail.json")
	if err := b.EcrireEtat(m, l, chemin, time.Now()); err != nil {
		t.Fatal(err)
	}
	st, _ := os.Stat(chemin)
	if st.Mode().Perm() != 0600 {
		t.Fatalf("mode %v", st.Mode())
	}
	brut, _ := os.ReadFile(chemin)
	var e EtatMail
	if err := json.Unmarshal(brut, &e); err != nil || e.Actif || e.Paniques != 2 || e.Leurres["imap"].Tentatives != 1 || e.TLS["imaps"].Connexions != 1 {
		t.Fatalf("%s %v", brut, err)
	}
}

// Muet mais EN MARCHE (ou état inconnu) : on ne prend pas sa place, on la rend, et
// on ne le dit qu'une fois.
func TestConteneurEnMarcheJamaisRemplace(t *testing.T) {
	var sortie bytes.Buffer
	log.SetOutput(&sortie)
	defer log.SetOutput(os.Stderr)
	f := &basculeFausse{marche: errors.New("le conteneur mail est en marche")}
	b := basculeTest(f, LeurresMailRelais)
	for i := 0; i < 5; i++ {
		b.tour(context.Background())
	}
	if b.actif || len(f.scripts) != 0 || strings.Count(sortie.String(), "non activés") != 1 {
		t.Fatalf("actif=%v scripts=%d : %s", b.actif, len(f.scripts), sortie.String())
	}
	f.marche = nil
	b.tour(context.Background())
	if b.actif {
		t.Fatal("les sondes ratées pendant la marche ne comptent pas")
	}
	b.tour(context.Background())
	if !b.actif {
		t.Fatal("arrêté : bascule")
	}
	f.marche = errors.New("le conteneur mail est en marche") // il démarre, la sonde échoue encore
	b.tour(context.Background())
	if b.actif || f.scripts[len(f.scripts)-1] != scriptRetrait {
		t.Fatal("un conteneur qui démarre reprend ses ports avant de répondre")
	}
}

func TestEtatLXC(t *testing.T) {
	d := t.TempDir()
	ecrit := func(chemin, texte string) {
		t.Helper()
		chemin = filepath.Join(d, chemin)
		if err := os.MkdirAll(filepath.Dir(chemin), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(chemin, []byte(texte), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	e := EtatLXC{Nom: "mail", Adresse: "10.100.0.10", LxcPaths: []string{d + "/lxc", d + "/autre"}, Cgroup: d + "/cg", ProcUnix: d + "/unix"}
	attend := func(quoi, motif string) {
		t.Helper()
		err := e.Remplacable()
		if (motif == "") != (err == nil) || (err != nil && !strings.Contains(err.Error(), motif)) {
			t.Fatalf("%s : %v, attendu %q", quoi, err, motif)
		}
	}
	attend("aucune configuration", "aucune configuration LXC du conteneur mail")
	ecrit("lxc/mail/config", "lxc.uts.name = mail\nlxc.net.0.ipv4.address = 10.100.0.10/24\n")
	attend("cgroup absent", "cgroup v2 illisible")
	ecrit("cg/cgroup.controllers", "cpu")
	attend("sockets illisibles", "sockets Unix illisibles")
	ecrit("unix", "Num RefCount\n0: 2 0 0 1 1 99 @/data/lxc/webmail/command\n0: 2 0 0 1 1 98 /run/mail/command\n")
	attend("arrêté", "")
	ecrit("cg/lxc.payload.mail/cgroup.events", "populated 0\nfrozen 0\n")
	ecrit("cg/lxc.payload.mailing/cgroup.events", "populated 1\n")
	attend("reste vide, voisin de même préfixe", "")
	ecrit("cg/lxc.payload.mail-1/cgroup.events", "populated 1\nfrozen 1\n")
	attend("gelé", "en marche")
	ecrit("cg/lxc.payload.mail-1/cgroup.events", "populated 0\n")
	ecrit("cg/system.slice/lxc.monitor.mail/cgroup.events", "populated 1\n")
	attend("moniteur vivant", "en marche")
	ecrit("cg/system.slice/lxc.monitor.mail/cgroup.events", "populated 0\n")
	ecrit("unix", "0: 2 0 10000 1 1 97 @/data/lxc/mail/command\n")
	attend("socket de commande", "en marche")
	ecrit("unix", "")
	ecrit("autre/mail/config", "lxc.net.0.ipv4.address = 10.100.0.11/24\n")
	attend("autre adresse", "n'est pas celle")
	ecrit("autre/mail/config", "lxc.net.0.type = veth\n")
	attend("adresse non déclarée", "n'est pas celle")
}

func TestReglagesDeRootSeulement(t *testing.T) {
	moi := uint32(os.Getuid())
	f := filepath.Join(t.TempDir(), "secubox-authwatch")
	if len(lireReglages(f, moi)) != 0 {
		t.Fatal("absent")
	}
	texte := "# commentaire\nLD_PRELOAD=/tmp/x.so\nSBX_MAIL_CONTENEUR=\"10.100.0.10\"\nSBX_MAIL_NOM=mail\n"
	if err := os.WriteFile(f, []byte(texte), 0o640); err != nil {
		t.Fatal(err)
	}
	r := lireReglages(f, moi)
	if len(r) != 2 || r["SBX_MAIL_CONTENEUR"] != "10.100.0.10" || r["SBX_MAIL_NOM"] != "mail" {
		t.Fatalf("%v", r)
	}
	if len(lireReglages(f, moi+1)) != 0 {
		t.Error("autre propriétaire : ignoré")
	}
	lien := f + ".lien"
	if err := os.Symlink(f, lien); err != nil {
		t.Fatal(err)
	}
	if len(lireReglages(lien, moi)) != 0 {
		t.Error("lien : ignoré")
	}
	for _, m := range []os.FileMode{0o660, 0o642} {
		if err := os.Chmod(f, m); err != nil {
			t.Fatal(err)
		}
		if len(lireReglages(f, moi)) != 0 {
			t.Errorf("%o : ignoré", m)
		}
	}
}
