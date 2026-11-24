// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/CyberMind-FR/secubox-deb/secubox-toolbox-ng/internal/reseau"
)

const motDePasseEssai = "S3cretUltra!77"

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

// joueMail envoie tout d'un bloc (enfilé), rend la réponse entière et la session.
func joueMail(t *testing.T, dialogue func(*sessionMail), envoi string) (string, *sessionMail) {
	t.Helper()
	client, serveur := net.Pipe()
	s := nouvelleSession(serveur, 150*time.Millisecond, 300*time.Millisecond)
	fini := make(chan struct{})
	go func() { defer close(fini); dialogue(s); _ = serveur.Close() }()
	go func() { _, _ = io.WriteString(client, envoi) }()
	lu, _ := io.ReadAll(client)
	<-fini
	_ = client.Close()
	return string(lu), s
}

func attendComptes(t *testing.T, s *sessionMail, essais int, comptes ...string) {
	t.Helper()
	if s.essais != essais || !reflect.DeepEqual(append([]string{}, s.comptes...), append([]string{}, comptes...)) {
		t.Fatalf("essais=%d comptes=%q ; attendu %d %q", s.essais, s.comptes, essais, comptes)
	}
}

// sansSecret : ni le mot de passe, ni sa forme base64, dans la session rendue
// (tampon compris) ni dans la réponse.
func sansSecret(t *testing.T, reponse string, s *sessionMail) {
	t.Helper()
	s.lec.efface()
	vidage := fmt.Sprintf("%s %+v %q", reponse, s.comptes, s.lec.tampon[:])
	for _, x := range []string{motDePasseEssai, b64(motDePasseEssai)} {
		if strings.Contains(vidage, x) {
			t.Fatalf("mot de passe retrouvé (%q)", x)
		}
	}
}

func temporaireSMTP(t *testing.T, reponse string) {
	t.Helper()
	if m := regexp.MustCompile(`(?m)^(5\d\d|354)`).FindString(reponse); m != "" {
		t.Fatalf("réponse permanente ou acceptation : %s dans %q", m, reponse)
	}
}

func TestSMTP25EchecTemporaire(t *testing.T) {
	r, s := joueMail(t, dialogueSMTP25, "EHLO mx.exemple.test\r\nMAIL FROM:<a@exemple.test>\r\nRCPT TO:<gk2@secubox.in>\r\nDATA\r\nRSET\r\nSTARTTLS\r\nQUIT\r\n")
	attendu := smtpAccueil + smtpEhlo25 + smtpRefus + smtpRefus + smtpRefus + smtpOk + smtpTLS + smtpAdieu
	if r != attendu {
		t.Fatalf("obtenu %q", r)
	}
	temporaireSMTP(t, r)
	for _, x := range []string{"STARTTLS\r", "PIPELINING", "CHUNKING", "AUTH"} {
		if strings.Contains(smtpEhlo25, x) {
			t.Errorf("%s annoncé sur 25", x)
		}
	}
	attendComptes(t, s, 0)
}

func TestSMTP587AnnonceAuthSansTLS(t *testing.T) {
	r, s := joueMail(t, dialogueSMTP587, "EHLO x\r\nQUIT\r\n")
	if !strings.Contains(r, "250-AUTH PLAIN LOGIN\r\n") || strings.Contains(r, "STARTTLS") {
		t.Fatalf("EHLO 587 : %q", r)
	}
	attendComptes(t, s, 0) // un client bien réglé s'arrête là : aucun signal
}

func TestSMTPAuth(t *testing.T) {
	plain := b64("\x00Gege@GK2.net\x00" + motDePasseEssai)
	cas := []struct {
		nom, envoi string
		essais     int
		comptes    []string
	}{
		{"PLAIN initiale", "EHLO x\r\nAUTH PLAIN " + plain + "\r\nQUIT\r\n", 1, []string{"gege@gk2.net"}},
		{"plain minuscules", "ehlo x\r\nauth plain " + plain + "\r\n", 1, []string{"gege@gk2.net"}},
		{"PLAIN en deux temps", "EHLO x\r\nAUTH PLAIN\r\n" + plain + "\r\nQUIT\r\n", 1, []string{"gege@gk2.net"}},
		{"PLAIN initiale vide", "EHLO x\r\nAUTH PLAIN =\r\n" + plain + "\r\n", 1, []string{"gege@gk2.net"}},
		{"PLAIN authzid seul", "AUTH PLAIN " + b64("moi@x\x00\x00"+motDePasseEssai) + "\r\n", 1, []string{"moi@x"}},
		{"LOGIN", "AUTH LOGIN\r\n" + b64("root") + "\r\n" + b64(motDePasseEssai) + "\r\n", 1, []string{"root"}},
		{"LOGIN initiale", "AUTH LOGIN " + b64("root") + "\r\n" + b64(motDePasseEssai) + "\r\n", 1, []string{"root"}},
		{"trois essais, mêmes comptes", strings.Repeat("AUTH PLAIN "+plain+"\r\n", 5), 3, []string{"gege@gk2.net"}},
		{"annulé", "AUTH LOGIN\r\n*\r\nQUIT\r\n", 0, nil},
		{"annulé au secret", "AUTH LOGIN\r\n" + b64("root") + "\r\n*\r\nQUIT\r\n", 0, nil},
		{"coupé avant le secret", "AUTH LOGIN\r\n" + b64("root") + "\r\n", 0, nil},
		{"mécanisme inconnu", "AUTH CRAM-MD5\r\nQUIT\r\n", 1, nil},
		{"base64 cassé", "AUTH PLAIN !!!!" + motDePasseEssai + "\r\nQUIT\r\n", 1, nil},
		{"AUTH nu", "AUTH\r\nQUIT\r\n", 1, nil},
	}
	for _, c := range cas {
		for nom, d := range map[string]func(*sessionMail){"25": dialogueSMTP25, "587": dialogueSMTP587} {
			t.Run(nom+" "+c.nom, func(t *testing.T) {
				r, s := joueMail(t, d, c.envoi)
				temporaireSMTP(t, r)
				if c.essais > 0 && !strings.Contains(r, smtpAuth) {
					t.Errorf("454 attendu : %q", r)
				}
				attendComptes(t, s, c.essais, c.comptes...)
				sansSecret(t, r, s)
			})
		}
	}
}

// Bruit : jamais un 5xx, jamais une panique, jamais un essai inventé.
func TestSMTPBruit(t *testing.T) {
	for _, e := range []string{
		"GET / HTTP/1.1\r\nHost: x\r\n\r\n", "\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03\r\n", "\r\n", "\x00\xff\xfe\r\n",
		strings.Repeat("A", 4000) + "\r\n", "MAIL FROM:" + strings.Repeat("x", 900) + "\r\n" + strings.Repeat("NOOP\r\n", 500),
		strings.Repeat("NOOP\r\n", 1000), "BDAT 10 LAST\r\n550 salut\r\n", "AUTH PLAIN " + strings.Repeat("A", 5000) + "\r\n",
	} {
		for _, d := range []func(*sessionMail){dialogueSMTP25, dialogueSMTP587} {
			r, s := joueMail(t, d, e)
			temporaireSMTP(t, r)
			if s.essais != 0 || s.lec.lus > mailOctetsMax {
				t.Errorf("%.20q : essais=%d lus=%d", e, s.essais, s.lec.lus)
			}
			if !strings.Contains(r, "421 4.3.2") {
				t.Errorf("%.20q : fermeture temporaire attendue, obtenu %q", e, r)
			}
		}
	}
}

func TestIMAP(t *testing.T) {
	p := motDePasseEssai
	plain := b64("\x00gege@gk2.net\x00" + p)
	cas := []struct {
		nom, envoi string
		essais     int
		comptes    []string
		contient   string
	}{
		{"LOGIN atomes", "a1 LOGIN gege@gk2.net " + p + "\r\na2 LOGOUT\r\n", 1, []string{"gege@gk2.net"}, "a1 NO [UNAVAILABLE]"},
		{"LOGIN guillemets", "a1 login \"ge\\\"ge\" \"" + p + "\"\r\na2 LOGOUT\r\n", 1, []string{`ge"ge`}, "a1 NO [UNAVAILABLE]"},
		{"LOGIN littéraux", fmt.Sprintf("a1 LOGIN {4}\r\ngege {%d}\r\n%s\r\na2 LOGOUT\r\n", len(p), p), 1, []string{"gege"}, "+ OK\r\n+ OK\r\na1 NO [UNAVAILABLE]"},
		{"LOGIN littéraux+", fmt.Sprintf("a1 LOGIN {4+}\r\ngege {%d+}\r\n%s\r\na2 LOGOUT\r\n", len(p), p), 1, []string{"gege"}, "a1 NO [UNAVAILABLE]"},
		{"AUTHENTICATE PLAIN", "a1 AUTHENTICATE PLAIN\r\n" + plain + "\r\na2 LOGOUT\r\n", 1, []string{"gege@gk2.net"}, "+ \r\na1 NO [UNAVAILABLE]"},
		{"AUTHENTICATE PLAIN initiale", "a1 AUTHENTICATE PLAIN " + plain + "\r\na2 LOGOUT\r\n", 1, []string{"gege@gk2.net"}, "a1 NO [UNAVAILABLE]"},
		{"AUTHENTICATE LOGIN", "a1 AUTHENTICATE LOGIN\r\n" + b64("root") + "\r\n" + b64(p) + "\r\na2 LOGOUT\r\n", 1, []string{"root"}, "a1 NO [UNAVAILABLE]"},
		{"LOGIN sans secret", "a1 LOGIN gege\r\na2 LOGOUT\r\n", 0, nil, "a1 BAD"},
		{"STARTTLS", "a1 CAPABILITY\r\na2 STARTTLS\r\na3 LOGOUT\r\n", 0, nil, "a2 NO [UNAVAILABLE]"},
		{"littéral géant", "a1 LOGIN {999999999}\r\n", 0, nil, "* BYE [UNAVAILABLE]"},
		{"verbe inconnu jamais renvoyé", p + " x\r\n", 0, nil, "* BYE [UNAVAILABLE]"},
		{"secret hors tour jamais renvoyé", "motdepasse\r\n", 0, nil, "* BYE [UNAVAILABLE]"},
		{"ligne énorme", strings.Repeat("z", 5000) + "\r\n", 0, nil, "* BYE [UNAVAILABLE]"},
		{"essais bornés", strings.Repeat("a LOGIN x "+p+"\r\n", 9), 3, []string{"x"}, "* BYE [UNAVAILABLE]"},
	}
	for _, c := range cas {
		t.Run(c.nom, func(t *testing.T) {
			r, s := joueMail(t, dialogueIMAP, c.envoi)
			if !strings.Contains(r, c.contient) || strings.Contains(r, "motdepasse") || strings.Contains(r, "STARTTLS") {
				t.Errorf("réponse %q", r)
			}
			attendComptes(t, s, c.essais, c.comptes...)
			sansSecret(t, r, s)
		})
	}
}

func TestPOP3(t *testing.T) {
	p := motDePasseEssai
	cas := []struct {
		nom, envoi string
		essais     int
		comptes    []string
	}{
		{"USER PASS", "CAPA\r\nUSER gege@gk2.net\r\nPASS " + p + "\r\nQUIT\r\n", 1, []string{"gege@gk2.net"}},
		{"USER seul", "USER gege@gk2.net\r\nQUIT\r\n", 0, nil},
		{"APOP", "APOP gege 0123456789abcdef\r\nQUIT\r\n", 1, []string{"gege"}},
		{"AUTH PLAIN", "AUTH PLAIN\r\n" + b64("\x00gege\x00"+p) + "\r\nQUIT\r\n", 1, []string{"gege"}},
		{"AUTH LOGIN", "AUTH LOGIN\r\n" + b64("gege") + "\r\n" + b64(p) + "\r\nQUIT\r\n", 1, []string{"gege"}},
		{"AUTH liste, STLS", "AUTH\r\nSTLS\r\nQUIT\r\n", 0, nil},
		{"bruit", "GET / HTTP/1.0\r\n\r\n", 0, nil},
		{"essais bornés", strings.Repeat("USER a\r\nPASS "+p+"\r\n", 9), 3, []string{"a"}},
	}
	for _, c := range cas {
		t.Run(c.nom, func(t *testing.T) {
			r, s := joueMail(t, dialoguePOP3, c.envoi)
			for _, l := range strings.Split(r, "\r\n") {
				if strings.HasPrefix(l, "-ERR") && !strings.HasPrefix(l, "-ERR [SYS/TEMP]") {
					t.Errorf("échec non temporaire : %q", l)
				}
			}
			if c.essais > 0 && !strings.Contains(r, pop3Refus) {
				t.Errorf("refus temporaire attendu : %q", r)
			}
			attendComptes(t, s, c.essais, c.comptes...)
			sansSecret(t, r, s)
		})
	}
}

// Un nom tronqué ou réécrit passerait pour INEXISTANT et ferait bannir.
func TestCompteDeNeReecritJamais(t *testing.T) {
	long := strings.Repeat("a", 60) + "@exemple-tres-long.secubox.in"
	if compteDe([]byte(long)) != long {
		t.Error("une adresse longue ne doit pas être tronquée")
	}
	if compteDe([]byte("Gérald@Exemple.fr")) != "gérald@exemple.fr" {
		t.Error("UTF-8 gardé")
	}
	for _, x := range []string{"", strings.Repeat("a", 300), "a b", "a\x00b", "a\x1b[2Jb", "a\xff"} {
		if c := compteDe([]byte(x)); c != "" {
			t.Errorf("%q → %q, attendu vide", x, c)
		}
	}
}

// Le lecteur efface ce qu'il a rendu dès la lecture suivante.
func TestLecteurEfface(t *testing.T) {
	client, serveur := net.Pipe()
	defer client.Close()
	s := nouvelleSession(serveur, time.Second, time.Second)
	go func() { _, _ = io.WriteString(client, "PASS "+motDePasseEssai+"\r\nNOOP\r\n"); client.Close() }()
	if l, err := s.lec.ligne(); err != nil || !strings.HasSuffix(string(l), motDePasseEssai) {
		t.Fatalf("%q %v", l, err)
	}
	if l, err := s.lec.ligne(); err != nil || string(l) != "NOOP" {
		t.Fatalf("%q %v", l, err)
	}
	if bytes.Contains(s.lec.tampon[:], []byte(motDePasseEssai)) {
		t.Fatal("ligne précédente encore dans le tampon")
	}
}

// ── serveur ─────────────────────────────────────────────────────────────────

// serveurTest écoute sur la boucle locale en faisant passer les visiteurs pour
// `ip` : la boucle est exemptée d'office.
type ecouteDeguisee struct {
	net.Listener
	ip string
}

type connDeguisee struct {
	net.Conn
	ip string
}

func (e ecouteDeguisee) Accept() (net.Conn, error) {
	c, err := e.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return connDeguisee{c, e.ip}, nil
}
func (c connDeguisee) RemoteAddr() net.Addr { return &net.TCPAddr{IP: net.ParseIP(c.ip), Port: 40000} }

func serveurTest(t *testing.T, l LeurreMail, ip, blanche string) (*ServeurMail, chan Signal, string) {
	t.Helper()
	return serveurTestDelai(t, l, ip, blanche, 2*time.Second)
}

func serveurTestDelai(t *testing.T, l LeurreMail, ip, blanche string, delai time.Duration) (*ServeurMail, chan Signal, string) {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	lb, err := NewListeBlanche(blanche)
	if err != nil {
		t.Fatal(err)
	}
	sig := make(chan Signal, 64)
	m := NewServeurMail(sig, lb)
	m.ligne, m.totale = delai, 2*delai
	ctx, fin := context.WithCancel(context.Background())
	t.Cleanup(func() { fin(); _ = ln.Close() })
	go m.Sert(ctx, ecouteDeguisee{ln, ip}, l)
	return m, sig, ln.Addr().String()
}

func parle(t *testing.T, adr, envoi string) string {
	t.Helper()
	c, err := net.Dial("tcp4", adr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	_, _ = io.WriteString(c, envoi)
	r, _ := io.ReadAll(c)
	return string(r)
}

func signalMail(t *testing.T, ch chan Signal) (Signal, bool) {
	t.Helper()
	select {
	case s := <-ch:
		return s, true
	case <-time.After(300 * time.Millisecond):
		return Signal{}, false
	}
}

func leurre(nom string) LeurreMail {
	for _, l := range append(append([]LeurreMail{}, LeurresMailRelais...), LeurresMailPermanents...) {
		if l.Nom == nom {
			return l
		}
	}
	panic(nom)
}

func TestSignalMailSansIdentifiants(t *testing.T) {
	for nom, envoi := range map[string]string{
		"smtp":       "EHLO x\r\nAUTH PLAIN " + b64("\x00gege@gk2.net\x00"+motDePasseEssai) + "\r\nQUIT\r\n",
		"submission": "EHLO x\r\nAUTH LOGIN\r\n" + b64("gege@gk2.net") + "\r\n" + b64(motDePasseEssai) + "\r\nQUIT\r\n",
		"imap":       "a LOGIN gege@gk2.net " + motDePasseEssai + "\r\nb LOGOUT\r\n",
		"pop3":       "USER gege@gk2.net\r\nPASS " + motDePasseEssai + "\r\nQUIT\r\n",
	} {
		l := leurre(nom)
		_, ch, adr := serveurTest(t, l, "203.0.113.50", "")
		parle(t, adr, envoi)
		s, ok := signalMail(t, ch)
		if !ok {
			t.Fatalf("%s : signal attendu", nom)
		}
		if s.Cible != "gege@gk2.net" || s.Severite != "medium" || s.Categorie != l.Categorie || s.LeurreMail != nom {
			t.Errorf("%s : %+v", nom, s)
		}
		if len(s.Essais) != 0 || strings.HasPrefix(s.Categorie, "leurre") || strings.Contains(fmt.Sprintf("%+v", s), motDePasseEssai) {
			t.Errorf("%s : identifiants ou catégorie de leurre : %+v", nom, s)
		}
		if f := reseau.Famille(s.Categorie); f != reseau.FamilleMessagerie {
			t.Errorf("%s : famille %s", nom, f)
		}
	}
}

// Une visite du port 25 n'est pas un signal : de vrais serveurs y passent.
func TestVisiteSimpleJamaisUnSignal(t *testing.T) {
	for _, nom := range []string{"smtp", "submission"} {
		_, ch, adr := serveurTest(t, leurre(nom), "203.0.113.51", "")
		parle(t, adr, "EHLO mx\r\nMAIL FROM:<a@b.test>\r\nRCPT TO:<gk2@secubox.in>\r\nQUIT\r\n")
		parle(t, adr, "GET / HTTP/1.0\r\n\r\n")
		if s, ok := signalMail(t, ch); ok {
			t.Fatalf("%s : %+v", nom, s)
		}
	}
}

func TestExemptesServisMaisJamaisInscrits(t *testing.T) {
	envoi := "AUTH PLAIN " + b64("\x00inexistant\x00"+motDePasseEssai) + "\r\nQUIT\r\n"
	for _, ip := range []string{"192.168.1.7", "10.10.0.5", "10.100.0.10", "100.64.3.4", "203.0.113.52", "127.0.0.1"} {
		_, ch, adr := serveurTest(t, leurre("submission"), ip, "203.0.113.52")
		if r := parle(t, adr, envoi); !strings.Contains(r, smtpAuth) {
			t.Errorf("%s : doit être servi : %q", ip, r)
		}
		if s, ok := signalMail(t, ch); ok {
			t.Errorf("%s : signal %+v", ip, s)
		}
	}
	m, _, adr := serveurTest(t, leurre("imaps"), "192.168.1.7", "")
	parle(t, adr, "\x16\x03\x01")
	if len(m.tls.Etat(time.Now())) != 0 {
		t.Error("une adresse du LAN ne doit pas être comptée")
	}
}

func TestTLSCompteJamaisSignale(t *testing.T) {
	for _, nom := range []string{"smtps", "imaps", "pop3s"} {
		m, ch, adr := serveurTest(t, leurre(nom), "203.0.113.53", "")
		if r := parle(t, adr, "\x16\x03\x01\x00\xa5\x01"); r != alerteTLS {
			t.Errorf("%s : alerte attendue, obtenu %q", nom, r)
		}
		parle(t, adr, "AUTH PLAIN "+motDePasseEssai+"\r\n")
		if s, ok := signalMail(t, ch); ok {
			t.Fatalf("%s : signal %+v", nom, s)
		}
		e := m.tls.Etat(time.Now())[nom]
		if e.Connexions != 2 || e.Adresses != 1 || e.Premieres[0].IP != "203.0.113.53" || e.Premieres[0].N != 2 {
			t.Errorf("%s : %+v", nom, e)
		}
	}
}

func TestDecompteTLSBorne(t *testing.T) {
	d := NewDecompteTLS()
	t0 := time.Unix(1_800_000_000, 0)
	for i := 0; i < tlsAdressesMax+300; i++ {
		d.Note("imaps", fmt.Sprintf("8.%d.%d.%d", i>>16, i>>8&255, i&255), t0.Add(time.Duration(i)*time.Second))
	}
	if n := len(d.par["imaps"]); n != tlsAdressesMax {
		t.Fatalf("%d adresses gardées", n)
	}
	if e := d.Etat(t0.Add(time.Hour)); len(e["imaps"].Premieres) != tlsPubliees {
		t.Fatalf("%d publiées", len(e["imaps"].Premieres))
	}
	if e := d.Etat(t0.Add(72 * time.Hour)); e["imaps"].Adresses != 0 {
		t.Fatal("oubli après 24 h")
	}
}

// Plafonds : par adresse puis par leurre ; l'excédent reçoit un refus temporaire ;
// tout est rendu ensuite, sans goroutine perdue.
func TestPlafondsEtLenteur(t *testing.T) {
	avant := runtime.NumGoroutine()
	m, ch, adr := serveurTestDelai(t, leurre("smtp"), "203.0.113.54", "", 400*time.Millisecond)
	var muettes []net.Conn
	for i := 0; i < mailParIP; i++ {
		c, err := net.Dial("tcp4", adr)
		if err != nil {
			t.Fatal(err)
		}
		muettes = append(muettes, c)
		_, _ = io.ReadFull(c, make([]byte, len(smtpAccueil)))
	}
	if r := parle(t, adr, ""); r != smtpSature {
		t.Fatalf("au-delà du plafond par adresse : %q", r)
	}
	// Goutte à goutte : l'échéance vaut pour la ligne entière.
	debut := time.Now()
	go func() {
		for i := 0; i < 20; i++ {
			_, _ = muettes[0].Write([]byte("E"))
			time.Sleep(100 * time.Millisecond)
		}
	}()
	_, _ = io.ReadAll(muettes[0])
	if d := time.Since(debut); d > 1500*time.Millisecond {
		t.Fatalf("connexion lente tenue %s", d)
	}
	for _, c := range muettes {
		_ = c.Close()
	}
	for limite := time.Now().Add(3 * time.Second); m.ouvertes() > 0 && time.Now().Before(limite); {
		time.Sleep(20 * time.Millisecond)
	}
	if m.ouvertes() != 0 || len(m.parIP) != 0 {
		t.Fatalf("places non rendues : %d, %v", m.ouvertes(), m.parIP)
	}
	if s, ok := signalMail(t, ch); ok {
		t.Fatalf("une connexion lente n'est pas un signal : %+v", s)
	}
	for limite := time.Now().Add(5 * time.Second); runtime.NumGoroutine() > avant+3 && time.Now().Before(limite); {
		time.Sleep(50 * time.Millisecond)
	}
	if n := runtime.NumGoroutine(); n > avant+3 {
		t.Fatalf("goroutines : %d avant, %d après", avant, n)
	}
	for i := 0; i < mailParLeurre; i++ {
		if !m.reserve("smtp", fmt.Sprintf("198.51.100.%d", i)) {
			t.Fatalf("place %d refusée", i)
		}
	}
	if m.reserve("smtp", "198.51.100.200") {
		t.Fatal("plafond par leurre non tenu")
	}
	if !m.reserve("imap", "198.51.100.200") {
		t.Fatal("un leurre plein n'en bloque pas un autre")
	}
}

// ── décision ────────────────────────────────────────────────────────────────

// decide joue des signaux dans la vraie boucle ; rend les bans, les lignes du
// journal et TOUT ce qui a été écrit (journal + journald).
func decide(t *testing.T, comptes *Comptes, camp *Campagnes, modes string, sigs ...Signal) ([]string, []map[string]any, string) {
	t.Helper()
	var sortie bytes.Buffer
	log.SetOutput(&sortie)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	if modes != "" {
		chemin := filepath.Join(t.TempDir(), "modes.json")
		ecrireModes(t, chemin, modes, time.Now())
		modesLeurres = NewModesLeurres(chemin)
		t.Cleanup(func() { modesLeurres = nil })
	}
	b, fx := banneurTest(t)
	j, chemin := journalTest(t)
	j.SetCampagnes(camp)
	lb, _ := NewListeBlanche("")
	ctx, fin := context.WithCancel(context.Background())
	ch := make(chan Signal, len(sigs))
	for _, s := range sigs {
		ch <- s
	}
	arret := make(chan struct{})
	go func() {
		defer close(arret)
		traite(ctx, ch, NewCompteur(10*time.Minute, 6, 30*time.Minute), camp, comptes, b, j, lb, false, nil)
	}()
	for limite := time.Now().Add(2 * time.Second); len(ch) > 0 && time.Now().Before(limite); {
		time.Sleep(5 * time.Millisecond)
	}
	time.Sleep(50 * time.Millisecond)
	fin()
	<-arret
	brut, _ := os.ReadFile(chemin)
	return fx.bannies, lignesJournal(t, chemin), string(brut) + sortie.String()
}

func sigMail(nom, ip, compte string) Signal {
	l := leurre(nom)
	return Signal{IP: ip, Service: l.Service, Categorie: l.Categorie, Severite: "medium", Detail: "authentification sur le leurre", Cible: compte, LeurreMail: nom}
}

func comptesReels(t *testing.T) *Comptes {
	t.Helper()
	c, err := NewComptes([]string{fichierComptes(t, "gk2@secubox.in:{SHA512-CRYPT}$6$a:5000:5000::::\n")})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestCompteInexistantBanniCompteMasque(t *testing.T) {
	bans, lignes, tout := decide(t, comptesReels(t), NewCampagnes(time.Hour, 5), "", sigMail("submission", "203.0.113.60", "gerald@gk2.net"))
	if len(bans) != 1 || len(lignes) != 1 || lignes[0]["action"] != "banned" || lignes[0]["severity"] != "high" {
		t.Fatalf("bans %v lignes %v", bans, lignes)
	}
	if strings.Contains(tout, "gerald@gk2.net") || lignes[0]["path"] != "ger…" || lignes[0]["category"] != "auth_smtp:leurre_submission" {
		t.Fatalf("compte non masqué : %s", tout)
	}
	if _, ok := lignes[0]["essais"]; ok {
		t.Fatal("jamais d'essais pour la messagerie")
	}
}

// Le leurre refuse MÊME le bon mot de passe : sur un compte réel, jamais plus vite
// que les règles d'aujourd'hui (3 échecs SASL de poids 2) — ici six essais.
func TestCompteReelPatient(t *testing.T) {
	var sigs []Signal
	for i := 0; i < 5; i++ {
		sigs = append(sigs, sigMail("submission", "203.0.113.61", "gk2@secubox.in"))
	}
	bans, lignes, tout := decide(t, comptesReels(t), NewCampagnes(time.Hour, 5), "", sigs...)
	if len(bans) != 0 || len(lignes) != 5 || lignes[4]["action"] != "warning" {
		t.Fatalf("bans %v lignes %v", bans, lignes)
	}
	if strings.Contains(tout, "gk2@secubox.in") {
		t.Fatal("compte réel en clair")
	}
	bans, _, _ = decide(t, comptesReels(t), NewCampagnes(time.Hour, 5), "", append(sigs, sigs[0])...)
	if len(bans) != 1 {
		t.Fatalf("la règle ordinaire s'applique ensuite : %v", bans)
	}
}

func TestCampagneSurCompteReel(t *testing.T) {
	var sigs []Signal
	for i := 0; i < 5; i++ {
		sigs = append(sigs, sigMail("imap", fmt.Sprintf("203.0.113.%d", 70+i), "gk2@secubox.in"))
	}
	bans, lignes, tout := decide(t, comptesReels(t), NewCampagnes(time.Hour, 5), "", sigs...)
	if len(bans) != 1 || bans[0] != "203.0.113.74" {
		t.Fatalf("seule la cinquième source participe à une campagne établie : %v", bans)
	}
	if lignes[4]["campagne"] != IdentifiantCampagne("gk2@secubox.in") || strings.Contains(tout, "gk2@secubox.in") {
		t.Fatalf("identifiant de campagne sans compte en clair : %v", lignes[4])
	}
}

func TestModeObserverNeBannitJamais(t *testing.T) {
	bans, lignes, _ := decide(t, comptesReels(t), NewCampagnes(time.Hour, 1), `{"modes": {"submission": "observer"}}`,
		sigMail("submission", "203.0.113.80", "inconnu@x"), sigMail("smtp", "203.0.113.81", "inconnu@x"))
	if len(bans) != 1 || bans[0] != "203.0.113.81" || lignes[0]["action"] != "detect" || lignes[1]["action"] != "banned" {
		t.Fatalf("bans %v lignes %v", bans, lignes)
	}
}

// Les ports TLS n'ont ni service ni catégorie : aucun signal ne peut en naître.
func TestLeurresTLSSansSignal(t *testing.T) {
	for _, l := range LeurresMailRelais {
		tls := l.Port == 465 || l.Port == 993 || l.Port == 995
		if tls != (l.Service == "") || tls != (l.Categorie == "") {
			t.Errorf("%+v", l)
		}
	}
}

// De bout en bout, mot de passe cherché dans tout ce qui est écrit.
func TestMotDePasseNullePart(t *testing.T) {
	var sigs []Signal
	for nom, envoi := range map[string]string{
		"smtp": "AUTH PLAIN " + b64("\x00inconnu@gk2.net\x00"+motDePasseEssai) + "\r\nQUIT\r\n",
		"imap": "a LOGIN inconnu@gk2.net \"" + motDePasseEssai + "\"\r\nb LOGOUT\r\n",
		"pop3": "USER inconnu@gk2.net\r\nPASS " + motDePasseEssai + "\r\nQUIT\r\n",
	} {
		_, ch, adr := serveurTest(t, leurre(nom), "203.0.113.90", "")
		parle(t, adr, envoi)
		s, ok := signalMail(t, ch)
		if !ok {
			t.Fatal(nom)
		}
		sigs = append(sigs, s)
	}
	camp := NewCampagnes(time.Hour, 1)
	_, _, tout := decide(t, nil, camp, "", sigs...)
	etat := filepath.Join(t.TempDir(), "campagnes.json")
	if err := EcrireEtat(camp, etat, time.Now()); err != nil {
		t.Fatal(err)
	}
	brut, _ := os.ReadFile(etat)
	js, _ := json.Marshal(sigs)
	tout += string(brut) + string(js) + fmt.Sprintf("%+v", sigs)
	for _, x := range []string{motDePasseEssai, b64(motDePasseEssai), b64("\x00inconnu@gk2.net\x00" + motDePasseEssai)} {
		if strings.Contains(tout, x) {
			t.Fatalf("mot de passe écrit : %s", x)
		}
	}
	if strings.Contains(string(brut), "inconnu@gk2.net") || !strings.Contains(string(brut), "inc…") {
		t.Fatalf("campagnes.json : %s", brut)
	}
}

// Le chemin d'identifiants en clair (#3728) ne s'applique pas à la messagerie.
func TestCheminDesIdentifiantsFerme(t *testing.T) {
	for svc := range servicesMessagerie {
		client, serveur := net.Pipe()
		go func() { _, _ = io.WriteString(client, "a LOGIN x "+motDePasseEssai+"\r\n"); client.Close() }()
		c := Dialogue(serveur, svc)
		if len(c.Essais) != 0 || c.Extrait != "" || c.Octets != 0 {
			t.Errorf("%s : capture %+v", svc, c)
		}
		serveur.Close()
		client.Close()
	}
	ls, err := AnalyseLeurres("25:smtp,143:toto,993,3389:rdp")
	if err != nil || len(ls) != 1 || ls[0].Port != 3389 {
		t.Fatalf("ports de messagerie à écarter : %v %v", ls, err)
	}
	for _, l := range LeurresConnus {
		if portsMessagerie[l.Port] {
			t.Errorf("port %d dans « defaut »", l.Port)
		}
	}
}
