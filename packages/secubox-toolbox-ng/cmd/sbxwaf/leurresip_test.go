// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// listeLeurresTest : le compte de l'exécutant tient lieu de root ; le journal est capturé.
func listeLeurresTest(chemin string, journal *[]string) *ListeLeurres {
	l := NewListeLeurres(chemin)
	moi := uint32(os.Getuid())
	l.proprietaireAdmis = func(uid uint32) bool { return uid == moi }
	l.logf = func(f string, a ...any) {
		if journal != nil {
			*journal = append(*journal, fmt.Sprintf(f, a...))
		}
	}
	return l
}

func leurresJSON(entrees map[string]int64) string {
	var b strings.Builder
	b.WriteString(`{"format": 1, "entrees": {`)
	premier := true
	for ip, fin := range entrees {
		if !premier {
			b.WriteString(",")
		}
		premier = false
		fmt.Fprintf(&b, `%q: {"fin": %d, "motif": "ai-leurre"}`, ip, fin)
	}
	b.WriteString("}}")
	return b.String()
}

func TestLeurresFichierAbsent(t *testing.T) {
	var journal []string
	l := listeLeurresTest(filepath.Join(t.TempDir(), "leurres-ip.json"), &journal)
	if _, ok := l.Cherche("203.0.113.7"); ok {
		t.Fatal("fichier absent : ensemble vide")
	}
	if len(journal) != 0 {
		t.Fatalf("un fichier absent n'est pas un refus : %v", journal)
	}
	var nilListe *ListeLeurres
	if _, ok := nilListe.Cherche("203.0.113.7"); ok {
		t.Fatal("nil-safe")
	}
}

func TestLeurresJSONInvalideUnSeulRefus(t *testing.T) {
	chemin := filepath.Join(t.TempDir(), "leurres-ip.json")
	ecrireListe(t, chemin, `{"format": 1, "entrees": {"203.0.113.7": {"fin": `, 0o644)
	var journal []string
	horloge := time.Now()
	l := listeLeurresTest(chemin, &journal)
	l.now = func() time.Time { return horloge }
	for i := 0; i < 5; i++ {
		if _, ok := l.Cherche("203.0.113.7"); ok {
			t.Fatal("JSON invalide : ensemble vide")
		}
		horloge = horloge.Add(6 * time.Second)
	}
	if len(journal) != 1 {
		t.Fatalf("un seul refus journalisé attendu : %v", journal)
	}
}

func TestLeurresFormatInconnuRefuse(t *testing.T) {
	chemin := filepath.Join(t.TempDir(), "leurres-ip.json")
	fin := time.Now().Add(time.Hour).Unix()
	ecrireListe(t, chemin, strings.Replace(leurresJSON(map[string]int64{"203.0.113.7": fin}), `"format": 1`, `"format": 2`, 1), 0o644)
	var journal []string
	if _, ok := listeLeurresTest(chemin, &journal).Cherche("203.0.113.7"); ok || len(journal) != 1 {
		t.Fatalf("format inconnu : ensemble vide et un refus (%v)", journal)
	}
}

func TestLeurresProprietaireNonRoot(t *testing.T) {
	chemin := filepath.Join(t.TempDir(), "leurres-ip.json")
	ecrireListe(t, chemin, leurresJSON(map[string]int64{"203.0.113.7": time.Now().Add(time.Hour).Unix()}), 0o644)
	var journal []string
	l := listeLeurresTest(chemin, &journal)
	l.proprietaireAdmis = func(uid uint32) bool { return uid == 0 } // le défaut : root seul
	if os.Getuid() == 0 {
		t.Skip("root est toujours admis")
	}
	if _, ok := l.Cherche("203.0.113.7"); ok {
		t.Fatal("fichier d'un autre que root : ensemble vide")
	}
	if len(journal) != 1 {
		t.Fatalf("un refus attendu : %v", journal)
	}
	// le défaut du constructeur n'admet que root
	if NewListeLeurres(chemin).proprietaireAdmis(uint32(os.Getuid())) {
		t.Fatal("seul root est admis par défaut")
	}
}

func TestLeurresFichierPasSur(t *testing.T) {
	fin := time.Now().Add(time.Hour).Unix()
	cas := []struct {
		nom     string
		prepare func(t *testing.T, dir, chemin string)
	}{
		{"lien symbolique", func(t *testing.T, dir, chemin string) {
			vrai := filepath.Join(dir, "vrai.json")
			ecrireListe(t, vrai, leurresJSON(map[string]int64{"203.0.113.7": fin}), 0o644)
			if err := os.Symlink(vrai, chemin); err != nil {
				t.Fatal(err)
			}
		}},
		{"inscriptible par le groupe", func(t *testing.T, _, chemin string) {
			ecrireListe(t, chemin, leurresJSON(map[string]int64{"203.0.113.7": fin}), 0o664)
		}},
		{"lien dur", func(t *testing.T, dir, chemin string) {
			vrai := filepath.Join(dir, "vrai.json")
			ecrireListe(t, vrai, leurresJSON(map[string]int64{"203.0.113.7": fin}), 0o644)
			if err := os.Link(vrai, chemin); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for _, c := range cas {
		t.Run(c.nom, func(t *testing.T) {
			dir := t.TempDir()
			chemin := filepath.Join(dir, "leurres-ip.json")
			c.prepare(t, dir, chemin)
			var journal []string
			if _, ok := listeLeurresTest(chemin, &journal).Cherche("203.0.113.7"); ok {
				t.Fatal("fichier pas sûr : ensemble vide")
			}
			if len(journal) != 1 {
				t.Fatalf("un refus attendu : %v", journal)
			}
		})
	}
}

func TestLeurres10000EntreesSeules2048Gardees(t *testing.T) {
	chemin := filepath.Join(t.TempDir(), "leurres-ip.json")
	fin := time.Now().Add(time.Hour).Unix()
	var b strings.Builder
	b.WriteString(`{"format": 1, "entrees": {`)
	for i := 0; i < 10000; i++ {
		if i > 0 {
			b.WriteString(",")
		}
		fmt.Fprintf(&b, `"11.%d.%d.1": {"fin": %d, "motif": "ai-leurre"}`, i/256, i%256, fin)
	}
	b.WriteString("}}")
	ecrireListe(t, chemin, b.String(), 0o644)
	l := listeLeurresTest(chemin, nil)
	ip := func(i int) string { return fmt.Sprintf("11.%d.%d.1", i/256, i%256) }
	for _, i := range []int{0, 1, 2047} {
		if _, ok := l.Cherche(ip(i)); !ok {
			t.Fatalf("entrée %d attendue", i)
		}
	}
	for _, i := range []int{2048, 5000, 9999} {
		if _, ok := l.Cherche(ip(i)); ok {
			t.Fatalf("entrée %d au-delà des 2 048 premières : ignorée", i)
		}
	}
	if n := l.Taille(); n != leurresMax {
		t.Fatalf("taille %d, veut %d", n, leurresMax)
	}
}

func TestLeurresEntreeExpiree(t *testing.T) {
	chemin := filepath.Join(t.TempDir(), "leurres-ip.json")
	horloge := time.Now()
	ecrireListe(t, chemin, leurresJSON(map[string]int64{
		"203.0.113.7":    horloge.Add(-time.Second).Unix(),
		"203.0.113.8":    horloge.Add(time.Hour).Unix(),
		"2001:db8::8":    horloge.Add(time.Hour).Unix(),
		"192.168.1.20":   horloge.Add(time.Hour).Unix(), // le LAN n'est jamais leurré
		"10.0.0.3":       horloge.Add(time.Hour).Unix(),
		"fd00::3":        horloge.Add(time.Hour).Unix(),
		"127.0.0.1":      horloge.Add(time.Hour).Unix(),
		"pas-une-ip":     horloge.Add(time.Hour).Unix(),
		"::ffff:1.2.3.4": horloge.Add(time.Hour).Unix(),
	}), 0o644)
	l := listeLeurresTest(chemin, nil)
	l.now = func() time.Time { return horloge }
	if _, ok := l.Cherche("203.0.113.7"); ok {
		t.Fatal("entrée expirée : non trouvée")
	}
	if e, ok := l.Cherche("203.0.113.8"); !ok || e.Motif != "ai-leurre" {
		t.Fatal("entrée active attendue")
	}
	if _, ok := l.Cherche("2001:0db8:0::8"); !ok {
		t.Fatal("IPv6 normalisée attendue")
	}
	for _, ip := range []string{"192.168.1.20", "10.0.0.3", "fd00::3", "127.0.0.1"} {
		if _, ok := l.Cherche(ip); ok {
			t.Fatalf("%s : une adresse non publique n'est jamais leurrée", ip)
		}
	}
	horloge = horloge.Add(2 * time.Hour)
	if _, ok := l.Cherche("203.0.113.8"); ok {
		t.Fatal("échue entre-temps : non trouvée")
	}
}

func TestLeurresRelectureAuPlusToutesLes5s(t *testing.T) {
	chemin := filepath.Join(t.TempDir(), "leurres-ip.json")
	horloge := time.Now()
	l := listeLeurresTest(chemin, nil)
	l.now = func() time.Time { return horloge }
	if _, ok := l.Cherche("203.0.113.7"); ok {
		t.Fatal("absent")
	}
	ecrireListe(t, chemin, leurresJSON(map[string]int64{"203.0.113.7": horloge.Add(time.Hour).Unix()}), 0o644)
	horloge = horloge.Add(4 * time.Second)
	if _, ok := l.Cherche("203.0.113.7"); ok {
		t.Fatal("moins de 5 s : pas de nouveau stat")
	}
	horloge = horloge.Add(2 * time.Second)
	if _, ok := l.Cherche("203.0.113.7"); !ok {
		t.Fatal("relecture attendue après 5 s")
	}
	ecrireListe(t, chemin, `{"format": 1, "entrees": {}}`, 0o644)
	_ = os.Chtimes(chemin, horloge.Add(time.Minute), horloge.Add(time.Minute))
	horloge = horloge.Add(6 * time.Second)
	if _, ok := l.Cherche("203.0.113.7"); ok {
		t.Fatal("liste vidée : plus leurrée")
	}
}

// serveurLeurreTest : un vrai service amont qui compte ses appels, une route vers lui, un journal des menaces.
func serveurLeurreTest(t *testing.T, chemin string) (*Server, *int64, string) {
	t.Helper()
	var appels int64
	amont := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt64(&appels, 1)
		_, _ = w.Write([]byte("VRAI SERVICE"))
	}))
	t.Cleanup(amont.Close)
	hote, port, _ := net.SplitHostPort(strings.TrimPrefix(amont.URL, "http://"))
	p, _ := strconv.Atoi(port)
	journalMenaces := filepath.Join(t.TempDir(), "waf-threats.log")
	srv := &Server{
		routeLookup:     func(string) (string, int, bool) { return hote, p, true },
		leurresIP:       listeLeurresTest(chemin, nil),
		leurreIP:        NewLeurreHTTP(true, nil, nil),
		threatLog:       NewThreatLog(journalMenaces),
		ban:             NewBan(300*time.Second, 1),
		escalateBan:     NewBan(time.Hour, 1),
		upstreamTimeout: 2 * time.Second,
	}
	return srv, &appels, journalMenaces
}

func TestLeurresRequeteListeeServieParLeTheatre(t *testing.T) {
	chemin := filepath.Join(t.TempDir(), "leurres-ip.json")
	ecrireListe(t, chemin, leurresJSON(map[string]int64{
		"203.0.113.7": time.Now().Add(time.Hour).Unix(),
		"2001:db8::7": time.Now().Add(time.Hour).Unix(),
	}), 0o644)
	srv, appels, journalMenaces := serveurLeurreTest(t, chemin)
	h := srv.handler()

	for _, remote := range []string{"203.0.113.7:5555", "[2001:db8::7]:5555"} {
		for _, chemin := range []string{"/.env", "/", "/wp-login.php"} {
			req := httptest.NewRequest(http.MethodGet, "http://vrai.example"+chemin, nil)
			req.Host = "vrai.example"
			req.RemoteAddr = remote
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), "VRAI SERVICE") {
				t.Fatalf("%s %s : scène du théâtre attendue, reçu %d %q", remote, chemin, rec.Code, rec.Body.String())
			}
			if chemin == "/.env" && !strings.Contains(rec.Body.String(), "APP_ENV=production") {
				t.Fatalf("scène « secret » attendue : %q", rec.Body.String())
			}
		}
	}
	// une méthode que le théâtre ne joue pas n'atteint pas non plus le vrai service
	req := httptest.NewRequest(http.MethodPut, "http://vrai.example/x", strings.NewReader("x"))
	req.Host = "vrai.example"
	req.RemoteAddr = "203.0.113.7:5555"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if strings.Contains(rec.Body.String(), "VRAI SERVICE") {
		t.Fatal("PUT d'une adresse leurrée : jamais le vrai service")
	}
	if n := atomic.LoadInt64(appels); n != 0 {
		t.Fatalf("le proxy ne doit jamais être appelé pour une adresse leurrée : %d appels", n)
	}

	// journal : catégorie leurre_redirige, gravité d'état, jamais un ban ni un compteur d'escalade
	f, err := os.Open(journalMenaces)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	lignes := 0
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var e map[string]any
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			t.Fatal(err)
		}
		if e["category"] != "leurre_redirige" || e["severity"] != "audit" || e["action"] != "leurre_redirige" {
			t.Fatalf("ligne inattendue : %v", e)
		}
		lignes++
	}
	if lignes != 7 {
		t.Fatalf("7 lignes leurre_redirige attendues, %d", lignes)
	}
	for _, ip := range []string{"203.0.113.7", "2001:db8::7"} {
		if srv.ban.Count(ip) != 0 || srv.escalateBan.Count(ip) != 0 {
			t.Fatalf("%s : une redirection vers le leurre n'est pas un signal d'attaque", ip)
		}
	}

	// une adresse non listée atteint le vrai service
	req = httptest.NewRequest(http.MethodGet, "http://vrai.example/", nil)
	req.Host = "vrai.example"
	req.RemoteAddr = "203.0.113.9:5555"
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if !strings.Contains(rec.Body.String(), "VRAI SERVICE") || atomic.LoadInt64(appels) != 1 {
		t.Fatalf("adresse non listée : le vrai service attendu (%q)", rec.Body.String())
	}
}

func TestLeurresHoteNonRouteAussi(t *testing.T) {
	chemin := filepath.Join(t.TempDir(), "leurres-ip.json")
	ecrireListe(t, chemin, leurresJSON(map[string]int64{"203.0.113.7": time.Now().Add(time.Hour).Unix()}), 0o644)
	srv, _, _ := serveurLeurreTest(t, chemin)
	srv.routeLookup = func(string) (string, int, bool) { return "", 0, false }
	srv.hostAnomaly = true
	req := httptest.NewRequest(http.MethodGet, "http://inconnu.example/.git/HEAD", nil)
	req.Host = "inconnu.example"
	req.RemoteAddr = "203.0.113.7:5555"
	rec := httptest.NewRecorder()
	srv.handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("scène du théâtre attendue, reçu %d", rec.Code)
	}
	if srv.ban.Count("203.0.113.7") != 0 {
		t.Fatal("hôte non routé d'une adresse leurrée : ni anomalie ni ban")
	}
}
