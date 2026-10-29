// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// Câblage de la capture multipart après la relecture finale (#3257) : I2a
// (catégorie désactivée = aucune capture), R12 (tous les clients analysés, le
// LAN journalisé « local » et jamais émis), M2 (fenêtre plafonnée à 1 Mio), M3
// (JA4 et outil sur les lignes multipart).
package main

import (
	"bytes"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/CyberMind-FR/secubox-deb/secubox-toolbox-ng/internal/actor/emit"
)

const corpusPHPDesactive = `{"categories": {"php2shell": {"name": "P", "severity": "high", "mode": "detect", "enabled": false,
  "patterns": [], "structural": [{"id": "php2shell-001", "check": "upload_progress_fichiers", "params": {"fichiers_apres_min": 2}}]}}}`

const corpusSansStructurelle = `{"categories": {"sqli": {"name": "S", "severity": "critical", "patterns": [{"id": "sq-1", "pattern": "union select"}]}}}`

// reecrire remplace le fichier de règles et avance sa date : Maybe(), appelé
// par le gestionnaire à chaque requête, le recharge.
func reecrire(t *testing.T, f, contenu string) {
	t.Helper()
	if err := os.WriteFile(f, []byte(contenu), 0o644); err != nil {
		t.Fatal(err)
	}
	plus := time.Now().Add(time.Duration(len(contenu)%7+2) * time.Second)
	if err := os.Chtimes(f, plus, plus); err != nil {
		t.Fatal(err)
	}
}

func grosEnvoi() []byte {
	return fabriquerMultipart("BND", []partieTest{{nom: "f", filename: "gros.bin", fichier: true, contenu: contenuTexte(3 << 20)}}, false)
}

// I2a : sans signature structurelle chargée et active, aucune capture n'est
// posée (le sémaphore plein le prouve : pas de ligne multipart-concurrence) et
// aucune ligne multipart-* n'est écrite. Vrai au démarrage et après rechargement.
func TestCaptureCategorieDesactiveeAucuneCapture(t *testing.T) {
	for nom, corpus := range map[string]string{"desactivee": corpusPHPDesactive, "sans structurelle": corpusSansStructurelle} {
		t.Run(nom, func(t *testing.T) {
			b := nouveauBancMultipart(t, nil)
			b.s.rules = LoadRules(ecrisRegles(t, corpus))
			b.envoyer("nc.example", "/upload", ipPublique, ctTest, bytes.NewReader(grosEnvoi()))
			b.s.capturesMultipart = make(chan struct{}, 1)
			b.s.capturesMultipart <- struct{}{}
			b.envoyer("nc.example", "/upload", ipPublique, ctTest, bytes.NewReader(corpsExploit()))
			if ls := lignesDe(b.lignes(t), "multipart-"); len(ls) != 0 {
				t.Fatalf("aucune ligne multipart-* attendue, eu %v", ls)
			}
		})
	}
}

func TestCaptureRechargementAChaudEnabled(t *testing.T) {
	b := nouveauBancMultipart(t, nil)
	f := ecrisRegles(t, corpusPHPDesactive)
	b.s.rules = LoadRules(f)
	b.envoyer("nc.example", "/upload", ipPublique, ctTest, bytes.NewReader(corpsExploit()))
	if ls := b.lignes(t); len(ls) != 0 {
		t.Fatalf("désactivée au démarrage : aucune ligne attendue, eu %v", ls)
	}
	reecrire(t, f, corpusMultipartTest)
	b.envoyer("nc.example", "/upload", ipPublique, ctTest, bytes.NewReader(corpsExploit()))
	if ls := lignesDe(b.lignes(t), "php2shell"); len(ls) != 1 {
		t.Fatalf("réactivée à chaud : une ligne php2shell attendue, eu %v", b.lignes(t))
	}
	reecrire(t, f, corpusPHPDesactive)
	avant := len(b.lignes(t))
	b.envoyer("nc.example", "/upload", ipPublique, ctTest, bytes.NewReader(grosEnvoi()))
	if ls := b.lignes(t); len(ls) != avant {
		t.Fatalf("désactivée à chaud : aucune nouvelle ligne attendue, eu %v", ls[avant:])
	}
}

// R12 : le réseau local et 127.0.0.1 sont analysés ; la ligne porte « local ».
func TestCaptureLANAnalyseeEnLocal(t *testing.T) {
	for _, ip := range []string{"192.168.1.10", "127.0.0.1", "10.100.0.7"} {
		b := nouveauBancMultipart(t, nil)
		corps := corpsExploit()
		if rec := b.envoyer("nc.example", "/upload", ip, ctTest, bytes.NewReader(corps)); rec.Code != http.StatusOK {
			t.Fatalf("%s : statut %d", ip, rec.Code)
		}
		b.verifierRecu(t, corps)
		ls := lignesDe(b.lignes(t), "php2shell")
		if len(ls) != 1 || ls[0]["client_ip"] != "local" {
			t.Fatalf("%s : une ligne php2shell « local » attendue, eu %v", ip, b.lignes(t))
		}
		b.verifierSansSanction(t, ip)
	}
}

// R12 : une adresse privée n'est jamais émise vers actord ; une publique l'est.
func TestCaptureLANJamaisEmiseVersActord(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "actord.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	recu := make(chan string, 16)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				buf := make([]byte, 1<<16)
				for {
					n, err := c.Read(buf)
					if n > 0 {
						recu <- string(buf[:n])
					}
					if err != nil {
						return
					}
				}
			}(c)
		}
	}()
	b := nouveauBancMultipart(t, nil)
	em := emit.New(sock, 16)
	defer em.Close()
	b.s.threatLog.SetEmitter(em)
	b.envoyer("nc.example", "/upload", "192.168.1.10", ctTest, bytes.NewReader(corpsExploit()))
	b.envoyer("nc.example", "/upload", ipPublique, ctTest, bytes.NewReader(corpsExploit()))
	var tout strings.Builder
	limite := time.After(3 * time.Second)
	for !strings.Contains(tout.String(), ipPublique) {
		select {
		case m := <-recu:
			tout.WriteString(m)
		case <-limite:
			t.Fatalf("l'adresse publique n'a pas été émise : %q", tout.String())
		}
	}
	time.Sleep(200 * time.Millisecond)
	for len(recu) > 0 {
		tout.WriteString(<-recu)
	}
	if strings.Contains(tout.String(), "192.168.1.10") || strings.Contains(tout.String(), `"local"`) {
		t.Fatalf("une adresse privée est partie vers actord : %q", tout.String())
	}
	if n := len(lignesDe(b.lignes(t), "php2shell")); n != 2 {
		t.Fatalf("deux lignes php2shell attendues au journal, eu %d", n)
	}
}

// M2 : la fenêtre de capture vaut min(--max-body-inspect, 1 Mio).
func TestFenetreCapturePlafonnee(t *testing.T) {
	s := &Server{}
	for inspect, want := range map[int64]int{0: 1 << 20, 64 << 10: 64 << 10, 1 << 20: 1 << 20, 8 << 20: 1 << 20} {
		s.maxBodyInspect = inspect
		if got := s.fenetreCapture(); got != want {
			t.Errorf("max-body-inspect=%d : fenêtre %d, attendu %d", inspect, got, want)
		}
	}
}

func TestCaptureFenetrePlafonneeMemeAvecInspectionLarge(t *testing.T) {
	b := nouveauBancMultipart(t, nil)
	b.s.maxBodyInspect = 8 << 20
	corps := fabriquerMultipart("BND", []partieTest{
		{nom: "f", filename: "gros.bin", fichier: true, contenu: contenuTexte(2 << 20)},
		{nom: nomProgressPHP, contenu: "x"},
		{nom: "f1", filename: "a", fichier: true, contenu: "y"},
		{nom: "f2", filename: "b", fichier: true, contenu: "z"},
	}, false)
	b.envoyer("nc.example", "/upload", ipPublique, ctTest, bytes.NewReader(corps))
	b.verifierRecu(t, corps)
	ls := b.lignes(t)
	if len(lignesDe(ls, "php2shell")) != 0 || len(lignesDe(ls, "multipart-tronque")) != 1 {
		t.Fatalf("fenêtre de 1 Mio : une seule ligne multipart-tronque attendue, eu %v", ls)
	}
}

// M3 : les lignes multipart (détection et état) portent JA4 et outil, comme
// les lignes detect des regex.
func TestCaptureLignesPortentJA4EtOutil(t *testing.T) {
	b := nouveauBancMultipart(t, nil)
	b.s.ja4Header = "X-Test-JA4"
	envoyer := func(corps []byte) {
		req := httptest.NewRequest(http.MethodPost, "http://nc.example/upload", bytes.NewReader(corps))
		req.Host = "nc.example"
		req.RemoteAddr = ipPublique + ":40000"
		req.Header.Set("Content-Type", ctTest)
		req.Header.Set("User-Agent", "sqlmap/1.7.2#stable (https://sqlmap.org)")
		req.Header.Set("X-Test-JA4", "t13d1516h2_8daaf6152771_02713d6af862")
		b.s.handler().ServeHTTP(httptest.NewRecorder(), req)
	}
	envoyer(corpsExploit())
	envoyer(grosEnvoi())
	b.s.capturesMultipart = make(chan struct{}, 1)
	b.s.capturesMultipart <- struct{}{}
	envoyer(corpsExploit())
	ls := b.lignes(t)
	vues := map[string]bool{}
	for _, l := range append(lignesDe(ls, "php2shell"), lignesDe(ls, "multipart-")...) {
		vues[l["category"].(string)] = true
		if l["ja4"] != "t13d1516h2_8daaf6152771_02713d6af862" || l["tool"] != "sqlmap" {
			t.Errorf("ligne sans JA4 ou sans outil : %v", l)
		}
	}
	for _, c := range []string{"php2shell", "multipart-tronque", "multipart-concurrence"} {
		if !vues[c] {
			t.Errorf("ligne %s absente : %v", c, ls)
		}
	}
}
