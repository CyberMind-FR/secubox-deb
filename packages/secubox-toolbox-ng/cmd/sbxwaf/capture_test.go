// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// Tests de la capture en flux (#3257, tâche 4) : le relais est intact, le
// préfixe est borné, et figer() arrête la copie sans arrêter le relais.
package main

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// octetsTest fabrique n octets déterministes (pas tous identiques, pour qu'un
// décalage du relais se voie dans l'empreinte).
func octetsTest(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i*7 + i/251)
	}
	return b
}

// lecteurSansWriterTo masque WriterTo : io.Copy passe alors par Read, comme
// le Transport lit le corps d'une requête.
type lecteurSansWriterTo struct{ io.Reader }

func TestCaptureRelaieIntactEtBorne(t *testing.T) {
	src := octetsTest(3 << 20)
	capt := nouvelleCapture(io.NopCloser(lecteurSansWriterTo{bytes.NewReader(src)}), 1<<20, -1)

	h := sha256.New()
	n, err := io.Copy(h, capt)
	if err != nil || n != int64(len(src)) {
		t.Fatalf("relais : n=%d err=%v, attendu %d octets sans erreur", n, err, len(src))
	}
	if got, want := h.Sum(nil), sha256.Sum256(src); !bytes.Equal(got, want[:]) {
		t.Fatal("les octets relayés diffèrent de la source")
	}
	prefixe, lus, complet := capt.figer()
	if len(prefixe) != 1<<20 || !bytes.Equal(prefixe, src[:1<<20]) {
		t.Fatalf("préfixe de %d octets, attendu le premier Mio de la source", len(prefixe))
	}
	if cap(prefixe) > 1<<20 {
		t.Errorf("capacité du préfixe %d > plafond : la mémoire n'est pas bornée", cap(prefixe))
	}
	if lus != 3<<20 {
		t.Errorf("lus = %d, attendu %d", lus, 3<<20)
	}
	if complet {
		t.Error("corps plus long que le plafond : complet doit être faux")
	}
}

func TestCaptureComplete(t *testing.T) {
	src := octetsTest(10_000)
	capt := nouvelleCapture(io.NopCloser(bytes.NewReader(src)), 1<<20, -1)
	if _, err := io.Copy(io.Discard, lecteurSansWriterTo{capt}); err != nil {
		t.Fatal(err)
	}
	prefixe, lus, complet := capt.figer()
	if !complet || lus != int64(len(src)) || !bytes.Equal(prefixe, src) {
		t.Fatalf("complet=%v lus=%d len(prefixe)=%d, attendu true/%d/corps entier", complet, lus, len(prefixe), len(src))
	}
}

// Un corps d'exactement le plafond, lu jusqu'à io.EOF, est complet.
func TestCaptureExactementLePlafondComplete(t *testing.T) {
	src := octetsTest(4096)
	capt := nouvelleCapture(io.NopCloser(bytes.NewReader(src)), 4096, -1)
	_, _ = io.Copy(io.Discard, lecteurSansWriterTo{capt})
	if prefixe, _, complet := capt.figer(); !complet || len(prefixe) != 4096 {
		t.Fatalf("complet=%v len=%d, attendu true/4096", complet, len(prefixe))
	}
}

// Une erreur de lecture (client coupé) n'est jamais un corps complet.
func TestCaptureErreurPasComplete(t *testing.T) {
	coupe := io.MultiReader(bytes.NewReader(octetsTest(100)), iotestErr{})
	capt := nouvelleCapture(io.NopCloser(coupe), 1<<20, -1)
	if _, err := io.Copy(io.Discard, lecteurSansWriterTo{capt}); err == nil {
		t.Fatal("l'erreur de la source doit être relayée telle quelle")
	}
	if _, lus, complet := capt.figer(); complet || lus != 100 {
		t.Fatalf("complet=%v lus=%d, attendu false/100", complet, lus)
	}
}

type iotestErr struct{}

func (iotestErr) Read([]byte) (int, error) { return 0, errors.New("connexion coupée") }

func TestCaptureFigeeIgnoreLaSuite(t *testing.T) {
	src := octetsTest(64 << 10)

	t.Run("sequentiel", func(t *testing.T) {
		capt := nouvelleCapture(io.NopCloser(bytes.NewReader(src)), 1<<20, -1)
		debut := make([]byte, 1000)
		if _, err := io.ReadFull(capt, debut); err != nil {
			t.Fatal(err)
		}
		prefixe, lus, complet := capt.figer()
		copie := append([]byte(nil), prefixe...)
		reste, err := io.ReadAll(lecteurSansWriterTo{capt})
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(append(debut, reste...), src) {
			t.Fatal("après figer(), la lecture doit encore relayer tous les octets")
		}
		if lus != 1000 || complet || !bytes.Equal(prefixe, src[:1000]) {
			t.Fatalf("lus=%d complet=%v len=%d, attendu 1000/false/1000", lus, complet, len(prefixe))
		}
		if !bytes.Equal(prefixe, copie) {
			t.Fatal("le préfixe figé a été modifié par les lectures suivantes")
		}
		// La capture ne retient plus le préfixe : la goroutine du Transport,
		// qui garde une référence à la capture, ne le fait pas survivre.
		if p2, l2, _ := capt.figer(); p2 != nil || l2 != 1000 {
			t.Fatalf("second figer() : préfixe retenu (%d octets) ou lus=%d au lieu de 1000", len(p2), l2)
		}
	})

	// La goroutine d'écriture du Transport lit pendant que le gestionnaire
	// fige : aucune course (go test -race), relais intact, préfixe stable.
	t.Run("concurrent", func(t *testing.T) {
		for i := 0; i < 50; i++ {
			capt := nouvelleCapture(io.NopCloser(bytes.NewReader(src)), 1<<20, -1)
			var relaye []byte
			var wg sync.WaitGroup
			wg.Add(1)
			go func() {
				defer wg.Done()
				buf := make([]byte, 997)
				for {
					n, err := capt.Read(buf)
					relaye = append(relaye, buf[:n]...)
					if err != nil {
						return
					}
				}
			}()
			prefixe, lus, _ := capt.figer()
			copie := append([]byte(nil), prefixe...)
			wg.Wait()
			if !bytes.Equal(relaye, src) {
				t.Fatal("relais altéré par figer() concurrent")
			}
			if int64(len(prefixe)) != lus || !bytes.Equal(prefixe, src[:len(prefixe)]) {
				t.Fatalf("préfixe incohérent : len=%d lus=%d", len(prefixe), lus)
			}
			if !bytes.Equal(prefixe, copie) {
				t.Fatal("le préfixe figé a bougé après figer()")
			}
		}
	})
}

// Content-Length connu : une seule allocation de min(plafond, taille) ; inconnu
// (-1, chunked) : croissance par doublement, jamais au-delà du plafond.
func TestCapturePrealloueContentLength(t *testing.T) {
	cas := []struct {
		nom            string
		n, plafond     int
		taille         int64
		capMin, capMax int
	}{
		{"petit corps", 10_000, 1 << 20, 10_000, 10_000, 10_000},
		{"gros corps", 3 << 20, 1 << 20, 3 << 20, 1 << 20, 1 << 20},
		{"taille inconnue", 10_000, 1 << 20, -1, 10_000, 1 << 20},
	}
	for _, c := range cas {
		t.Run(c.nom, func(t *testing.T) {
			src := octetsTest(c.n)
			capt := nouvelleCapture(io.NopCloser(bytes.NewReader(src)), c.plafond, c.taille)
			if c.taille > 0 {
				if got := cap(capt.buf); got != c.capMin {
					t.Fatalf("capacité préallouée %d, attendu %d", got, c.capMin)
				}
			}
			_, _ = io.Copy(io.Discard, lecteurSansWriterTo{capt})
			prefixe, _, _ := capt.figer()
			if got := cap(prefixe); got < c.capMin || got > c.capMax {
				t.Fatalf("capacité finale %d, attendu dans [%d, %d]", got, c.capMin, c.capMax)
			}
			if want := min(c.n, c.plafond); !bytes.Equal(prefixe, src[:want]) {
				t.Fatalf("préfixe de %d octets, attendu les %d premiers", len(prefixe), want)
			}
		})
	}
}

// Une panique pendant l'analyse est rattrapée, journalisée avec sa pile, et le
// jeton est rendu quand même (son defer est posé avant figer()).
func TestAnalyseCapturePaniqueRattrapee(t *testing.T) {
	var sortie bytes.Buffer
	log.SetOutput(&sortie)
	defer log.SetOutput(os.Stderr)
	// Une signature chargée : l'évaluation lit l'entrée, nil ici, donc panique.
	s := &Server{capturesMultipart: make(chan struct{}, 1), rules: LoadRules(ecrisRegles(t, corpusMultipartTest))}
	s.capturesMultipart <- struct{}{}

	s.analyserRequetePHP(nil, corpsMultipart, nil, requeteMultipart{host: "nc.example"}, true, true, corpsAucun) // entrée nil : panique

	if n := len(s.capturesMultipart); n != 0 {
		t.Fatalf("jeton non rendu après une panique (%d pris)", n)
	}
	if !strings.Contains(sortie.String(), "ERREUR analyse PHP") || !strings.Contains(sortie.String(), "goroutine ") {
		t.Fatalf("panique non journalisée avec sa pile : %q", sortie.String())
	}
}

// Non relayé : figée, jeton rendu, aucune analyse ni ligne.
func TestAnalyseCaptureNonRelayeeMuette(t *testing.T) {
	journal := filepath.Join(t.TempDir(), "menaces.jsonl")
	s := &Server{
		capturesMultipart: make(chan struct{}, 1),
		rules:             LoadRules(ecrisRegles(t, corpusMultipartTest)),
		threatLog:         NewThreatLog(journal),
	}
	s.capturesMultipart <- struct{}{}
	corps := corpsExploit()
	capt := nouvelleCapture(io.NopCloser(bytes.NewReader(corps)), 1<<20, int64(len(corps)))
	_, _ = io.Copy(io.Discard, lecteurSansWriterTo{capt}) // lu par le chemin texte, par exemple

	s.analyserRequetePHP(capt, corpsMultipart, &EntreePHP{}, requeteMultipart{ip: ipPublique, host: "nc.example", contentType: ctTest}, false, true, corpsAucun)

	if n := len(s.capturesMultipart); n != 0 {
		t.Fatalf("jeton non rendu (%d pris)", n)
	}
	if _, err := os.Stat(journal); !os.IsNotExist(err) {
		brut, _ := os.ReadFile(journal)
		t.Fatalf("corps jamais relayé : aucune ligne attendue, eu %s", brut)
	}
	if _, _, complet := capt.figer(); complet {
		t.Error("la capture n'a pas été figée (préfixe encore retenu)")
	}
}

// Close est relayé à la source (le ReverseProxy ferme le corps).
func TestCaptureCloseRelaie(t *testing.T) {
	f := &fermetureTest{}
	if err := nouvelleCapture(f, 10, -1).Close(); err != nil || !f.ferme {
		t.Fatalf("Close non relayé : err=%v ferme=%v", err, f.ferme)
	}
}

type fermetureTest struct{ ferme bool }

func (f *fermetureTest) Read([]byte) (int, error) { return 0, io.EOF }
func (f *fermetureTest) Close() error             { f.ferme = true; return nil }
