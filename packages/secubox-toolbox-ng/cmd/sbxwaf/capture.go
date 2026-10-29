// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// SecuBox-Deb :: toolbox-ng :: sbxwaf — capture en flux du multipart PHP (#3257)
//
// LE CHOIX DU PROPRIÉTAIRE : « EN FLUX ». Aucun tampon n'est ajouté avant le
// relais au backend. Le proxy lit le corps exactement comme avant, et
// captureCorps copie au passage les premiers octets lus, dans une mémoire
// bornée. L'analyse a lieu APRÈS la réponse, sur ce préfixe figé : elle ne
// peut donc que détecter, jamais bloquer, et elle ne bannit jamais.
//
// LA CONCURRENCE. http.Transport lit le corps dans SA goroutine d'écriture,
// qui peut survivre au gestionnaire (backend qui répond sans tout lire, client
// lent). figer() pose donc un drapeau sous verrou : la copie s'arrête, la
// lecture continue de relayer, et le préfixe rendu n'est plus jamais modifié.
// Le verrou n'est JAMAIS tenu pendant la lecture de la source : un client lent
// ne peut pas retenir figer(), donc la fin de la réponse.
//
// LA MÉMOIRE. Au plus capturesMultipartMax captures à la fois, chacune bornée
// à la fenêtre d'inspection (1 Mio par défaut) : 16 Mio au pire sur une carte
// de 1 Go. Au-delà, pas de capture, une ligne « multipart-limite », et la
// requête suit son cours.

package main

import (
	"io"
	"log"
	"sync"
)

// capturesMultipartMax borne les captures simultanées (spécification § 8).
const capturesMultipartMax = 16

// captureCorps relaie un corps de requête tel quel et en copie le début.
// Il n'implémente volontairement pas io.WriterTo : io.Copy passerait alors à
// côté de Read, donc de la copie.
type captureCorps struct {
	mu   sync.Mutex
	src  io.ReadCloser
	buf  []byte // jamais plus de max octets, ni en longueur ni en capacité
	max  int
	lus  int64 // octets relayés avant figer()
	eof  bool  // la source a rendu io.EOF
	fige bool
	err  error // première erreur autre que io.EOF
}

func nouvelleCapture(src io.ReadCloser, plafond int) *captureCorps {
	return &captureCorps{src: src, max: plafond}
}

// Read relaie la source sans rien changer (octets ni erreur) et, tant que la
// capture n'est pas figée, en copie au plus max octets.
func (c *captureCorps) Read(p []byte) (int, error) {
	n, err := c.src.Read(p)
	c.mu.Lock()
	if !c.fige {
		c.lus += int64(n)
		c.copier(p[:n])
		switch {
		case err == io.EOF:
			c.eof = true
		case err != nil && c.err == nil:
			c.err = err
		}
	}
	c.mu.Unlock()
	return n, err
}

// copier ajoute b au préfixe, sous verrou. La capacité grandit par doublement
// mais ne dépasse jamais max : append pourrait réserver au-delà.
func (c *captureCorps) copier(b []byte) {
	place := c.max - len(c.buf)
	if place <= 0 || len(b) == 0 {
		return
	}
	if len(b) > place {
		b = b[:place]
	}
	if besoin := len(c.buf) + len(b); besoin > cap(c.buf) {
		nc := 2 * cap(c.buf)
		if nc < besoin {
			nc = besoin
		}
		if nc > c.max {
			nc = c.max
		}
		nb := make([]byte, len(c.buf), nc)
		copy(nb, c.buf)
		c.buf = nb
	}
	c.buf = append(c.buf, b...)
}

// Close ferme la source (le ReverseProxy ferme le corps en fin de relais).
func (c *captureCorps) Close() error { return c.src.Close() }

// figer arrête la copie et rend le préfixe, qui ne sera plus jamais modifié.
// complet : la source a rendu io.EOF sans erreur, et tout ce qui a été lu tient
// dans le préfixe.
func (c *captureCorps) figer() (prefixe []byte, lus int64, complet bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.fige = true
	return c.buf, c.lus, c.eof && c.err == nil && c.lus == int64(len(c.buf))
}

// requeteMultipart : ce que le journal retient de la requête. Ni requête
// (query), ni corps.
type requeteMultipart struct{ ip, host, method, path, ua, contentType string }

// prendreCapture prend un jeton sans jamais attendre. nil = pas de limite.
func (s *Server) prendreCapture() bool {
	if s.capturesMultipart == nil {
		return true
	}
	select {
	case s.capturesMultipart <- struct{}{}:
		return true
	default:
		return false
	}
}

func (s *Server) rendreCapture() {
	if s.capturesMultipart != nil {
		<-s.capturesMultipart
	}
}

// journaliserMultipart complète rec avec la requête et l'écrit (nil-safe).
func (s *Server) journaliserMultipart(rm requeteMultipart, rec ThreatRecord) {
	if s.threatLog == nil {
		return
	}
	rec.ClientIP, rec.Host, rec.Method, rec.Path, rec.UA = rm.ip, rm.host, rm.method, rm.path, rm.ua
	s.threatLog.Record(rec)
}

// limiteCaptureAtteinte : plus de jeton libre, donc pas de capture. La ligne
// porte la capacité réelle du sémaphore (16 en production).
func (s *Server) limiteCaptureAtteinte(rm requeteMultipart) {
	s.journaliserMultipart(rm, ThreatRecord{
		Category: "multipart-limite", Severity: "audit", Action: "multipart-limite",
		Signaux: map[string]int{"concurrence": cap(s.capturesMultipart)},
	})
}

// analyserCaptureMultipart fige la capture, l'analyse et journalise. Appelée
// par defer dans le gestionnaire, donc après le relais et la réponse.
//
// MODE DETECT SEULEMENT : aucun appel au ban, à nft ni à l'escalade. La
// gravité journalisée est celle de la signature ; elle part vers actord comme
// toute ligne du journal. Une ligne d'état (tronque, malforme, limite) est
// d'une gravité « audit », qui ne compte pas comme hostile.
//
// Le jeton est rendu APRÈS l'analyse : le préfixe vit jusque-là, et la borne
// mémoire couvre aussi les allocations de l'analyseur.
func (s *Server) analyserCaptureMultipart(capt *captureCorps, rm requeteMultipart) {
	prefixe, lus, complet := capt.figer()
	defer s.rendreCapture()
	// Une panique de l'analyseur ne doit pas casser une réponse déjà relayée :
	// en detect, l'analyse n'a pas le droit d'empêcher quoi que ce soit. Ce
	// recover est différé PAR CETTE FONCTION : il ne rattrape que ses propres
	// paniques, jamais celle du gestionnaire (http.ErrAbortHandler) qui
	// traverserait ce defer.
	defer func() {
		if e := recover(); e != nil {
			log.Printf("sbxwaf: ERREUR analyse multipart host=%s path=%s ip=%s : %v", rm.host, rm.path, rm.ip, e)
		}
	}()
	if lus == 0 || s.rules == nil {
		return // corps jamais lu (requête bloquée avant le relais, backend muet)
	}
	res := analyserMultipart(prefixe, rm.contentType, !complet, LimitesMultipart{})
	signaux := res.Signaux()
	for _, d := range s.rules.EvaluerStructurel(res) {
		s.journaliserMultipart(rm, ThreatRecord{
			Category: d.Categorie, Severity: d.Severity, RuleID: d.RuleID,
			Action: "detect", Mode: modeDetect, Signaux: signaux,
		})
		log.Printf("sbxwaf: DETECT %s rule=%s host=%s path=%s ip=%s parties=%d",
			d.Categorie, d.RuleID, rm.host, rm.path, rm.ip, res.Parties)
	}
	if res.Statut != MultipartAnalyse {
		statut := "multipart-" + string(res.Statut)
		s.journaliserMultipart(rm, ThreatRecord{
			Category: statut, Severity: "audit", Action: statut, Signaux: signaux,
		})
	}
}
