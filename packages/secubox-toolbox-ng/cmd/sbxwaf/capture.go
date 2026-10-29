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
// LA MÉMOIRE. Au plus capturesMultipartMax captures multipart à la fois, et
// capturesUrlencodedMax urlencoded (#3273, R-W7), chacune bornée à
// min(--max-body-inspect, 1 Mio) (fenetreCapture) : 24 Mio au pire sur une
// carte de 1 Go, même si l'inspection texte est relevée. Au-delà, pas de
// capture, une ligne « capture-concurrence », et la requête suit son cours.
//
// SEUL UN CORPS RELAYÉ EST ANALYSÉ. Une requête bloquée (403, ban, réponse du
// cache média) n'a jamais atteint le backend : même si un chemin texte en a lu
// la fenêtre au travers de la capture, rien n'est journalisé pour elle.

package main

import (
	"io"
	"net/http"
	"sync"
	"time"
)

// capturesMultipartMax borne les captures simultanées (spécification § 8).
const capturesMultipartMax = 16

// capturesUrlencodedMax borne les captures urlencoded simultanées (#3273,
// arbitrage R-W7) : un sémaphore À PART, pour qu'une rafale de POST de
// formulaire (Roundcube, Nextcloud) ne prive jamais le multipart PHP2Shell de
// ses 16 jetons. Au pire 8 Mio de plus. Seuil provisoire, non sourcé (2026-10-29).
const capturesUrlencodedMax = 8

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

// nouvelleCapture borne la copie à plafond octets. taille est le
// Content-Length (-1 s'il est inconnu) : connu, le préfixe est réservé d'un
// coup à min(plafond, taille) ; inconnu, il grandit par doublement.
func nouvelleCapture(src io.ReadCloser, plafond int, taille int64) *captureCorps {
	c := &captureCorps{src: src, max: plafond}
	if taille > 0 && plafond > 0 {
		reserve := int64(plafond)
		if taille < reserve {
			reserve = taille
		}
		c.buf = make([]byte, 0, reserve)
	}
	return c
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
// dans le préfixe. La capture lâche le préfixe : la goroutine du Transport, qui
// peut garder une référence à la capture après le gestionnaire, ne le fait pas
// survivre à l'analyse.
func (c *captureCorps) figer() (prefixe []byte, lus int64, complet bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.fige = true
	prefixe, c.buf = c.buf, nil
	return prefixe, c.lus, c.eof && c.err == nil && c.lus == int64(len(prefixe))
}

// requeteMultipart : ce que le journal retient de la requête. Ni requête
// (query), ni corps. ja4 et tool (relecture finale M3) : les mêmes que sur une
// ligne detect des regex, pour que la détection PHP2Shell arrive chez actord
// avec l'empreinte qui relie l'acteur. Ils ne sont calculés qu'à l'écriture
// de la première ligne (relecture I2 de #3273), depuis ua et entetes : une
// requête sans ligne ne paie ni les regex d'outil ni la lecture du JA4.
type requeteMultipart struct {
	ip, host, method, path, ua, contentType string
	entetes                                 http.Header // en-têtes de la requête (lecture seule)
	ja4, tool                               string
	etiquetee                               bool // ja4 et tool calculés
}

// semaphoreCapture rend le sémaphore du genre de corps : urlencoded a le
// sien (R-W7), tout autre genre à jeton prend celui du multipart.
func (s *Server) semaphoreCapture(genre genreCorps) chan struct{} {
	if genre == corpsUrlencoded {
		return s.capturesUrlencoded
	}
	return s.capturesMultipart
}

// prendreCapture prend un jeton du genre sans jamais attendre. nil = pas de limite.
func (s *Server) prendreCapture(genre genreCorps) bool {
	sem := s.semaphoreCapture(genre)
	if sem == nil {
		return true
	}
	select {
	case sem <- struct{}{}:
		return true
	default:
		return false
	}
}

func (s *Server) rendreCapture(genre genreCorps) {
	if sem := s.semaphoreCapture(genre); sem != nil {
		<-sem
	}
}

// etiqueterRequete calcule ja4 et tool une seule fois par requête.
func (s *Server) etiqueterRequete(rm *requeteMultipart) {
	if rm.etiquetee {
		return
	}
	rm.etiquetee = true
	if s.ja4Header != "" && rm.entetes != nil {
		rm.ja4 = rm.entetes.Get(s.ja4Header)
	}
	rm.tool = etiquetteOutilPHP(rm.ua, rm.path)
}

// journaliserMultipart complète rec avec la requête et l'écrit (nil-safe).
// ja4 et tool sont calculés ici, une fois par requête.
func (s *Server) journaliserMultipart(rm *requeteMultipart, rec ThreatRecord) {
	if s.threatLog == nil {
		return
	}
	s.etiqueterRequete(rm)
	rec.ClientIP, rec.Host, rec.Method, rec.Path, rec.UA = rm.ip, rm.host, rm.method, rm.path, rm.ua
	rec.JA4, rec.Tool = rm.ja4, rm.tool
	s.threatLog.Record(rec)
}

// limiteCaptureAtteinte : plus de jeton libre, donc pas de capture. La ligne
// porte la capacité réelle du sémaphore plein (16 multipart, 8 urlencoded en
// production) et son genre (signal genre : 1 = multipart, 2 = urlencoded,
// valeurs de genreCorps). Catégorie capture-concurrence (R-W7) : elle couvre
// les deux sémaphores ; multipart-limite reste réservé au plafond de parties
// de l'analyseur (R10).
//
// Appelée par analyserRequetePHP, après la réponse (passe finale M1). Au plus
// une ligne par seconde et par genre : une saturation, c'est une attaque, et
// chaque ligne coûte JA4, étiquette d'outil, JSON et écriture. La ligne suivante
// porte le nombre de lignes supprimées entre-temps (signal supprimees).
func (s *Server) limiteCaptureAtteinte(rm *requeteMultipart, genre genreCorps) {
	ok, supprimees := s.concurrence.autoriser(genre, horlogeConcurrence())
	if !ok {
		return
	}
	signaux := map[string]int{"concurrence": cap(s.semaphoreCapture(genre)), "genre": int(genre)}
	if supprimees > 0 {
		signaux["supprimees"] = supprimees
	}
	s.journaliserMultipart(rm, ThreatRecord{
		Category: "capture-concurrence", Severity: "audit", Action: "capture-concurrence",
		Signaux: signaux,
	})
}

// concurrenceIntervalle : au plus une ligne capture-concurrence par genre dans
// cet intervalle. Seuil provisoire, non sourcé (2026-10-29).
const concurrenceIntervalle = time.Second

// limiteurConcurrence : débit des lignes capture-concurrence, par genre de
// corps. Valeur zéro prête à l'emploi. Mémoire fixe (un créneau par genre).
type limiteurConcurrence struct {
	mu         sync.Mutex
	derniere   [corpsDebut + 1]time.Time
	supprimees [corpsDebut + 1]int
}

// autoriser dit si une ligne de ce genre peut être écrite à t ; sinon la
// suppression est comptée. ok : supprimees est le compte depuis la dernière
// ligne écrite, remis à zéro.
func (l *limiteurConcurrence) autoriser(g genreCorps, t time.Time) (ok bool, supprimees int) {
	if g < 0 || int(g) >= len(l.derniere) {
		return false, 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if d := l.derniere[g]; !d.IsZero() && t.Sub(d) < concurrenceIntervalle {
		l.supprimees[g]++
		return false, 0
	}
	l.derniere[g] = t
	supprimees, l.supprimees[g] = l.supprimees[g], 0
	return true, supprimees
}

// capturePlafond borne la fenêtre de capture quel que soit --max-body-inspect
// (relecture finale M2) : les indicateurs PHP2Shell tiennent dans 1 Mio
// (spécification § 6.4) ; une inspection texte relevée à 8 Mio ne doit pas
// porter la mémoire des captures à 16 × 8 = 128 Mio sur une carte de 1 Go.
const capturePlafond = 1 << 20

// fenetreCapture vaut min(--max-body-inspect, 1 Mio).
func (s *Server) fenetreCapture() int {
	if f := s.fenetreCorps(); f < capturePlafond {
		return int(f)
	}
	return capturePlafond
}

// horlogeConcurrence : horloge du débit des lignes capture-concurrence (crochet de test).
var horlogeConcurrence = time.Now
