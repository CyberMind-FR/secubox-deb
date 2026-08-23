// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package web

import (
	"net"
	"net/http"
	"sync"
	"time"
)

// fenetrePresence : un visiteur est « en ligne » s'il a été vu dans cette fenêtre.
const fenetrePresence = 5 * time.Minute

// presence : compteur de présence EN MÉMOIRE (rien en base : c'est éphémère et
// local). Clé = « u:<handle> » pour un membre (UNIQUE par compte), « a:<ip> »
// pour un visiteur anonyme.
type presence struct {
	mu  sync.Mutex
	vus map[string]entreePresence
}

type entreePresence struct {
	dernier time.Time
	membre  bool
}

func nouvellePresence() *presence { return &presence{vus: make(map[string]entreePresence)} }

// vu enregistre le passage d'une clé (membre ou anonyme).
func (p *presence) vu(cle string, membre bool) {
	if p == nil || cle == "" {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.vus[cle] = entreePresence{dernier: time.Now(), membre: membre}
	if len(p.vus) > 8192 { // garde-fou : purge si la carte enfle
		p.purgerLocked()
	}
}

func (p *presence) purgerLocked() {
	lim := time.Now().Add(-fenetrePresence)
	for k, e := range p.vus {
		if e.dernier.Before(lim) {
			delete(p.vus, k)
		}
	}
}

// compte rend (en_ligne, membres_uniques) sur la fenêtre courante.
func (p *presence) compte() (enLigne, membres int) {
	if p == nil {
		return 0, 0
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	lim := time.Now().Add(-fenetrePresence)
	for _, e := range p.vus {
		if e.dernier.Before(lim) {
			continue
		}
		enLigne++
		if e.membre {
			membres++
		}
	}
	return
}

// ipClient extrait l'IP RÉELLE du visiteur : le BBS est derrière nginx/HAProxy,
// r.RemoteAddr est le mandataire. X-Real-IP (posé par nginx) porte l'origine.
func ipClient(r *http.Request) string {
	if ip := r.Header.Get("X-Real-IP"); ip != "" {
		return ip
	}
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if i := indexVirgule(xff); i > 0 {
			return trim(xff[:i])
		}
		return trim(xff)
	}
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

func indexVirgule(s string) int {
	for i := 0; i < len(s); i++ {
		if s[i] == ',' {
			return i
		}
	}
	return -1
}

func trim(s string) string {
	for len(s) > 0 && (s[0] == ' ' || s[0] == '\t') {
		s = s[1:]
	}
	for len(s) > 0 && (s[len(s)-1] == ' ' || s[len(s)-1] == '\t') {
		s = s[:len(s)-1]
	}
	return s
}
