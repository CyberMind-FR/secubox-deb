// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package main

// LIGNES BORNÉES (#3924). Ces ports sont ouverts à Internet : une rafale ne doit
// pas remplir le journal des menaces. Par (adresse, leurre), une ligne au plus par
// minute, portant le TOTAL depuis la précédente ; pour tous les leurres de
// messagerie, 60 lignes « detect » par minute, l'excédent attend et se résume en une
// ligne de journald. Les compteurs du jour, eux, ne perdent rien.
//
// Une ligne de ban n'entre pas dans le plafond commun (sans elle, le ban ne serait
// pas retrouvé au redémarrage), mais une adresse n'en écrit qu'une par minute.

import (
	"log"
	"sync"
	"time"
)

const (
	mailLigneParMinute = time.Minute
	mailLignesMax      = 60   // lignes « detect » par minute, tous leurres
	mailPaquetsMax     = 4096 // couples (adresse, leurre) suivis
)

// CompteMail : compteurs du jour d'un leurre. Sans ligne ≠ sans compte.
type CompteMail struct {
	Tentatives int `json:"tentatives"`
	Bans       int `json:"bans"`
	Lignes     int `json:"lignes"`
	SansDetail int `json:"sans_detail"` // jamais détaillées par adresse (table pleine)
}

type paquetMail struct {
	sig   Signal
	n     int // vues depuis la dernière ligne
	ecrit time.Time
}

// LimiteMail borne les lignes ; ses méthodes sont sûres entre goroutines.
type LimiteMail struct {
	mu       sync.Mutex
	paquets  map[string]*paquetMail
	bans     map[string]time.Time
	jour     string
	comptes  map[string]*CompteMail
	fenetre  time.Time
	lignes   int
	retenues int // vues sans ligne dans la fenêtre, faute de place
}

func NewLimiteMail() *LimiteMail {
	return &LimiteMail{paquets: map[string]*paquetMail{}, bans: map[string]time.Time{}, comptes: map[string]*CompteMail{}}
}

// compte rend le compteur du jour d'un leurre (verrou tenu).
func (l *LimiteMail) compte(nom string, quand time.Time) *CompteMail {
	if j := quand.Format("2006-01-02"); j != l.jour {
		l.jour, l.comptes = j, map[string]*CompteMail{}
	}
	c := l.comptes[nom]
	if c == nil {
		c = &CompteMail{}
		l.comptes[nom] = c
	}
	return c
}

// tourne ouvre une fenêtre d'une minute et résume la précédente (verrou tenu).
func (l *LimiteMail) tourne(quand time.Time) {
	if d := quand.Sub(l.fenetre); d >= 0 && d < time.Minute {
		return
	}
	if l.retenues > 0 {
		log.Printf("sbx-authwatch: leurres de messagerie : %d tentative(s) sans ligne propre en une minute (plafond %d), comptées", l.retenues, mailLignesMax)
	}
	l.fenetre, l.lignes, l.retenues = quand, 0, 0
}

// ecrit inscrit un paquet s'il reste de la place (verrou tenu).
func (l *LimiteMail) ecrit(j *JournalMenaces, p *paquetMail, quand time.Time) bool {
	if l.lignes >= mailLignesMax {
		return false
	}
	l.lignes++
	l.compte(p.sig.LeurreMail, quand).Lignes++
	j.Inscrit(p.sig, "detect", p.n)
	p.n, p.ecrit = 0, quand
	return true
}

// Detecte compte une tentative et écrit, ou non, sa ligne.
func (l *LimiteMail) Detecte(j *JournalMenaces, sig Signal, quand time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.tourne(quand)
	c := l.compte(sig.LeurreMail, quand)
	c.Tentatives++
	if sig.Cible != "" && !sig.CompteReel {
		sig.Cible = "?" // un nom inconnu n'est pas gardé en attente d'écriture
	}
	cle := sig.LeurreMail + "|" + sig.IP
	p := l.paquets[cle]
	if p == nil {
		if len(l.paquets) >= mailPaquetsMax {
			c.SansDetail++
			l.retenues++
			return
		}
		p = &paquetMail{}
		l.paquets[cle] = p
	}
	p.sig = sig
	p.n++
	if !p.ecrit.IsZero() && quand.Sub(p.ecrit) < mailLigneParMinute {
		return
	}
	if !l.ecrit(j, p, quand) {
		l.retenues++
	}
}

// Bannit compte une tentative à bannir ; faux si cette adresse vient de l'être
// par ce leurre (la ligne et le ban existent déjà).
func (l *LimiteMail) Bannit(sig Signal, quand time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	c := l.compte(sig.LeurreMail, quand)
	c.Tentatives++
	cle := sig.LeurreMail + "|" + sig.IP
	if t, ok := l.bans[cle]; ok && quand.Sub(t) < mailLigneParMinute {
		return false
	}
	l.bans[cle] = quand
	c.Bans++
	c.Lignes++
	return true
}

// Vide écrit ce qui attend (dans le plafond) et oublie ce qui est écrit depuis une
// minute. `tout` : arrêt du service, sans attendre la minute.
func (l *LimiteMail) Vide(j *JournalMenaces, quand time.Time, tout bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.tourne(quand)
	for cle, p := range l.paquets {
		if !tout && quand.Sub(p.ecrit) < mailLigneParMinute {
			continue
		}
		if p.n == 0 {
			delete(l.paquets, cle)
		} else {
			l.ecrit(j, p, quand)
		}
	}
	for cle, t := range l.bans {
		if quand.Sub(t) >= mailLigneParMinute {
			delete(l.bans, cle)
		}
	}
}

// Etat rend une copie des compteurs du jour.
func (l *LimiteMail) Etat(quand time.Time) map[string]CompteMail {
	l.mu.Lock()
	defer l.mu.Unlock()
	if quand.Format("2006-01-02") != l.jour {
		return map[string]CompteMail{}
	}
	out := map[string]CompteMail{}
	for nom, c := range l.comptes {
		out[nom] = *c
	}
	return out
}
