// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package api

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"

	"github.com/CyberMind-FR/secubox-deb/gabriel-mood/internal/audio"
	"github.com/CyberMind-FR/secubox-deb/gabriel-mood/internal/moteur"
	"github.com/CyberMind-FR/secubox-deb/gabriel-mood/internal/store"
)

// Session : un navigateur, un micro, une chaîne d'analyse.
//
// UNE PAR PERSONNE, ET RIEN DE PARTAGÉ. L'étalon prosodique est celui d'une
// voix et le plancher de bruit celui d'une pièce : les mutualiser produirait
// un ordinaire qui n'est celui de personne, et des écarts imaginaires pour
// tout le monde.
type Session struct {
	ID        string
	Debut     time.Time
	Source    *audio.Navigateur
	Analyseur *moteur.Analyseur
	derniere  time.Time
	mu        sync.Mutex
}

// Touche note l'activité — sert à désigner la session « courante » pour
// /api/mood, qui n'en expose qu'une.
func (s *Session) Touche() {
	s.mu.Lock()
	s.derniere = time.Now()
	s.mu.Unlock()
}

func (s *Session) Activite() time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.derniere
}

// Sessions : le registre.
type Sessions struct {
	mu   sync.RWMutex
	tout map[string]*Session
	db   *store.Store
}

func NouveauRegistre(db *store.Store) *Sessions {
	return &Sessions{tout: map[string]*Session{}, db: db}
}

func identifiant() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		// Un identifiant prévisible permettrait à un autre onglet de
		// s'attacher à la session de quelqu'un. On préfère échouer.
		panic("gabriel-mood : générateur aléatoire indisponible")
	}
	return hex.EncodeToString(b)
}

// Ouvre crée une session et sa chaîne.
func (r *Sessions) Ouvre(origine string) *Session {
	src := audio.NouveauNavigateur(origine, audio.Echantillonnage*2)
	s := &Session{
		ID: identifiant(), Debut: time.Now(), Source: src,
		Analyseur: moteur.Nouveau(src), derniere: time.Now(),
	}
	r.mu.Lock()
	r.tout[s.ID] = s
	r.mu.Unlock()
	return s
}

// Ferme retire la session. SON IDENTIFIANT EST JETÉ : rien ne permet de
// rattacher une session suivante à celle-ci.
func (r *Sessions) Ferme(s *Session) {
	if s == nil {
		return
	}
	s.Source.Ferme()
	r.mu.Lock()
	delete(r.tout, s.ID)
	r.mu.Unlock()
}

// Par rend une session par identifiant.
func (r *Sessions) Par(id string) (*Session, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	s, ok := r.tout[id]
	return s, ok
}

// Courante : la session active la plus récente.
//
// /api/mood n'expose qu'une valeur, comme le contrat le demande ; quand
// plusieurs personnes écoutent en même temps, c'est la plus récemment active
// qui répond — et la réponse porte son identifiant, pour qu'on sache DE QUI
// l'on parle. Sans cela, deux personnes liraient l'humeur l'une de l'autre.
func (r *Sessions) Courante() (*Session, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var meilleure *Session
	for _, s := range r.tout {
		if meilleure == nil || s.Activite().After(meilleure.Activite()) {
			meilleure = s
		}
	}
	return meilleure, meilleure != nil
}

// Nombre de sessions ouvertes.
func (r *Sessions) Nombre() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.tout)
}

// Liste rend les identifiants ouverts, pour l'affichage d'état.
func (r *Sessions) Liste() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, 0, len(r.tout))
	for id := range r.tout {
		out = append(out, id)
	}
	return out
}
