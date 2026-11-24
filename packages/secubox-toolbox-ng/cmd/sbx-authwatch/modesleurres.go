// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// SecuBox-Deb :: toolbox-ng :: sbx-authwatch — mode par leurre de service (#3741)
//
// Chaque leurre peut être réglé « observer » (journaliser sans bannir) ou
// « bannir » (comportement d'origine) depuis la page Modes du WAF. Le réglage
// vit dans /etc/secubox/authwatch/leurres-modes.json, écrit par `wafctl
// leurres-modes ecrire` (root), relu à chaud sur changement de mtime :
//
//	{"modes": {"rdp": "observer", "redis": "bannir"}}
//
// FERMÉ PAR DÉFAUT : fichier absent ou illisible, service absent, valeur
// inconnue → bannir. Seul « observer » écrit en toutes lettres allège. (Leurres
// de messagerie : l'inverse, voir BannitMail.)
package main

import (
	"encoding/json"
	"log"
	"os"
	"sync"
	"time"
)

const (
	modeLeurreObserver = "observer"
	modeLeurreBannir   = "bannir"
)

// ModesLeurres porte le réglage par service, relu quand le fichier change.
type ModesLeurres struct {
	chemin string
	mu     sync.Mutex
	mtime  time.Time
	taille int64
	vu     bool
	modes  map[string]string
}

// NewModesLeurres prépare la relecture ; chemin vide = toujours bannir.
func NewModesLeurres(chemin string) *ModesLeurres {
	return &ModesLeurres{chemin: chemin}
}

// Observe dit si ce service est réglé « observer ». Nil-safe (nil = bannir).
func (m *ModesLeurres) Observe(service string) bool {
	if m == nil || m.chemin == "" {
		return false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.relire()
	return m.modes[service] == modeLeurreObserver
}

// BannitMail dit si un leurre de messagerie (#3924) peut bannir. SENS INVERSE des
// autres : « bannir » doit être écrit en toutes lettres ; absent, illisible ou
// inconnu → observer. Derrière ces ports, il y a de vrais comptes.
func (m *ModesLeurres) BannitMail(nom string) bool {
	if m == nil || m.chemin == "" {
		return false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.relire()
	return m.modes[nom] == modeLeurreBannir
}

// relire recharge le fichier si sa date ou sa taille a changé (verrou tenu).
func (m *ModesLeurres) relire() {
	st, err := os.Stat(m.chemin)
	if err != nil {
		if m.vu || m.modes != nil {
			log.Printf("sbx-authwatch: modes des leurres %s absent ou illisible — tous les leurres bannissent", m.chemin)
		}
		m.vu, m.modes = false, nil
		return
	}
	if m.vu && st.ModTime().Equal(m.mtime) && st.Size() == m.taille {
		return
	}
	m.vu, m.mtime, m.taille = true, st.ModTime(), st.Size()
	brut, err := os.ReadFile(m.chemin)
	if err != nil {
		log.Printf("sbx-authwatch: modes des leurres illisibles (%v) — tous les leurres bannissent", err)
		m.modes = nil
		return
	}
	var f struct {
		Modes map[string]string `json:"modes"`
	}
	if err := json.Unmarshal(brut, &f); err != nil {
		log.Printf("sbx-authwatch: modes des leurres mal formés (%v) — tous les leurres bannissent", err)
		m.modes = nil
		return
	}
	modes := make(map[string]string, len(f.Modes))
	for svc, mode := range f.Modes {
		switch mode {
		case modeLeurreObserver, modeLeurreBannir:
			modes[svc] = mode
		default:
			log.Printf("sbx-authwatch: mode %q inconnu pour le leurre %s — bannir", mode, svc)
		}
	}
	m.modes = modes
	log.Printf("sbx-authwatch: modes des leurres relus (%d réglage(s))", len(modes))
}

// modesLeurres est posé par main ; nil (tests) = tous les leurres bannissent.
var modesLeurres *ModesLeurres
