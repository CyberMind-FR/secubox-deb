// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// Émission Actor Intelligence depuis authwatch (#1240, corrélation multi-couche).
//
// POURQUOI CETTE COUCHE COMPTE PLUS QUE LES AUTRES. Le contrat d'enveloppe
// déclare cinq capteurs — waf, dpi, authwatch, sentinel, replay — et un seul
// émettait : le WAF. Le graphe d'acteurs ne voyait donc que du HTTP.
//
// authwatch apporte deux choses qu'aucun autre capteur ne peut donner :
//
//   - le COMPTE VISÉ, qui alimente `CredentialTokenHash` — l'axe le plus lourd
//     du barème de similarité (30 points sur 96), et le seul qui était
//     totalement mort. Deux tentatives visant le même compte rare sont un
//     indice de continuité bien plus fort qu'une même famille d'outillage ;
//   - une COUCHE DIFFÉRENTE. Un acteur qui sonde le HTTP *et* force du SSH est
//     une personnalité bien plus reconnaissable que la somme de deux profils
//     séparés — c'est précisément ce que « corréler sur le même score » veut
//     dire : une seule identité de comportement, nourrie par plusieurs sens.
//
// Le compte n'est JAMAIS émis en clair : il part en HMAC-SHA256 avec un secret
// local rotatable (envelope.Hasher). Le graphe peut reconnaître « le même
// compte » sans que l'adresse visée quitte la box, et un secret tourné rend les
// anciens condensés inexploitables.
//
// Émission FIRE-AND-FORGET, comme celle du WAF : si actord est absent, lent ou
// arrêté, authwatch continue de détecter et de bannir sans ralentir. Un moteur
// d'intelligence en panne ne doit jamais affaiblir la protection.
package main

import (
	"log"
	"os"
	"strings"
	"time"

	"github.com/CyberMind-FR/secubox-deb/secubox-toolbox-ng/internal/actor/emit"
	"github.com/CyberMind-FR/secubox-deb/secubox-toolbox-ng/internal/actor/envelope"
)

// Acteur émet les signaux d'authwatch vers sbx-actord.
type Acteur struct {
	emetteur *emit.Emitter
	hacheur  *envelope.Hasher
}

// NewActeur prépare l'émission. `socket` vide = désactivée. Un secret illisible
// n'empêche pas d'émettre : on perd l'axe « compte », pas la couche entière —
// l'IP, le service visé et la gravité valent déjà mieux que rien.
func NewActeur(socket, fichierSecret string) *Acteur {
	if socket == "" {
		return nil
	}
	a := &Acteur{emetteur: emit.New(socket, 4096)}
	secret, err := os.ReadFile(fichierSecret)
	if err != nil {
		log.Printf("authwatch: pas de secret d'identifiants (%v) — "+
			"émission sans l'axe « compte visé »", err)
		return a
	}
	h, err := envelope.NewHasher([]byte(strings.TrimSpace(string(secret))))
	if err != nil {
		log.Printf("authwatch: secret d'identifiants inutilisable (%v) — "+
			"émission sans l'axe « compte visé »", err)
		return a
	}
	a.hacheur = h
	return a
}

// Emet dépose une enveloppe pour un signal. `banni` distingue l'observation de
// la sanction : actord doit savoir ce qui a été SUBI et ce qui a été DÉCIDÉ.
func (a *Acteur) Emet(sig Signal, banni bool) {
	if a == nil || a.emetteur == nil {
		return
	}
	action := envelope.ActionObserve
	if banni {
		action = envelope.ActionBlock
	}
	e := &envelope.Envelope{
		EventID:    envelope.NewEventID(),
		Timestamp:  time.Now().Unix(),
		Sensor:     envelope.SensorAuthWatch,
		SrcIP:      sig.IP,
		DstService: sig.Service,
		Transport:  "tcp",
		Protocol:   sig.Service,
		Action:     action,
		Severity:   severite(sig.Severite),
		RuleID:     sig.Categorie,
	}
	if sig.Categorie != "" {
		e.BehaviorTags = append(e.BehaviorTags, sig.Categorie)
	}
	// LE COMPTE VISÉ, HACHÉ. C'est l'axe à 30 points, et la raison d'être de
	// cette émission.
	if a.hacheur != nil && sig.Cible != "" {
		e.CredentialTokenHash = a.hacheur.Hash(strings.ToLower(sig.Cible))
	}
	a.emetteur.Emit(e)
}

// Close ferme l'émetteur. Sans effet si l'émission est désactivée.
func (a *Acteur) Close() {
	if a != nil && a.emetteur != nil {
		a.emetteur.Close()
	}
}

// severite traduit le vocabulaire d'authwatch vers l'échelle 0..100 du contrat.
func severite(s string) int {
	switch s {
	case "high":
		return 80
	case "medium":
		return 50
	default:
		return 30
	}
}
