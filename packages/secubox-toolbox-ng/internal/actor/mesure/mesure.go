// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>

// Package mesure choisit le cran de l'ÉCHELLE DE RÉPONSE d'un acteur : OBSERVE → DELAY → CHALLENGE → TARPIT → DENY (→ QUARANTINE pour un appareil du LAN).
//
// POURQUOI (#2274). Un mois d'écoute passive n'avait rien déclenché : seuls DENY/QUARANTINE sortaient d'actord, sbxwaf exigeait deux sanctions locales avant
// de bannir, et une décision BLOCK (deux capteurs, confiance ≥ 80) est rare pour un acteur que seul le WAF voit. Ici la détection devient une mesure à chaque
// cran, et un acteur qui INSISTE sous une mesure monte d'un cran — c'est ainsi que le WAF seul mène à un ban, sans jamais bannir sur une incertitude.
//
// Fonctions PURES : l'entrée (risque, confiance, capteurs, événements hostiles) vient de l'analyse, l'état précédent est rendu avec la mesure.
package mesure

import "time"

type Niveau string

const (
	Observe    Niveau = "OBSERVE"
	Delay      Niveau = "DELAY"
	Challenge  Niveau = "CHALLENGE"
	Tarpit     Niveau = "TARPIT"
	Deny       Niveau = "DENY"
	Quarantine Niveau = "QUARANTINE"
)

// Seuils : les mêmes que la politique de décision v2 (analysis.go) — MITIGATE à 42 de risque et 50 de confiance, BLOCK à 75 / 80 avec deux capteurs.
const (
	SeuilDelay      = 42
	SeuilChallenge  = 55
	SeuilTarpit     = 65
	SeuilBlock      = 75
	SeuilConfiance  = 50
	SeuilConfBlock  = 80
	MinCapteurs     = 2
	SeuilInsistance = 10 // événements hostiles NOUVEAUX sous la mesure courante pour monter d'un cran
)

var rang = map[Niveau]int{Observe: 0, Delay: 1, Challenge: 2, Tarpit: 3, Deny: 4, Quarantine: 4}

var ttl = map[Niveau]time.Duration{Delay: 5 * time.Minute, Challenge: 15 * time.Minute, Tarpit: 30 * time.Minute, Deny: time.Hour, Quarantine: 6 * time.Hour}

// TTL : durée de vie de la mesure (réversibilité). 0 pour OBSERVE.
func TTL(n Niveau) time.Duration { return ttl[n] }

type Entree struct {
	Risque    int
	Confiance int
	Capteurs  int  // capteurs distincts
	Hostiles  int  // événements hostiles cumulés de l'acteur
	LAN       bool // toutes ses adresses sont privées : appareil du réseau local
}

type Mesure struct {
	Niveau Niveau
	TTL    time.Duration
	Raison string
}

// Etat est ce que l'appelant retient d'un tour à l'autre pour un acteur.
type Etat struct {
	Niveau         Niveau
	Depuis         int64
	Expire         int64
	HostilesDepart int
}

func base(e Entree) (Niveau, string) {
	if e.Confiance < SeuilConfiance || e.Risque < SeuilDelay {
		return Observe, ""
	}
	blocage := e.Risque >= SeuilBlock && e.Confiance >= SeuilConfBlock && e.Capteurs >= MinCapteurs
	if e.LAN {
		if blocage {
			return Quarantine, "niveau BLOCK sur un appareil du réseau local : isolement par le NAC"
		}
		return Observe, "" // pas de délai ni de défi pour un appareil du LAN, et jamais d'isolement sur un seul capteur
	}
	switch {
	case blocage:
		return Deny, "risque ≥ 75, confiance ≥ 80, deux capteurs distincts au moins"
	case e.Risque >= SeuilTarpit:
		return Tarpit, "risque élevé sans preuve suffisante pour bloquer : ralentissement"
	case e.Risque >= SeuilChallenge:
		return Challenge, "comportement suspect : vérification"
	default:
		return Delay, "bruit automatisé : délai"
	}
}

func suivant(n Niveau, lan bool) Niveau {
	if lan {
		return Quarantine
	}
	switch n {
	case Delay:
		return Challenge
	case Challenge:
		return Tarpit
	case Tarpit:
		return Deny
	}
	return n
}

// Choisir rend la mesure du moment et l'état à retenir. `prev` est l'état du tour précédent (nil au premier).
func Choisir(e Entree, prev *Etat, now int64) (Mesure, Etat) {
	niv, raison := base(e)
	actif := prev != nil && prev.Niveau != Observe && now < prev.Expire
	if actif {
		// Hystérésis : une mesure en cours ne descend pas avant son échéance.
		if rang[prev.Niveau] > rang[niv] {
			niv, raison = prev.Niveau, "mesure en cours, maintenue jusqu'à son échéance"
		}
		// Insistance : l'acteur continue sous la mesure → un cran de plus, si la confiance le permet.
		if niv == prev.Niveau && niv != Observe && e.Confiance >= SeuilConfiance && e.Hostiles-prev.HostilesDepart >= SeuilInsistance {
			if s := suivant(niv, e.LAN); s != niv {
				niv, raison = s, "l'acteur insiste sous la mesure : cran supérieur"
			}
		}
	}
	if niv == Observe {
		return Mesure{Niveau: Observe}, Etat{Niveau: Observe}
	}
	st := Etat{Niveau: niv, Depuis: now, Expire: now + int64(ttl[niv].Seconds()), HostilesDepart: e.Hostiles}
	if actif && prev.Niveau == niv {
		st = *prev // même cran, même horloge
	}
	return Mesure{Niveau: niv, TTL: ttl[niv], Raison: raison}, st
}
