// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package main

import (
	"regexp"
	"sort"
	"sync"

	"github.com/CyberMind-FR/secubox-deb/secubox-toolbox-ng/internal/actor/envelope"
)

// LES ROBOTS CONNUS SONT CLASSÉS À PART (#2201).
//
// Un robot qui s'annonce (meta-externalagent, googlebot…) et que le WAF refuse
// selon la politique du vhost n'est pas un acteur à surveiller : il a changé
// d'adresse 2 743 fois, vient de 65 pays et a été « sanctionné » 7 845 fois, et
// ce profil le plaçait en tête des acteurs critiques (score 89) devant les vrais
// balayages. Il ne crée donc plus d'acteur : ses accès sont comptés par famille
// dans un registre à part (accès, adresses distinctes, première et dernière
// vue), exposé par GET /robots et par l'aperçu.
//
// Le classement est STRICT. Un événement n'est « robot connu » que s'il porte
// l'unique étiquette `robots` (donc aucune sonde de reconnaissance, aucun leurre,
// aucune règle déclenchée), qu'il est de sévérité basse, non bloqué, et que le
// WAF a nommé la famille. Dès qu'un robot sort de ce rôle, ses événements
// redeviennent ordinaires et alimentent un acteur comme avant.
//
// Limite assumée : un attaquant qui se déguise en robot connu sur un vhost
// anti-robots n'apparaît que dans ce registre (son volume reste visible, par
// famille). Les requêtes qui touchent une règle d'attaque, elles, sont des
// événements ordinaires.

const (
	robotsIPsMax    = 20000 // plafond d'adresses retenues par famille (mémoire bornée) ; au-delà on compte les accès seulement
	robotsVhostsMax = 50
	severiteRobot   = 40 // « info » dans sevToInt de sbxwaf
)

var motifFamilleRobot = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,39}$`)

// estRobotConnu rend la famille du robot si l'événement est un accès de robot connu, strictement.
func estRobotConnu(e *envelope.Envelope) (string, bool) {
	if e.Action == envelope.ActionBlock || e.RuleID != "" || e.Severity > severiteRobot {
		return "", false
	}
	if len(e.BehaviorTags) != 1 || e.BehaviorTags[0] != "robots" {
		return "", false
	}
	f := e.UserAgentFamily
	if f == "other" || f == "browser-generic" || !motifFamilleRobot.MatchString(f) {
		return "", false
	}
	return f, true
}

// RobotFamille est ce que l'API expose d'une famille : des compteurs, jamais une adresse.
type RobotFamille struct {
	Famille string `json:"famille"`
	Hits    int    `json:"hits"`
	IPs     int    `json:"ips"`
	First   string `json:"first"`
	Last    string `json:"last"`
	Vhosts  int    `json:"vhosts"`
}

type familleRobot struct {
	hits          int
	ips           map[string]struct{}
	premier, last int64
	vhosts        map[string]struct{}
}

// Robots est le registre des accès de robots connus. Les méthodes sont sûres sur un pointeur nil.
type Robots struct {
	mu sync.Mutex
	f  map[string]*familleRobot
}

func (r *Robots) Observe(famille, ip string, ts int64, vhost string) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.f == nil {
		r.f = map[string]*familleRobot{}
	}
	f := r.f[famille]
	if f == nil {
		f = &familleRobot{ips: map[string]struct{}{}, vhosts: map[string]struct{}{}, premier: ts}
		r.f[famille] = f
	}
	f.hits++
	if ts < f.premier {
		f.premier = ts
	}
	if ts > f.last {
		f.last = ts
	}
	if _, vu := f.ips[ip]; !vu && len(f.ips) < robotsIPsMax {
		f.ips[ip] = struct{}{}
	}
	if _, vu := f.vhosts[vhost]; !vu && vhost != "" && len(f.vhosts) < robotsVhostsMax {
		f.vhosts[vhost] = struct{}{}
	}
}

// Snapshot rend les familles, la plus active d'abord.
func (r *Robots) Snapshot() []RobotFamille {
	out := []RobotFamille{}
	if r == nil {
		return out
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for nom, f := range r.f {
		out = append(out, RobotFamille{Famille: nom, Hits: f.hits, IPs: len(f.ips), First: hhmm(f.premier), Last: hhmm(f.last), Vhosts: len(f.vhosts)})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Hits != out[j].Hits {
			return out[i].Hits > out[j].Hits
		}
		return out[i].Famille < out[j].Famille
	})
	return out
}
