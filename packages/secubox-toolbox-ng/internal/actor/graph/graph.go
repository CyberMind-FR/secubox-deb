// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// Package graph est l'ActorGraph (RFC-0013 §3 / RFC-0001) : il regroupe les
// observations en « acteurs candidats » par similarité multi-signal explicable
// (union par seuil), agrège leurs sources/cibles et construit un ThreatVector.
// Une IP n'est pas une identité : le regroupement est probabiliste et réversible,
// jamais une attribution. Le clustering est volontairement EXPLICABLE (similarité
// pondérée + composantes), pas un modèle opaque (RFC-0004 v1).
//
// Le graphe ne calcule PAS lui-même KnowledgeScore/IntentScore : ces axes sont
// injectés par l'appelant (SetScores) depuis internal/actor/{knowledge,intent},
// pour rester découplé. Il calcule continuité, confiance, gravité et priorité.
package graph

import (
	"fmt"
	"sort"

	"github.com/CyberMind-FR/secubox-deb/secubox-toolbox-ng/internal/actor/score"
	"github.com/CyberMind-FR/secubox-deb/secubox-toolbox-ng/internal/actor/similarity"
)

// DefaultThreshold : continuité minimale pour rattacher une observation à un
// acteur existant plutôt que d'en créer un (« campagne probable », RFC-0013 §3).
const DefaultThreshold = 50

// Vector est le ThreatVector d'un acteur (RFC-0013 §7). Chaque axe 0..100.
type Vector struct {
	Severity    int `json:"severity"`
	Knowledge   int `json:"knowledge"`
	Continuity  int `json:"continuity"`
	Intent      int `json:"intent"`
	Automation  int `json:"automation"`
	Persistence int `json:"persistence"`
	Confidence  int `json:"confidence"`
}

// Actor est une Actor Card agrégée (RFC-0013 §1). Les ensembles sont exposés
// triés et dédupliqués.
type Actor struct {
	ID        string   `json:"actor_id"`
	FirstSeen int64    `json:"first_seen"`
	LastSeen  int64    `json:"last_seen"`
	Events    int      `json:"events"`
	IPs       []string `json:"ips"`
	ASNs      []string `json:"asns"`
	Countries []string `json:"countries"`
	Targets   []string `json:"targets"`
	Vector    Vector   `json:"vector"`
	Priority  int      `json:"priority"`

	// état interne de corrélation
	sig     similarity.Signature
	concord map[string]bool // types de signaux indépendants ayant concordé
	ips     map[string]bool
	asns    map[string]bool
	ctys    map[string]bool
	tgts    map[string]bool
}

// Obs est une observation à corréler (dérivée d'une enveloppe par l'appelant).
type Obs struct {
	Sig       similarity.Signature
	Severity  int
	Target    string // dst_service
	Timestamp int64
}

// Graph maintient l'ensemble des acteurs.
type Graph struct {
	threshold int
	seq       int
	actors    map[string]*Actor
}

// New crée un graphe. threshold<=0 => DefaultThreshold.
func New(threshold int) *Graph {
	if threshold <= 0 {
		threshold = DefaultThreshold
	}
	return &Graph{threshold: threshold, actors: map[string]*Actor{}}
}

// Observe rattache une observation à l'acteur le plus similaire (si la continuité
// atteint le seuil) ou en crée un nouveau, met à jour les agrégats, la continuité,
// la confiance et la priorité, puis retourne l'acteur concerné.
func (g *Graph) Observe(o Obs) *Actor {
	var best *Actor
	var bestScore score.Score
	for _, a := range g.actors {
		s := similarity.Similarity(a.sig, o.Sig)
		if s.Value > bestScore.Value {
			bestScore, best = s, a
		}
	}
	if best == nil || bestScore.Value < g.threshold {
		best = g.newActor(o)
	} else {
		// rattachement : la continuité de l'acteur est la meilleure jointure vue,
		// et les types de signaux concordants nourrissent la confiance.
		if bestScore.Value > best.Vector.Continuity {
			best.Vector.Continuity = bestScore.Value
		}
		for _, c := range bestScore.Contributions {
			best.concord[c.Label] = true
		}
	}
	g.absorb(best, o)
	return best
}

func (g *Graph) newActor(o Obs) *Actor {
	g.seq++
	a := &Actor{
		ID:      fmt.Sprintf("ACT-%04d", g.seq),
		sig:     o.Sig,
		concord: map[string]bool{},
		ips:     map[string]bool{}, asns: map[string]bool{},
		ctys: map[string]bool{}, tgts: map[string]bool{},
		FirstSeen: o.Timestamp, LastSeen: o.Timestamp,
	}
	g.actors[a.ID] = a
	return a
}

// absorb met à jour les agrégats d'un acteur avec une observation.
func (g *Graph) absorb(a *Actor, o Obs) {
	a.Events++
	if o.Timestamp < a.FirstSeen || a.FirstSeen == 0 {
		a.FirstSeen = o.Timestamp
	}
	if o.Timestamp > a.LastSeen {
		a.LastSeen = o.Timestamp
		a.sig = o.Sig // exemplar = observation la plus récente
	}
	if o.Severity > a.Vector.Severity {
		a.Vector.Severity = o.Severity
	}
	if o.Sig.IP != "" {
		a.ips[o.Sig.IP] = true
	}
	if o.Sig.ASN != 0 {
		a.asns[fmt.Sprintf("AS%d", o.Sig.ASN)] = true
	}
	if o.Sig.Country != "" {
		a.ctys[o.Sig.Country] = true
	}
	if o.Target != "" {
		a.tgts[o.Target] = true
	}
	// Confiance : nombre de signaux indépendants concordants (RFC : « 3+ signaux
	// indépendants » = forte confiance) + petit bonus de volume.
	a.Vector.Confidence = score.Clamp(len(a.concord)*22 + min(a.Events, 8))
	g.materialize(a)
	a.Priority = Priority(a.Vector)
}

// SetScores injecte les axes calculés hors du graphe (KnowledgeScore d'internal/
// actor/knowledge, IntentScore/AutomationScore/PersistenceScore d'internal/actor/
// intent), puis recalcule la priorité. Sans effet si l'acteur est inconnu.
func (g *Graph) SetScores(actorID string, knowledge, intent, automation, persistence int) {
	a, ok := g.actors[actorID]
	if !ok {
		return
	}
	a.Vector.Knowledge = score.Clamp(knowledge)
	a.Vector.Intent = score.Clamp(intent)
	a.Vector.Automation = score.Clamp(automation)
	a.Vector.Persistence = score.Clamp(persistence)
	a.Priority = Priority(a.Vector)
}

// Priority applique le PriorityScore de la RFC-0013 §8. L'automation N'entre PAS
// dans la gravité : elle décrit le mode opératoire, pas la sévérité.
func Priority(v Vector) int {
	p := 0.25*float64(v.Severity) +
		0.20*float64(v.Knowledge) +
		0.20*float64(v.Intent) +
		0.15*float64(v.Continuity) +
		0.10*float64(v.Persistence) +
		0.10*float64(v.Confidence)
	return score.Clamp(int(p + 0.5))
}

// materialize projette les ensembles internes en slices triées exposables.
func (g *Graph) materialize(a *Actor) {
	a.IPs = sortedKeys(a.ips)
	a.ASNs = sortedKeys(a.asns)
	a.Countries = sortedKeys(a.ctys)
	a.Targets = sortedKeys(a.tgts)
}

// Get retourne un acteur par id.
func (g *Graph) Get(id string) (*Actor, bool) {
	a, ok := g.actors[id]
	return a, ok
}

// Actors retourne tous les acteurs, triés par priorité décroissante.
func (g *Graph) Actors() []*Actor {
	out := make([]*Actor, 0, len(g.actors))
	for _, a := range g.actors {
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Priority != out[j].Priority {
			return out[i].Priority > out[j].Priority
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// Len retourne le nombre d'acteurs.
func (g *Graph) Len() int { return len(g.actors) }

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
