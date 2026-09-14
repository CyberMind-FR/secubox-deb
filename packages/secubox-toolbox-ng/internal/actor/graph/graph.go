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
	// INDEX DES CANDIDATS (2026-09-14). `Observe` comparait chaque observation a
	// TOUS les acteurs : cout quadratique. Avec un acteur cree par evenement —
	// ce qui arrivait faute d'agregation — le demon a brule 6 h 46 de processeur
	// sans jamais ouvrir son API.
	//
	// Or la similarite n'accorde de points qu'a des axes EGAUX : un acteur qui ne
	// partage aucune valeur avec l'observation score zero, quoi qu'il arrive. Le
	// restreindre aux candidats indexes n'approxime donc rien — c'est le meme
	// resultat, sans le balayage.
	idx map[string]map[string]bool // "axe:valeur" -> ensemble d'ID d'acteurs
}

// New crée un graphe. threshold<=0 => DefaultThreshold.
func New(threshold int) *Graph {
	if threshold <= 0 {
		threshold = DefaultThreshold
	}
	return &Graph{threshold: threshold, actors: map[string]*Actor{},
		idx: map[string]map[string]bool{}}
}

// Observe rattache une observation à l'acteur le plus similaire (si la continuité
// atteint le seuil) ou en crée un nouveau, met à jour les agrégats, la continuité,
// la confiance et la priorité, puis retourne l'acteur concerné.
func (g *Graph) Observe(o Obs) *Actor {
	var best *Actor
	var bestScore score.Score
	for _, id := range g.candidats(o.Sig) {
		a := g.actors[id]
		if a == nil {
			continue
		}
		s := similarity.Similarity(a.sig, o.Sig)
		// Egalite tranchee par l'ID : sans cela, l'ordre d'un parcours de map
		// rendrait le rattachement non reproductible d'une execution a l'autre.
		if s.Value > bestScore.Value || (s.Value == bestScore.Value && best != nil && a.ID < best.ID) {
			bestScore, best = s, a
		}
	}
	// SEUIL ADAPTE AUX CAPTEURS PRESENTS. Le seuil nominal (50) suppose les huit
	// axes alimentes ; ici trois le sont. On le ramene a la masse reellement
	// comparable entre ces deux signatures, sans jamais descendre sous
	// MasseMin — voir similarity.SeuilEffectif.
	seuil := g.threshold
	if best != nil {
		seuil = similarity.SeuilEffectif(g.threshold, similarity.Comparable(best.sig, o.Sig))
	}
	if best == nil || bestScore.Value < seuil {
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
	g.indexer(best, o.Sig)
	return best
}

// cles derive d'une signature les valeurs sur lesquelles un rattachement est
// seulement POSSIBLE. Un axe vide n'en produit aucune : il ne peut pas egaler.
func cles(sig similarity.Signature) []string {
	var k []string
	if sig.CredentialHash != "" {
		k = append(k, "cred:"+sig.CredentialHash)
	}
	if sig.PathSig != "" {
		k = append(k, "path:"+sig.PathSig)
	}
	if sig.UAFamily != "" {
		k = append(k, "ua:"+sig.UAFamily)
	}
	if sig.TLSFingerprint != "" {
		k = append(k, "tls:"+sig.TLSFingerprint)
	}
	if sig.CadenceBucket != "" {
		k = append(k, "cad:"+sig.CadenceBucket)
	}
	if sig.IP != "" {
		k = append(k, "ip:"+sig.IP)
	}
	if sig.ASN != 0 {
		k = append(k, fmt.Sprintf("asn:%d", sig.ASN))
	}
	if sig.Country != "" {
		k = append(k, "cty:"+sig.Country)
	}
	return k
}

// indexer enregistre l'acteur sous chaque cle de la signature observee. Les
// cles s'ACCUMULENT : un acteur reste joignable par une IP qu'il n'utilise
// plus, ce qui est precisement ce qui permet de le reconnaitre quand il y
// revient.
func (g *Graph) indexer(a *Actor, sig similarity.Signature) {
	for _, k := range cles(sig) {
		if g.idx[k] == nil {
			g.idx[k] = map[string]bool{}
		}
		g.idx[k][a.ID] = true
	}
}

// candidats rend, triee, la liste des acteurs partageant au moins une valeur
// avec la signature. Le tri rend le parcours reproductible.
func (g *Graph) candidats(sig similarity.Signature) []string {
	vus := map[string]bool{}
	for _, k := range cles(sig) {
		for id := range g.idx[k] {
			vus[id] = true
		}
	}
	out := make([]string, 0, len(vus))
	for id := range vus {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
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
