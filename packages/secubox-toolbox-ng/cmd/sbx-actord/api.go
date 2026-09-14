// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package main

import (
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/CyberMind-FR/secubox-deb/secubox-toolbox-ng/internal/actor/evidence"
	"github.com/CyberMind-FR/secubox-deb/secubox-toolbox-ng/internal/actor/graph"
	"github.com/CyberMind-FR/secubox-deb/secubox-toolbox-ng/internal/actor/score"
)

// webActor est la projection d'un graph.Actor dans le format consommé par la
// console (docs/design/actor-intelligence-webui.html). Rien n'est inventé : tous
// les champs dérivent du ThreatVector réel et des agrégats du graphe.
type webActor struct {
	ID       string       `json:"id"`
	Name     string       `json:"name"`
	Priority int          `json:"priority"`
	Level    string       `json:"level"`
	Tags     [][2]string  `json:"tags"`
	Vec      graph.Vector `json:"vec"`
	Src      srcCounts    `json:"src"`
	First    string       `json:"first"`
	Last     string       `json:"last"`
	Targets  []string     `json:"targets"`
	// Bans : combien de fois cet acteur a ete SANCTIONNE. L'interface en fait un
	// niveau DEFCON — un profil sanctionne dix fois et qui revient n'a pas le
	// meme poids qu'un profil observe une fois.
	Bans int      `json:"bans"`
	Hyp  [][2]any `json:"hyp"`
	TL   []any    `json:"tl"`
}

type srcCounts struct {
	IPs       int `json:"ips"`
	ASNs      int `json:"asns"`
	Countries int `json:"countries"`
}

func hhmm(ts int64) string {
	if ts == 0 {
		return "—"
	}
	return time.Unix(ts, 0).UTC().Format("15:04")
}

func niveau(prio int) string {
	switch {
	case prio >= 80:
		return "HIGH"
	case prio >= 50:
		return "MED"
	default:
		return "LOW"
	}
}

func tags(v graph.Vector) [][2]string {
	var out [][2]string
	if v.Automation >= 70 {
		out = append(out, [2]string{"automatisé", "auto"})
	}
	if v.Intent >= 70 {
		out = append(out, [2]string{"ciblé", "target"})
	}
	if v.Knowledge >= 45 {
		out = append(out, [2]string{"reconnaissance", "recon"})
	}
	if len(out) == 0 {
		out = append(out, [2]string{"observé", ""})
	}
	return out
}

// hypotheses dérive une distribution d'hypothèses concurrentes du ThreatVector
// (RFC-0013 §10 : contre-hypothèses). Probabilités normalisées, arrondies.
func hypotheses(v graph.Vector) [][2]any {
	type h struct {
		label string
		w     float64
	}
	hs := []h{
		{"campagne ciblée automatisée", float64(v.Automation+v.Intent) / 2},
		{"bot générique / scanner", float64(v.Automation)},
		{"bruit non relié", float64(score.Clamp(100 - v.Confidence))},
	}
	sum := 0.0
	for _, x := range hs {
		sum += x.w
	}
	if sum <= 0 {
		sum = 1
	}
	sort.Slice(hs, func(i, j int) bool { return hs[i].w > hs[j].w })
	out := make([][2]any, 0, len(hs))
	for _, x := range hs {
		p := float64(int(x.w/sum*100+0.5)) / 100
		out = append(out, [2]any{x.label, p})
	}
	return out
}

func toWeb(a *graph.Actor) webActor {
	return webActor{
		Bans: a.Bans,
		ID:   a.ID, Name: "", Priority: a.Priority, Level: niveau(a.Priority),
		Tags: tags(a.Vector), Vec: a.Vector,
		Src:   srcCounts{IPs: len(a.IPs), ASNs: len(a.ASNs), Countries: len(a.Countries)},
		First: hhmm(a.FirstSeen), Last: hhmm(a.LastSeen),
		Targets: a.Targets, Hyp: hypotheses(a.Vector), TL: []any{},
	}
}

func (s *Server) handleActors(w http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	list := s.graph.Actors()
	out := make([]webActor, 0, len(list))
	for _, a := range list {
		out = append(out, toWeb(a))
	}
	s.mu.Unlock()
	writeJSON(w, out)
}

func (s *Server) handleActor(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	s.mu.Lock()
	a, ok := s.graph.Get(id)
	var wa webActor
	if ok {
		wa = toWeb(a)
	}
	s.mu.Unlock()
	if !ok {
		http.Error(w, "acteur inconnu", http.StatusNotFound)
		return
	}
	writeJSON(w, wa)
}

// handleCampaigns : une campagne = un acteur multi-sources (plusieurs IP ou pays)
// — un même comportement reproduit par des sources successives (RFC-0004).
// handleCampaigns rend les CAMPAGNES : des groupes d'acteurs partageant le meme
// mode operatoire.
//
// CE QUE CETTE VUE CORRIGE. Elle rendait « les acteurs ayant au moins deux IP »,
// ce qui n'est pas une campagne — c'est un acteur mobile. L'operateur, lui,
// voyait trente-quatre profils rigoureusement identiques (memes cibles, meme
// priorite, meme continuite) et se demandait a juste titre pourquoi ils n'etaient
// pas regroupes.
//
// POURQUOI ON REGROUPE SANS FUSIONNER. Ces trente-quatre profils visent
// `git.gk2` et `gitea.gk2` — des hotes qui EXISTENT. Trente-quatre sources qui
// chassent du Gitea ne sont pas une meme personne : ce peut etre le meme outil
// public lance par trente-quatre inconnus. Les fusionner affirmerait une identite
// que la preuve ne soutient pas — l'erreur que ce moteur refuse de commettre.
// Les REGROUPER dit ce qu'on sait : meme mode operatoire, continuite de campagne
// probable.
//
// LA SIGNATURE EST L'ENSEMBLE DES CIBLES. C'est ce qui distingue un mode
// operatoire : l'enumerateur de sous-domaines recite sa liste, le chasseur de
// Gitea vise deux noms precis. Deux acteurs qui visent exactement le meme jeu
// font la meme chose, quel que soit leur nombre d'adresses.
func signatureCampagne(cibles []string) string {
	tri := append([]string(nil), cibles...)
	sort.Strings(tri)
	h := sha1.Sum([]byte(strings.Join(tri, "\n")))
	return hex.EncodeToString(h[:4])
}

// UN DICTIONNAIRE QUI AVANCE NE SE RÉPÈTE JAMAIS — et c'est ce qui le rendait
// invisible en tant que campagne.
//
// LE DÉFAUT OBSERVÉ. Un énumérateur de sous-domaines tire sa liste dans l'ordre
// alphabétique et la répartit entre ses adresses : l'une voit `tencent, tw,
// user, vip`, la suivante `wanted, wazuh, web-login`. Comme la signature est le
// JEU EXACT des cibles, deux tranches consécutives du MÊME dictionnaire ne
// partagent aucune signature. Une opération unique se présentait donc en 35
// campagnes de 2 à 4 cibles — 237 adresses et 94 noms d'hôtes, éparpillés au
// point qu'aucune ligne ne paraissait grave.
//
// LA CORRECTION. Quand toutes les cibles d'un acteur sont INEXISTANTES et
// partagent un même domaine, ce n'est plus « ce jeu de noms » qui décrit son
// mode opératoire, c'est « réciter un dictionnaire sur ce domaine ». La
// signature devient donc le domaine, et les tranches se rejoignent.
//
// ON REGROUPE TOUJOURS SANS FUSIONNER. Le groupe dit « même mode opératoire »,
// jamais « même personne » — deux inconnus lançant le même outil public sur le
// même domaine feraient exactement cela, et rien ne permet de les distinguer.
// C'est la règle de ce moteur, et elle ne bouge pas.
//
// LA CONDITION EST STRICTE : TOUTES les cibles inexistantes. Une seule cible
// réelle, et l'acteur cherche quelque chose de précis — pas la même chose que
// celui qui récite. Le doute profite à la séparation.
func suffixeDictionnaire(cibles []string, inexistants map[string]bool) (string, bool) {
	if len(cibles) == 0 {
		return "", false
	}
	suffixe := ""
	for _, c := range cibles {
		if !inexistants[c] {
			return "", false // une cible réelle : ce n'est pas une récitation
		}
		// On retire le port éventuel, puis le PREMIER label — celui que le
		// dictionnaire fait varier.
		h := c
		if i := strings.IndexByte(h, ':'); i >= 0 {
			h = h[:i]
		}
		i := strings.IndexByte(h, '.')
		if i < 0 {
			return "", false // pas de domaine parent : rien à regrouper
		}
		parent := h[i+1:]
		// Un suffixe doit rester un domaine : « in » seul regrouperait la
		// moitié de l'internet.
		if strings.Count(parent, ".") < 1 {
			return "", false
		}
		if suffixe == "" {
			suffixe = parent
		} else if suffixe != parent {
			return "", false // deux domaines : pas le même dictionnaire
		}
	}
	return suffixe, suffixe != ""
}

// signatureActeur choisit la bonne signature pour un acteur : celle du
// dictionnaire quand il en récite un, celle du jeu de cibles sinon.
func (s *Server) signatureActeur(cibles []string) string {
	if suf, ok := suffixeDictionnaire(cibles, s.inexistants); ok {
		h := sha1.Sum([]byte("dictionnaire\n" + suf))
		return hex.EncodeToString(h[:4])
	}
	return signatureCampagne(cibles)
}

func (s *Server) handleCampaigns(w http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	type grp struct {
		Signature   string   `json:"signature"`
		Acteurs     []string `json:"acteurs"`
		NbActeurs   int      `json:"nb_acteurs"`
		Sources     int      `json:"sources"`
		Pays        int      `json:"pays"`
		Cibles      []string `json:"cibles"`
		Inexistants int      `json:"cibles_inexistantes"`
		Priorite    int      `json:"priorite"`
		Continuite  int      `json:"continuite"`
		Premier     int64    `json:"premier"`
		Dernier     int64    `json:"dernier"`
	}
	par := map[string]*grp{}
	ips := map[string]map[string]bool{}
	pays := map[string]map[string]bool{}
	vues := map[string]map[string]bool{} // cibles déjà comptées, par groupe
	for _, a := range s.graph.Actors() {
		if len(a.Targets) == 0 {
			continue // sans cible, pas de mode operatoire a comparer
		}
		sig := s.signatureActeur(a.Targets)
		g := par[sig]
		if g == nil {
			g = &grp{Signature: sig, Premier: a.FirstSeen, Dernier: a.LastSeen}
			par[sig] = g
			ips[sig] = map[string]bool{}
			pays[sig] = map[string]bool{}
			vues[sig] = map[string]bool{}
		}
		// LES CIBLES DU GROUPE SONT L'UNION, PAS CELLES DU PREMIER ARRIVÉ.
		// On ne gardait que le jeu du premier acteur : une campagne regroupée
		// n'aurait montré que sa part du dictionnaire — trois noms pour une
		// opération qui en récite quatre-vingt-quatorze.
		for _, t := range a.Targets {
			if !vues[sig][t] {
				vues[sig][t] = true
				// Borne d'affichage : au-delà, la liste ne s'inspecte plus à
				// l'œil et le compteur dit déjà l'ampleur.
				if len(g.Cibles) < 300 {
					g.Cibles = append(g.Cibles, t)
				}
				if s.inexistants[t] {
					g.Inexistants++
				}
			}
		}
		g.Acteurs = append(g.Acteurs, a.ID)
		g.NbActeurs++
		for _, ip := range a.IPs {
			ips[sig][ip] = true
		}
		for _, c := range a.Countries {
			pays[sig][c] = true
		}
		if a.Priority > g.Priorite {
			g.Priorite = a.Priority
		}
		if a.Vector.Continuity > g.Continuite {
			g.Continuite = a.Vector.Continuity
		}
		if a.FirstSeen != 0 && (g.Premier == 0 || a.FirstSeen < g.Premier) {
			g.Premier = a.FirstSeen
		}
		if a.LastSeen > g.Dernier {
			g.Dernier = a.LastSeen
		}
	}
	out := make([]*grp, 0, len(par))
	for sig, g := range par {
		// UNE CAMPAGNE SUPPOSE UNE PLURALITE : soit plusieurs acteurs, soit un
		// acteur qui s'est deplace. Un profil isole n'en est pas une.
		if g.NbActeurs < 2 && len(ips[sig]) < 2 {
			continue
		}
		g.Sources = len(ips[sig])
		g.Pays = len(pays[sig])
		sort.Strings(g.Acteurs)
		out = append(out, g)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].NbActeurs != out[j].NbActeurs {
			return out[i].NbActeurs > out[j].NbActeurs
		}
		return out[i].Signature < out[j].Signature
	})
	s.mu.Unlock()
	writeJSON(w, out)
}

func (s *Server) handleEvidence(w http.ResponseWriter, r *http.Request) {
	if s.ledger == nil {
		http.Error(w, "ledger indisponible", http.StatusServiceUnavailable)
		return
	}
	rec, ok, err := s.ledger.Get(r.PathValue("id"))
	if err != nil {
		http.Error(w, "erreur ledger", http.StatusInternalServerError)
		return
	}
	if !ok {
		http.Error(w, "preuve inconnue", http.StatusNotFound)
		return
	}
	writeJSON(w, rec)
}

// handleFeedback : le feedback opérateur (RFC-0013 §9) est CONSIGNÉ (preuve
// inviolable) mais ne réécrit jamais l'historique ; l'ajustement des poids
// futurs viendra dans une phase de calibration séparée.
func (s *Server) handleFeedback(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	body, _ := io.ReadAll(io.LimitReader(r.Body, 4096))
	var in struct {
		Label string `json:"label"`
	}
	_ = json.Unmarshal(body, &in)
	valid := map[string]bool{"false_positive": true, "confirmed_campaign": true, "known_scanner": true, "unknown": true}
	if !valid[in.Label] {
		http.Error(w, "label invalide", http.StatusUnprocessableEntity)
		return
	}
	if s.ledger != nil {
		_, _ = s.ledger.Append(evidence.Record{
			ID:               "fb-" + id + "-" + time.Now().UTC().Format("20060102T150405"),
			Timestamp:        time.Now().Unix(),
			Sensor:           "operator",
			Observation:      "feedback " + in.Label + " sur " + id,
			Explanation:      "consigné, sans réécriture de l'historique",
			AlgorithmVersion: score.AlgoVersion,
		})
	}
	writeJSON(w, map[string]any{"ok": true, "label": in.Label, "actor": id})
}
