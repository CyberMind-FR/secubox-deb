// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// See LICENCE-CMSD-1.0.md for terms.

package main

import (
	"net"
	"net/http"
	"sort"
	"time"

	"github.com/CyberMind-FR/secubox-deb/secubox-toolbox-ng/internal/actor/analysis"
	"github.com/CyberMind-FR/secubox-deb/secubox-toolbox-ng/internal/actor/graph"
)

// RADAR DES ACTEURS (Actor Intelligence 2.0, phase 5, #2240) : la synthèse que le Hall affiche — pour chaque acteur suivi, son risque et sa confiance
// SÉPARÉS avec leurs facteurs, le niveau de décision proposé et les étapes de son scénario. Servie aussi dans la vue réduite (c'est la vue du Hall) :
// d'où une liste blanche stricte — ni adresse, ni cible, ni référence de preuve, ni identifiant d'événement. Les routes détaillées (/actors/{id}/risk,
// /timeline, /graph) restent réservées à la vue complète.
const (
	radarTTL        = 15 * time.Second
	radarLimiteDef  = 30
	radarLimiteMax  = 100
	radarPopulation = 200 // acteurs évalués au plus : l'évaluation relit les événements de chacun
)

type radarFacteur struct {
	Libelle string `json:"libelle"`
	Points  int    `json:"points"`
}

type radarScore struct {
	Valeur   int            `json:"valeur"`
	Facteurs []radarFacteur `json:"facteurs"`
}

type radarEtape struct {
	Etape      analysis.Etape `json:"etape"`
	Libelle    string         `json:"libelle"`
	Evenements int            `json:"evenements"`
	Capteurs   []string       `json:"capteurs"`
}

type radarActeur struct {
	ID         string       `json:"id"`
	Risque     radarScore   `json:"risque"`
	Confiance  radarScore   `json:"confiance"`
	Niveau     string       `json:"niveau"`
	Action     string       `json:"action_proposee"`
	Raisons    []string     `json:"raisons"`
	Refus      []string     `json:"refus,omitempty"`
	Etapes     []radarEtape `json:"etapes"`
	Scenario   string       `json:"scenario"`
	Capteurs   []string     `json:"capteurs"`
	Evenements int          `json:"evenements"`
	Mesure     *mesureVue   `json:"mesure,omitempty"` // la mesure en cours (cran et durée restante), sans adresse
}

func projeterScore(sc analysis.Score) radarScore {
	out := radarScore{Valeur: sc.Valeur, Facteurs: make([]radarFacteur, 0, len(sc.Facteurs))}
	for _, f := range sc.Facteurs {
		out.Facteurs = append(out.Facteurs, radarFacteur{Libelle: f.Libelle, Points: f.Points})
	}
	return out
}

// evalActeur : un acteur évalué (analyse complète), avec ce dont l'échelle de réponse a besoin en plus.
type evalActeur struct {
	Acteur   graph.Actor
	Ev       analysis.Evaluation
	Hostiles int // événements hostiles (gravité ≥ 40) cumulés
	// HostilesIP : événements hostiles des dernières 24 h, PAR adresse — la preuve individuelle sur laquelle une mesure s'appuie.
	HostilesIP map[string]int
	LAN        bool // toutes ses adresses sont privées
}

// evaluerActeurs évalue les acteurs les plus prioritaires. UN SEUL calcul pour le radar et pour les mesures : ils ne peuvent pas diverger.
func (s *Server) evaluerActeurs(now int64) ([]evalActeur, error) {
	s.mu.Lock()
	tous := s.graph.Actors()
	sort.Slice(tous, func(i, j int) bool { return tous[i].Priority > tous[j].Priority })
	if len(tous) > radarPopulation {
		tous = tous[:radarPopulation]
	}
	copies := make([]graph.Actor, 0, len(tous))
	for _, a := range tous {
		c := *a // le graphe vivant n'est jamais lu hors verrou
		c.IPs = append([]string(nil), a.IPs...)
		copies = append(copies, c)
	}
	s.mu.Unlock()

	evs, err := s.evenements()
	if err != nil {
		return nil, err
	}
	parIP := map[string][]analysis.Event{}
	for _, e := range evs {
		if _, robot := estRobotConnu(&e); robot {
			continue
		}
		parIP[e.SrcIP] = append(parIP[e.SrcIP], projeter(e))
	}
	out := make([]evalActeur, 0, len(copies))
	for _, c := range copies {
		var mine []analysis.Event
		for _, ip := range c.IPs {
			mine = append(mine, parIP[ip]...)
		}
		if len(mine) == 0 {
			continue
		}
		sort.Slice(mine, func(i, j int) bool { return mine[i].TS < mine[j].TS })
		hostiles := 0
		parAdresse := map[string]int{}
		for _, e := range mine {
			if e.Severity >= 40 {
				hostiles++
				if e.TS >= now-86400 {
					parAdresse[e.SrcIP]++
				}
			}
		}
		out = append(out, evalActeur{Acteur: c, Ev: analysis.Evaluer(analysis.Entree{Events: mine, Vecteur: c.Vector, Maintenant: now}), Hostiles: hostiles, HostilesIP: parAdresse, LAN: toutesPrivees(c.IPs)})
	}
	return out, nil
}

// toutesPrivees : l'acteur n'a que des adresses privées, de boucle locale ou de lien local — un appareil du réseau, pas un attaquant venu d'internet.
func toutesPrivees(ips []string) bool {
	if len(ips) == 0 {
		return false
	}
	for _, s := range ips {
		p := net.ParseIP(s)
		if p == nil || !(p.IsPrivate() || p.IsLoopback() || p.IsLinkLocalUnicast()) {
			return false
		}
	}
	return true
}

// calculerRadar : la synthèse du radar (double tampon : jamais sur le chemin d'une requête plus d'une fois par radarTTL).
func (s *Server) calculerRadar() ([]radarActeur, error) {
	evalues, err := s.evaluerActeurs(time.Now().Unix())
	if err != nil {
		return nil, err
	}
	out := make([]radarActeur, 0, len(evalues))
	for _, x := range evalues {
		ev := x.Ev
		ra := radarActeur{ID: x.Acteur.ID, Risque: projeterScore(ev.Risque), Confiance: projeterScore(ev.Confiance), Niveau: ev.Decision.Niveau,
			Action: ev.Decision.Action, Raisons: ev.Decision.Raisons, Refus: ev.Decision.Refus, Scenario: ev.Scenario.Libelle,
			Capteurs: ev.Capteurs, Evenements: ev.Evenements, Mesure: s.mesureDe(x.Acteur.ID)}
		for _, st := range ev.Scenario.Etapes {
			ra.Etapes = append(ra.Etapes, radarEtape{Etape: st.Etape, Libelle: st.Libelle, Evenements: st.Evenements, Capteurs: st.Capteurs})
		}
		out = append(out, ra)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Risque.Valeur > out[j].Risque.Valeur })
	return out, nil
}

func (s *Server) handleRadar(w http.ResponseWriter, r *http.Request) {
	liste, err := s.radarT.lire(radarTTL, s.calculerRadar)
	if err != nil {
		http.Error(w, "radar indisponible", http.StatusServiceUnavailable)
		return
	}
	lim := radarLimiteDef
	if n := limiteDe(r); r.URL.Query().Get("limit") != "" {
		lim = min(n, radarLimiteMax)
	}
	if len(liste) > lim {
		liste = liste[:lim]
	}
	writeJSON(w, map[string]any{"genere_le": time.Now().Unix(), "politique": analysis.VersionPolitique, "acteurs": liste})
}
