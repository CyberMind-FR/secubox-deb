// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package main

import (
	"net/http"
	"sort"
	"time"

	"github.com/CyberMind-FR/secubox-deb/secubox-toolbox-ng/internal/actor/envelope"
	"github.com/CyberMind-FR/secubox-deb/secubox-toolbox-ng/internal/actor/graph"
)

// Aperçu (vue d'ensemble de la carte du Hall) : pays d'origine, derniers événements, activité sur 24 h, techniques par acteur.
// RIEN d'identifiant : ni adresse IP, ni cible, ni chemin — des compteurs et des noms de règles. Servi dans la vue réduite.

const (
	apercuEchantillon = 5000 // derniers événements examinés
	apercuRecents     = 8
	apercuPays        = 8
	apercuTechniques  = 4
)

type PaysN struct {
	Code string `json:"code"`
	N    int    `json:"n"`
}

type EvenementRecent struct {
	Ts     int64  `json:"ts"`
	Heure  string `json:"heure"`
	Acteur string `json:"acteur"`
	Type   string `json:"type"`
	Module string `json:"module"`
	Score  int    `json:"score"`
}

type Technique struct {
	Nom string `json:"nom"`
	N   int    `json:"n"`
}

type Apercu struct {
	GenereLe    int64                  `json:"genere_le"`
	Echantillon int                    `json:"echantillon"`
	TopPays     []PaysN                `json:"top_pays"`
	Recents     []EvenementRecent      `json:"recents"`
	Activite24h []int                  `json:"activite_24h"` // 24 compartiments d'une heure ; le dernier est l'heure en cours
	Techniques  map[string][]Technique `json:"techniques"`
	// ActiviteActeurs : même découpage que Activite24h, par acteur (seulement ceux qui ont de l'activité sur la période).
	ActiviteActeurs map[string][]int `json:"activite_acteurs"`
}

func typeEvenement(e envelope.Envelope) string {
	switch {
	case e.RuleID != "":
		return e.RuleID
	case e.UserAgentFamily != "":
		return "outil " + e.UserAgentFamily
	case e.Protocol != "":
		return e.Protocol
	}
	return e.Sensor
}

// apercu calcule la vue d'ensemble à partir des derniers événements (du plus récent au plus ancien) et des acteurs du graphe.
func apercu(evs []envelope.Envelope, acteurs []*graph.Actor, now int64) Apercu {
	parIP := map[string]string{}
	for _, a := range acteurs {
		for _, ip := range a.IPs {
			parIP[ip] = a.ID
		}
	}
	out := Apercu{GenereLe: now, Echantillon: len(evs), TopPays: []PaysN{}, Recents: []EvenementRecent{},
		Activite24h: make([]int, 24), Techniques: map[string][]Technique{}, ActiviteActeurs: map[string][]int{}}
	pays := map[string]int{}
	tech := map[string]map[string]int{}
	for i, e := range evs {
		if e.GeoCountry != "" {
			pays[e.GeoCountry]++
		}
		if ago := now - e.Timestamp; ago >= 0 && ago < 86400 {
			out.Activite24h[23-int(ago/3600)]++
		}
		id := parIP[e.SrcIP]
		if ago := now - e.Timestamp; id != "" && ago >= 0 && ago < 86400 {
			if out.ActiviteActeurs[id] == nil {
				out.ActiviteActeurs[id] = make([]int, 24)
			}
			out.ActiviteActeurs[id][23-int(ago/3600)]++
		}
		if i < apercuRecents {
			out.Recents = append(out.Recents, EvenementRecent{Ts: e.Timestamp, Heure: hhmm(e.Timestamp), Acteur: id,
				Type: typeEvenement(e), Module: e.Sensor, Score: e.Severity})
		}
		if id != "" {
			if tech[id] == nil {
				tech[id] = map[string]int{}
			}
			tech[id][typeEvenement(e)]++
		}
	}
	for c, n := range pays {
		out.TopPays = append(out.TopPays, PaysN{Code: c, N: n})
	}
	sort.Slice(out.TopPays, func(i, j int) bool {
		if out.TopPays[i].N != out.TopPays[j].N {
			return out.TopPays[i].N > out.TopPays[j].N
		}
		return out.TopPays[i].Code < out.TopPays[j].Code
	})
	if len(out.TopPays) > apercuPays {
		out.TopPays = out.TopPays[:apercuPays]
	}
	for id, m := range tech {
		var l []Technique
		for nom, n := range m {
			l = append(l, Technique{Nom: nom, N: n})
		}
		sort.Slice(l, func(i, j int) bool {
			if l[i].N != l[j].N {
				return l[i].N > l[j].N
			}
			return l[i].Nom < l[j].Nom
		})
		if len(l) > apercuTechniques {
			l = l[:apercuTechniques]
		}
		out.Techniques[id] = l
	}
	return out
}

func (s *Server) handleApercu(w http.ResponseWriter, _ *http.Request) {
	evs, err := s.store.Recent(apercuEchantillon)
	if err != nil {
		http.Error(w, "aperçu indisponible", http.StatusInternalServerError)
		return
	}
	s.mu.Lock()
	acteurs := s.graph.Actors()
	s.mu.Unlock()
	writeJSON(w, apercu(evs, acteurs, time.Now().Unix()))
}
