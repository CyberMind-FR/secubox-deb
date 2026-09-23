// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package api

import (
	"math"
	"net/http"
	"sort"
	"time"

	"github.com/CyberMind-FR/secubox-deb/gabriel-mood/internal/ser"
	"github.com/CyberMind-FR/secubox-deb/gabriel-mood/internal/store"
)

// LE RÉSUMÉ : ce que des heures de mesures donnent, en quelques lignes.
//
// L'historique brut rend une ligne par minute. Mille quatre cents lignes pour
// une journée, c'est une matière première, pas une réponse : personne ne lit
// mille quatre cents lignes, et un graphique qui les affiche toutes montre du
// bruit. Ce fichier en tire ce qu'on peut honnêtement en dire.
//
// ── CE QU'ON REGARDE, ET CE QU'ON REFUSE DE REGARDER ───────────────────────
//
// On agrège PAR HEURE et l'on compare la première moitié de la période à la
// seconde : c'est la comparaison la plus grossière possible, et c'est
// précisément pour cela qu'elle tient. Une régression sur des indices
// prosodiques bruités donnerait une pente avec trois décimales dont aucune
// n'aurait de sens.
//
// ON NE PRÉDIT RIEN, et il faut le dire parce que la tentation est immédiate :
// « la tension monte depuis trois heures » invite à extrapoler, et rien dans
// ces mesures ne permet d'extrapoler quoi que ce soit. On décrit ce qui a été
// mesuré, au passé.
//
// ON NE COMPARE PAS LES JOURS ENTRE EUX non plus : parler dans une réunion et
// parler seul n'ont pas la même prosodie, et l'agenda explique ces écarts bien
// mieux que l'humeur.

// Heure : une heure d'observation, résumée.
type Heure struct {
	Debut      int64   `json:"debut"`
	Minutes    int     `json:"minutes"` // combien de minutes ont porté de la voix
	Etat       string  `json:"etat"`    // l'état le plus fréquent
	Activation float64 `json:"activation"`
	F0         float64 `json:"f0"`
	Energie    float64 `json:"energie"`
	Debit      float64 `json:"debit"`
}

// Evolution : le résumé complet.
type Evolution struct {
	Depuis      int64              `json:"depuis"`
	Heures      []Heure            `json:"heures"`
	MinutesVoix int                `json:"minutes_voix"`
	Repartition map[string]float64 `json:"repartition"` // part de chaque état
	Dominant    string             `json:"dominant"`
	Tendance    map[string]float64 `json:"tendance"` // seconde moitié moins première
	Detail      string             `json:"detail"`
	Reserve     string             `json:"reserve"`
}

// GET /api/mood/evolution?heures=24&session=…
func (s *Serveur) evolution(w http.ResponseWriter, r *http.Request) {
	if s.Store == nil {
		ecris(w, http.StatusOK, Evolution{
			Detail: "aucun historique n'est tenu sur cette board", Reserve: ser.Reserve})
		return
	}
	n := 24
	if v := r.URL.Query().Get("heures"); v != "" {
		if k := atoiBorne(v, 1, 24*30); k > 0 {
			n = k
		}
	}
	depuis := time.Now().Add(-time.Duration(n) * time.Hour)
	lignes, err := s.Store.Depuis(depuis, 10000)
	if err != nil {
		ecris(w, http.StatusInternalServerError, map[string]string{"erreur": err.Error()})
		return
	}
	// UNE SESSION NOMMÉE, OU RIEN. Même règle que /api/mood : sans clé, on ne
	// livre pas l'historique de quelqu'un d'autre.
	if id := r.URL.Query().Get("session"); id != "" {
		garde := lignes[:0]
		for _, l := range lignes {
			if l.Session == id {
				garde = append(garde, l)
			}
		}
		lignes = garde
	} else if len(lignes) > 0 {
		ecris(w, http.StatusOK, Evolution{
			Depuis: depuis.Unix(), Reserve: ser.Reserve,
			Detail: "précisez ?session=<id> : l'historique d'une personne ne se " +
				"livre pas à qui ne le possède pas"})
		return
	}

	ev := Evolution{Depuis: depuis.Unix(), Reserve: ser.Reserve,
		Repartition: map[string]float64{}, Tendance: map[string]float64{}}
	if len(lignes) == 0 {
		ev.Detail = "aucune minute de voix sur la période"
		ecris(w, http.StatusOK, ev)
		return
	}

	parHeure := map[int64][]store.Resume{}
	compte := map[string]int{}
	for _, l := range lignes {
		h := l.Minute - l.Minute%3600
		parHeure[h] = append(parHeure[h], l)
		if l.Etat != "" && l.Etat != ser.Indetermine {
			compte[l.Etat]++
			ev.MinutesVoix++
		}
	}

	cles := make([]int64, 0, len(parHeure))
	for k := range parHeure {
		cles = append(cles, k)
	}
	sort.Slice(cles, func(i, j int) bool { return cles[i] < cles[j] })
	for _, k := range cles {
		g := parHeure[k]
		h := Heure{Debut: k, Minutes: len(g)}
		freq := map[string]int{}
		for _, l := range g {
			h.Activation += l.Activation
			h.F0 += l.F0Median
			h.Energie += l.Energie
			h.Debit += l.Debit
			if l.Etat != "" && l.Etat != ser.Indetermine {
				freq[l.Etat]++
			}
		}
		m := float64(len(g))
		h.Activation = arrondi3(h.Activation / m)
		h.F0 = arrondi3(h.F0 / m)
		h.Energie = arrondi3(h.Energie / m)
		h.Debit = math.Round(h.Debit / m)
		// L'état le plus fréquent, départagé par nom : sans tri déterministe,
		// deux états à égalité feraient clignoter le résumé d'un appel à
		// l'autre sans que rien n'ait bougé.
		meilleur, nom := 0, ""
		noms := make([]string, 0, len(freq))
		for e := range freq {
			noms = append(noms, e)
		}
		sort.Strings(noms)
		for _, e := range noms {
			if freq[e] > meilleur {
				meilleur, nom = freq[e], e
			}
		}
		h.Etat = nom
		ev.Heures = append(ev.Heures, h)
	}

	if ev.MinutesVoix > 0 {
		meilleur := 0
		noms := make([]string, 0, len(compte))
		for e := range compte {
			noms = append(noms, e)
		}
		sort.Strings(noms)
		for _, e := range noms {
			ev.Repartition[e] = arrondi3(float64(compte[e]) / float64(ev.MinutesVoix))
			if compte[e] > meilleur {
				meilleur, ev.Dominant = compte[e], e
			}
		}
	}

	// LA TENDANCE : seconde moitié moins première. Grossier, et c'est voulu —
	// une pente à trois décimales sur des indices bruités n'aurait aucun sens.
	if len(ev.Heures) >= 4 {
		mi := len(ev.Heures) / 2
		avant, apres := moyenneHeures(ev.Heures[:mi]), moyenneHeures(ev.Heures[mi:])
		ev.Tendance["activation"] = arrondi3(apres.Activation - avant.Activation)
		ev.Tendance["f0"] = arrondi3(apres.F0 - avant.F0)
		ev.Tendance["energie"] = arrondi3(apres.Energie - avant.Energie)
		ev.Tendance["debit"] = math.Round(apres.Debit - avant.Debit)
		ev.Detail = "comparaison grossière entre les deux moitiés de la période. " +
			"Aucune prédiction : on décrit ce qui a été mesuré, au passé."
	} else {
		ev.Detail = "pas assez d'heures observées pour dégager une tendance"
	}
	ecris(w, http.StatusOK, ev)
}

func moyenneHeures(h []Heure) Heure {
	var out Heure
	if len(h) == 0 {
		return out
	}
	for _, x := range h {
		out.Activation += x.Activation
		out.F0 += x.F0
		out.Energie += x.Energie
		out.Debit += x.Debit
	}
	n := float64(len(h))
	out.Activation /= n
	out.F0 /= n
	out.Energie /= n
	out.Debit /= n
	return out
}

func arrondi3(v float64) float64 { return math.Round(v*1000) / 1000 }
