// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package main

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"net/http"

	"github.com/CyberMind-FR/secubox-deb/secubox-toolbox-ng/internal/actor/graph"
)

// VUE RÉDUITE PAR DÉFAUT (#1608).
//
// L'API sert deux publics par le même socket : la console d'administration, qui
// a besoin de tout (services visés, preuves, feedback), et les relais de lecture
// grand public (le Hall), qui n'ont besoin que de la forme d'une menace — sa
// priorité, son vecteur, le nombre de ses sources.
//
// LA VUE RÉDUITE EST LE DÉFAUT. La vue complète n'est servie que si deux
// conditions sont réunies :
//
//  1. la requête arrive à la RACINE (/actors, /campaigns…), sans le préfixe
//     /api/v1/actor : c'est le chemin de l'agrégateur, qui retire le préfixe ;
//  2. elle porte exactement `X-Sbx-Vue: complete` — une seule valeur, en
//     minuscules. C'est la route qui le pose avec `proxy_set_header` ou son
//     équivalent, jamais le visiteur : l'agrégateur, et lui seul, après sa
//     garde d'administration (#1581). Les consoles admin.gk2 et actor.gk2
//     passent toutes deux par lui.
//
// Tout le reste reçoit la vue réduite : en-tête absent, vide, mal écrit ou en
// double. Un relais qui oublie l'en-tête, ou qui le vide, ne rouvre rien — une
// valeur vide côté nginx (`proxy_set_header X-Sbx-Vue "";`) n'envoie même pas
// l'en-tête. Le Hall peut poser `X-Sbx-Vue: reduite` : c'est la même vue.
//
// L'ARBRE PRÉFIXÉ /api/v1/actor/… NE SERT QUE LA VUE RÉDUITE, quel que soit
// l'en-tête. C'est celui des relais qui recopient le chemin tel quel (le Hall) :
// un en-tête que le client ferait passer par un tel relais n'y change rien.
//
// LA RÈGLE EST UNE LISTE BLANCHE. La vue réduite ne retire pas des champs de la
// vue complète : elle en recopie quelques-uns, nommés un par un. Un champ ajouté
// demain à webActor ou à une campagne n'apparaît dans la vue réduite que si
// quelqu'un décide de l'y mettre.
//
// CE QUI N'Y FIGURE JAMAIS : les cibles (noms d'hôtes et adresses de la box que
// visent les acteurs), toute adresse IP, toute référence de preuve. /evidence et
// /feedback n'existent pas dans cette vue : 404, comme une route inconnue.

const (
	// enteteVue est l'en-tête par lequel la route relayante choisit la vue.
	enteteVue = "X-Sbx-Vue"
	// valeurComplete est la seule valeur qui ouvre la vue complète, à la racine.
	valeurComplete = "complete"
)

// cleArbreRelais marque, dans le contexte d'une requête, une route de l'arbre
// préfixé.
type cleArbreRelais struct{}

// arbreRelais réserve une route de l'arbre préfixé à la vue réduite.
func arbreRelais(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		h(w, r.WithContext(context.WithValue(r.Context(), cleArbreRelais{}, true)))
	}
}

// vueReduite dit si la requête reçoit la vue réduite : toujours, sauf à la
// racine avec exactement `X-Sbx-Vue: complete`. Le doute profite à la vue
// réduite.
func vueReduite(r *http.Request) bool {
	if relais, _ := r.Context().Value(cleArbreRelais{}).(bool); relais {
		return true
	}
	v := r.Header.Values(enteteVue)
	return len(v) != 1 || v[0] != valeurComplete
}

// horsVueReduite réserve une route à la vue complète : dans la vue réduite elle
// répond exactement comme une route qui n'existe pas.
func horsVueReduite(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if vueReduite(r) {
			http.NotFound(w, r)
			return
		}
		h(w, r)
	}
}

// webActorReduit est la projection d'un acteur dans la vue réduite. Liste
// blanche : ni cibles, ni chronologie (qui portera des références de preuve),
// seulement des compteurs et le vecteur.
type webActorReduit struct {
	ID       string       `json:"id"`
	Priority int          `json:"priority"`
	Level    string       `json:"level"`
	Tags     [][2]string  `json:"tags"`
	Vec      graph.Vector `json:"vec"`
	Src      srcCounts    `json:"src"`
	First    string       `json:"first"`
	Last     string       `json:"last"`
	// NbCibles dit l'ampleur de ce qui est visé sans dire quoi.
	NbCibles int      `json:"nb_cibles"`
	Bans     int      `json:"bans"`
	Hyp      [][2]any `json:"hyp"`
}

func toWebReduit(a *graph.Actor) webActorReduit {
	return webActorReduit{
		ID: a.ID, Priority: a.Priority, Level: niveau(a.Priority),
		Tags: tags(a.Vector), Vec: a.Vector,
		Src:   srcCounts{IPs: len(a.IPs), ASNs: len(a.ASNs), Countries: len(a.Countries)},
		First: hhmm(a.FirstSeen), Last: hhmm(a.LastSeen),
		NbCibles: len(a.Targets), Bans: a.Bans, Hyp: hypotheses(a.Vector),
	}
}

// campagneReduite est la projection d'une campagne dans la vue réduite. La
// signature y est remplacée par un identifiant opaque (voir signatureOpaque) :
// la signature complète est calculée sur les noms visés.
type campagneReduite struct {
	Signature   string   `json:"signature"`
	Acteurs     []string `json:"acteurs"`
	NbActeurs   int      `json:"nb_acteurs"`
	Sources     int      `json:"sources"`
	Pays        int      `json:"pays"`
	NbCibles    int      `json:"nb_cibles"`
	Inexistants int      `json:"cibles_inexistantes"`
	Priorite    int      `json:"priorite"`
	Continuite  int      `json:"continuite"`
	Premier     int64    `json:"premier"`
	Dernier     int64    `json:"dernier"`
}

func (s *Server) campagneReduite(c *campagne) campagneReduite {
	return campagneReduite{
		Signature: s.signatureOpaque(c.Signature),
		Acteurs:   c.Acteurs, NbActeurs: c.NbActeurs,
		Sources: c.Sources, Pays: c.Pays,
		NbCibles: c.nbCibles, Inexistants: c.Inexistants,
		Priorite: c.Priorite, Continuite: c.Continuite,
		Premier: c.Premier, Dernier: c.Dernier,
	}
}

// signatureOpaque rend un identifiant de groupe stable le temps du processus,
// qui ne permet pas de retrouver ni de confirmer les noms visés : HMAC de la
// signature complète sous une clé tirée au hasard au premier usage, jamais
// écrite nulle part.
func (s *Server) signatureOpaque(sig string) string {
	s.cleVueOnce.Do(func() {
		s.cleVue = make([]byte, 32)
		if _, err := rand.Read(s.cleVue); err != nil {
			// Sans aléa, aucune clé fiable : on ne sert pas d'identifiant
			// dérivé des noms visés, on en sert un vide.
			s.cleVue = nil
		}
	})
	if s.cleVue == nil {
		return ""
	}
	m := hmac.New(sha256.New, s.cleVue)
	m.Write([]byte(sig))
	return hex.EncodeToString(m.Sum(nil)[:4])
}
