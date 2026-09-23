// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// Package api — la surface HTTP et WebSocket.
package api

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/CyberMind-FR/secubox-deb/gabriel-mood/internal/audio"
	"github.com/CyberMind-FR/secubox-deb/gabriel-mood/internal/ser"
	"github.com/CyberMind-FR/secubox-deb/gabriel-mood/internal/store"
)

// Serveur : l'état partagé des poignées HTTP.
type Serveur struct {
	Sessions *Sessions
	Store    *store.Store
	Version  string
	Racine   http.Handler // les fichiers du cockpit, s'ils sont livrés
}

// Humeur : la réponse de GET /api/mood.
//
// Les quatre champs du contrat (`state`, `confidence`, `pitch`, `energy`,
// `speech_rate`) sont là, à l'identique. Ce qui suit les ACCOMPAGNE — et n'est
// pas décoratif : un chiffre voyage toujours plus loin que la page qui
// l'explique, donc son garde-fou doit voyager avec lui.
type Humeur struct {
	Etat      string  `json:"state"`
	Confiance float64 `json:"confidence"`
	Pitch     float64 `json:"pitch"`
	Energie   float64 `json:"energy"`
	Debit     float64 `json:"speech_rate"`

	Indices    map[string]float64 `json:"indices"`
	Tendances  map[string]float64 `json:"trends"`
	Motif      string             `json:"motif,omitempty"`
	Activation float64            `json:"activation"`
	Jitter     float64            `json:"jitter"`
	Shimmer    float64            `json:"shimmer"`
	PartVoisee float64            `json:"voiced_ratio"`

	Session string `json:"session"`
	// « calibration » garde son nom JSON pour les consommateurs existants,
	// mais ce n'est plus une progression vers un achèvement : c'est la
	// fiabilité de la référence, qui monte sans jamais « finir ».
	Fiabilite    float64           `json:"calibration"`
	Observations int               `json:"observations"`
	Suffisant    bool              `json:"signal_suffisant"`
	Pourquoi     []string          `json:"pourquoi"`
	Reserve      string            `json:"reserve"`
	Source       audio.Description `json:"source"`
	Emoji        string            `json:"emoji"`
}

func ecris(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	// Un indice d'humeur n'a aucune raison d'être mis en cache par un
	// intermédiaire, ni d'être relu plus tard comme s'il était d'actualité.
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

// Routes monte la surface HTTP.
func (s *Serveur) Routes() *http.ServeMux {
	m := http.NewServeMux()
	m.HandleFunc("/api/mood", s.humeur)
	m.HandleFunc("/api/mood/traits", s.traits)
	m.HandleFunc("/api/mood/commun", s.commun)
	m.HandleFunc("/api/mood/historique", s.historique)
	m.HandleFunc("/api/mood/oubli", s.oubli)
	m.HandleFunc("/api/sante", s.sante)
	m.HandleFunc("/ws/mood", s.websocket)
	if s.Racine != nil {
		m.Handle("/", s.Racine)
	}
	return m
}

// GET /api/mood
func (s *Serveur) humeur(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.sessionDemandee(r)
	if !ok {
		// PAS DE SESSION N'EST PAS UNE ERREUR : personne n'écoute, c'est tout.
		// Rendre 404 ferait croire à une panne ; rendre un état ferait croire
		// à une mesure.
		ecris(w, http.StatusOK, Humeur{
			Etat: ser.Indetermine, Emoji: ser.Emoji[ser.Indetermine],
			Indices: map[string]float64{},
			Pourquoi: []string{"aucune session nommée : précisez ?session=<id>, " +
				"celui que la WebSocket vous a remis à l'ouverture"},
			Reserve: ser.Reserve,
			Source:  audio.Description{Genre: "absente", Detail: "aucun navigateur connecté"},
		})
		return
	}
	lec := sess.Analyseur.Lecture()
	t := sess.Analyseur.Traits()
	img := sess.Analyseur.Derniere()
	ecris(w, http.StatusOK, Humeur{
		Etat: lec.Etat, Confiance: lec.Confiance,
		Pitch: img.Pitch, Energie: img.Energie, Debit: t.Debit,
		Indices: lec.Indices, Tendances: img.Tendances, Motif: lec.Motif,
		Activation: lec.Activation,
		Jitter:     t.Jitter, Shimmer: t.Shimmer, PartVoisee: t.PartVoisee,
		Session: sess.ID, Fiabilite: img.Fiabilite, Observations: img.Observations, Suffisant: lec.Suffisant,
		Pourquoi: lec.Pourquoi, Reserve: ser.Reserve,
		Source: sess.Analyseur.Source(), Emoji: ser.Emoji[lec.Etat],
	})
}

// GET /api/mood/traits — les mesures BRUTES, sans interprétation.
//
// Elle existe pour qu'on puisse contester la lecture : qui trouve le verdict
// douteux peut regarder ce sur quoi il repose. Une boîte noire qu'on ne peut
// pas ouvrir n'a pas sa place ici.
func (s *Serveur) traits(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.sessionDemandee(r)
	if !ok {
		ecris(w, http.StatusOK, map[string]any{"session": nil})
		return
	}
	ecris(w, http.StatusOK, map[string]any{
		"session":  sess.ID,
		"traits":   sess.Analyseur.Traits(),
		"lecture":  sess.Analyseur.Lecture(),
		"source":   sess.Analyseur.Source(),
		"depuis_s": time.Since(sess.Debut).Seconds(),
	})
}

// GET /api/mood/historique?heures=24
func (s *Serveur) historique(w http.ResponseWriter, r *http.Request) {
	if s.Store == nil {
		ecris(w, http.StatusOK, map[string]any{"resumes": []any{}, "actif": false})
		return
	}
	heures := 24
	if v := r.URL.Query().Get("heures"); v != "" {
		if n := atoiBorne(v, 1, 24*30); n > 0 {
			heures = n
		}
	}
	res, err := s.Store.Depuis(time.Now().Add(-time.Duration(heures)*time.Hour), 5000)
	if err != nil {
		ecris(w, http.StatusInternalServerError, map[string]string{"erreur": err.Error()})
		return
	}
	ecris(w, http.StatusOK, map[string]any{"resumes": res, "actif": true})
}

// POST /api/mood/oubli — « oubliez-moi ».
//
// Sans session nommée, efface TOUT l'historique. Ce geste doit être simple :
// s'il faut chercher comment faire, il n'existe pas vraiment.
func (s *Serveur) oubli(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		ecris(w, http.StatusMethodNotAllowed, map[string]string{"erreur": "POST attendu"})
		return
	}
	if s.Store == nil {
		ecris(w, http.StatusOK, map[string]any{"efface": 0, "detail": "aucun historique n'est tenu"})
		return
	}
	var n int64
	var err error
	if id := r.URL.Query().Get("session"); id != "" {
		n, err = s.Store.OublieSession(id)
	} else {
		n, err = s.Store.Tout()
	}
	if err != nil {
		ecris(w, http.StatusInternalServerError, map[string]string{"erreur": err.Error()})
		return
	}
	ecris(w, http.StatusOK, map[string]any{"efface": n})
}

// GET /api/sante
func (s *Serveur) sante(w http.ResponseWriter, r *http.Request) {
	peripheriques, motif := audio.EntreesDisponibles()
	ecris(w, http.StatusOK, map[string]any{
		"version":           s.Version,
		"sessions":          s.Sessions.Nombre(),
		"historique":        s.Store != nil,
		"entrees_locales":   peripheriques,
		"entrees_motif":     motif,
		"echantillonnage":   audio.Echantillonnage,
		"classifieur":       "heuristique-prosodique-v1",
		"plafond_confiance": ser.PlafondConfiance,
		"reserve":           ser.Reserve,
	})
}

// sessionDemandee : la session NOMMÉE, et elle seule.
//
// ELLE RENDAIT « LA PLUS RÉCEMMENT ACTIVE » QUAND AUCUNE N'ÉTAIT NOMMÉE, et
// c'était une fuite. Sur un réseau local avec une seule personne, la commodité
// ne coûtait rien. Exposé au WAN, `GET /api/mood` livrait à n'importe quel
// passant la lecture de qui était en train d'utiliser la page — hauteur,
// débit, état, en temps réel. C'est précisément le genre de donnée dont tout
// ce module s'applique à dire qu'elle ne doit servir à évaluer personne.
//
// L'identifiant de session n'est connu que de celui à qui la WebSocket l'a
// remis. Sans lui, on répond « aucune session », ce qui est vrai du point de
// vue de l'appelant : il n'en a aucune.
//
// Le contrat annoncé n'en souffre pas — le cockpit et la carte se nourrissent
// du flux, pas de cette route — et `/api/mood?session=…` reste exactement ce
// qu'il a toujours été pour qui la possède.
func (s *Serveur) sessionDemandee(r *http.Request) (*Session, bool) {
	if id := r.URL.Query().Get("session"); id != "" {
		return s.Sessions.Par(id)
	}
	return nil, false
}

func atoiBorne(s string, min, max int) int {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0
		}
		n = n*10 + int(c-'0')
		if n > max {
			return max
		}
	}
	if n < min {
		return min
	}
	return n
}
