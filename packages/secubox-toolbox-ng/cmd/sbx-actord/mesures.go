// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>

package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/CyberMind-FR/secubox-deb/secubox-toolbox-ng/internal/actor/mesure"
)

// ÉCHELLE DE RÉPONSE (#2274). actord décide le cran de chaque acteur (internal/actor/mesure) et PUBLIE les mesures actives ; sbxwaf les applique. Les crans
// sont les six du moteur de réponse : OBSERVE → DELAY → CHALLENGE → TARPIT → DENY, et QUARANTINE pour un appareil du LAN (isolement par le NAC).

// MesureActeur est une mesure active, avec la preuve de pourquoi.
type MesureActeur struct {
	Actor     string        `json:"actor"`
	IPs       []string      `json:"ips"`
	Niveau    mesure.Niveau `json:"niveau"`
	TTLs      int64         `json:"ttl_s"`
	Depuis    int64         `json:"depuis"`
	Expire    int64         `json:"expire"`
	Risque    int           `json:"risque"`
	Confiance int           `json:"confiance"`
	Capteurs  []string      `json:"capteurs"`
	Hostiles  int           `json:"hostiles"`
	LAN       bool          `json:"lan"`
	Raison    string        `json:"raison"`
}

// FichierMesures est ce que lit sbxwaf : daté, pour qu'il ignore un fichier périmé.
type FichierMesures struct {
	GenereLe int64          `json:"genere_le"`
	Shadow   bool           `json:"shadow"`
	Mesures  []MesureActeur `json:"mesures"`
}

// mesureVue : ce que la vue réduite montre d'une mesure — le cran et le temps restant, jamais une adresse.
type mesureVue struct {
	Niveau mesure.Niveau `json:"niveau"`
	Reste  int64         `json:"reste_s"`
}

type etatsMesures struct {
	mu      sync.Mutex
	etats   map[string]mesure.Etat
	courant []MesureActeur
}

// recalculerMesures évalue les acteurs, choisit le cran de chacun (avec l'état du tour précédent) et rend les mesures ACTIVES (OBSERVE exclu).
func (s *Server) recalculerMesures(now int64) ([]MesureActeur, error) {
	evalues, err := s.evaluerActeurs(now)
	if err != nil {
		return nil, err
	}
	s.mes.mu.Lock()
	defer s.mes.mu.Unlock()
	if s.mes.etats == nil {
		s.mes.etats = map[string]mesure.Etat{}
	}
	vus := map[string]bool{}
	var out []MesureActeur
	for _, x := range evalues {
		id := x.Acteur.ID
		vus[id] = true
		var prev *mesure.Etat
		if e, ok := s.mes.etats[id]; ok {
			prev = &e
		}
		m, st := mesure.Choisir(mesure.Entree{Risque: x.Ev.Risque.Valeur, Confiance: x.Ev.Confiance.Valeur, Capteurs: len(x.Ev.Capteurs), Hostiles: x.Hostiles, LAN: x.LAN}, prev, now)
		s.mes.etats[id] = st
		if m.Niveau == mesure.Observe {
			continue
		}
		out = append(out, MesureActeur{Actor: id, IPs: append([]string(nil), x.Acteur.IPs...), Niveau: m.Niveau, TTLs: int64(m.TTL.Seconds()), Depuis: st.Depuis, Expire: st.Expire,
			Risque: x.Ev.Risque.Valeur, Confiance: x.Ev.Confiance.Valeur, Capteurs: x.Ev.Capteurs, Hostiles: x.Hostiles, LAN: x.LAN, Raison: m.Raison})
	}
	for id := range s.mes.etats { // un acteur sorti de la population évaluée n'a plus d'état
		if !vus[id] {
			delete(s.mes.etats, id)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Risque > out[j].Risque })
	s.mes.courant = out
	return out, nil
}

// mesureDe : la mesure en cours d'un acteur, pour le radar (vue réduite).
func (s *Server) mesureDe(id string) *mesureVue {
	s.mes.mu.Lock()
	defer s.mes.mu.Unlock()
	for _, m := range s.mes.courant {
		if m.Actor == id {
			return &mesureVue{Niveau: m.Niveau, Reste: max(0, m.Expire-time.Now().Unix())}
		}
	}
	return nil
}

// publierMesuresUneFois recalcule et écrit le fichier de façon atomique (0640, groupe actord-ingest comme les propositions).
func (s *Server) publierMesuresUneFois(chemin string, now time.Time) error {
	ms, err := s.recalculerMesures(now.Unix())
	if err != nil {
		return err
	}
	if ms == nil {
		ms = []MesureActeur{}
	}
	b, err := json.Marshal(FichierMesures{GenereLe: now.Unix(), Shadow: s.shadow, Mesures: ms})
	if err != nil {
		return err
	}
	tmp := chemin + ".tmp"
	if err := os.WriteFile(tmp, b, 0o640); err != nil {
		return err
	}
	if g, err := user.LookupGroup("actord-ingest"); err == nil {
		if gid, err := strconv.Atoi(g.Gid); err == nil {
			_ = os.Chown(tmp, -1, gid)
		}
	}
	_ = os.Chmod(tmp, 0o640)
	return os.Rename(tmp, filepath.Clean(chemin))
}

// publierMesures réécrit le fichier toutes les `pas`.
func (s *Server) publierMesures(chemin string, pas time.Duration) {
	for {
		if err := s.publierMesuresUneFois(chemin, time.Now()); err != nil {
			log.Printf("actord: mesures: %v", err)
		}
		time.Sleep(pas)
	}
}

// handleMesures : compteurs par cran (vue réduite) ; la vue complète ajoute les mesures, adresses comprises.
func (s *Server) handleMesures(w http.ResponseWriter, r *http.Request) {
	s.mes.mu.Lock()
	cur := append([]MesureActeur(nil), s.mes.courant...)
	s.mes.mu.Unlock()
	par := map[mesure.Niveau]int{mesure.Delay: 0, mesure.Challenge: 0, mesure.Tarpit: 0, mesure.Deny: 0, mesure.Quarantine: 0}
	for _, m := range cur {
		par[m.Niveau]++
	}
	rep := map[string]any{"genere_le": time.Now().Unix(), "par_niveau": par}
	if !vueReduite(r) {
		rep["mesures"] = cur
	}
	writeJSON(w, rep)
}
