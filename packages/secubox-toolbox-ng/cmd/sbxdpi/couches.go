// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package main

import (
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"sync"
	"time"
)

// Couches de menace nourries par nDPId (#4010).
//
// Par adresse SOURCE externe (publique) qui ouvre un flux VERS la box ou le réseau local (destination locale), sbxdpi tient, sur une fenêtre
// glissante (24 h par défaut) :
//   - accès : flux par service visé (« protocole L7/port »), y compris hors HTTP — ce que le WAF ne voit pas ;
//   - raisons : risques nDPI du flux, comptés une fois par flux (à sa fin) ;
//   - agent : empreintes JA4 calculées depuis le ClientHello (tlsfp.go), rattachées à la source par l'identifiant de flux.
//
// Mesuré sur gk2 (27/11) : ~5 flux entrants par seconde, contre ~60 flux par seconde au total ; le coût est une table bornée en mémoire et un
// fichier sur tmpfs toutes les 30 s. Les adresses du LAN, privées, CGNAT, locales ne sont jamais suivies comme sources (adressePublique).
//
// Le fichier de sortie porte les adresses : il est INTERNE (0640, groupe secubox, sous /run/secubox/sbxdpi) et sert l'API ndpid et les populations
// (#4005). Aucune route de sbxdpi ne le rend. Double tampon : un relevé « dégradé » (distributeur absent, démarrage depuis moins de 10 min) n'écrase
// jamais un relevé complet de moins de deux fenêtres.
const (
	fenetreCouchesDefaut = 24 * time.Hour
	chauffeCouches       = 10 * time.Minute
	maxSourcesCouches    = 4096
	maxServicesParSrc    = 32
	maxRisquesParSrc     = 32
	maxJA4ParSrc         = 8
	maxFluxSuivis        = 8192
)

type srcCouche struct {
	Premier  int64             `json:"premier"`
	Dernier  int64             `json:"dernier"`
	Flux     uint64            `json:"flux"`
	Octets   uint64            `json:"octets"`
	Services map[string]uint64 `json:"services"`
	Risques  map[string]uint64 `json:"risques"`
	JA4      map[string]uint64 `json:"ja4"`
}

type releveCouches struct {
	Version  int                   `json:"version"`
	Genere   int64                 `json:"genere"`
	Depuis   int64                 `json:"depuis"`
	Complet  bool                  `json:"complet"`
	Fenetre  int64                 `json:"fenetre_s"`
	Sources  map[string]*srcCouche `json:"sources"`
	Ignorees uint64                `json:"sources_ignorees"`
}

type couchesMenaces struct {
	chemin   string
	fenetre  time.Duration
	now      func() time.Time
	muet     func(string) bool
	connecte func() bool

	mu       sync.Mutex
	debut    time.Time
	acc      map[string]*srcCouche
	flux     map[uint64]string // identifiant de flux → source externe (flux entrants seulement)
	attente  map[uint64]string // identifiant de flux → JA4 vu avant l'événement « new »
	ignorees uint64
}

func newCouchesMenaces(chemin string, fenetre time.Duration) *couchesMenaces {
	if fenetre <= 0 {
		fenetre = fenetreCouchesDefaut
	}
	return &couchesMenaces{chemin: chemin, fenetre: fenetre, now: time.Now, debut: time.Now(),
		acc: map[string]*srcCouche{}, flux: map[uint64]string{}, attente: map[uint64]string{}}
}

// entrant : source publique vers destination locale. Un flux sortant (source locale) ou de transit (deux publiques) n'est pas une tentative d'accès.
func entrant(ev *dpiEvent) bool { return adressePublique(ev.SrcIP) && isLocalIP(ev.DstIP) }

// source rend l'entrée d'une adresse, créée au besoin (verrou tenu) ; nil si la table est pleine de sources plus récentes.
func (c *couchesMenaces) source(ip string, t int64) *srcCouche {
	s := c.acc[ip]
	if s != nil {
		return s
	}
	if len(c.acc) >= maxSourcesCouches {
		var pire string
		var tp int64
		for k, v := range c.acc {
			if pire == "" || v.Dernier < tp {
				pire, tp = k, v.Dernier
			}
		}
		delete(c.acc, pire)
		c.ignorees++
	}
	s = &srcCouche{Premier: t, Dernier: t, Services: map[string]uint64{}, Risques: map[string]uint64{}, JA4: map[string]uint64{}}
	c.acc[ip] = s
	return s
}

func borne(m map[string]uint64, k string, n uint64, max int) {
	if _, ok := m[k]; ok || len(m) < max {
		m[k] += n
	}
}

func (c *couchesMenaces) noterJA4(s *srcCouche, ja4 string) {
	if ja4 != "" {
		borne(s.JA4, ja4, 1, maxJA4ParSrc)
	}
}

// Observe : un événement de flux, avant tout filtrage d'affichage (une app écartée des statistiques reste une tentative d'accès). Nil-safe.
func (c *couchesMenaces) Observe(ev *dpiEvent) {
	if c == nil || ev.FlowEventName == "" {
		return
	}
	t := c.now().Unix()
	c.mu.Lock()
	defer c.mu.Unlock()
	if ev.FlowEventName == "new" {
		if !entrant(ev) {
			return
		}
		s := c.source(ev.SrcIP, t)
		s.Flux++
		s.Dernier = t
		if len(c.flux) >= maxFluxSuivis {
			c.flux = map[uint64]string{} // bornage brutal : on perd au pire le rattachement JA4 de flux en cours
		}
		c.flux[ev.FlowID] = ev.SrcIP
		if j, ok := c.attente[ev.FlowID]; ok {
			delete(c.attente, ev.FlowID)
			c.noterJA4(s, j)
		}
		return
	}
	if !entrant(ev) {
		return
	}
	s := c.source(ev.SrcIP, t)
	s.Dernier = t
	switch ev.FlowEventName {
	case "detected", "guessed", "not-detected":
		proto := ev.master()
		if ev.FlowEventName == "not-detected" {
			proto = "Unknown"
		}
		borne(s.Services, proto+"/"+strconv.Itoa(ev.DstPort), 1, maxServicesParSrc)
	case "end", "idle":
		s.Octets += ev.bytes()
		for _, r := range ev.NDPI.FlowRisk {
			if r.Risk != "" && (c.muet == nil || !c.muet(r.Risk)) {
				borne(s.Risques, r.Risk, 1, maxRisquesParSrc)
			}
		}
		delete(c.flux, ev.FlowID)
	}
}

// Empreinte : JA4 d'un ClientHello lu sur un paquet du flux (les événements packet-flow ne portent pas d'adresse, d'où le rattachement par flux).
func (c *couchesMenaces) Empreinte(flux uint64, ja4 string) {
	if c == nil || ja4 == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if ip, ok := c.flux[flux]; ok {
		if s := c.acc[ip]; s != nil {
			c.noterJA4(s, ja4)
		}
		return
	}
	if len(c.attente) >= maxFluxSuivis {
		c.attente = map[uint64]string{}
	}
	c.attente[flux] = ja4
}

// ja4De : l'empreinte la plus vue d'une source (pour le capteur Actor Intelligence, dont l'événement nDPI ne porte pas de JA4).
func (c *couchesMenaces) ja4De(ip string) string {
	if c == nil {
		return ""
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	s := c.acc[ip]
	if s == nil {
		return ""
	}
	var best string
	var n uint64
	for k, v := range s.JA4 {
		if v > n || (v == n && k < best) {
			best, n = k, v
		}
	}
	return best
}

func copieCompte(m map[string]uint64) map[string]uint64 {
	o := make(map[string]uint64, len(m))
	for k, v := range m {
		o[k] = v
	}
	return o
}

// releve purge les sources échues et rend une copie.
func (c *couchesMenaces) releve() releveCouches {
	now := c.now()
	limite := now.Add(-c.fenetre).Unix()
	c.mu.Lock()
	defer c.mu.Unlock()
	out := releveCouches{Version: 1, Genere: now.Unix(), Depuis: c.debut.Unix(), Fenetre: int64(c.fenetre / time.Second),
		Sources: make(map[string]*srcCouche, len(c.acc)), Ignorees: c.ignorees}
	for ip, s := range c.acc {
		if s.Dernier < limite {
			delete(c.acc, ip)
			continue
		}
		out.Sources[ip] = &srcCouche{Premier: s.Premier, Dernier: s.Dernier, Flux: s.Flux, Octets: s.Octets,
			Services: copieCompte(s.Services), Risques: copieCompte(s.Risques), JA4: copieCompte(s.JA4)}
	}
	out.Complet = now.Sub(c.debut) >= chauffeCouches && (c.connecte == nil || c.connecte())
	return out
}

// ecrire : tmp + rename, sans jamais remplacer un relevé complet récent par un relevé dégradé.
func (c *couchesMenaces) ecrire() {
	if c == nil || c.chemin == "" {
		return
	}
	r := c.releve()
	if !r.Complet {
		if buf, err := os.ReadFile(c.chemin); err == nil {
			var ancien releveCouches
			if json.Unmarshal(buf, &ancien) == nil && ancien.Complet && r.Genere-ancien.Genere < 2*r.Fenetre {
				return
			}
		}
	}
	buf, err := json.Marshal(r)
	if err != nil {
		log.Printf("sbxdpi: couches marshal: %v", err)
		return
	}
	if err := os.MkdirAll(filepath.Dir(c.chemin), 0o750); err != nil {
		log.Printf("sbxdpi: couches mkdir: %v", err)
		return
	}
	tmp := c.chemin + ".tmp"
	if err := os.WriteFile(tmp, buf, 0o640); err != nil {
		log.Printf("sbxdpi: couches write: %v", err)
		return
	}
	if err := os.Rename(tmp, c.chemin); err != nil {
		log.Printf("sbxdpi: couches rename: %v", err)
	}
}

// servicesTries : utilitaire de test et de journal.
func servicesTries(s *srcCouche) []string {
	k := make([]string, 0, len(s.Services))
	for n := range s.Services {
		k = append(k, n)
	}
	sort.Strings(k)
	return k
}
