// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// See LICENCE-CMSD-1.0.md for terms.

package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"log"
	"net"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// Ban des campagnes (#2238, décision du propriétaire du 2026-10-11).
//
// Une CAMPAGNE (profileur #1070 phase D) est un même workflow de sondes mené par plusieurs adresses. On la bannit quand elle porte des sondes de
// HAUTE VALEUR (secrets, exécution, administration, #1240) : un balayage bruyant sans cible précieuse reste observé.
//
// GARDE-FOUS, tous testés :
//   - la preuve est PAR ADRESSE. La clé JA4 est volontairement retirée avant le regroupement : deux visiteurs ordinaires partagent le JA4 d'un
//     navigateur courant, et le profileur les aurait fondus en un seul « attaquant ». Une adresse n'est bannie que pour ses propres sondes ;
//   - les robots connus (action « robot ») et l'auto-test de santé sont écartés avant tout calcul ;
//   - jamais d'adresse privée, de boucle locale, de lien-local ni de plage protégée déclarée ;
//   - coupe-circuit : au plus `maxParHeure` bans par heure glissante ; une adresse déjà bannie n'est pas rebannie ;
//   - durée GRADUÉE à la récidive (catégorie « campagne: » dans le journal de bans) : 4 h, 24 h, 7 j ;
//   - mode `propose` : rien n'est appliqué, l'état (candidats, décisions) est écrit pour le panneau ; chaque ban est une ligne du journal de bans.
const fenetreRecidiveCampagne = 30 * 24 * time.Hour

func dureeCampagne(recidives int) time.Duration {
	switch {
	case recidives <= 0:
		return 4 * time.Hour
	case recidives == 1:
		return 24 * time.Hour
	default:
		return 7 * 24 * time.Hour
	}
}

type banneurDuree interface {
	BanFor(ip, cat, sev string, d time.Duration)
}

type campagneCandidat struct {
	IP        string `json:"ip"`
	Signature string `json:"signature"`
	Sondes    int    `json:"sondes"`
	HV        int    `json:"haute_valeur"`
	Decision  string `json:"decision"`
	DureeS    int64  `json:"duree_s,omitempty"`
}

type campagneEtat struct {
	GenereLe       int64              `json:"genere_le"`
	Mode           string             `json:"mode"`
	Candidats      []campagneCandidat `json:"candidats"`
	AppliquesHeure int                `json:"appliques_derniere_heure"`
	PlafondAtteint bool               `json:"plafond_atteint"`
}

type CampagneBan struct {
	journal     string
	mode        string // off | propose | auto
	store       *BanStore
	banneur     banneurDuree
	etat        string
	protegees   []*net.IPNet
	fenetre     time.Duration
	minSondes   int // sondes de l'adresse
	minHV       int // sondes de haute valeur de la CAMPAGNE
	minMembres  int
	maxParHeure int
	now         func() time.Time

	mu      sync.Mutex
	recents []time.Time
}

func NewCampagneBan(journal, mode string, store *BanStore, b banneurDuree) *CampagneBan {
	return &CampagneBan{journal: journal, mode: mode, store: store, banneur: b, fenetre: 24 * time.Hour, minSondes: 5, minHV: 2,
		minMembres: 2, maxParHeure: 30, now: time.Now}
}

// profilsDuJournal relit le journal du jour, sans robots ni auto-test, clé = adresse (JA4 retiré), dans la fenêtre.
func (c *CampagneBan) profilsDuJournal() map[string]*AttackerProfile {
	f, err := os.Open(c.journal)
	if err != nil {
		return nil
	}
	defer f.Close()
	depuis := c.now().Add(-c.fenetre)
	var tampon bytes.Buffer
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		var e logEntry
		if json.Unmarshal(sc.Bytes(), &e) != nil || e.ClientIP == "" || e.Action == "robot" || e.Category == "robots" || estAutoTest(e.ClientIP, e.UserAgent) {
			continue
		}
		if t, err := time.Parse(time.RFC3339, e.Timestamp); err == nil && t.Before(depuis) {
			continue
		}
		e.JA4 = ""
		b, _ := json.Marshal(e)
		tampon.Write(b)
		tampon.WriteByte('\n')
	}
	return construireProfils(&tampon)
}

func (c *CampagneBan) Tick() {
	if c.mode != "propose" && c.mode != "auto" {
		return
	}
	profs := c.profilsDuJournal()
	now := c.now()
	actifs := map[string]bool{}
	for _, r := range c.store.ActiveBans(now.Unix()) {
		actifs[r.IP] = true
	}
	c.mu.Lock()
	garde := c.recents[:0]
	for _, t := range c.recents {
		if now.Sub(t) < time.Hour {
			garde = append(garde, t)
		}
	}
	c.recents = garde
	c.mu.Unlock()

	etat := campagneEtat{GenereLe: now.Unix(), Mode: c.mode}
	campagnes := clusteriser(profs)
	sort.SliceStable(campagnes, func(i, j int) bool { return campagnes[i].HauteValeur > campagnes[j].HauteValeur })
	for _, camp := range campagnes {
		if len(camp.Attaquants) < c.minMembres || camp.HauteValeur < c.minHV {
			continue
		}
		for _, ip := range camp.Attaquants {
			p := profs[ip]
			if p == nil || p.Sondes < c.minSondes || p.HauteValeur < 1 {
				continue
			}
			cand := campagneCandidat{IP: ip, Signature: camp.Signature, Sondes: p.Sondes, HV: p.HauteValeur}
			switch {
			case adresseProtegee(ip, c.protegees):
				cand.Decision = "ecarte:protegee"
			case actifs[ip]:
				cand.Decision = "ecarte:deja_banni"
			case c.mode == "propose":
				cand.Decision = "a_bannir"
			default:
				c.mu.Lock()
				plein := len(c.recents) >= c.maxParHeure
				if !plein {
					c.recents = append(c.recents, now)
				}
				c.mu.Unlock()
				if plein {
					cand.Decision, etat.PlafondAtteint = "ecarte:plafond_horaire", true
				} else {
					d := dureeCampagne(c.store.CompteCategorie(ip, "campagne:", now.Add(-fenetreRecidiveCampagne).Unix()))
					c.banneur.BanFor(ip, "campagne:"+camp.Signature, "high", d)
					cand.Decision, cand.DureeS = "banni", int64(d.Seconds())
					log.Printf("sbxwaf: campagne-ban %s ← %s (%d sondes, %d haute valeur, %s)", ip, camp.Signature, p.Sondes, p.HauteValeur, d)
				}
			}
			etat.Candidats = append(etat.Candidats, cand)
		}
	}
	c.mu.Lock()
	etat.AppliquesHeure = len(c.recents)
	c.mu.Unlock()
	c.ecrireEtat(etat)
}

func (c *CampagneBan) ecrireEtat(e campagneEtat) {
	if c.etat == "" {
		return
	}
	b, err := json.Marshal(e)
	if err != nil {
		return
	}
	_ = os.MkdirAll(filepath.Dir(c.etat), 0o755)
	tmp := c.etat + ".tmp"
	if os.WriteFile(tmp, b, 0o640) == nil {
		_ = os.Rename(tmp, c.etat)
	}
}

// Veiller relance Tick à intervalle régulier.
func (c *CampagneBan) Veiller(pas time.Duration) {
	for {
		c.Tick()
		time.Sleep(pas)
	}
}
