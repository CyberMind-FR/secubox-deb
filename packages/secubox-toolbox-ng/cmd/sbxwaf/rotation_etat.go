// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// See LICENCE-CMSD-1.0.md for terms.

package main

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Fichiers du détecteur de rotation (#3919) : liste des sorties Tor, état (panneau, relevé populations), audit. Tout est lu et écrit depuis Tick.

// chargerTor relit la liste des sorties Tor au plus toutes les 10 min ; illisible ou vide = garde inactive (signalée dans l'état).
func (r *Rotation) chargerTor(t time.Time) {
	if !r.torLuLe.IsZero() && t.Sub(r.torLuLe) < rotationTorPas && t.After(r.torLuLe) {
		return
	}
	r.torLuLe = t
	avant := r.tor != nil
	r.tor = nil
	if r.cfg.SortiesTor != "" {
		if f, err := os.Open(r.cfg.SortiesTor); err == nil {
			m := map[string]struct{}{}
			sc := bufio.NewScanner(f)
			for sc.Scan() {
				l := strings.TrimSpace(sc.Text())
				if l == "" || strings.HasPrefix(l, "#") {
					continue
				}
				if a, err := netip.ParseAddr(strings.Fields(l)[0]); err == nil {
					m[a.Unmap().String()] = struct{}{}
				}
			}
			f.Close()
			if len(m) > 0 {
				r.tor = m
			}
		}
	}
	if r.tor == nil && !r.torAverti {
		r.torAverti = true
		log.Printf("sbxwaf: rotation — liste des sorties Tor absente ou vide (%s) : garde Tor INACTIVE", r.cfg.SortiesTor)
	}
	if avant != (r.tor != nil) {
		r.mu.Lock()
		r.etatSale = true
		r.mu.Unlock()
	}
}

// ── État ─────────────────────────────────────────────────────────────────────────────────────────────────────────────

type rotationCampagneEtat struct {
	Signature string         `json:"signature"`
	Hote      string         `json:"hote"`
	EtablieLe int64          `json:"etablie_le"`
	Dernier   int64          `json:"dernier"`
	Sources   int            `json:"sources"`
	Une       int            `json:"une"`
	Le3       int            `json:"le3"`
	Classes   map[string]int `json:"classes"`
	Bannies   int            `json:"bannies"`
	Epargnees int            `json:"epargnees"`
	ABannir   int            `json:"a_bannir"`
	Ecartees  int            `json:"ecartees"`
}

type rotationEtat struct {
	GenereLe       int64                  `json:"genere_le"`
	Mode           string                 `json:"mode"`
	Verdict        string                 `json:"verdict"`
	TorGarde       bool                   `json:"tor_garde"`
	Campagnes      []rotationCampagneEtat `json:"campagnes"`
	AppliquesHeure int                    `json:"appliques_derniere_heure"`
	PlafondAtteint bool                   `json:"plafond_atteint"`
	MemoireSaturee bool                   `json:"memoire_saturee"` // trop de navigateurs à retenir : plus aucun ban
	Navigateurs    int                    `json:"navigateurs"`     // adresses retenues comme navigateurs
	EnGrace        bool                   `json:"en_grace"`        // démarrage : rien n'est jugé
}

// campagnesActives : copie triée (plus ancienne d'abord) des campagnes actives.
func (r *Rotation) campagnesActives() []rotationCampagneEtat {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.listeCampagnes()
}

func (r *Rotation) listeCampagnes() []rotationCampagneEtat {
	out := make([]rotationCampagneEtat, 0, len(r.campagnes))
	for _, c := range r.campagnes {
		cl := map[string]int{}
		for k, v := range c.classes {
			cl[k] = v
		}
		out = append(out, rotationCampagneEtat{Signature: c.signature, Hote: c.hote, EtablieLe: c.etablieLe, Dernier: c.dernier,
			Sources: c.sources, Une: c.une, Le3: c.le3, Classes: cl, Bannies: c.bannies, Epargnees: c.epargnees, ABannir: c.aBannir,
			Ecartees: c.ecartees})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].EtablieLe != out[j].EtablieLe {
			return out[i].EtablieLe < out[j].EtablieLe
		}
		return out[i].Signature < out[j].Signature
	})
	return out
}

// etatCourant (sous verrou).
func (r *Rotation) etatCourant(t time.Time) rotationEtat {
	e := rotationEtat{GenereLe: t.Unix(), Mode: r.cfg.Mode, Verdict: r.cfg.Verdict, TorGarde: r.tor != nil,
		Campagnes: r.listeCampagnes(), PlafondAtteint: r.plafondDit, MemoireSaturee: r.memoire.saturee(t.Unix()),
		Navigateurs: r.memoire.nb(), EnGrace: t.Before(r.graceFin)}
	if r.cfg.Mode == "auto" {
		e.AppliquesHeure = len(r.recents)
	}
	return e
}

func (r *Rotation) ecrireEtat(e rotationEtat) {
	if r.cfg.Etat == "" {
		return
	}
	b, err := json.Marshal(e)
	if err != nil {
		return
	}
	_ = os.MkdirAll(filepath.Dir(r.cfg.Etat), 0o755)
	tmp := r.cfg.Etat + ".tmp"
	if os.WriteFile(tmp, b, 0o640) == nil {
		_ = os.Rename(tmp, r.cfg.Etat)
	}
}

// relireEtat reprend les campagnes d'un état de moins de Duree ; état absent, corrompu, périmé ou daté du futur : ignoré.
func (r *Rotation) relireEtat(maintenant time.Time) {
	if r.cfg.Etat == "" || r.cfg.Mode == "off" {
		return
	}
	b, err := os.ReadFile(r.cfg.Etat)
	if err != nil {
		return
	}
	var e rotationEtat
	s := maintenant.Unix()
	duree, futur := int64(r.cfg.Duree/time.Second), s+rotationToleranceFutur
	if json.Unmarshal(b, &e) != nil || s-e.GenereLe > duree || e.GenereLe > futur {
		return
	}
	for _, x := range e.Campagnes {
		brut, err := hex.DecodeString(x.Signature)
		if err != nil || len(brut) != 32 || s-x.Dernier > duree || x.Dernier > futur || x.EtablieLe > futur || len(r.campagnes) >= r.cfg.MaxCampagnes {
			continue
		}
		var cle [32]byte
		copy(cle[:], brut)
		r.campagnes[cle] = &rotCampagne{cle: cle, signature: hex.EncodeToString(brut), hote: x.Hote, etablieLe: x.EtablieLe, dernier: x.Dernier,
			sources: x.Sources, une: x.Une, le3: x.Le3, classes: x.Classes, bannies: x.Bannies, epargnees: x.Epargnees, aBannir: x.ABannir,
			ecartees: x.Ecartees}
	}
	if len(r.campagnes) > 0 {
		log.Printf("sbxwaf: rotation — %d campagne(s) active(s) reprise(s) de %s", len(r.campagnes), r.cfg.Etat)
	}
}

// auditer ajoute une ligne JSON au journal d'audit du WAF (même verrou d'ajout que le compactage, voir reevaluation.go).
func (r *Rotation) auditer(v map[string]any) {
	if r.cfg.Audit == "" {
		return
	}
	b, err := json.Marshal(v)
	if err != nil {
		return
	}
	_ = os.MkdirAll(filepath.Dir(r.cfg.Audit), 0o755)
	mu := verrouAjout(r.cfg.Audit)
	mu.Lock()
	defer mu.Unlock()
	f, err := os.OpenFile(r.cfg.Audit, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o640)
	if err != nil {
		log.Printf("sbxwaf: rotation — audit %s impossible : %v", r.cfg.Audit, err)
		return
	}
	defer f.Close()
	_, _ = f.Write(append(b, '\n'))
}
