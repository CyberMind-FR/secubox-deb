// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package main

import (
	"bufio"
	"encoding/json"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Ban automatique piloté par Actor Intelligence (RFC-0013 §8, phase 2).
//
// actord PUBLIE les adresses des acteurs que son moteur range à DENY/QUARANTINE (il n'a aucun droit d'agir). sbxwaf, qui a déjà le ban nft,
// les relit et n'applique QUE ce que ses propres garde-fous laissent passer :
//
//   - preuve locale : l'adresse a déjà été sanctionnée au moins `minBans` fois par CE WAF dans la fenêtre (jamais sur la seule parole d'actord) ;
//     les bans « actor:… » ne comptent pas (un ban automatique ne doit pas se nourrir de lui-même) ;
//   - jamais d'adresse privée, de boucle locale, de lien-local, de multicast, ni de plage protégée déclarée (box, Freebox, mesh) ;
//   - coupe-circuit : au plus `maxParHeure` bans automatiques par heure glissante ;
//   - fichier périmé = rien (actord arrêté ou figé) ; mode `propose` = aucune action, seulement l'état écrit pour le panneau ;
//   - toute action est une ligne du journal de bans (catégorie « actor:ACT-n »), annulable comme les autres, et expire avec le timeout nft.

// actorProp / actorFichier reflètent le fichier publié par actord (cmd/sbx-actord/propositions.go).
type actorProp struct {
	Actor string   `json:"actor"`
	Mode  string   `json:"mode"`
	IPs   []string `json:"ips"`
	TTLs  int64    `json:"ttl_s"`
}

type actorFichier struct {
	GenereLe     int64       `json:"genere_le"`
	Shadow       bool        `json:"shadow"`
	Propositions []actorProp `json:"propositions"`
}

type actorCandidat struct {
	IP       string `json:"ip"`
	Actor    string `json:"actor"`
	Mode     string `json:"mode"`
	DejaBans int    `json:"deja_bans"`
	Decision string `json:"decision"` // a_bannir | banni | ecarte:<motif>
}

type actorEtat struct {
	GenereLe       int64           `json:"genere_le"`
	Mode           string          `json:"mode"`
	Candidats      []actorCandidat `json:"candidats"`
	AppliquesHeure int             `json:"appliques_derniere_heure"`
	PlafondAtteint bool            `json:"plafond_atteint"`
}

type banneur interface{ Ban(ip, cat, sev string) }

type ActorBan struct {
	chemin      string
	mode        string // off | propose | auto
	store       *BanStore
	banneur     banneur
	etat        string
	minBans     int
	fenetre     time.Duration
	maxParHeure int
	fraicheur   time.Duration
	protegees   []*net.IPNet
	now         func() time.Time

	mu      sync.Mutex
	recents []time.Time // bans automatiques posés, pour l'heure glissante
}

func NewActorBan(chemin, mode string, store *BanStore, b banneur) *ActorBan {
	return &ActorBan{chemin: chemin, mode: mode, store: store, banneur: b, minBans: 2, fenetre: 24 * time.Hour,
		maxParHeure: 20, fraicheur: 10 * time.Minute, now: time.Now}
}

func parseCIDRs(liste string) []*net.IPNet {
	var out []*net.IPNet
	for _, c := range strings.Split(liste, ",") {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		if _, n, err := net.ParseCIDR(c); err == nil {
			out = append(out, n)
		} else if ip := net.ParseIP(c); ip != nil {
			bits := 32
			if ip.To4() == nil {
				bits = 128
			}
			out = append(out, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
		}
	}
	return out
}

func (a *ActorBan) protegee(ip string) bool { return adresseProtegee(ip, a.protegees) }

// adresseProtegee : jamais bannie automatiquement (privée, boucle locale, lien-local, multicast, plages déclarées : box, Freebox, mesh).
func adresseProtegee(ip string, protegees []*net.IPNet) bool {
	p := net.ParseIP(ip)
	if p == nil || p.IsLoopback() || p.IsPrivate() || p.IsLinkLocalUnicast() || p.IsLinkLocalMulticast() || p.IsMulticast() || p.IsUnspecified() {
		return true
	}
	for _, n := range protegees {
		if n.Contains(p) {
			return true
		}
	}
	return false
}

// sanctions compte, par IP, les bans posés par le WAF lui-même dans la fenêtre (hors bans automatiques).
func (a *ActorBan) sanctions(depuis int64) map[string]int {
	out := map[string]int{}
	if a.store == nil {
		return out
	}
	a.store.mu.Lock()
	defer a.store.mu.Unlock()
	f, err := os.Open(a.store.path)
	if err != nil {
		return out
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		var r BanRecord
		if json.Unmarshal(sc.Bytes(), &r) != nil || r.Action != "ban" || r.At < depuis || strings.HasPrefix(r.Category, "actor:") {
			continue
		}
		out[r.IP]++
	}
	return out
}

func (a *ActorBan) lire() (actorFichier, bool) {
	var f actorFichier
	b, err := os.ReadFile(a.chemin)
	if err != nil || json.Unmarshal(b, &f) != nil {
		return f, false
	}
	if a.now().Sub(time.Unix(f.GenereLe, 0)) > a.fraicheur {
		return f, false // périmé : actord arrêté ou figé
	}
	return f, true
}

// Tick relit les propositions et applique (auto) ou seulement consigne (propose) ce que les garde-fous laissent passer.
func (a *ActorBan) Tick() {
	if a.mode != "propose" && a.mode != "auto" {
		return
	}
	f, ok := a.lire()
	if !ok {
		return
	}
	now := a.now()
	sanc := a.sanctions(now.Add(-a.fenetre).Unix())

	a.mu.Lock()
	garde := a.recents[:0]
	for _, t := range a.recents {
		if now.Sub(t) < time.Hour {
			garde = append(garde, t)
		}
	}
	a.recents = garde
	a.mu.Unlock()

	etat := actorEtat{GenereLe: now.Unix(), Mode: a.mode}
	vus := map[string]bool{}
	for _, p := range f.Propositions {
		for _, ip := range p.IPs {
			if vus[ip] {
				continue
			}
			vus[ip] = true
			c := actorCandidat{IP: ip, Actor: p.Actor, Mode: p.Mode, DejaBans: sanc[ip]}
			switch {
			case a.protegee(ip):
				c.Decision = "ecarte:protegee"
			case c.DejaBans < a.minBans:
				c.Decision = "ecarte:preuve_locale_insuffisante"
			default:
				c.Decision = "a_bannir"
			}
			if c.Decision == "a_bannir" && a.mode == "auto" {
				a.mu.Lock()
				plein := len(a.recents) >= a.maxParHeure
				if !plein {
					a.recents = append(a.recents, now)
				}
				a.mu.Unlock()
				if plein {
					c.Decision = "ecarte:plafond_horaire"
					etat.PlafondAtteint = true
				} else {
					a.banneur.Ban(ip, "actor:"+p.Actor, "high")
					c.Decision = "banni"
					log.Printf("sbxwaf: actor-ban %s ← %s (%s, %d sanctions locales)", ip, p.Actor, p.Mode, c.DejaBans)
				}
			}
			etat.Candidats = append(etat.Candidats, c)
		}
	}
	a.mu.Lock()
	etat.AppliquesHeure = len(a.recents)
	a.mu.Unlock()
	a.ecrireEtat(etat)
}

func (a *ActorBan) ecrireEtat(e actorEtat) {
	if a.etat == "" {
		return
	}
	b, err := json.Marshal(e)
	if err != nil {
		return
	}
	_ = os.MkdirAll(filepath.Dir(a.etat), 0o755)
	tmp := a.etat + ".tmp"
	if os.WriteFile(tmp, b, 0o640) == nil {
		_ = os.Rename(tmp, a.etat)
	}
}

// Veiller relance Tick à intervalle régulier.
func (a *ActorBan) Veiller(pas time.Duration) {
	for {
		a.Tick()
		time.Sleep(pas)
	}
}
