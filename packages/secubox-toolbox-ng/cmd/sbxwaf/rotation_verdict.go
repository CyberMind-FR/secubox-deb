// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// See LICENCE-CMSD-1.0.md for terms.

package main

import (
	"log"
	"net/netip"
	"time"

	"github.com/CyberMind-FR/secubox-deb/secubox-toolbox-ng/internal/reseau"
)

// ── Verdicts ─────────────────────────────────────────────────────────────────────────────────────────────────────────

// juger rend les verdicts échus : au plus rotationMaxDecisions et rotationTempsDecisions par Tick, le plafond horaire avant tout DNS.
func (r *Rotation) juger(t time.Time) {
	garde := r.recents[:0]
	for _, x := range r.recents {
		if t.Sub(x) < time.Hour {
			garde = append(garde, x)
		}
	}
	r.recents = garde
	if len(r.recents) < r.cfg.MaxParHeure {
		r.plafondDit = false
	}
	ns, debut := t.UnixNano(), time.Now()
	for i := 0; i < rotationMaxDecisions && time.Since(debut) < r.tempsDecisions; i++ {
		r.mu.Lock()
		if len(r.attente) == 0 || r.attente[0].echeance > ns {
			r.mu.Unlock()
			return
		}
		v := r.attente[0]
		r.attente = r.attente[1:]
		delete(r.enAttente, v.adr)
		r.retenirJuge(v.adr, ns)
		c := r.campagnes[v.cle]
		r.mu.Unlock()
		if c == nil {
			continue // campagne finie entre-temps : pas de ban
		}
		r.rendre(v, c.signature[:8], t)
	}
}

// retenirJuge (sous verrou) : une adresse n'est jugée qu'une fois par jour. Au plafond, la plus ancienne est oubliée (elle pourra être rejugée).
func (r *Rotation) retenirJuge(a netip.Addr, ns int64) {
	for len(r.juges) >= r.maxVerdicts && len(r.ordreJuges) > 0 {
		delete(r.juges, r.ordreJuges[0])
		r.ordreJuges = r.ordreJuges[1:]
	}
	r.juges[a] = ns
	r.ordreJuges = append(r.ordreJuges, a)
}

// rendre (hors verrou) : garde-fous, puis ban (auto) ou proposition (propose).
func (r *Rotation) rendre(v rotVerdict, court string, t time.Time) {
	ip := v.adr.String()
	epargnee := r.memoire.contient(v.h, t.Unix())
	raison := ""
	switch {
	case epargnee:
	case r.exemptes.contient(v.h, t.Unix()): // campagne finie puis rétablie pendant l'attente : l'adresse en est devenue une source
		raison = "exemptee"
	case t.UnixNano()-v.echeance > int64(rotationVerdictPerime):
		raison = "perime"
	case r.memoire.saturee(t.Unix()):
		raison = "memoire_saturee"
	case t.Before(r.graceFin):
		raison = "grace"
	case len(r.recents) >= r.cfg.MaxParHeure:
		raison = "plafond_horaire"
		r.direPlafond(t)
	default:
		raison = r.ecarter(ip)
		epargnee = r.memoire.contient(v.h, time.Now().Unix()) || r.memoire.contient(v.h, t.Unix()) // une preuve a pu arriver pendant le DNS
	}

	r.mu.Lock()
	r.etatSale = true
	c := r.campagnes[v.cle]
	if c == nil { // finie pendant le DNS
		r.mu.Unlock()
		return
	}
	switch {
	case epargnee:
		c.epargnees++
	case raison != "":
		c.ecartees++
	case r.cfg.Mode == "auto":
		c.bannies++
	default:
		c.aBannir++
	}
	r.mu.Unlock()
	if epargnee || raison != "" {
		return
	}
	r.recents = append(r.recents, t)
	action := "detect"
	if r.cfg.Mode == "auto" {
		action = "banned"
		r.banneur.BanFor(ip, "rotation:"+court, "high", r.cfg.Duree)
		log.Printf("sbxwaf: rotation-ban %s ← %s (aucune ressource, cookie ni référent %s après sa page)", ip, court, r.cfg.Delai)
	}
	if r.journal != nil {
		// Ni chemin ni navigateur déclaré (une ligne de verdict n'est pas une sonde) ; jamais vers actord : un constat d'absence, proposé ou non, ne doit
		// nourrir ni score d'acteur ni mesure.
		r.journal(ThreatRecord{ClientIP: ip, Host: v.hote, Method: "GET", Category: "rotation:" + court, Severity: "high", RuleID: "rotation",
			Action: action, HorsActeur: true})
	}
}

func (r *Rotation) direPlafond(t time.Time) {
	if r.plafondDit {
		return
	}
	r.plafondDit = true
	r.mu.Lock()
	r.audits = append(r.audits, map[string]any{"ts": t.UTC().Format("2006-01-02T15:04:05Z"), "module": "waf", "action": "rotation_plafond",
		"detail": "plafond de verdicts de rotation atteint", "plafond": r.cfg.MaxParHeure, "mode": r.cfg.Mode})
	r.mu.Unlock()
	log.Printf("sbxwaf: rotation — plafond de %d verdicts par heure atteint (mode=%s)", r.cfg.MaxParHeure, r.cfg.Mode)
}

// ecarter rend la raison pour laquelle l'adresse ne doit jamais être bannie, "" sinon. Le DNS (robots) en dernier.
func (r *Rotation) ecarter(ip string) string {
	if adresseProtegee(ip, r.cfg.Protegees) {
		return "protegee"
	}
	if _, ok := r.tor[ip]; ok {
		return "sortie_tor"
	}
	switch r.classer(ip).Classe {
	case reseau.ClasseRelaisViePrivee:
		return "relais_vie_privee"
	case reseau.ClasseMobilePartage:
		return "mobile_partage" // CGNAT, satellite : la page et ses ressources peuvent sortir par deux adresses, et le ban toucherait des tiers
	}
	if r.robots != nil {
		if nom, sur := r.robots(ip); nom != "" {
			return "robot_verifie"
		} else if !sur {
			return "robot_inverifiable"
		}
	}
	return ""
}
