// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package main

import (
	"encoding/json"
	"errors"
	"io/fs"
	"log"
	"os"
	"sort"
	"time"
)

// Instantané des compteurs d'activité (#3936). Le rejeu de démarrage ne recharge que les derniers
// événements (--rebuild-max, une demi-journée sur gk2) : sans lui, une mise à jour du paquet
// effacerait les sept jours. Écrit toutes les heures et à l'arrêt, à côté de la base (0600, même
// répertoire, même propriétaire, adresses comprises comme elle) ; jamais exposé.
//
// Les identifiants d'acteurs changent au redémarrage : une entrée se rattache par ses adresses
// (les plus récentes) à l'acteur reconstruit qui en porte le plus. Une entrée sans acteur est
// oubliée : le graphe aussi l'a oubliée. L'instantané n'est repris que s'il rejoint le rejeu
// (sinon la couverture aurait une lacune inconnue). RIEN n'est rendu au graphe.
const (
	instantanePas     = time.Hour
	instantaneVersion = 1
	instantaneMax     = 64 << 20
	adressesParEntree = 64
)

type entreeInstantane struct {
	IPs     []string          `json:"ips"`
	Premier int64             `json:"premier"`
	Ban     int64             `json:"ban,omitempty"`
	Heures  [][6]int64        `json:"h,omitempty"` // heure absolue, événements, bans, adresses, pays, cibles
	Jours   [][2]int64        `json:"j,omitempty"` // jour absolu, événements
	Semaine [][2]int64        `json:"s,omitempty"` // heure absolue, événements
	Modules map[string]uint32 `json:"m,omitempty"`
	Tech    map[string]uint32 `json:"t,omitempty"`
}

type instantane struct {
	Version  int                `json:"version"`
	GenereLe int64              `json:"genere_le"`
	Depuis   int64              `json:"depuis"`
	Trous    [][2]int64         `json:"trous,omitempty"`
	Global   entreeInstantane   `json:"global"`
	Acteurs  []entreeInstantane `json:"acteurs"`
}

func (t *activite) exporter(x *activiteActeur) entreeInstantane {
	o := entreeInstantane{Premier: x.premier, Ban: x.dernierBan}
	for r := x.heure - heuresGardees + 1; x.heure > 0 && r <= x.heure; r++ {
		if h := lireRang(x.heures[:], x.heure, r); h != (trancheHeure{}) {
			o.Heures = append(o.Heures, [6]int64{r, int64(h.evts), int64(h.bans), int64(h.ips), int64(h.pays), int64(h.cibles)})
		}
	}
	for r := x.jour - joursGardes + 1; x.jour > 0 && r <= x.jour; r++ {
		if n := lireRang(x.jours[:], x.jour, r); n > 0 {
			o.Jours = append(o.Jours, [2]int64{r, int64(n)})
		}
	}
	for r := x.rangS - semaineGardee + 1; x.rangS > 0 && r <= x.rangS; r++ {
		if n := lireRang(x.semaine[:], x.rangS, r); n > 0 {
			o.Semaine = append(o.Semaine, [2]int64{r, int64(n)})
		}
	}
	for i, n := range x.modules {
		if n > 0 {
			if o.Modules == nil {
				o.Modules = map[string]uint32{}
			}
			o.Modules[modulesConnus[i]] = n
		}
	}
	for _, te := range x.tech {
		if o.Tech == nil {
			o.Tech = map[string]uint32{}
		}
		o.Tech[t.noms[te.nom]] += te.n
	}
	return o
}

func u32(v int64) uint32 {
	if v < 0 {
		return 0
	}
	return uint32(min(v, 1<<32-1))
}

func (t *activite) importer(o entreeInstantane, now int64) *activiteActeur {
	x := &activiteActeur{premier: o.Premier, dernierBan: o.Ban}
	for _, h := range o.Heures {
		if h[0] <= 0 || h[0] > now/3600+1 {
			continue
		}
		if d := x.tranche(h[0]); d != nil {
			d.evts, d.bans = u32(h[1]), u32(h[2])
			d.ips, d.pays, d.cibles = 0, 0, 0
			plus16(&d.ips, int(u32(h[3])))
			plus16(&d.pays, int(u32(h[4])))
			plus16(&d.cibles, int(u32(h[5])))
		}
	}
	for _, j := range o.Jours {
		if j[0] > 0 && j[0] <= now/86400+1 {
			x.ajouterJour(j[0], u32(j[1]))
		}
	}
	for _, h := range o.Semaine {
		if h[0] > 0 && h[0] <= now/3600+1 {
			x.ajouterSemaine(h[0], int(u32(h[1])))
		}
	}
	for m, n := range o.Modules {
		x.modules[indexModule(m)] += n
	}
	for n, v := range o.Tech {
		x.ajouterTech(t.nom(n), v)
	}
	return x
}

// prendreInstantane copie l'état sous s.mu ; l'encodage et l'écriture se font hors verrou.
func (s *Server) prendreInstantane() *instantane {
	s.mu.Lock()
	defer s.mu.Unlock()
	t := &s.act
	if t.depuis == 0 {
		return nil
	}
	o := &instantane{Version: instantaneVersion, GenereLe: maintenant(), Depuis: t.depuis,
		Trous: append([][2]int64(nil), t.trous...), Global: t.exporter(&t.global)}
	o.Acteurs = make([]entreeInstantane, 0, len(t.acteurs))
	for id, x := range t.acteurs {
		a, ok := s.graph.Get(id)
		if !ok {
			continue
		}
		e := t.exporter(x)
		ips := append([]string(nil), a.IPs...)
		if len(ips) > adressesParEntree {
			vu := func(ip string) int64 {
				if f := s.sources[ip]; f != nil {
					return f.dernier
				}
				return 0
			}
			sort.SliceStable(ips, func(i, j int) bool { return vu(ips[i]) > vu(ips[j]) })
			ips = ips[:adressesParEntree]
		}
		e.IPs = ips
		o.Acteurs = append(o.Acteurs, e)
	}
	return o
}

// sauverActivite écrit l'instantané (atomique, 0600). Chemin vide : désactivé.
func (s *Server) sauverActivite() {
	if s.actChemin == "" {
		return
	}
	o := s.prendreInstantane()
	if o == nil {
		return
	}
	b, err := json.Marshal(o)
	if err == nil {
		tmp := s.actChemin + ".tmp"
		if err = os.WriteFile(tmp, b, 0o600); err == nil {
			err = os.Rename(tmp, s.actChemin)
		}
	}
	if err != nil {
		log.Printf("actord: instantané d'activité : %v", err)
	}
}

func (s *Server) boucleInstantane() {
	tic := time.NewTicker(instantanePas)
	defer tic.Stop()
	for range tic.C {
		s.sauverActivite()
	}
}

// lireInstantane rend nil si le fichier manque ou n'est pas exploitable.
func lireInstantane(chemin string, now int64) *instantane {
	if chemin == "" {
		return nil
	}
	st, err := os.Stat(chemin)
	if err == nil && st.Size() > instantaneMax {
		err = errors.New("fichier trop gros")
	}
	var b []byte
	if err == nil {
		b, err = os.ReadFile(chemin)
	}
	o := &instantane{}
	if err == nil {
		err = json.Unmarshal(b, o)
	}
	if err == nil && (o.Version != instantaneVersion || o.Depuis <= 0 || o.GenereLe < o.Depuis || o.GenereLe > now+futurTolere) {
		err = errors.New("contenu inattendu")
	}
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			log.Printf("actord: instantané d'activité ignoré : %v", err)
		}
		return nil
	}
	return o
}

// ouvrirRejeu pose la couverture avant le rejeu de [plusAncien, plusRecent] (0, 0 : magasin vide) et
// rend l'instantané à verser ensuite, nil s'il ne rejoint pas le rejeu.
func (s *Server) ouvrirRejeu(plusAncien, plusRecent int64) *instantane {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, now := &s.act, maintenant()
	if plusAncien <= 0 || plusAncien > now {
		plusAncien, plusRecent = now, now
	}
	t.depuis, t.depuisGraphe, t.trous = plusAncien, plusAncien, nil
	o := lireInstantane(s.actChemin, now)
	if o != nil && (o.GenereLe < plusAncien || o.Depuis > plusAncien) {
		log.Printf("actord: instantané d'activité écarté (ne rejoint pas le rejeu)")
		o = nil
	}
	dernier := plusRecent
	if o != nil {
		t.depuis, t.seuil = o.Depuis, o.GenereLe
		dernier = max(dernier, o.GenereLe)
		for _, tr := range o.Trous {
			if tr[0] < tr[1] {
				t.trous = append(t.trous, tr)
			}
		}
	}
	if now-dernier > trouMin {
		t.trous = append(t.trous, [2]int64{dernier, now})
	}
	if n := len(t.trous); n > trousMax {
		// Au-delà du plafond, la couverture repart après les plus anciens trous.
		t.depuis = max(t.depuis, t.trous[n-trousMax-1][1])
		t.trous = t.trous[n-trousMax:]
	}
	return o
}

// fermerRejeu verse l'instantané dans les acteurs reconstruits.
func (s *Server) fermerRejeu(o *instantane) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, now := &s.act, maintenant()
	t.seuil = 0
	if o == nil {
		return
	}
	parIP := map[string]string{}
	for _, a := range s.graph.Actors() {
		for _, ip := range a.IPs {
			parIP[ip] = a.ID
		}
	}
	repris := 0
	for _, e := range o.Acteurs {
		voix, choisi := map[string]int{}, ""
		for _, ip := range e.IPs {
			if id := parIP[ip]; id != "" {
				voix[id]++
				if choisi == "" || voix[id] > voix[choisi] || voix[id] == voix[choisi] && id < choisi {
					choisi = id
				}
			}
		}
		if x := t.acteurs[choisi]; choisi != "" && x != nil {
			x.verser(t.importer(e, now))
			repris++
		}
	}
	t.global.verser(t.importer(o.Global, now))
	log.Printf("actord: activité reprise pour %d acteur(s) sur %d (couverture depuis %s)",
		repris, len(o.Acteurs), time.Unix(t.depuis, 0).UTC().Format(time.RFC3339))
}
