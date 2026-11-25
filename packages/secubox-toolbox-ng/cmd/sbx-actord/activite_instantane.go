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
// (les plus récentes) à l'acteur reconstruit qui en porte le plus. Une entrée sans acteur attend que
// l'une de ses adresses revienne (15 jours au plus). L'instantané n'est repris que s'il rejoint le rejeu
// (sinon la couverture aurait une lacune inconnue). RIEN n'est rendu au graphe.
const (
	instantanePas     = time.Hour
	instantaneVersion = 1
	instantaneMaxDef  = 64 << 20
	adressesParEntree = 512
	// avanceTolere : l'instantané peut dépasser l'horloge du démarrage (pas de pile) ; ce qu'il date
	// au-delà de maintenant n'est pas repris, et la remise à l'heure sera un trou (verifierHorloge).
	avanceTolere = 86400
	attenteMax   = 200000 // adresses en attente
)

// instantaneMax : plafond du fichier, à la lecture comme à l'écriture ; réduit en test.
var instantaneMax = instantaneMaxDef

type entreeInstantane struct {
	IPs     []string          `json:"ips"`
	Premier int64             `json:"premier"`
	Depuis  int64             `json:"d,omitempty"`
	Plein   int64             `json:"p,omitempty"`
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
	o := entreeInstantane{Premier: x.premier, Ban: x.dernierBan, Depuis: x.depuis, Plein: x.plein}
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
	x := &activiteActeur{premier: o.Premier, dernierBan: o.Ban, depuis: o.Depuis, plein: o.Plein}
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

// dernierJour : jour absolu de la dernière activité de l'entrée.
func (o *entreeInstantane) dernierJour() int64 {
	if n := len(o.Jours); n > 0 {
		return o.Jours[n-1][0]
	}
	return 0
}

// prendreInstantane copie l'état sous s.mu ; l'encodage et l'écriture se font hors verrou.
func (s *Server) prendreInstantane() *instantane {
	s.mu.Lock()
	defer s.mu.Unlock()
	t := &s.act
	if t.depuis == 0 {
		return nil
	}
	now := maintenant()
	t.verifierHorloge(now)
	t.global.remettre(now)
	o := &instantane{Version: instantaneVersion, GenereLe: now, Depuis: t.depuis,
		Trous: append([][2]int64(nil), t.trous...), Global: t.exporter(&t.global)}
	o.Acteurs = make([]entreeInstantane, 0, len(t.acteurs))
	for id, x := range t.acteurs {
		a, ok := s.graph.Get(id)
		if !ok {
			continue
		}
		x.remettre(now)
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
	vues := map[*entreeInstantane]bool{}
	for _, e := range t.attente {
		if !vues[e] && e.dernierJour() > o.GenereLe/86400-joursGardes {
			vues[e] = true
			o.Acteurs = append(o.Acteurs, *e)
		}
	}
	return o
}

// sauverActivite écrit l'instantané (atomique, 0600). Chemin vide : désactivé.
func (s *Server) sauverActivite() {
	if s.actChemin == "" {
		return
	}
	s.actEcrit.Lock() // la passe horaire et l'arrêt peuvent se croiser
	defer s.actEcrit.Unlock()
	o := s.prendreInstantane()
	if o == nil {
		return
	}
	b, err := o.encoder()
	if err == nil {
		tmp := s.actChemin + ".tmp"
		if err = ecrireSync(tmp, b); err == nil {
			err = os.Rename(tmp, s.actChemin)
		}
	}
	if err != nil {
		log.Printf("actord: instantané d'activité : %v", err)
	}
}

// encoder rend l'instantané sous instantaneMax, sans quoi il ne se relirait pas : les entrées les plus
// anciennes partent d'abord (leurs acteurs repartiront du rejeu).
func (o *instantane) encoder() ([]byte, error) {
	b, err := json.Marshal(o)
	if err != nil || len(b) <= instantaneMax {
		return b, err
	}
	total := len(o.Acteurs)
	sort.SliceStable(o.Acteurs, func(i, j int) bool { return o.Acteurs[i].dernierJour() > o.Acteurs[j].dernierJour() })
	for len(b) > instantaneMax && len(o.Acteurs) > 0 && err == nil {
		// Au prorata, avec une marge : deux ou trois tours au plus.
		n := int(int64(len(o.Acteurs)) * int64(instantaneMax) * 9 / (int64(len(b)) * 10))
		o.Acteurs = o.Acteurs[:min(n, len(o.Acteurs)-1)]
		b, err = json.Marshal(o)
	}
	if err == nil && len(b) > instantaneMax {
		err = errors.New("trop gros sans aucun acteur")
	}
	log.Printf("actord: instantané d'activité : %d entrée(s) sur %d (plafond de taille)", len(o.Acteurs), total)
	return b, err
}

// ecrireSync : contenu sur le disque avant le renommage (coupure de courant).
func ecrireSync(chemin string, b []byte) error {
	f, err := os.OpenFile(chemin, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	_, err = f.Write(b)
	return errors.Join(err, f.Sync(), f.Close())
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
	if err == nil && st.Size() > int64(instantaneMax) {
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
	if err == nil && (o.Version != instantaneVersion || o.Depuis <= 0 || o.GenereLe < o.Depuis || o.GenereLe > now+avanceTolere) {
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
	t.mur, t.mono = now, monotone()
	t.depuis, t.depuisGraphe, t.trous = plusAncien, plusAncien, nil
	o := lireInstantane(s.actChemin, now)
	dernier := plusRecent
	if o != nil {
		// Les trous connus valent aussi pour le rejeu, même si l'instantané est écarté ensuite.
		for _, tr := range o.Trous {
			if tr[0] < tr[1] && tr[0] < now {
				t.ajouterTrou(tr[0], min(tr[1], now))
			}
		}
		if o.GenereLe < plusAncien || o.Depuis > plusAncien {
			log.Printf("actord: instantané d'activité écarté (ne rejoint pas le rejeu)")
			o = nil
		}
	}
	if o != nil {
		t.depuis, t.seuil = max(o.Depuis, t.depuisTrous), min(o.GenereLe, now)
		dernier = max(dernier, o.GenereLe)
	}
	if now-dernier > trouMin {
		t.ajouterTrou(dernier, now)
	}
	t.enRejeu = true
	return o
}

// fermerRejeu verse l'instantané dans les acteurs reconstruits. Trois cas : l'acteur choisi par une
// entrée reçoit l'entrée plus ce que le rejeu a vu APRÈS elle ; un acteur qui porte une adresse d'une
// entrée versée ailleurs ne garde que l'après (le reste y est déjà compté) ; les autres gardent tout
// leur rejeu, couverts depuis son début.
func (s *Server) fermerRejeu(o *instantane) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t := &s.act
	now := maintenant()
	t.seuil, t.enRejeu = 0, false
	if o == nil {
		return
	}
	parIP := map[string][]string{}
	for _, a := range s.graph.Actors() {
		for _, ip := range a.IPs {
			parIP[ip] = append(parIP[ip], a.ID)
		}
	}
	choix := make([]string, len(o.Acteurs))
	touches, repris := map[string]bool{}, map[string]bool{}
	for i, e := range o.Acteurs {
		voix, choisi := map[string]int{}, ""
		for _, ip := range e.IPs {
			for _, id := range parIP[ip] {
				if t.acteurs[id] == nil {
					continue
				}
				touches[id] = true
				voix[id]++
				if choisi == "" || voix[id] > voix[choisi] || voix[id] == voix[choisi] && id < choisi {
					choisi = id
				}
			}
		}
		choix[i] = choisi
	}
	for id := range touches {
		x := t.acteurs[id]
		ap := x.apres
		if ap == nil {
			ap = &activiteActeur{}
		}
		ap.premier, ap.dernierBan, ap.temoin = x.premier, x.dernierBan, x.temoin
		ap.nIPs, ap.nPays, ap.nCible = x.nIPs, x.nPays, x.nCible
		ap.depuis, ap.plein = min(o.GenereLe, now), min(o.GenereLe, now)
		t.acteurs[id] = ap
	}
	var seules []*entreeInstantane
	for i, e := range o.Acteurs {
		id := choix[i]
		if id == "" {
			seules = append(seules, &o.Acteurs[i])
			continue
		}
		x, b := t.acteurs[id], t.importer(e, now)
		if !repris[id] { // l'entrée EST cet acteur : sa couverture, pas une fusion
			x.depuis, x.plein = b.depuis, b.plein
			repris[id] = true
		}
		x.verser(b)
	}
	for _, x := range t.acteurs {
		x.apres = nil
	}
	// Les plus récentes d'abord : ce sont elles qui peuvent revenir.
	sort.SliceStable(seules, func(i, j int) bool { return seules[i].dernierJour() > seules[j].dernierJour() })
	for _, e := range seules {
		t.mettreEnAttente(e, now)
	}
	t.global.verser(t.importer(o.Global, now))
	log.Printf("actord: activité reprise pour %d acteur(s) sur %d (couverture depuis %s)",
		len(repris), len(o.Acteurs), time.Unix(t.depuis, 0).UTC().Format(time.RFC3339))
}

// mettreEnAttente garde une entrée sans acteur, par adresse ; bornée en entrées et en adresses.
func (t *activite) mettreEnAttente(e *entreeInstantane, now int64) {
	if e.dernierJour() <= now/86400-joursGardes || len(e.IPs) == 0 || t.nAttente >= activiteMax || len(t.attente)+len(e.IPs) > attenteMax {
		return
	}
	if t.attente == nil {
		t.attente = map[string]*entreeInstantane{}
	}
	pris := false
	for _, ip := range e.IPs {
		if t.attente[ip] == nil { // une adresse ne désigne qu'une entrée : la plus récente
			t.attente[ip], pris = e, true
		}
	}
	if pris {
		t.nAttente++
	}
}

func (t *activite) retirerAttente(e *entreeInstantane) {
	vue := false
	for _, ip := range e.IPs {
		if t.attente[ip] == e {
			delete(t.attente, ip)
			vue = true
		}
	}
	if vue {
		t.nAttente--
	}
}

// purgerAttente oublie les entrées sans activité depuis joursGardes jours. Sous s.mu.
func (t *activite) purgerAttente(now int64) {
	for _, e := range t.attente {
		if e.dernierJour() <= now/86400-joursGardes {
			t.retirerAttente(e)
		}
	}
}
