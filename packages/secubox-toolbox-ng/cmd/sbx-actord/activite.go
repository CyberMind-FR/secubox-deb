// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package main

import (
	"regexp"
	"sort"
	"unicode/utf8"

	"github.com/CyberMind-FR/secubox-deb/secubox-toolbox-ng/internal/actor/envelope"
	"github.com/CyberMind-FR/secubox-deb/secubox-toolbox-ng/internal/actor/graph"
)

// Activité par acteur (#3936) : compteurs horaires et journaliers tenus À L'INGESTION.
//
// POURQUOI EN MÉMOIRE. Le graphe ne garde aucune série ; l'aperçu ne relit que les 5 000 derniers
// événements (un acteur sur trois) ; balayer sept jours du magasin à chaque profil coûterait des
// secondes sur une box saturée. Ici un événement coûte quelques additions, et une lecture ne touche
// jamais le magasin.
//
// CE QUE CES COMPTEURS NE FONT PAS. Ils LISENT l'acteur que le graphe vient de choisir ; ils ne le
// modifient pas et n'alimentent ni rattachement, ni score, ni mesure, ni proposition
// (correlation_3936_test.go fige la corrélation octet pour octet).
//
// MESURE ABSENTE ≠ ZÉRO. `depuis` dit à partir de quand on compte. Une tranche d'avant, ou dans un
// trou (démon arrêté), vaut null ; une tranche couverte en partie est servie ET signalée partielle.
//
// MÉMOIRE : environ 1 Ko par acteur (3 658 acteurs sur gk2 : moins de 4 Mo), plafond activiteMax.
// Au plafond, un acteur nouveau n'a pas de série (null), il n'en chasse aucun.
const (
	heuresGardees = 50 // deux fenêtres de 24 h pleines, plus l'heure en cours
	joursGardes   = 15 // la rétention des événements (--retention 360h)
	activiteMax   = 20000
	nomsMax       = 4096 // noms de techniques distincts retenus
	techParActeur = 24
	techNomMax    = 64
	trousMax      = 8
	trouMin       = 600 // secondes : un redémarrage ordinaire n'est pas un trou
	futurTolere   = 300
	// chauffeNouveau : pour dire qu'une adresse est NOUVELLE, il faut l'avoir cherchée un moment.
	chauffeNouveau = 24 // heures
	techAutres     = "autres"
)

// modulesConnus : liste fermée des capteurs (envelope) ; le dernier rang compte le reste.
var modulesConnus = [...]string{envelope.SensorWAF, envelope.SensorDPI, envelope.SensorAuthWatch, envelope.SensorSentinel,
	envelope.SensorFirewall, envelope.SensorDNS, envelope.SensorReplay, "autre"}

func indexModule(m string) int {
	for i, x := range modulesConnus {
		if x == m {
			return i
		}
	}
	return len(modulesConnus) - 1
}

// trancheHeure : ce qu'une heure a compté pour un acteur.
type trancheHeure struct {
	evts, bans        uint32
	ips, pays, cibles uint16 // NOUVEAUX sur cette heure
}

type techniqueN struct {
	nom uint16
	n   uint32
}

type activiteActeur struct {
	premier, dernierBan int64
	temoin              string // une adresse de l'acteur : retrouve l'absorbeur après une fusion
	heure               int64  // dernière heure écrite (epoch / 3600) ; les anneaux sont relatifs à elle
	jour                int64  // dernier jour écrit (epoch / 86400, UTC)
	heures              [heuresGardees]trancheHeure
	jours               [joursGardes]uint32
	modules             [len(modulesConnus)]uint32
	tech                []techniqueN
	nIPs, nPays, nCible int
}

// activite : l'ensemble. Tout accès se fait sous Server.mu.
type activite struct {
	acteurs map[string]*activiteActeur
	depuis  int64 // début de la couverture ; 0 = rien compté
	// depuisGraphe : plus ancien événement vu par CE graphe. Une adresse n'est « nouvelle » que
	// par rapport à lui (le rejeu de démarrage ne recharge pas les adresses plus anciennes).
	depuisGraphe int64
	trous        [][2]int64
	seuil        int64 // pendant le rejeu : ce qui est antérieur est déjà dans l'instantané
	noms         []string
	parNom       map[string]uint16
	global       activiteActeur // série de tous les événements (robots connus compris, comme /stats)
}

func avancer[T any](anneau []T, dernier *int64, rang int64) bool {
	n := int64(len(anneau))
	if *dernier == 0 {
		*dernier = rang
	}
	if rang <= *dernier-n {
		return false // trop ancien pour l'anneau
	}
	var zero T
	for *dernier < rang {
		if rang-*dernier > n {
			*dernier = rang - n
		}
		*dernier++
		anneau[*dernier%n] = zero
	}
	return true
}

// lireRang rend la case d'un rang, ou zéro s'il n'y est pas (après le dernier écrit : rien compté).
func lireRang[T any](anneau []T, dernier, rang int64) T {
	var zero T
	n := int64(len(anneau))
	if dernier == 0 || rang > dernier || rang <= dernier-n {
		return zero
	}
	return anneau[rang%n]
}

func (x *activiteActeur) tranche(heure int64) *trancheHeure {
	if !avancer(x.heures[:], &x.heure, heure) {
		return nil
	}
	return &x.heures[heure%heuresGardees]
}

func (x *activiteActeur) ajouterJour(jour int64, n uint32) {
	if avancer(x.jours[:], &x.jour, jour) {
		x.jours[jour%joursGardes] += n
	}
}

func plus16(p *uint16, n int) {
	if n <= 0 {
		return
	}
	if v := int(*p) + n; v < 65535 {
		*p = uint16(v)
	} else {
		*p = 65535
	}
}

func estBlocage(e *envelope.Envelope) bool {
	return e.Action == envelope.ActionBlock || e.Action == envelope.ActionQuarantps
}

// noterGlobal compte un événement dans la série d'ensemble. Sous s.mu.
func (t *activite) noterGlobal(e *envelope.Envelope) {
	if !t.admis(e) || t.seuil > 0 && e.Timestamp <= t.seuil {
		return
	}
	if h := t.global.tranche(e.Timestamp / 3600); h != nil {
		h.evts++
		if estBlocage(e) {
			h.bans++
		}
	}
}

// admis ouvre la couverture au premier événement et écarte une horloge absurde.
func (t *activite) admis(e *envelope.Envelope) bool {
	if e.Timestamp <= 0 || e.Timestamp > maintenant()+futurTolere {
		return false
	}
	if t.depuis == 0 || t.depuisGraphe == 0 {
		t.ouvrir(e.Timestamp)
	}
	return true
}

func (t *activite) ouvrir(ts int64) {
	if t.depuis == 0 {
		t.depuis = ts
	}
	if t.depuisGraphe == 0 {
		t.depuisGraphe = ts
	}
}

// noter compte un événement pour l'acteur que le graphe lui a choisi (a est seulement LU). Sous s.mu.
func (t *activite) noter(a *graph.Actor, e *envelope.Envelope) {
	if !t.admis(e) {
		return
	}
	x := t.acteurs[a.ID]
	if x == nil {
		if len(t.acteurs) >= activiteMax {
			return
		}
		if t.acteurs == nil {
			t.acteurs = map[string]*activiteActeur{}
		}
		x = &activiteActeur{premier: e.Timestamp}
		t.acteurs[a.ID] = x
	}
	x.temoin = e.SrcIP
	dIP, dPays, dCible := len(a.IPs)-x.nIPs, len(a.Countries)-x.nPays, len(a.Targets)-x.nCible
	x.nIPs, x.nPays, x.nCible = len(a.IPs), len(a.Countries), len(a.Targets)
	if e.Timestamp < x.premier {
		x.premier = e.Timestamp
	}
	bloc := e.Action == envelope.ActionBlock // le même critère que graph.Actor.Bans
	if bloc && e.Timestamp > x.dernierBan {
		x.dernierBan = e.Timestamp
	}
	if t.seuil > 0 && e.Timestamp <= t.seuil {
		return // déjà compté dans l'instantané rechargé
	}
	if h := x.tranche(e.Timestamp / 3600); h != nil {
		h.evts++
		if bloc {
			h.bans++
		}
		plus16(&h.ips, dIP)
		plus16(&h.pays, dPays)
		plus16(&h.cibles, dCible)
	}
	x.ajouterJour(e.Timestamp/86400, 1)
	x.modules[indexModule(e.Sensor)]++
	x.ajouterTech(t.nom(typeEvenement(*e)), 1)
}

func (x *activiteActeur) ajouterTech(nom uint16, n uint32) {
	for i := range x.tech {
		if x.tech[i].nom == nom {
			x.tech[i].n += n
			return
		}
	}
	if len(x.tech) >= techParActeur && nom != 0 {
		x.ajouterTech(0, n)
		return
	}
	x.tech = append(x.tech, techniqueN{nom, n})
}

// motifAdresse : un nom de technique qui porterait une adresse n'est pas retenu.
var motifAdresse = regexp.MustCompile(`\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|[0-9A-Fa-f]{0,4}:[0-9A-Fa-f]{0,4}:|@`)

// nom rend le rang d'un nom de technique dans la table partagée (0 = « autres »).
func (t *activite) nom(n string) uint16 {
	if utf8.RuneCountInString(n) > techNomMax {
		n = string([]rune(n)[:techNomMax])
	}
	if i, ok := t.parNom[n]; ok {
		return i
	}
	if t.parNom == nil {
		t.parNom, t.noms = map[string]uint16{techAutres: 0}, []string{techAutres}
	}
	if n == "" || len(t.noms) >= nomsMax || motifAdresse.MatchString(n) {
		return 0
	}
	i := uint16(len(t.noms))
	n = string(append([]byte(nil), n...)) // ne retient pas l'enveloppe d'origine
	t.noms, t.parNom[n] = append(t.noms, n), i
	return i
}

// verser ajoute b à x (fusion d'acteurs, ou instantané rechargé).
func (x *activiteActeur) verser(b *activiteActeur) {
	if b.premier != 0 && (x.premier == 0 || b.premier < x.premier) {
		x.premier = b.premier
	}
	x.dernierBan = max(x.dernierBan, b.dernierBan)
	for r := b.heure - heuresGardees + 1; b.heure > 0 && r <= b.heure; r++ {
		src := lireRang(b.heures[:], b.heure, r)
		if src == (trancheHeure{}) {
			continue
		}
		if d := x.tranche(r); d != nil {
			d.evts += src.evts
			d.bans += src.bans
			plus16(&d.ips, int(src.ips))
			plus16(&d.pays, int(src.pays))
			plus16(&d.cibles, int(src.cibles))
		}
	}
	for r := b.jour - joursGardes + 1; b.jour > 0 && r <= b.jour; r++ {
		if n := lireRang(b.jours[:], b.jour, r); n > 0 {
			x.ajouterJour(r, n)
		}
	}
	for i, n := range b.modules {
		x.modules[i] += n
	}
	for _, te := range b.tech {
		x.ajouterTech(te.nom, te.n)
	}
}

// suivreFusions rattache à l'absorbeur les compteurs d'un acteur que le graphe a fusionné : après
// Consolider, l'adresse témoin de l'absorbé est une adresse de l'absorbeur. Sous s.mu.
func (t *activite) suivreFusions(g *graph.Graph) {
	orphelins := map[string][]*activiteActeur{}
	for id, x := range t.acteurs {
		if _, ok := g.Get(id); !ok {
			orphelins[x.temoin] = append(orphelins[x.temoin], x)
			delete(t.acteurs, id)
		}
	}
	if len(orphelins) == 0 {
		return
	}
	for _, a := range g.Actors() {
		for _, ip := range a.IPs {
			l := orphelins[ip]
			if l == nil {
				continue
			}
			delete(orphelins, ip)
			x := t.acteurs[a.ID]
			if x == nil {
				x = &activiteActeur{temoin: ip}
				t.acteurs[a.ID] = x
			}
			for _, o := range l {
				x.verser(o)
			}
		}
		if x := t.acteurs[a.ID]; x != nil { // une fusion n'apporte aucune adresse NOUVELLE
			x.nIPs, x.nPays, x.nCible = len(a.IPs), len(a.Countries), len(a.Targets)
		}
	}
}

// ── Lecture ─────────────────────────────────────────────────────────────────────────────────────

const (
	couvNulle = iota
	couvPartielle
	couvPleine
)

// couverture dit si [a, b[ (borné à maintenant) a été observé.
func (t *activite) couverture(a, b, now int64) int {
	if t.depuis == 0 || b <= t.depuis || a > now {
		return couvNulle
	}
	b = min(b, now)
	etat := couvPleine
	if a < t.depuis {
		etat = couvPartielle
	}
	for _, tr := range t.trous {
		if tr[0] <= max(a, t.depuis) && tr[1] >= b {
			return couvNulle
		}
		if tr[0] < b && tr[1] > a {
			etat = couvPartielle
		}
	}
	return etat
}

// serieVue : une série datée. null = tranche non couverte ; Partielles = rangs couverts en partie.
// La dernière tranche est toujours en cours.
type serieVue struct {
	Debut      int64     `json:"debut"` // epoch du début de la première tranche
	Pas        int64     `json:"pas"`
	Valeurs    []*uint32 `json:"valeurs"`
	Partielles []int     `json:"partielles,omitempty"`
}

func (t *activite) serie(pas int64, n int, now int64, val func(rang int64) uint32) serieVue {
	fin := now / pas
	s := serieVue{Debut: (fin - int64(n) + 1) * pas, Pas: pas, Valeurs: make([]*uint32, n)}
	for i := range s.Valeurs {
		r := fin - int64(n) + 1 + int64(i)
		c := t.couverture(r*pas, (r+1)*pas, now)
		if c == couvNulle {
			continue
		}
		if c == couvPartielle {
			s.Partielles = append(s.Partielles, i)
		}
		v := val(r)
		s.Valeurs[i] = &v
	}
	return s
}

func (x *activiteActeur) heureEvts(r int64) uint32 { return lireRang(x.heures[:], x.heure, r).evts }
func (x *activiteActeur) heureBans(r int64) uint32 { return lireRang(x.heures[:], x.heure, r).bans }
func (x *activiteActeur) jourEvts(r int64) uint32  { return lireRang(x.jours[:], x.jour, r) }

// paireTendance : les 24 dernières heures PLEINES et les 24 d'avant. Absente (null) si non mesurable.
type paireTendance struct {
	Dernieres   uint32 `json:"dernieres_24h"`
	Precedentes uint32 `json:"precedentes_24h"`
}

type tendanceVue struct {
	Evenements *paireTendance `json:"evenements"`
	Bans       *paireTendance `json:"bans"`
	Adresses   *paireTendance `json:"adresses"`  // adresses NOUVELLES pour cet acteur
	Pays       *paireTendance `json:"pays"`      // idem
	Cibles     *paireTendance `json:"nb_cibles"` // idem
}

func (t *activite) tendance(x *activiteActeur, now int64) tendanceVue {
	var v tendanceVue
	h := now / 3600
	debut := (h - 48) * 3600
	for r := h - 48; r < h; r++ {
		if t.couverture(r*3600, (r+1)*3600, now) != couvPleine {
			return v
		}
	}
	paire := func(f func(tr trancheHeure) uint32) *paireTendance {
		p := &paireTendance{}
		for r := h - 48; r < h; r++ {
			n := f(lireRang(x.heures[:], x.heure, r))
			if r >= h-24 {
				p.Dernieres += n
			} else {
				p.Precedentes += n
			}
		}
		return p
	}
	v.Evenements = paire(func(tr trancheHeure) uint32 { return tr.evts })
	v.Bans = paire(func(tr trancheHeure) uint32 { return tr.bans })
	if t.depuisGraphe <= debut-chauffeNouveau*3600 {
		v.Adresses = paire(func(tr trancheHeure) uint32 { return uint32(tr.ips) })
		v.Pays = paire(func(tr trancheHeure) uint32 { return uint32(tr.pays) })
		v.Cibles = paire(func(tr trancheHeure) uint32 { return uint32(tr.cibles) })
	}
	return v
}

func trierTechniques(l []Technique, n int) []Technique {
	sort.Slice(l, func(i, j int) bool {
		if l[i].N != l[j].N {
			return l[i].N > l[j].N
		}
		return l[i].Nom < l[j].Nom
	})
	if len(l) > n {
		l = l[:n]
	}
	return l
}

func (t *activite) techniques(x *activiteActeur) []Technique {
	l := make([]Technique, 0, len(x.tech))
	for _, te := range x.tech {
		l = append(l, Technique{Nom: t.noms[te.nom], N: int(te.n)})
	}
	return trierTechniques(l, techDetail)
}

func (x *activiteActeur) parModule() []Technique {
	var l []Technique
	for i, n := range x.modules {
		if n > 0 {
			l = append(l, Technique{Nom: modulesConnus[i], N: int(n)})
		}
	}
	return trierTechniques(l, len(modulesConnus))
}
