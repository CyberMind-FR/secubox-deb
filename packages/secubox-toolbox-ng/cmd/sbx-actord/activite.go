// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package main

import (
	"regexp"
	"sort"
	"time"
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
// MÉMOIRE : environ 1,3 Ko par acteur (3 658 acteurs sur gk2 : moins de 5 Mo), plafond activiteMax.
// Au plafond, un acteur nouveau n'a pas de série (null), il n'en chasse aucun.
const (
	heuresGardees = 50  // deux fenêtres de 24 h pleines, plus l'heure en cours
	semaineGardee = 168 // carte de chaleur heure × jour
	joursGardes   = 15  // la rétention des événements (--retention 360h)
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
	rangS               int64 // dernière heure écrite de `semaine`
	semaine             [semaineGardee]uint16
	modules             [len(modulesConnus)]uint32
	tech                []techniqueN
	nIPs, nPays, nCible int
	// Couverture PROPRE à l'acteur : avant `depuis`, rien n'est su de lui ; entre `depuis` et `plein`
	// (fusion avec un acteur suivi depuis moins longtemps), un compte non nul est un minorant et un
	// zéro n'en est pas un. 0 = la couverture commune (série d'ensemble).
	depuis, plein int64
	// apres : pendant le rejeu, ce qui est postérieur à l'instantané ; retiré à la fin du rejeu.
	apres *activiteActeur
}

// activite : l'ensemble. Tout accès se fait sous Server.mu.
type activite struct {
	acteurs map[string]*activiteActeur
	depuis  int64 // début de la couverture ; 0 = rien compté
	// depuisGraphe : plus ancien événement vu par CE graphe. Une adresse n'est « nouvelle » que
	// par rapport à lui (le rejeu de démarrage ne recharge pas les adresses plus anciennes).
	depuisGraphe int64
	trous        [][2]int64
	// attente : entrées de l'instantané dont aucun acteur du rejeu ne porte une adresse, par adresse ;
	// reprises quand une de leurs adresses revient, réécrites dans l'instantané, oubliées à 15 jours.
	attente  map[string]*entreeInstantane
	nAttente int
	// depuisTrous : fin du dernier trou abandonné au plafond ; la couverture ne remonte pas avant.
	depuisTrous int64
	// mur et mono : horloges à la dernière vérification (verifierHorloge).
	mur, mono int64
	enRejeu   bool
	seuil     int64 // pendant le rejeu : ce qui est antérieur est déjà dans l'instantané
	noms      []string
	parNom    map[string]uint16
	global    activiteActeur // série de tous les événements (robots connus compris, comme /stats)
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

func (x *activiteActeur) ajouterSemaine(heure int64, n int) {
	if avancer(x.semaine[:], &x.rangS, heure) {
		plus16(&x.semaine[heure%semaineGardee], n)
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

// debutProcessus et monotone : une horloge que ni NTP ni l'opérateur ne déplacent.
var debutProcessus = time.Now()
var monotone = func() int64 { return int64(time.Since(debutProcessus) / time.Second) }

// verifierHorloge compare le temps mural écoulé au temps réellement passé. Saut en avant (remise à
// l'heure, mise en veille) : le morceau sauté n'a pas été observé, c'est un trou. Saut en arrière :
// ce qui se trouve dans le futur est retiré, pour tous les acteurs, actifs ou non. Aucune déduction
// tirée de la date d'un événement ou d'un fichier. Sous s.mu.
func (t *activite) verifierHorloge(now int64) {
	m := monotone()
	mur, mono := t.mur, t.mono
	t.mur, t.mono = now, m
	if mur == 0 {
		return
	}
	saut := (now - mur) - (m - mono)
	switch {
	case saut > futurTolere:
		t.ajouterTrou(mur, now)
	case saut < -futurTolere:
		t.depuis, t.depuisGraphe = min(t.depuis, now), min(t.depuisGraphe, now)
		garde := t.trous[:0]
		for _, tr := range t.trous {
			if tr[0] < now {
				garde = append(garde, [2]int64{tr[0], min(tr[1], now)})
			}
		}
		t.trous = garde
		t.depuisTrous = min(t.depuisTrous, now)
		t.global.remettre(now)
		for _, x := range t.acteurs {
			x.remettre(now)
		}
	}
}

// dansLeFutur : un saut d'horloge en avant a poussé les anneaux au-delà de maintenant.
func (x *activiteActeur) dansLeFutur(now int64) bool {
	return x.heure > now/3600+1 || x.rangS > now/3600+1 || x.jour > now/86400+1 || x.depuis > now+futurTolere || x.plein > now+futurTolere
}

// remettre vide des anneaux partis dans le futur : sans cela, plus aucun événement n'y entrerait. Ce
// qu'ils savaient est perdu, la couverture repart de maintenant.
func (x *activiteActeur) remettre(now int64) {
	if !x.dansLeFutur(now) {
		return
	}
	*x = activiteActeur{premier: min(x.premier, now), dernierBan: min(x.dernierBan, now), temoin: x.temoin, modules: x.modules, tech: x.tech,
		nIPs: x.nIPs, nPays: x.nPays, nCible: x.nCible, depuis: now, plein: now}
}

// noterGlobal compte un événement dans la série d'ensemble. Sous s.mu.
func (t *activite) noterGlobal(e *envelope.Envelope) {
	if !t.admis(e) || t.seuil > 0 && e.Timestamp <= t.seuil {
		return
	}
	t.global.remettre(maintenant())
	if h := t.global.tranche(e.Timestamp / 3600); h != nil {
		h.evts++
		if estBlocage(e) {
			h.bans++
		}
	}
}

// admis ouvre la couverture au premier événement et écarte une horloge absurde.
func (t *activite) admis(e *envelope.Envelope) bool {
	now := maintenant()
	t.verifierHorloge(now)
	if e.Timestamp <= 0 || e.Timestamp > now+futurTolere {
		return false // un événement daté en avance n'avance aucun anneau, au rejeu non plus
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
		x = &activiteActeur{premier: e.Timestamp, depuis: t.depuisGraphe, plein: t.depuisGraphe}
		if a.Events > 1 { // déjà connu du graphe, pas de nous (plafond) : on ne sait rien d'avant
			x.depuis, x.plein = e.Timestamp, e.Timestamp
		}
		t.acteurs[a.ID] = x
		t.reprendre(x, e.SrcIP, true)
	} else {
		t.reprendre(x, e.SrcIP, false)
	}
	x.remettre(maintenant())
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
	cpt := func(x *activiteActeur) {
		if h := x.tranche(e.Timestamp / 3600); h != nil {
			h.evts++
			if bloc {
				h.bans++
			}
			plus16(&h.ips, dIP)
			plus16(&h.pays, dPays)
			plus16(&h.cibles, dCible)
		}
		x.ajouterSemaine(e.Timestamp/3600, 1)
		x.ajouterJour(e.Timestamp/86400, 1)
		x.modules[indexModule(e.Sensor)]++
		x.ajouterTech(t.nom(typeEvenement(*e)), 1)
	}
	cpt(x)
	if t.seuil > 0 && e.Timestamp > t.seuil { // rejeu : ce que l'instantané n'a pas
		if x.apres == nil {
			x.apres = &activiteActeur{}
		}
		cpt(x.apres)
	}
}

// reprendre verse dans x l'entrée en attente qui porte cette adresse. Acteur tout neuf : c'est le
// retour de l'ancien, avec sa couverture. Sinon, la règle des fusions (verser).
func (t *activite) reprendre(x *activiteActeur, ip string, neuf bool) {
	if t.enRejeu || len(t.attente) == 0 {
		return
	}
	o := t.attente[ip]
	if o == nil {
		return
	}
	t.retirerAttente(o)
	b := t.importer(*o, maintenant())
	if neuf {
		x.depuis, x.plein = b.depuis, b.plein
	}
	x.verser(b)
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
	if b.depuis > 0 {
		if x.depuis == 0 || b.depuis < x.depuis {
			x.depuis = b.depuis
		}
		x.plein = max(x.plein, b.plein)
	}
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
	for r := b.rangS - semaineGardee + 1; b.rangS > 0 && r <= b.rangS; r++ {
		if n := lireRang(b.semaine[:], b.rangS, r); n > 0 {
			x.ajouterSemaine(r, int(n))
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
//
// Une adresse PARTAGÉE par plusieurs acteurs ne survit pas à Consolider (c'est une preuve de fusion) ;
// s'il en restait, le premier acteur par priorité reçoit les compteurs, une seule fois. Un absorbé dont
// aucune adresse ne se retrouve (ne devrait pas arriver : Validate exige src_ip) est oublié.
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

func (t *activite) ajouterTrou(a, b int64) {
	t.trous = append(t.trous, [2]int64{a, b})
	if n := len(t.trous); n > trousMax {
		// Au-delà du plafond, la couverture repart après les plus anciens trous.
		t.depuisTrous = max(t.depuisTrous, t.trous[n-trousMax-1][1])
		t.depuis = max(t.depuis, t.depuisTrous)
		t.trous = t.trous[n-trousMax:]
	}
}

// ── Lecture ─────────────────────────────────────────────────────────────────────────────────────

const (
	couvNulle      = iota
	couvIncertaine // un compte non nul est un minorant, un zéro ne dit rien
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

// couvertureDe : la même, bornée par ce qu'on sait de CET acteur.
func (t *activite) couvertureDe(x *activiteActeur, a, b, now int64) int {
	c := t.couverture(a, b, now)
	if x != nil && x.dansLeFutur(now) {
		return couvNulle // jamais un zéro lu dans un anneau déplacé
	}
	if x == nil || x.depuis == 0 || c == couvNulle {
		return c
	}
	switch {
	case b <= x.depuis:
		return couvNulle
	case a < x.plein && x.plein > x.depuis:
		return couvIncertaine
	case a < x.depuis:
		return couvPartielle
	}
	return c
}

// serieVue : une série datée. null = tranche non couverte ; Partielles = rangs couverts en partie.
// La dernière tranche est toujours en cours.
type serieVue struct {
	Debut      int64     `json:"debut"` // epoch du début de la première tranche
	Pas        int64     `json:"pas"`
	Valeurs    []*uint32 `json:"valeurs"`
	Partielles []int     `json:"partielles,omitempty"`
}

func (t *activite) serieDe(x *activiteActeur, pas int64, n int, now int64, val func(rang int64) uint32) serieVue {
	return t.serie(pas, n, now, func(a, b int64) int { return t.couvertureDe(x, a, b, now) }, val)
}

func (t *activite) serie(pas int64, n int, now int64, couv func(a, b int64) int, val func(rang int64) uint32) serieVue {
	fin := now / pas
	s := serieVue{Debut: (fin - int64(n) + 1) * pas, Pas: pas, Valeurs: make([]*uint32, n)}
	for i := range s.Valeurs {
		r := fin - int64(n) + 1 + int64(i)
		c := couv(r*pas, (r+1)*pas)
		if c == couvNulle {
			continue
		}
		v := val(r)
		if c == couvIncertaine && v == 0 {
			continue
		}
		if c != couvPleine {
			s.Partielles = append(s.Partielles, i)
		}
		s.Valeurs[i] = &v
	}
	return s
}

func (x *activiteActeur) heureEvts(r int64) uint32 { return lireRang(x.heures[:], x.heure, r).evts }
func (x *activiteActeur) heureBans(r int64) uint32 { return lireRang(x.heures[:], x.heure, r).bans }
func (x *activiteActeur) jourEvts(r int64) uint32  { return lireRang(x.jours[:], x.jour, r) }

func (x *activiteActeur) semaineEvts(r int64) uint32 {
	return uint32(lireRang(x.semaine[:], x.rangS, r))
}

// serieNouveaux : des adresses, pays ou cibles NOUVEAUX par heure ; null tant que le graphe n'a pas
// regardé chauffeNouveau heures (tout y paraîtrait nouveau).
func (t *activite) serieNouveaux(now int64, f func(tr trancheHeure) uint16, x *activiteActeur) serieVue {
	s := t.serieDe(x, 3600, 24, now, func(r int64) uint32 { return uint32(f(lireRang(x.heures[:], x.heure, r))) })
	for i := range s.Valeurs {
		if s.Debut+int64(i)*3600 < t.depuisGraphe+chauffeNouveau*3600 {
			s.Valeurs[i] = nil
		}
	}
	return s
}

// seriesVue : sur 24 h, comme `heures`.
type seriesVue struct {
	Bans     serieVue `json:"bans"`
	Adresses serieVue `json:"adresses"`
	Pays     serieVue `json:"pays"`
	Cibles   serieVue `json:"nb_cibles"`
}

func (t *activite) series(x *activiteActeur, now int64) *seriesVue {
	return &seriesVue{
		Bans:     t.serieDe(x, 3600, 24, now, x.heureBans),
		Adresses: t.serieNouveaux(now, func(tr trancheHeure) uint16 { return tr.ips }, x),
		Pays:     t.serieNouveaux(now, func(tr trancheHeure) uint16 { return tr.pays }, x),
		Cibles:   t.serieNouveaux(now, func(tr trancheHeure) uint16 { return tr.cibles }, x),
	}
}

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
		if t.couvertureDe(x, r*3600, (r+1)*3600, now) != couvPleine {
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
