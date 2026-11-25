// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package main

import (
	"net/http"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/CyberMind-FR/secubox-deb/secubox-toolbox-ng/internal/actor/graph"
	"github.com/CyberMind-FR/secubox-deb/secubox-toolbox-ng/internal/reseau"
)

// DÉTAIL D'UN ACTEUR, À LA DEMANDE (#3936) : GET /actors/{id} et GET /activite.
//
// COÛT. Jamais le magasin. Le détail lit, pour UN acteur : ses compteurs (activite.go), la fiche de
// detailAdresses de ses adresses au plus, et la base ASN locale (projetée en mémoire) ; hors verrou
// pour la base. Le groupement en campagnes vient d'un double tampon. Résultat gardé detailTTL,
// detailPlaces calculs à la fois ; au-delà de detailAttente, `detail` vaut null.
//
// VUE RÉDUITE. Liste blanche, comme vue.go : ni adresse, ni cible, ni référence de preuve, ni numéro
// de réseau. Des compteurs, des noms de capteurs, de techniques (déjà dans /overview), des codes pays
// et des classes (déjà dans /campaigns), des noms d'opérateurs. La signature d'une campagne y est
// l'identifiant opaque. En vue complète s'ajoute ce que webActor portait déjà, rien d'autre.
//
// L'ASN reste hors de la corrélation (#3919) : il n'est lu ici que pour nommer des réseaux.
const (
	detailTTL      = 20 * time.Second
	detailMax      = 64 // résultats gardés
	detailPlaces   = 2
	detailAttente  = 3 * time.Second
	detailAdresses = 3000 // adresses examinées par détail ; au-delà, une sur k, et on le dit
	campDetTTL     = 60 * time.Second
	operateursTop  = 5
	paysTopDetail  = 8
	techDetail     = 8
	activiteIDs    = 60
)

type cacheDetail struct {
	mu     sync.Mutex
	vals   map[string]detailGarde
	places chan struct{}
}

type detailGarde struct {
	at time.Time
	d  *detailActeur
}

type operateurPart struct {
	Nom    string `json:"nom"`
	Classe string `json:"classe"`
	Part   int    `json:"part"`
}

// reseauxVue : parts (en %) des adresses EXAMINÉES de l'acteur.
type reseauxVue struct {
	Examinees  int             `json:"adresses_examinees"`
	Classes    map[string]int  `json:"classes"`
	Operateurs []operateurPart `json:"operateurs"`
}

// paysVue : parts parmi les adresses vues depuis moins de 48 h (celles dont on garde le pays).
type paysVue struct {
	Adresses int        `json:"adresses"`
	Top      []PaysPart `json:"top"`
}

type campagneDeActeur struct {
	Signature string `json:"signature"`
	Famille   string `json:"famille"`
	NbActeurs int    `json:"nb_acteurs"`
	Sources   int    `json:"sources"`
	Rotation  bool   `json:"rotation"`
}

// detailActeur : ce que /actors/{id} ajoute. Un bloc absent ou null n'a pas été mesuré.
type detailActeur struct {
	GenereLe         int64 `json:"genere_le"`
	CouvertureDepuis int64 `json:"couverture_depuis,omitempty"`
	// PremierBorne : le premier passage touche le début de la couverture ; l'acteur peut être plus ancien.
	PremierBorne bool               `json:"premier_borne"`
	Evenements   int                `json:"evenements"`
	Heures       *serieVue          `json:"heures"`
	Semaine      *serieVue          `json:"semaine"` // 168 heures
	Jours        *serieVue          `json:"jours"`   // 15 jours UTC
	Series       *seriesVue         `json:"series"`
	Tendance     *tendanceVue       `json:"tendance"`
	Modules      []Technique        `json:"modules"`
	Techniques   []Technique        `json:"techniques"`
	Pays         *paysVue           `json:"pays"`
	Reseaux      *reseauxVue        `json:"reseaux"`
	DernierBan   *int64             `json:"dernier_ban"`
	Mesure       *mesureVue         `json:"mesure"`
	Campagnes    []campagneDeActeur `json:"campagnes"`
}

// premierVu : premier passage connu, instantané d'activité compris (le graphe, lui, n'est pas
// modifié : il ne connaît que son rejeu). Sous s.mu.
func (s *Server) premierVu(a *graph.Actor) int64 {
	if x := s.act.acteurs[a.ID]; x != nil && x.premier > 0 && (a.FirstSeen == 0 || x.premier < a.FirstSeen) {
		return x.premier
	}
	return a.FirstSeen
}

func (s *Server) handleActor(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	reduite := vueReduite(r)
	s.mu.Lock()
	a, ok := s.graph.Get(id)
	var red webActorReduit
	var comp webActor
	if ok {
		if reduite {
			red = toWebReduit(a)
			red.Premier = s.premierVu(a)
		} else {
			comp = toWeb(a)
			comp.Targets = append([]string(nil), a.Targets...) // encodé hors verrou
			comp.Premier = s.premierVu(a)
		}
	}
	s.mu.Unlock()
	if !ok {
		http.Error(w, "acteur inconnu", http.StatusNotFound)
		return
	}
	d := s.detail(id, reduite, r) // nil : toutes les places prises ; la fiche de base est servie quand même
	if reduite {
		writeJSON(w, struct {
			webActorReduit
			Detail *detailActeur `json:"detail"`
		}{red, d})
		return
	}
	writeJSON(w, struct {
		webActor
		Detail *detailActeur `json:"detail"`
	}{comp, d})
}

// detail rend le détail gardé, ou le calcule dès qu'une place est libre ; nil : pas de place à temps, ou acteur disparu.
func (s *Server) detail(id string, reduite bool, r *http.Request) *detailActeur {
	c := &s.detailT
	cle := id
	if reduite {
		cle = "r:" + id
	}
	c.mu.Lock()
	if c.places == nil {
		c.places = make(chan struct{}, detailPlaces)
	}
	places := c.places
	g, ok := c.vals[cle]
	c.mu.Unlock()
	if ok && time.Since(g.at) < detailTTL {
		return g.d
	}
	attente := time.NewTimer(detailAttente)
	defer attente.Stop()
	select {
	case places <- struct{}{}:
	case <-attente.C:
		return nil
	case <-r.Context().Done():
		return nil
	}
	defer func() { <-places }()
	d := s.calculerDetail(id, reduite)
	if d == nil {
		return nil
	}
	c.mu.Lock()
	if c.vals == nil || len(c.vals) >= detailMax {
		c.vals = map[string]detailGarde{}
	}
	c.vals[cle] = detailGarde{time.Now(), d}
	c.mu.Unlock()
	return d
}

type adresseVue struct {
	ip   string
	asn  uint32
	pays [2]byte
}

func (s *Server) calculerDetail(id string, reduite bool) *detailActeur {
	now := maintenant()
	// Le groupement d'abord : son calcul prend lui-même s.mu.
	camps, errCamp := s.campDetT.lire(campDetTTL, s.campagnesParActeur)
	mesure := s.mesureDe(id)

	s.mu.Lock()
	a, ok := s.graph.Get(id)
	if !ok {
		s.mu.Unlock()
		return nil
	}
	t := &s.act
	d := &detailActeur{GenereLe: now, CouvertureDepuis: t.depuis, Evenements: a.Events, Mesure: mesure,
		PremierBorne: t.depuis > 0 && s.premierVu(a) < t.depuis+3600}
	if x := t.acteurs[id]; x != nil {
		h := t.serie(3600, 24, now, x.heureEvts)
		j := t.serie(86400, joursGardes, now, x.jourEvts)
		te := t.tendance(x, now)
		sem := t.serie(3600, semaineGardee, now, x.semaineEvts)
		d.Heures, d.Jours, d.Semaine, d.Tendance, d.Series = &h, &j, &sem, &te, t.series(x, now)
		d.Modules, d.Techniques = x.parModule(), t.techniques(x)
		if x.dernierBan > 0 {
			b := x.dernierBan
			d.DernierBan = &b
		}
	}
	pas := max(1, (len(a.IPs)+detailAdresses-1)/detailAdresses)
	adrs := make([]adresseVue, 0, len(a.IPs)/pas+1)
	for i := 0; i < len(a.IPs); i += pas {
		v := adresseVue{ip: a.IPs[i]}
		if f := s.sources[v.ip]; f != nil {
			v.asn, v.pays = f.asn, f.pays
		}
		adrs = append(adrs, v)
	}
	s.mu.Unlock()

	d.Pays = paysDe(adrs)
	d.Reseaux = reseauxDe(s.annuaire, adrs)
	if errCamp == nil {
		d.Campagnes = []campagneDeActeur{}
		for _, c := range camps[id] {
			sig := c.Signature
			if reduite {
				sig = s.signatureOpaque(sig)
			}
			d.Campagnes = append(d.Campagnes, campagneDeActeur{Signature: sig, Famille: c.Famille, NbActeurs: c.NbActeurs,
				Sources: c.Sources, Rotation: c.Rotation})
		}
	}
	return d
}

func (s *Server) campagnesParActeur() (map[string][]*campagne, error) {
	out := map[string][]*campagne{}
	for _, c := range s.campagnes() {
		for _, id := range c.Acteurs {
			out[id] = append(out[id], c)
		}
	}
	return out, nil
}

func paysDe(adrs []adresseVue) *paysVue {
	n, par := 0, map[string]int{}
	for _, v := range adrs {
		if v.pays != [2]byte{} {
			n++
			par[string(v.pays[:])]++
		}
	}
	if n == 0 {
		return nil
	}
	out := &paysVue{Adresses: n, Top: []PaysPart{}}
	for _, k := range premiers(par, paysTopDetail) {
		out.Top = append(out.Top, PaysPart{Code: k, Part: part(par[k], n)})
	}
	return out
}

// reseauxDe classe les adresses par la base locale (aucun DNS, aucun appel réseau). nil : base et
// catalogue muets sur toutes les adresses, donc rien de mesuré.
func reseauxDe(an *reseau.Annuaire, adrs []adresseVue) *reseauxVue {
	if len(adrs) == 0 {
		return nil
	}
	classes, parASN, exemple := map[string]int{}, map[uint32]int{}, map[uint32]string{}
	classeDe := map[uint32]string{}
	for _, v := range adrs {
		asn := v.asn
		if asn == 0 {
			asn = an.Classer(v.ip).ASN
		}
		cl, ok := classeDe[asn]
		if !ok {
			cl = an.ClasseASN(asn)
			classeDe[asn] = cl
		}
		classes[cl]++
		if asn != 0 {
			parASN[asn]++
			exemple[asn] = v.ip
		}
	}
	if len(parASN) == 0 {
		return nil
	}
	out := &reseauxVue{Examinees: len(adrs), Classes: map[string]int{}, Operateurs: []operateurPart{}}
	for k, v := range classes {
		out.Classes[k] = part(v, len(adrs))
	}
	// Un opérateur peut annoncer plusieurs réseaux : on compte par nom.
	type op struct {
		n      int
		classe string
	}
	parNom, noms := map[string]op{}, map[string]int{}
	for asn, n := range parASN {
		nom := an.Classer(exemple[asn]).Org
		if nom == "" {
			continue
		}
		o := parNom[nom]
		if o.n == 0 || classeDe[asn] < o.classe {
			o.classe = classeDe[asn]
		}
		o.n += n
		parNom[nom], noms[nom] = o, o.n
	}
	for _, nom := range premiers(noms, operateursTop) {
		out.Operateurs = append(out.Operateurs, operateurPart{Nom: nom, Classe: parNom[nom].classe, Part: part(noms[nom], len(adrs))})
	}
	return out
}

// ── GET /activite?ids=… : l'activité sur 24 h des lignes visibles ────────────────────────────────
//
// UNE ROUTE PAR LOT PLUTÔT QU'UN CHAMP DANS /actors. 24 entiers pour 3 658 acteurs ajouteraient
// 180 à 300 Ko à un corps de 1,34 Mo relu toutes les 15 s, pour quelque dix lignes à l'écran. Ici
// 60 lignes au plus, quelques Ko, des lectures de table seulement. Le Hall ne relaie pas cette route.
// `ids` peut être absent : seules les séries d'ensemble sont alors rendues. `campagnes=1` ajoute la
// somme des acteurs des 60 premières campagnes (même ordre que /campaigns, groupement gardé 60 s).

var motifActeur = regexp.MustCompile(`^[A-Za-z0-9_-]{1,32}$`)

type lotActivite struct {
	GenereLe         int64                `json:"genere_le"`
	CouvertureDepuis int64                `json:"couverture_depuis,omitempty"`
	Debut            int64                `json:"debut"`
	Pas              int64                `json:"pas"`
	Partielles       []int                `json:"partielles,omitempty"`
	Evenements       []*uint32            `json:"evenements"` // tous capteurs, robots connus compris (comme /stats)
	Bloques          []*uint32            `json:"bloques"`
	Acteurs          map[string][]*uint32 `json:"acteurs"`
	Campagnes        map[string][]*uint32 `json:"campagnes,omitempty"`
}

func (s *Server) handleActivite(w http.ResponseWriter, r *http.Request) {
	var ids []string
	if q := r.URL.Query().Get("ids"); q != "" {
		ids = strings.Split(q, ",")
	}
	if len(ids) > activiteIDs {
		http.Error(w, "60 acteurs au plus", http.StatusBadRequest)
		return
	}
	for _, id := range ids {
		if !motifActeur.MatchString(id) {
			http.Error(w, "identifiant invalide", http.StatusBadRequest)
			return
		}
	}
	now := maintenant()
	var camps []*campagne
	if r.URL.Query().Get("campagnes") == "1" {
		// Groupement par acteur gardé : on en tire les campagnes distinctes, les plus grosses d'abord.
		if par, err := s.campDetT.lire(campDetTTL, s.campagnesParActeur); err == nil {
			camps = premieresCampagnes(par, activiteIDs)
		}
	}
	reduite := vueReduite(r)
	s.mu.Lock()
	t := &s.act
	g := t.serie(3600, 24, now, t.global.heureEvts)
	out := lotActivite{GenereLe: now, CouvertureDepuis: t.depuis, Debut: g.Debut, Pas: g.Pas, Partielles: g.Partielles,
		Evenements: g.Valeurs, Bloques: t.serie(3600, 24, now, t.global.heureBans).Valeurs, Acteurs: map[string][]*uint32{}}
	for _, id := range ids {
		if x := t.acteurs[id]; x != nil {
			out.Acteurs[id] = t.serie(3600, 24, now, x.heureEvts).Valeurs
		}
	}
	if len(camps) > 0 {
		out.Campagnes = make(map[string][]*uint32, len(camps))
	}
	for _, c := range camps {
		xs := make([]*activiteActeur, 0, len(c.Acteurs))
		for _, id := range c.Acteurs {
			if x := t.acteurs[id]; x != nil {
				xs = append(xs, x)
			}
		}
		if len(xs) == 0 {
			continue
		}
		sig := c.Signature
		if reduite {
			sig = s.signatureOpaque(sig)
		}
		out.Campagnes[sig] = t.serie(3600, 24, now, func(r int64) (n uint32) {
			for _, x := range xs {
				n += x.heureEvts(r)
			}
			return n
		}).Valeurs
	}
	s.mu.Unlock()
	writeJSON(w, out)
}

// premieresCampagnes rend les n plus grosses campagnes, dans l'ordre de /campaigns.
func premieresCampagnes(par map[string][]*campagne, n int) []*campagne {
	vues, out := map[*campagne]bool{}, []*campagne{}
	for _, l := range par {
		for _, c := range l {
			if !vues[c] {
				vues[c] = true
				out = append(out, c)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].NbActeurs != out[j].NbActeurs {
			return out[i].NbActeurs > out[j].NbActeurs
		}
		return out[i].Signature < out[j].Signature
	})
	return out[:min(n, len(out))]
}
