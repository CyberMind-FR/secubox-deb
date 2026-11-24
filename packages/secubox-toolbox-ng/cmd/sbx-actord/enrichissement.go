// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package main

import (
	"net"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/CyberMind-FR/secubox-deb/secubox-toolbox-ng/internal/actor/envelope"
	"github.com/CyberMind-FR/secubox-deb/secubox-toolbox-ng/internal/reseau"
)

// Campagnes lisibles (#3919) : famille, cibles, classes de réseau, pays et
// part des sources éphémères, pour qu'une carte de campagne se lise sans
// ouvrir la liste de ses acteurs.
//
// POURQUOI PAR SOURCE ET À L'INGESTION. Le graphe ne garde, par acteur, que
// des ensembles (adresses, pays, cibles) : ni le nombre d'événements par
// adresse, ni l'ASN d'une adresse, ni la catégorie. Les recalculer à la
// demande voudrait relire le magasin (376 Mo sur gk2) à chaque requête. On
// tient donc, à l'ingestion, une petite fiche PAR ADRESSE SOURCE ; la
// campagne agrège les fiches de ses adresses, en temps linéaire et sans
// E/S. Clé par adresse plutôt que par acteur : la consolidation (fusion de
// deux acteurs) n'a ainsi rien à recopier.

// ciblesParSourceMax borne les cibles retenues par adresse : un réciteur de
// dictionnaire viserait sinon des centaines de noms par adresse.
const ciblesParSourceMax = 16

// BORNES MÉMOIRE DES FICHES (#3919, revue). Les fiches ne vivent qu'en
// mémoire, et secubox-actord.service tourne sous GOMEMLIMIT=180MiB /
// MemoryMax=256M. À ~1 000 adresses nouvelles par heure, garder les fiches
// aussi longtemps que les acteurs (360 h) en ferait ~360 000. D'où :
//   - une rétention PROPRE aux fiches, 48 h, indépendante de celle des acteurs ;
//   - un plafond dur de 200 000 fiches : plein, on ÉVINCE les plus anciennes
//     (par `dernier`) plutôt que de refuser les nouvelles — une campagne en
//     cours compte plus qu'une adresse muette depuis deux jours ;
//   - une fiche compacte (voir ficheSource), ~150 o pour une source à une cible.
const (
	sourcesMaxDefaut = 200000
	retentionSources = 48 * 3600 // secondes
	// evictionPart : part du plafond libérée d'un coup quand il est atteint.
	// Évincer par lot (un tri toutes les 20 000 adresses nouvelles) plutôt
	// qu'une fiche à la fois (un balayage complet par adresse nouvelle).
	evictionPart = 10
)

// Familles indexées : un compteur par famille dans un tableau fixe, sans map.
var famillesIndex = [...]string{
	reseau.FamilleMessagerie, reseau.FamilleAccesDistant, reseau.FamilleCollecte,
	reseau.FamilleBalayageWeb, reseau.FamilleAutre,
}

const familleAutreIdx = len(famillesIndex) - 1

func indexFamille(f string) int {
	for i, x := range famillesIndex {
		if x == f {
			return i
		}
	}
	return familleAutreIdx
}

// ficheSource : ce qu'actord retient d'une adresse source. Compacte : la
// première cible est gardée en ligne, la map n'est allouée qu'à partir de la
// deuxième cible distincte.
type ficheSource struct {
	dernier  int64
	asn      uint32 // 0 = pas encore résolu (retenté à chaque événement)
	evts     uint32
	familles [len(famillesIndex)]uint32
	pays     [2]byte
	cible    string // première cible (déjà masquée si c'est un compte)
	nCible   uint32
	cibles   map[string]uint32 // cibles suivantes, nil tant qu'il n'y en a qu'une
}

// PaysPart : un pays et sa part (en %) des sources d'une campagne.
type PaysPart struct {
	Code string `json:"code"`
	Part int    `json:"part"`
}

// maintenant : horloge des fiches, remplaçable en test.
var maintenant = func() int64 { return time.Now().Unix() }

// noterSource met à jour la fiche de l'adresse d'un événement. Appelée sous s.mu.
func (s *Server) noterSource(e *envelope.Envelope) {
	if e.SrcIP == "" || e.Timestamp < maintenant()-retentionSources {
		return // hors rétention des fiches (rejeu au démarrage) : rien à retenir
	}
	if s.sources == nil {
		s.sources = map[string]*ficheSource{}
	}
	f := s.sources[e.SrcIP]
	if f == nil {
		if max := s.plafondSources(); len(s.sources) >= max {
			s.evincerSources(max)
		}
		f = &ficheSource{}
		s.sources[e.SrcIP] = f
	}
	f.evts++
	if e.Timestamp > f.dernier {
		f.dernier = e.Timestamp
	}
	if e.ASN != 0 {
		f.asn = e.ASN
	} else if f.asn == 0 {
		// Enveloppe sans ASN : recherche dans l'annuaire local d'actord. Un
		// échec n'est PAS mémorisé : l'annuaire peut être rechargé (SIGHUP,
		// 24 h) et la recherche suivante aboutir.
		f.asn = s.annuaire.Classer(e.SrcIP).ASN
	}
	if len(e.GeoCountry) == 2 {
		f.pays = [2]byte{e.GeoCountry[0], e.GeoCountry[1]}
	}
	f.familles[indexFamille(familleEvenement(e))]++
	if c := cibleAffichee(e); c != "" {
		f.noterCible(c)
	}
}

func (f *ficheSource) noterCible(c string) {
	switch {
	case f.nCible == 0 || f.cible == c:
		f.cible = c
		f.nCible++
	case f.cibles != nil:
		if _, ok := f.cibles[c]; ok || len(f.cibles) < ciblesParSourceMax-1 {
			f.cibles[c]++
		}
	default:
		f.cibles = map[string]uint32{c: 1}
	}
}

// estCompte : la cible de l'événement est un compte visé, d'après son
// ORIGINE (capteur authwatch, catégorie auth_*) ; une adresse de messagerie
// en est un signal de plus.
func estCompte(e *envelope.Envelope) bool {
	if e.Sensor == envelope.SensorAuthWatch || strings.HasPrefix(e.RuleID, "auth_") ||
		strings.Contains(e.DstService, "@") {
		return true
	}
	for _, t := range e.BehaviorTags {
		if strings.HasPrefix(t, "auth_") {
			return true
		}
	}
	return false
}

// servicesAuthwatch : LISTE FERMÉE des services que sbx-authwatch met dans
// DstService (motifs, leurres, bannières, filtres livrés). Un nom de cette liste
// s'affiche tel quel ; tout autre reste un compte, masqué. Un service déclaré par
// l'opérateur et absent d'ici est donc masqué : c'est le sens sûr de l'erreur.
// TestServicesConnusSuiventAuthwatch échoue si authwatch en gagne un.
var servicesAuthwatch = map[string]bool{
	"ssh": true, "smtp": true, "imap": true, "ftp": true, // motifs, bannières
	"rdp": true, "vnc": true, "telnet": true, "smb": true, "mysql": true, // leurres
	"postgres": true, "redis": true, "mongodb": true, "elasticsearch": true, "mssql": true,
	"gitea": true, "nextcloud": true, "peertube": true, // services.json livré
}

// cibleMax borne une cible retenue (en caractères) : l'hôte vient de l'attaquant.
const cibleMax = 64

// cibleAffichee : la cible telle que la carte la montrera. Un compte est
// masqué DÈS L'INGESTION : la fiche ne garde jamais le compte en clair. Un hôte
// qui est une adresse n'est pas retenu : aucune adresse ne sort par les cibles.
func cibleAffichee(e *envelope.Envelope) string {
	c := strings.TrimSpace(e.DstService)
	if c == "" {
		return ""
	}
	if estCompte(e) {
		if s := strings.ToLower(c); e.Sensor == envelope.SensorAuthWatch && servicesAuthwatch[s] {
			return s
		}
		return reseau.MasquerCompte(c)
	}
	if estAdresseLitterale(c) {
		return ""
	}
	if utf8.RuneCountInString(c) > cibleMax {
		// Copie (conversion de runes) : la chaîne longue n'est pas retenue.
		c = string([]rune(c)[:cibleMax])
	}
	return c
}

// estAdresseLitterale : l'hôte (port compris) est une adresse IP, écriture
// décimale, octale ou hexadécimale incluse (dernier label numérique).
func estAdresseLitterale(hote string) bool {
	h := strings.TrimSuffix(hote, ".")
	if strings.HasPrefix(h, "[") {
		return true
	}
	if strings.Count(h, ":") == 1 {
		h = strings.TrimSuffix(h[:strings.IndexByte(h, ':')], ".")
	}
	if net.ParseIP(h) != nil {
		return true
	}
	d := strings.ToLower(h[strings.LastIndexByte(h, '.')+1:])
	if x, ok := strings.CutPrefix(d, "0x"); ok {
		return strings.Trim(x, "0123456789abcdef") == ""
	}
	return d != "" && strings.Trim(d, "0123456789") == ""
}

// familleEvenement : la famille de la catégorie de l'événement. La catégorie
// est la règle d'authwatch (RuleID) ou la première étiquette du WAF ; on
// prend la première qui se range dans une famille.
func familleEvenement(e *envelope.Envelope) string {
	if e.RuleID != "" {
		if f := reseau.Famille(e.RuleID); f != reseau.FamilleAutre {
			return f
		}
	}
	for _, t := range e.BehaviorTags {
		if f := reseau.Famille(t); f != reseau.FamilleAutre {
			return f
		}
	}
	return reseau.FamilleAutre
}

func (s *Server) plafondSources() int {
	if s.sourcesMax > 0 {
		return s.sourcesMax
	}
	return sourcesMaxDefaut
}

// evincerSources libère evictionPart % du plafond (au moins une fiche) en
// retirant les fiches les plus anciennes par `dernier`. Appelée sous s.mu.
func (s *Server) evincerSources(max int) {
	k := max * evictionPart / 100
	if k < 1 {
		k = 1
	}
	if k > len(s.sources) {
		k = len(s.sources)
	}
	if k == 0 {
		return
	}
	d := make([]int64, 0, len(s.sources))
	for _, f := range s.sources {
		d = append(d, f.dernier)
	}
	sort.Slice(d, func(i, j int) bool { return d[i] < d[j] })
	seuil := d[k-1]
	for ip, f := range s.sources {
		if f.dernier <= seuil {
			delete(s.sources, ip)
		}
	}
}

// oublierSources retire les fiches non vues depuis `avant`. Appelée sous s.mu.
func (s *Server) oublierSources(avant int64) {
	for ip, f := range s.sources {
		if f.dernier < avant {
			delete(s.sources, ip)
		}
	}
}

// purgerSources applique la rétention propre aux fiches (48 h).
func (s *Server) purgerSources() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.oublierSources(maintenant() - retentionSources)
}

// part rend k/n en pourcentage entier, arrondi au plus proche (moitié vers le
// haut) : 50/60 → 83.
func part(k, n int) int {
	if n == 0 {
		return 0
	}
	return (k*100 + n/2) / n
}

// rotationFiches et rotationLe3 : seuils de l'indicateur de rotation (spec 5.3).
const (
	rotationFiches = 50
	rotationLe3    = 80
)

// enrichir calcule les champs lisibles d'une campagne depuis les fiches de
// ses adresses. Appelée sous s.mu.
//
// DÉNOMINATEUR : LES ADRESSES QUI ONT UNE FICHE, PAS TOUTES (#3919). Une fiche
// vit 48 h, une campagne des jours : compter les adresses sorties de la fenêtre
// (ou évincées) comme « inconnu » diluait toutes les parts et éteignait
// `rotation` à tort. `sources` garde son sens (toutes les adresses). Aucune
// fiche : parts absentes du JSON, jamais un zéro inventé.
func (s *Server) enrichir(g *campagne, ips map[string]bool) {
	n := 0 // adresses qui ont encore une fiche
	classes := map[string]int{}
	pays := map[string]int{}
	var familles [len(famillesIndex)]int
	cibles := map[string]int{}
	classeDe := map[uint32]string{} // un verrou d'annuaire par ASN, pas par adresse
	une, le3 := 0, 0
	for ip := range ips {
		f := s.sources[ip]
		if f == nil {
			continue
		}
		n++
		cl, ok := classeDe[f.asn]
		if !ok {
			cl = s.annuaire.ClasseASN(f.asn)
			classeDe[f.asn] = cl
		}
		classes[cl]++
		if f.pays != [2]byte{} {
			pays[string(f.pays[:])]++
		}
		if f.evts == 1 {
			une++
		}
		if f.evts >= 1 && f.evts <= 3 {
			le3++
		}
		for i, v := range f.familles {
			familles[i] += int(v)
		}
		if f.nCible > 0 {
			cibles[f.cible] += int(f.nCible)
		}
		for k, v := range f.cibles {
			cibles[k] += int(v)
		}
	}

	g.CiblesNoms = []string{}
	// Les comptes y sont déjà masqués (cibleAffichee, à l'ingestion).
	g.CiblesNoms = append(g.CiblesNoms, premiers(cibles, 3)...)
	// La famille est la plus fréquente parmi les événements rangés ; « autre »
	// seulement quand aucun ne l'est. Égalité : ordre alphabétique.
	g.Famille = reseau.FamilleAutre
	meilleur := 0
	for i, v := range familles[:familleAutreIdx] {
		if v > meilleur || v == meilleur && v > 0 && famillesIndex[i] < g.Famille {
			meilleur, g.Famille = v, famillesIndex[i]
		}
	}
	if n == 0 {
		return // rien de mesuré : parts absentes, rotation fausse
	}
	g.Classes = make(map[string]int, len(classes))
	for k, v := range classes {
		g.Classes[k] = part(v, n)
	}
	for _, k := range premiers(pays, 3) {
		g.PaysTop = append(g.PaysTop, PaysPart{Code: k, Part: part(pays[k], n)})
	}
	pUne, pLe3 := part(une, n), part(le3, n)
	g.Une, g.Le3 = &pUne, &pLe3
	g.Rotation = pLe3 >= rotationLe3 && n >= rotationFiches
}

// premiers rend les max clés de plus forte valeur, égalités par ordre
// alphabétique (reproductible d'une requête à l'autre).
func premiers(m map[string]int, max int) []string {
	cles := make([]string, 0, len(m))
	for k, v := range m {
		if v > 0 {
			cles = append(cles, k)
		}
	}
	sort.Slice(cles, func(i, j int) bool {
		if m[cles[i]] != m[cles[j]] {
			return m[cles[i]] > m[cles[j]]
		}
		return cles[i] < cles[j]
	})
	if len(cles) > max {
		cles = cles[:max]
	}
	return cles
}
