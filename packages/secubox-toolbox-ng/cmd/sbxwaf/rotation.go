// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// See LICENCE-CMSD-1.0.md for terms.

package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/CyberMind-FR/secubox-deb/secubox-toolbox-ng/internal/reseau"
)

// Détecteur de campagnes à ROTATION web (#3919, spec 5.4).
//
// Une campagne à rotation fait tourner une même requête sur des milliers d'adresses louées, chacune ne servant qu'une à trois fois : aucune adresse
// ne franchit seule un seuil de ban. On la reconnaît à sa SIGNATURE (navigateur déclaré exact, empreinte TLS JA4 si présente, hôte visé).
//
// Campagne ÉTABLIE quand, dans la fenêtre glissante d'1 h d'une signature : ≥ SeuilSources adresses distinctes, ≥ PartUneATrois % d'entre elles à
// ≤ 3 requêtes, ≥ PartLouee % d'entre elles classées `proxy_loue` ou `hebergeur` (`inconnu` ne compte jamais : sans annuaire, jamais de campagne).
//
// VERDICT DIFFÉRÉ (défaut, décision du propriétaire du 24/11) : une NOUVELLE adresse portant la signature d'une campagne établie est servie, puis
// jugée après `Delai` (10 s). Elle n'est bannie (24 h, « rotation:<8 hex> ») que si elle s'est comportée en robot : aucune ressource de page
// chargée DEPUIS LA MÊME ADRESSE (quel que soit le navigateur déclaré), aucun cookie, aucun référent. Une adresse épargnée est mémorisée et n'est
// plus rejugée (une page suivante servie depuis le cache du navigateur n'a pas de ressource). `immediat` : jugée au premier Tick, sans délai.
//
// GARDE-FOUS, rejoués au moment du ban (en plus de ceux de NftBanner.banAt) : adresse privée/locale/protégée, robot d'indexation vérifié,
// classe `relais_vie_privee`, sortie Tor connue ; plafond de MaxParHeure bans par heure glissante. Mode `propose` : tout est établi, compté et
// écrit (état, audit), rien n'est banni.
//
// CHEMIN DE LA REQUÊTE : Observe est O(1) sous un seul verrou court, sans E/S, sans appel à l'annuaire (la classe d'une source est résolue plus
// tard par Tick, hors verrou), sans allocation pour une signature et une adresse déjà suivies. Toute E/S (état, audit, BanFor, DNS des robots,
// liste Tor) se fait dans Tick, appelé toutes les 2 s par Veiller.
//
// MÉMOIRE BORNÉE :
//   - au plus MaxSignatures signatures suivies (LRU) ; une signature sans activité depuis Fenetre est oubliée ;
//   - au plus maxSourcesSig (5 000) adresses par signature : au-delà, les nouvelles adresses ne sont plus COMPTÉES dans les statistiques (la
//     preuve des 5 000 premières suffit), mais elles reçoivent toujours un verdict et entretiennent la campagne ;
//   - au plus maxSourcesTotal (200 000) adresses toutes signatures confondues : au-delà, les signatures les moins récentes sont oubliées ;
//   - au plus maxVerdicts (50 000) adresses en verdict ou mémorisées : au-delà, les plus anciennes sont abandonnées — un verdict abandonné n'est
//     JAMAIS un ban (échec sûr) ;
//   - au plus MaxCampagnes campagnes actives : au-delà, la moins récemment active sort.

// RotationConfig : réglages du détecteur ; une valeur nulle prend le défaut.
type RotationConfig struct {
	Mode          string        // off | propose | auto
	Verdict       string        // differe | immediat
	Fenetre       time.Duration // 1 h
	Delai         time.Duration // 10 s
	SeuilSources  int           // 50
	PartUneATrois int           // 80 (%)
	PartLouee     int           // 60 (%)
	Duree         time.Duration // 24 h : durée du ban ET durée de vie d'une campagne sans nouvelle source
	MaxParHeure   int           // 1500
	MaxCampagnes  int           // 10
	MaxSignatures int           // 20000
	Etat          string        // fichier d'état (panneau, relevé populations)
	Audit         string        // journal d'audit du WAF (ajout seul)
	Protegees     []*net.IPNet  // jamais bannies (en plus du privé/local)
	SortiesTor    string        // liste locale des sorties Tor (une adresse par ligne) ; absente = garde inactive, signalée dans l'état
}

const (
	rotationPasEval       = 10 * time.Second // une signature est réévaluée au plus toutes les 10 s
	rotationEtatPas       = time.Minute      // état réécrit au moins chaque minute, sinon sur changement
	rotationTorPas        = 10 * time.Minute // liste Tor relue au plus toutes les 10 min
	rotationBudgetClasses = 20000            // adresses classées au plus par Tick
)

// Classes de réseau, codées sur un octet (0 = pas encore classée).
var rotationClasses = []string{"", reseau.ClasseAcces, reseau.ClasseCDN, reseau.ClasseHebergeur, reseau.ClasseProxyLoue,
	reseau.ClasseScannerRecherche, reseau.ClasseMobilePartage, reseau.ClasseRelaisViePrivee, reseau.ClasseInconnu}

func codeClasse(c string) uint8 {
	for i := 1; i < len(rotationClasses); i++ {
		if rotationClasses[i] == c {
			return uint8(i)
		}
	}
	return uint8(len(rotationClasses) - 1) // inconnu
}

const (
	verdictAttente uint8 = iota
	verdictEpargne
	verdictJuge
)

type rotSource struct {
	n      uint16 // requêtes (saturé)
	classe uint8
	vu     int64 // dernière requête (UnixNano)
}

type rotSignature struct {
	cle        [32]byte
	hote       string
	sources    map[string]rotSource
	dernier    int64 // dernière requête (UnixNano)
	evalue     int64 // dernière évaluation
	prec, suiv *rotSignature
}

type rotCampagne struct {
	cle                [32]byte
	signature, hote    string
	etablieLe, dernier int64 // Unix (s) ; dernier = dernière NOUVELLE source
	sources, une, le3  int
	classes            map[string]int // en %
	bannies, epargnees int
	aBannir, ecartees  int
}

type rotVerdict struct {
	etat     uint8
	cle      [32]byte
	echeance int64 // UnixNano
	cree     int64
}

type rotDecision struct {
	ip  string
	cle [32]byte
}

// Rotation : le détecteur. Sûr pour un usage concurrent (Observe depuis les requêtes, Tick depuis un seul ticker).
type Rotation struct {
	cfg     RotationConfig
	banneur banneurDuree
	annu    classeur
	robots  func(ip string) string // robot d'indexation vérifié → nom, "" sinon (nil : pas de vérification ici, banAt la refait)

	maxSourcesSig   int
	maxSourcesTotal int
	maxVerdicts     int

	mu          sync.Mutex
	sigs        map[[32]byte]*rotSignature
	tete, queue *rotSignature // LRU : tête = plus récente
	nSources    int
	aEvaluer    map[*rotSignature]struct{}
	campagnes   map[[32]byte]*rotCampagne
	verdicts    map[string]*rotVerdict
	attente     []string // FIFO des adresses en attente de verdict
	attenteDeb  int
	ordre       []string // FIFO de toutes les adresses mémorisées (expiration, plafond)
	ordreDeb    int

	// propres à Tick (un seul appelant)
	recents     []time.Time
	plafondDit  bool
	tor         map[string]struct{}
	torLuLe     time.Time
	etatSale    bool
	etatEcritLe time.Time
	audits      []map[string]any
}

// NewRotation construit le détecteur et relit l'état persistant (campagnes actives de moins de Duree).
func NewRotation(cfg RotationConfig, b banneurDuree, a classeur) *Rotation {
	if cfg.Mode != "propose" && cfg.Mode != "auto" {
		cfg.Mode = "off"
	}
	if cfg.Verdict != "immediat" {
		cfg.Verdict = "differe"
	}
	defD := func(v *time.Duration, d time.Duration) {
		if *v <= 0 {
			*v = d
		}
	}
	defI := func(v *int, d int) {
		if *v <= 0 {
			*v = d
		}
	}
	defD(&cfg.Fenetre, time.Hour)
	defD(&cfg.Delai, 10*time.Second)
	defD(&cfg.Duree, 24*time.Hour)
	defI(&cfg.SeuilSources, 50)
	defI(&cfg.PartUneATrois, 80)
	defI(&cfg.PartLouee, 60)
	defI(&cfg.MaxParHeure, 1500)
	defI(&cfg.MaxCampagnes, 10)
	defI(&cfg.MaxSignatures, 20000)
	r := &Rotation{cfg: cfg, banneur: b, annu: a, maxSourcesSig: 5000, maxSourcesTotal: 200000, maxVerdicts: 50000,
		sigs: map[[32]byte]*rotSignature{}, aEvaluer: map[*rotSignature]struct{}{}, campagnes: map[[32]byte]*rotCampagne{},
		verdicts: map[string]*rotVerdict{}, etatSale: true}
	r.relireEtat(time.Now())
	return r
}

// SetRobots branche la vérification des robots d'indexation (Crawlers.Verifie).
func (r *Rotation) SetRobots(f func(ip string) string) { r.robots = f }

// Signature : SHA-256 hexadécimal de ua, ja4 et hôte séparés par un octet nul.
func Signature(ua, ja4, host string) string {
	c := cleSignature(ua, ja4, host)
	return hex.EncodeToString(c[:])
}

func cleSignature(ua, ja4, host string) [32]byte {
	var pile [768]byte
	n := len(ua) + len(ja4) + len(host) + 2
	b := pile[:0]
	if n > len(pile) {
		b = make([]byte, 0, n)
	}
	b = append(b, ua...)
	b = append(b, 0)
	b = append(b, ja4...)
	b = append(b, 0)
	b = append(b, host...)
	return sha256.Sum256(b)
}

// Observe note une requête. ressource = chargement d'une ressource de page (staticAsset) ; cookie, referent = en-têtes présents.
func (r *Rotation) Observe(ip, ua, ja4, host string, ressource, cookie, referent bool, t time.Time) {
	if r == nil || r.cfg.Mode == "off" || ip == "" {
		return
	}
	navigateur := ressource || cookie || referent
	var cle [32]byte
	if ua != "" {
		cle = cleSignature(ua, ja4, host) // hors verrou
	}
	ns := t.UnixNano()

	r.mu.Lock()
	defer r.mu.Unlock()
	v := r.verdicts[ip]
	if v != nil && v.etat == verdictAttente && navigateur {
		v.etat = verdictEpargne
		if c := r.campagnes[v.cle]; c != nil {
			c.epargnees++
			r.etatSale = true
		}
	}
	if ua == "" {
		return
	}
	s := r.signatureSuivie(cle, host, ns)
	nouvelle := r.noterSource(s, ip, ns)
	c := r.campagnes[cle]
	if c == nil {
		return
	}
	if nouvelle {
		c.dernier = t.Unix()
	}
	if v != nil {
		return // déjà en attente, épargnée ou jugée
	}
	if navigateur {
		c.epargnees++
		r.etatSale = true
		r.memoriser(strings.Clone(ip), &rotVerdict{etat: verdictEpargne, cle: cle, cree: ns})
		return
	}
	ech := ns
	if r.cfg.Verdict == "differe" {
		ech += int64(r.cfg.Delai)
	}
	ipc := strings.Clone(ip)
	r.memoriser(ipc, &rotVerdict{etat: verdictAttente, cle: cle, echeance: ech, cree: ns})
	r.attente = append(r.attente, ipc)
}

// memoriser (sous verrou) ajoute une adresse ; au-delà de maxVerdicts, la plus ancienne est abandonnée (jamais bannie).
func (r *Rotation) memoriser(ip string, v *rotVerdict) {
	for len(r.verdicts) >= r.maxVerdicts && r.ordreDeb < len(r.ordre) {
		delete(r.verdicts, r.ordre[r.ordreDeb])
		r.ordre[r.ordreDeb] = ""
		r.ordreDeb++
	}
	r.verdicts[ip] = v
	r.ordre = append(r.ordre, ip)
	r.ordre, r.ordreDeb = compacter(r.ordre, r.ordreDeb)
}

func compacter(f []string, deb int) ([]string, int) {
	if deb > 1024 && deb*2 > len(f) {
		n := copy(f, f[deb:])
		for i := n; i < len(f); i++ {
			f[i] = ""
		}
		return f[:n], 0
	}
	return f, deb
}

// signatureSuivie (sous verrou) rend la signature, créée au besoin, placée en tête du LRU.
func (r *Rotation) signatureSuivie(cle [32]byte, host string, ns int64) *rotSignature {
	s := r.sigs[cle]
	if s == nil {
		for len(r.sigs) >= r.cfg.MaxSignatures && r.queue != nil {
			r.oublier(r.queue)
		}
		s = &rotSignature{cle: cle, hote: strings.Clone(host), sources: map[string]rotSource{}}
		r.sigs[cle] = s
	} else {
		r.detacher(s)
	}
	s.suiv = r.tete
	if r.tete != nil {
		r.tete.prec = s
	}
	r.tete = s
	if r.queue == nil {
		r.queue = s
	}
	s.dernier = ns
	return s
}

func (r *Rotation) detacher(s *rotSignature) {
	if s.prec != nil {
		s.prec.suiv = s.suiv
	} else {
		r.tete = s.suiv
	}
	if s.suiv != nil {
		s.suiv.prec = s.prec
	} else {
		r.queue = s.prec
	}
	s.prec, s.suiv = nil, nil
}

func (r *Rotation) oublier(s *rotSignature) {
	r.detacher(s)
	delete(r.sigs, s.cle)
	delete(r.aEvaluer, s)
	r.nSources -= len(s.sources)
	s.sources = nil
}

// noterSource (sous verrou) compte la requête ; rend vrai si l'adresse n'était pas connue de la signature.
func (r *Rotation) noterSource(s *rotSignature, ip string, ns int64) bool {
	if src, ok := s.sources[ip]; ok {
		if src.n < 0xffff {
			src.n++
		}
		src.vu = ns
		s.sources[ip] = src
		return false
	}
	if len(s.sources) >= r.maxSourcesSig {
		return true // hors statistiques, mais nouvelle pour la campagne
	}
	for r.nSources >= r.maxSourcesTotal && r.queue != nil && r.queue != s {
		r.oublier(r.queue)
	}
	if r.nSources >= r.maxSourcesTotal {
		return true
	}
	s.sources[strings.Clone(ip)] = rotSource{n: 1, vu: ns}
	r.nSources++
	if len(s.sources) >= r.cfg.SeuilSources {
		r.aEvaluer[s] = struct{}{}
	}
	return true
}

// Veiller relance Tick à intervalle régulier.
func (r *Rotation) Veiller(pas time.Duration) {
	for {
		r.Tick(time.Now())
		time.Sleep(pas)
	}
}

type rotAClasser struct {
	s  *rotSignature
	ip string
	cl uint8
}

// Tick : liste Tor, verdicts échus, évaluation des signatures, expirations, audit et état. Un seul appelant à la fois.
func (r *Rotation) Tick(t time.Time) {
	if r == nil || r.cfg.Mode == "off" {
		return
	}
	r.chargerTor(t)
	ns := t.UnixNano()

	// 1. Verdicts échus et signatures à classer, sous verrou ; rien d'autre.
	var decisions []rotDecision
	var aClasser []rotAClasser
	r.mu.Lock()
	for r.attenteDeb < len(r.attente) {
		ip := r.attente[r.attenteDeb]
		v := r.verdicts[ip]
		if v != nil && v.etat == verdictAttente && v.echeance > ns {
			break
		}
		r.attente[r.attenteDeb] = ""
		r.attenteDeb++
		if v == nil || v.etat != verdictAttente {
			continue // abandonné ou épargné entre-temps
		}
		v.etat = verdictJuge
		decisions = append(decisions, rotDecision{ip: ip, cle: v.cle})
	}
	r.attente, r.attenteDeb = compacter(r.attente, r.attenteDeb)
	limite := ns - int64(r.cfg.Fenetre)
	for s := range r.aEvaluer {
		if ns-s.evalue < int64(rotationPasEval) {
			continue
		}
		for ip, src := range s.sources {
			if src.vu < limite {
				delete(s.sources, ip)
				r.nSources--
			} else if src.classe == 0 && len(aClasser) < rotationBudgetClasses {
				aClasser = append(aClasser, rotAClasser{s: s, ip: ip})
			}
		}
	}
	r.mu.Unlock()

	// 2. Classes résolues hors verrou.
	for i := range aClasser {
		aClasser[i].cl = codeClasse(r.classer(aClasser[i].ip).Classe)
	}

	// 3. Évaluation, établissements, expirations.
	r.mu.Lock()
	for _, a := range aClasser {
		if src, ok := a.s.sources[a.ip]; ok {
			src.classe = a.cl
			a.s.sources[a.ip] = src
		}
	}
	for s := range r.aEvaluer {
		if ns-s.evalue < int64(rotationPasEval) || r.sigs[s.cle] != s {
			continue
		}
		r.evaluer(s, t)
	}
	r.expirer(t)
	r.mu.Unlock()

	// 4. Verdicts : garde-fous, plafond, ban — hors verrou (DNS des robots, nft).
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
	for _, d := range decisions {
		r.juger(d, t)
	}

	// 5. Audit et état.
	r.mu.Lock()
	audits := r.audits
	r.audits = nil
	ecrire := r.etatSale || t.Sub(r.etatEcritLe) >= rotationEtatPas
	var e rotationEtat
	if ecrire {
		e = r.etatCourant(t)
		r.etatSale = false
	}
	r.mu.Unlock()
	for _, a := range audits {
		r.auditer(a)
	}
	if ecrire {
		r.ecrireEtat(e)
		r.etatEcritLe = t
	}
}

func (r *Rotation) classer(ip string) reseau.Info {
	if r.annu == nil {
		return reseau.Info{Classe: reseau.ClasseInconnu}
	}
	return r.annu.Classer(ip)
}

// evaluer (sous verrou) calcule les statistiques de la fenêtre et établit ou met à jour la campagne.
func (r *Rotation) evaluer(s *rotSignature, t time.Time) {
	n := len(s.sources)
	var une, le3, louee int
	var parClasse [16]int
	for _, src := range s.sources {
		if src.classe == 0 {
			return // classes pas encore toutes résolues : au prochain Tick
		}
		if src.n == 1 {
			une++
		}
		if src.n <= 3 {
			le3++
		}
		parClasse[src.classe]++
		if cl := rotationClasses[src.classe]; cl == reseau.ClasseProxyLoue || cl == reseau.ClasseHebergeur {
			louee++
		}
	}
	s.evalue = t.UnixNano()
	delete(r.aEvaluer, s)
	c := r.campagnes[s.cle]
	if c == nil {
		if n < r.cfg.SeuilSources || le3*100 < r.cfg.PartUneATrois*n || louee*100 < r.cfg.PartLouee*n {
			return
		}
		for len(r.campagnes) >= r.cfg.MaxCampagnes {
			var vieille *rotCampagne
			for _, x := range r.campagnes {
				if vieille == nil || x.dernier < vieille.dernier {
					vieille = x
				}
			}
			r.finir(vieille, t, "plafond_campagnes")
		}
		c = &rotCampagne{cle: s.cle, signature: hex.EncodeToString(s.cle[:]), hote: s.hote, etablieLe: t.Unix(), dernier: t.Unix()}
		r.campagnes[s.cle] = c
		defer func() {
			r.audits = append(r.audits, map[string]any{"ts": t.UTC().Format("2006-01-02T15:04:05Z"), "module": "waf", "action": "rotation_etablie",
				"detail": "campagne à rotation " + c.signature[:8] + " sur " + c.hote, "signature": c.signature, "hote": c.hote,
				"sources": c.sources, "une": c.une, "le3": c.le3, "classes": c.classes, "mode": r.cfg.Mode, "verdict": r.cfg.Verdict})
			log.Printf("sbxwaf: rotation — campagne %s établie sur %s (%d sources, mode=%s, verdict=%s)", c.signature[:8], c.hote, c.sources,
				r.cfg.Mode, r.cfg.Verdict)
		}()
	}
	if n == 0 {
		return
	}
	c.sources, c.une, c.le3 = n, une*100/n, le3*100/n
	c.classes = map[string]int{}
	for i, k := range parClasse {
		if k > 0 && i < len(rotationClasses) {
			c.classes[rotationClasses[i]] = k * 100 / n
		}
	}
	r.etatSale = true
}

// finir (sous verrou) retire une campagne et l'écrit dans l'audit.
func (r *Rotation) finir(c *rotCampagne, t time.Time, raison string) {
	delete(r.campagnes, c.cle)
	r.etatSale = true
	r.audits = append(r.audits, map[string]any{"ts": t.UTC().Format("2006-01-02T15:04:05Z"), "module": "waf", "action": "rotation_fin",
		"detail": "campagne à rotation " + c.signature[:8] + " terminée (" + raison + ")", "signature": c.signature, "hote": c.hote,
		"raison": raison, "bannies": c.bannies, "epargnees": c.epargnees, "a_bannir": c.aBannir})
	log.Printf("sbxwaf: rotation — campagne %s terminée (%s, %d bannies, %d épargnées)", c.signature[:8], raison, c.bannies, c.epargnees)
}

// expirer (sous verrou) : campagnes sans nouvelle source depuis Duree, signatures inactives depuis Fenetre, adresses mémorisées depuis Duree.
func (r *Rotation) expirer(t time.Time) {
	for _, c := range r.campagnes {
		if t.Unix()-c.dernier > int64(r.cfg.Duree/time.Second) {
			r.finir(c, t, "inactive")
		}
	}
	limite := t.UnixNano() - int64(r.cfg.Fenetre)
	for r.queue != nil && r.queue.dernier < limite {
		r.oublier(r.queue)
	}
	vieux := t.UnixNano() - int64(r.cfg.Duree)
	for r.ordreDeb < len(r.ordre) {
		ip := r.ordre[r.ordreDeb]
		if v := r.verdicts[ip]; v != nil {
			if v.cree >= vieux || v.etat == verdictAttente {
				break
			}
			delete(r.verdicts, ip)
		}
		r.ordre[r.ordreDeb] = ""
		r.ordreDeb++
	}
	r.ordre, r.ordreDeb = compacter(r.ordre, r.ordreDeb)
}

// juger (hors verrou) rend le verdict d'une adresse restée muette : garde-fous, plafond, ban ou proposition.
func (r *Rotation) juger(d rotDecision, t time.Time) {
	r.mu.Lock()
	c := r.campagnes[d.cle]
	var court string
	if c != nil {
		court = c.signature[:8]
	}
	r.mu.Unlock()
	if c == nil {
		return // campagne finie entre-temps : pas de ban
	}
	raison := r.ecarter(d.ip)
	applique := false
	if raison == "" && r.cfg.Mode == "auto" {
		if len(r.recents) >= r.cfg.MaxParHeure {
			raison = "plafond_horaire"
			if !r.plafondDit {
				r.plafondDit = true
				r.mu.Lock()
				r.audits = append(r.audits, map[string]any{"ts": t.UTC().Format("2006-01-02T15:04:05Z"), "module": "waf",
					"action": "rotation_plafond", "detail": "plafond de bans de rotation atteint", "plafond": r.cfg.MaxParHeure})
				r.mu.Unlock()
				log.Printf("sbxwaf: rotation — plafond de %d bans par heure atteint", r.cfg.MaxParHeure)
			}
		} else {
			r.recents = append(r.recents, t)
			r.banneur.BanFor(d.ip, "rotation:"+court, "high", r.cfg.Duree)
			applique = true
		}
	}
	r.mu.Lock()
	if c := r.campagnes[d.cle]; c != nil {
		switch {
		case applique:
			c.bannies++
		case raison != "":
			c.ecartees++
		default:
			c.aBannir++
		}
	}
	r.etatSale = true
	r.mu.Unlock()
	if applique {
		log.Printf("sbxwaf: rotation-ban %s ← %s (aucune ressource, cookie ni référent en %s)", d.ip, court, r.cfg.Delai)
	}
}

// ecarter rend la raison pour laquelle l'adresse ne doit jamais être bannie, "" sinon.
func (r *Rotation) ecarter(ip string) string {
	if adresseProtegee(ip, r.cfg.Protegees) {
		return "protegee"
	}
	if r.tor != nil {
		if a, err := netip.ParseAddr(ip); err == nil {
			if _, ok := r.tor[a.Unmap().String()]; ok {
				return "sortie_tor"
			}
		}
	}
	if r.classer(ip).Classe == reseau.ClasseRelaisViePrivee {
		return "relais_vie_privee"
	}
	if r.robots != nil && r.robots(ip) != "" {
		return "robot_verifie"
	}
	return ""
}

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
	return rotationEtat{GenereLe: t.Unix(), Mode: r.cfg.Mode, Verdict: r.cfg.Verdict, TorGarde: r.tor != nil,
		Campagnes: r.listeCampagnes(), AppliquesHeure: len(r.recents), PlafondAtteint: r.plafondDit}
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

// relireEtat reprend les campagnes d'un état de moins de Duree ; état absent, corrompu ou périmé : ignoré.
func (r *Rotation) relireEtat(maintenant time.Time) {
	if r.cfg.Etat == "" || r.cfg.Mode == "off" {
		return
	}
	b, err := os.ReadFile(r.cfg.Etat)
	if err != nil {
		return
	}
	var e rotationEtat
	if json.Unmarshal(b, &e) != nil || maintenant.Unix()-e.GenereLe > int64(r.cfg.Duree/time.Second) {
		return
	}
	for _, x := range e.Campagnes {
		brut, err := hex.DecodeString(x.Signature)
		if err != nil || len(brut) != 32 || maintenant.Unix()-x.Dernier > int64(r.cfg.Duree/time.Second) || len(r.campagnes) >= r.cfg.MaxCampagnes {
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

// ── Introspection (tests) ────────────────────────────────────────────────────────────────────────────────────────────

func (r *Rotation) nbSignatures() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.sigs)
}

func (r *Rotation) nbSources() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.nSources
}

func (r *Rotation) nbVerdicts() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.verdicts)
}
