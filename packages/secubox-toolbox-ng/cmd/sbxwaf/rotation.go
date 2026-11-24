// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// See LICENCE-CMSD-1.0.md for terms.

package main

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"log"
	"net"
	"net/netip"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/CyberMind-FR/secubox-deb/secubox-toolbox-ng/internal/reseau"
)

// Détecteur de campagnes à ROTATION web (#3919, spec 5.4).
//
// Une campagne à rotation fait tourner une même requête sur des milliers d'adresses louées, chacune ne servant qu'une à trois fois : aucune adresse
// ne franchit seule un seuil de ban. On la reconnaît à sa SIGNATURE (navigateur déclaré exact, empreinte TLS JA4 si présente, hôte visé).
//
// RÈGLE ABSOLUE : ne jamais bannir un vrai visiteur ni un client légitime ; au moindre doute, pas de ban.
//
// SUIVI (rotation_requete.go) : seules les NAVIGATIONS (GET d'une page) des clients qui se disent navigateurs interactifs. git, apt, sondes, flux,
// robots déclarés, /.well-known/ : jamais suivis, donc jamais jugés.
//
// Campagne ÉTABLIE quand, dans la fenêtre glissante d'1 h d'une signature, les sources SANS PREUVE de navigateur sont ≥ SeuilSources, celles d'entre
// elles à ≤ 3 pages ≥ PartUneATrois % et celles classées `proxy_loue` ou `hebergeur` ≥ PartLouee % de TOUTES les sources (`inconnu` ne compte jamais :
// sans annuaire, jamais de campagne). Une source = une adresse IPv4 ou un /64 IPv6. Une campagne finit dès qu'une fenêtre recalculée (à chaque source
// nouvelle) ne tient plus les seuils, ou après 24 h sans nouvelle source sans preuve.
//
// VERDICT DIFFÉRÉ (défaut, décision du propriétaire du 24/11) : une adresse qui porte la signature d'une campagne établie est servie, puis jugée
// `Delai` (10 s) après la FIN d'une réponse 2xx text/html qui appelle des ressources (rotation_reponse.go, rotation_verdict.go). Elle n'est bannie (24 h,
// « rotation:<8 hex> ») que si AUCUNE preuve de navigateur n'est venue d'elle, ni pendant ce délai ni dans les 7 jours (rotation_memoire.go). Les
// sources qui ont servi à établir la campagne ne sont pas jugées. `immediat` : même chose sans délai (au premier Tick après la réponse).
//
// CLASSE DE L'ADRESSE ELLE-MÊME : seules `proxy_loue` et `hebergeur` sont bannissables, les classes où vivent les campagnes. Un particulier (`acces`,
// `mobile_partage`), un réseau inconnu, un CDN, un relais de vie privée, un scanner de recherche ne sont jamais bannis, même muets : un visiteur connu
// qui revient sous une nouvelle adresse est là. RESTE : un visiteur derrière un VPN hébergé dans un de ces réseaux, sans cookie ni preuve depuis 7 jours,
// et qui ne charge rien de la page (ressources en cache, navigateur qui les bloque).
//
// GARDE-FOUS, rejoués au moment du ban (en plus de ceux de NftBanner.banAt) : adresse privée/locale/protégée, robot d'indexation vérifié OU
// INVÉRIFIABLE (DNS en panne), sortie Tor connue, mémoire des navigateurs saturée, source d'établissement oubliée (la campagne ne juge plus), période de grâce après un démarrage, trou de plus d'une minute entre deux Tick (horloge, machine figée : verdicts abandonnés) ;
// plafond de MaxParHeure verdicts par heure glissante, gardé à travers un redémarrage, vérifié avant tout DNS. Mode `propose` : tout est établi, compté et
// écrit (état, audit), rien n'est banni et AUCUNE ligne de menace n'est écrite.
// Un ban de rotation n'est jamais prolongé (reevaluation.go) et ne compte pas comme sanction (actorban.go) ; sa ligne de journal n'est ni émise vers
// actord ni comptée comme sonde (profiler.go).
//
// CHEMIN DE LA REQUÊTE : Observe est O(1) sous deux verrous courts (mémoire, détecteur), sans E/S, sans appel à l'annuaire (les classes sont résolues
// par Tick, hors verrou), sans allocation pour une signature et une adresse déjà suivies. Toute E/S se fait dans Tick, appelé toutes les 2 s par
// Veiller. Aucune section critique de Tick ne parcourt plus de maxSourcesSig sources.
//
// MÉMOIRE BORNÉE :
//   - au plus MaxSignatures signatures suivies (LRU) ; une signature sans activité depuis Fenetre est oubliée ;
//   - au plus maxSourcesSig (5 000) sources par signature : au-delà, les nouvelles ne sont plus COMPTÉES tant que des places ne se libèrent pas
//     (purge des sources de plus d'une heure à chaque évaluation, demandée dès que le plafond est atteint) ;
//   - au plus maxSourcesTotal (200 000) sources toutes signatures confondues : au-delà, les signatures les moins récentes sont oubliées ;
//   - au plus maxAttente (3 000) verdicts en attente : au-delà, la nouvelle adresse n'est pas jugée (jamais bannie) ;
//   - au plus maxVerdicts (50 000) adresses déjà jugées retenues (une seule ligne par adresse et par jour) ;
//   - pages : 64 réponses suivies (64 Kio chacune), 8 analyses, un travailleur, 20 000 adresses examinées retenues 10 min ;
//   - navigateurs : 200 000, sources exemptées : 50 000 (rotation_memoire.go) ; MaxCampagnes campagnes actives, la moins récente sort.

// RotationConfig : réglages du détecteur ; une valeur nulle prend le défaut.
type RotationConfig struct {
	Mode          string        // off | propose | auto
	Verdict       string        // differe | immediat
	Fenetre       time.Duration // 1 h
	Delai         time.Duration // 10 s, à partir de la fin de la réponse
	Grace         time.Duration // 10 min après un démarrage sans juger (`auto` : tant que la mémoire a moins de 24 h) ; négatif : aucune
	SeuilSources  int           // 50
	PartUneATrois int           // 80 (%)
	PartLouee     int           // 60 (%)
	Duree         time.Duration // 24 h : durée du ban ET durée de vie d'une campagne sans nouvelle source
	MaxParHeure   int           // 1500
	MaxCampagnes  int           // 10
	MaxSignatures int           // 20000
	Etat          string        // fichier d'état (panneau, relevé populations)
	Navigateurs   string        // mémoire des navigateurs ; vide : rotation-navigateurs.bin à côté de l'état
	Audit         string        // journal d'audit du WAF (ajout seul)
	Protegees     []*net.IPNet  // jamais bannies (en plus du privé/local)
	SortiesTor    string        // liste locale des sorties Tor (une adresse par ligne) ; absente = garde inactive, signalée dans l'état
	Horloge       func() time.Time
}

const (
	rotationPasEval        = 10 * time.Second // une signature est réévaluée au plus toutes les 10 s (une campagne : à chaque Tick)
	rotationEtatPas        = time.Minute      // état réécrit au moins chaque minute, sinon sur changement
	rotationTorPas         = 10 * time.Minute // liste Tor relue au plus toutes les 10 min
	rotationBudgetEval     = 60000            // sources évaluées au plus par Tick
	rotationMaxEval        = 2000             // signatures évaluées au plus par Tick
	rotationMaxPurge       = 2000             // signatures ou adresses oubliées au plus par Tick
	rotationMaxDecisions   = 100              // verdicts rendus (et lignes de journal) au plus par Tick
	rotationTempsDecisions = 5 * time.Second  // défaut de tempsDecisions
	rotationVerdictPerime  = time.Minute      // verdict échu depuis plus longtemps : abandonné, jamais un ban
	rotationTrouTick       = time.Minute      // trou entre deux Tick : verdicts en attente abandonnés
	rotationGrace          = 10 * time.Minute
	rotationGraceVide      = 24 * time.Hour // `auto` : âge minimal de la mémoire des navigateurs (avant, on ne connaît pas les visiteurs)
	rotationEchantillon    = 10             // fenêtre partielle (première heure) : sources nécessaires pour conclure sur les parts
	rotationToleranceFutur = 60             // s : écart d'horloge toléré dans un état relu
	rotationRobotsTires    = 5              // sources vérifiées (robots d'indexation) avant d'établir une campagne
	rotationExemptesMax    = 50000
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

type rotSource struct {
	cle    uint64 // condensé (mémoire des navigateurs)
	vu     uint32 // dernière navigation (Unix, s)
	n      uint8  // navigations (saturé)
	classe uint8
}

type rotSignature struct {
	cle        [32]byte
	hote       string
	sources    map[[16]byte]rotSource // origine (IPv4, ou /64 IPv6)
	premier    int64                  // début du suivi (UnixNano)
	dernier    int64                  // dernière navigation (UnixNano)
	evalue     int64                  // dernière évaluation
	prec, suiv *rotSignature
}

type rotCampagne struct {
	cle                [32]byte
	signature, hote    string
	etablieLe, dernier int64          // Unix (s) ; dernier = dernière NOUVELLE source sans preuve
	sources, une, le3  int            // sources sans preuve de la fenêtre
	classes            map[string]int // en %
	bannies, epargnees int
	aBannir, ecartees  int
	classeProtegee     int // adresse d'une classe jamais bannie
	suspendues         int // une source d'établissement a été oubliée : la campagne ne juge plus
}

// rotCandidat : adresse neuve portant la signature d'une campagne établie ; le verdict ne s'ouvre qu'avec Servie.
type rotCandidat struct {
	adr  netip.Addr
	h    uint64
	cle  [32]byte
	hote string
}

type rotVerdict struct {
	rotCandidat
	echeance int64 // UnixNano
}

// Rotation : le détecteur. Sûr pour un usage concurrent (Observe et Servie depuis les requêtes, Tick depuis un seul ticker).
type Rotation struct {
	cfg     RotationConfig
	banneur banneurDuree
	annu    classeur
	robots  func(ip string) (nom string, sur bool) // robot d'indexation vérifié, à trois états (Crawlers.VerifieSur) ; nil : pas de vérification ici
	journal func(ThreatRecord)                     // journal des menaces (une ligne par verdict) ; nil : aucun
	temoin  *rotationTemoin                        // rejeu hors ligne seulement (rotation_rejeu.go) ; nil en service

	maxSourcesSig   int
	maxSourcesTotal int
	maxVerdicts     int
	maxAttente      int
	tempsDecisions  time.Duration // temps réel donné aux verdicts d'un Tick (DNS) ; le reste attend le suivant

	sel      [32]byte         // sel des condensés d'adresses (fixe après NewRotation)
	memoire  *memoireAdresses // navigateurs
	exemptes *memoireAdresses // sources qui ont servi à établir une campagne
	graceFin time.Time
	// memoireDepuis : la mémoire des navigateurs est continue depuis (Unix, s) ; fixe après NewRotation
	memoireDepuis int64
	debut         time.Time
	captures      atomic.Int32 // réponses candidates suivies en ce moment

	// analyse des pages (rotation_reponse.go)
	analyses      atomic.Int32 // déposées ou en cours
	abandonnees   atomic.Int64 // réponses non suivies ou pages non analysées, faute de place
	aAnalyser     chan rotationAnalyse
	unTravailleur sync.Once
	examinees     *memoireAdresses // adresses dont une page vient d'être analysée (10 min)
	avantAnalyse  func()           // essais

	mu          sync.Mutex
	sigs        map[[32]byte]*rotSignature
	tete, queue *rotSignature // LRU : tête = plus récente
	nSources    int
	aEvaluer    map[*rotSignature]struct{}
	campagnes   map[[32]byte]*rotCampagne
	enAttente   map[netip.Addr]struct{}
	attente     []rotVerdict // FIFO des verdicts ouverts
	juges       map[netip.Addr]int64
	ordreJuges  []netip.Addr // FIFO des adresses jugées
	etatSale    bool
	audits      []map[string]any

	// propres à Tick (un seul appelant)
	dernierTick time.Time
	recents     []time.Time // verdicts « robot » (bans en auto, propositions en propose) de l'heure glissante
	plafondDit  bool
	tor         map[string]struct{}
	torLuLe     time.Time
	torAverti   bool
	etatEcritLe time.Time
	tampon      []rotExamen

	ecritMu        sync.Mutex // fichier de la mémoire (Tick et arrêt du service)
	memoireEcritLe time.Time
}

// rotationTemoin suit ce que fait le détecteur, sans rien y changer. Appelé depuis Tick ; etablie et finie le sont SOUS le verrou : elles ne rappellent
// jamais le détecteur.
type rotationTemoin struct {
	etablie func(c *rotCampagne, premier int64) // premier : début du suivi de la signature (Unix, s)
	finie   func(c *rotCampagne, t time.Time, raison string)
	verdict func(v rotVerdict, raison string, t time.Time) // raison vide : à bannir
}

// NewRotation construit le détecteur, relit l'état persistant (campagnes actives de moins de Duree) et la mémoire des navigateurs.
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
	if cfg.Grace == 0 {
		cfg.Grace = rotationGrace
	}
	if cfg.Navigateurs == "" && cfg.Etat != "" {
		cfg.Navigateurs = filepath.Join(filepath.Dir(cfg.Etat), "rotation-navigateurs.bin")
	}
	if cfg.Horloge == nil {
		cfg.Horloge = time.Now
	}
	t := cfg.Horloge()
	r := &Rotation{cfg: cfg, banneur: b, annu: a, maxSourcesSig: 5000, maxSourcesTotal: 200000, maxVerdicts: 50000, maxAttente: 3000, tempsDecisions: rotationTempsDecisions,
		sel: nouveauSel(), memoire: nouvelleMemoire(rotationMemoireMax, rotationMemoireTTL), exemptes: nouvelleMemoire(rotationExemptesMax, rotationMemoireTTL),
		examinees: nouvelleMemoire(rotationExamens, rotationExamen), aAnalyser: make(chan rotationAnalyse, rotationAnalyses),
		debut: t, graceFin: t, sigs: map[[32]byte]*rotSignature{}, aEvaluer: map[*rotSignature]struct{}{}, campagnes: map[[32]byte]*rotCampagne{},
		enAttente: map[netip.Addr]struct{}{}, juges: map[netip.Addr]int64{}, etatSale: true}
	if cfg.Mode == "off" {
		return r
	}
	r.relireEtat(t)
	r.relireMemoire(t)
	if cfg.Grace > 0 {
		r.graceFin = t.Add(cfg.Grace)
		if plein := time.Unix(r.memoireDepuis, 0).Add(rotationGraceVide); cfg.Mode == "auto" && plein.After(r.graceFin) {
			r.graceFin = t.Add(plein.Sub(t).Round(time.Second))
			log.Printf("sbxwaf: rotation — mémoire des navigateurs trop jeune (%s) : rien ne sera jugé avant %s", cfg.Navigateurs, r.graceFin.Format(time.RFC3339))
		}
	}
	return r
}

// relireMemoire reprend la mémoire des navigateurs. Absente, illisible, du futur ou trop vieille pour être complète : elle (re)commence maintenant.
func (r *Rotation) relireMemoire(t time.Time) {
	r.memoireDepuis = t.Unix()
	if r.cfg.Navigateurs == "" {
		return
	}
	sel, depuis, ecritLe, err := lireMemoires(r.cfg.Navigateurs, t, r.memoire, r.exemptes)
	if err != nil {
		// Sans la liste de ses sources d'établissement, une campagne relue pourrait les juger : elle devra se rétablir.
		r.campagnes = map[[32]byte]*rotCampagne{}
		return
	}
	r.sel = sel
	if age := t.Unix() - ecritLe; depuis <= ecritLe && age >= -rotationToleranceFutur && age <= int64(rotationMemoireTrou/time.Second) {
		r.memoireDepuis = depuis
	}
}

// EcrireMemoire écrit la mémoire des navigateurs (Tick, et arrêt du service).
func (r *Rotation) EcrireMemoire(t time.Time) {
	if r == nil || r.cfg.Mode == "off" || r.cfg.Navigateurs == "" {
		return
	}
	r.ecritMu.Lock()
	defer r.ecritMu.Unlock()
	if err := ecrireMemoires(r.cfg.Navigateurs, r.sel, r.memoireDepuis, t, r.memoire, r.exemptes); err != nil {
		log.Printf("sbxwaf: rotation — mémoire des navigateurs non écrite : %v", err)
	}
	r.memoireEcritLe = t
}

func (r *Rotation) entretenirMemoire(t time.Time) {
	r.ecritMu.Lock()
	age := t.Sub(r.memoireEcritLe)
	du := r.memoireEcritLe.IsZero() || age < 0 || age >= rotationMemoireRepos || age >= rotationMemoirePas && (r.memoire.estSale() || r.exemptes.estSale())
	r.ecritMu.Unlock()
	if du {
		r.EcrireMemoire(t)
	}
}

// SetRobots branche la vérification des robots d'indexation à trois états (Crawlers.VerifieSur).
func (r *Rotation) SetRobots(f func(ip string) (string, bool)) { r.robots = f }

// SetJournal branche le journal des menaces : une ligne par verdict « robot », écrite depuis Tick.
func (r *Rotation) SetJournal(f func(ThreatRecord)) { r.journal = f }

// Signature : SHA-256 hexadécimal de ua, ja4 et hôte séparés par un octet nul.
func Signature(ua, ja4, host string) string {
	c := cleSignature(ua, ja4, host)
	return hex.EncodeToString(c[:])
}

// groupeDe : la campagne, en 32 bits (jamais 0, qui veut dire « plusieurs »).
func groupeDe(cle [32]byte) uint32 { return binary.LittleEndian.Uint32(cle[:4]) | 1 }

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

func adresse(ip string) (netip.Addr, bool) {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return a, false
	}
	return a.Unmap().WithZone(""), true
}

// NoterPreuve retient qu'un vrai navigateur tient cette adresse. Appelée pour TOUTE requête non privée portant une preuve.
func (r *Rotation) NoterPreuve(ip string, t time.Time) {
	if r == nil || r.cfg.Mode == "off" {
		return
	}
	if a, ok := adresse(ip); ok {
		r.memoire.noter(cleAdresse(&r.sel, a), t.Unix())
	}
}

// Observe note une requête et rend un candidat si l'adresse doit être jugée : l'appelant appelle Servie quand la page est partie (jamais sinon).
func (r *Rotation) Observe(q RotationRequete, t time.Time) *rotCandidat {
	if r == nil || r.cfg.Mode == "off" {
		return nil
	}
	if q.Preuve {
		r.NoterPreuve(q.IP, t)
	}
	if !q.Navigation || len(q.JA4) > rotationJA4Max || !navigateurInteractif(q.UA) {
		return nil
	}
	a, ok := adresse(q.IP)
	hote := hoteRotation(q.Hote)
	if !ok || hote == "" {
		return nil
	}
	cle, h, s := cleSignature(q.UA, q.JA4, hote), cleAdresse(&r.sel, a), t.Unix()
	navigateur := q.Preuve || r.memoire.contient(h, s)

	r.mu.Lock()
	defer r.mu.Unlock()
	c := r.campagnes[cle]
	sig := r.signatureSuivie(cle, hote, t.UnixNano())
	nouvelle, comptee := r.noterSource(sig, origine(a).As16(), h, s, c != nil)
	if c == nil {
		return nil
	}
	if navigateur {
		if nouvelle && comptee {
			c.epargnees++
			r.etatSale = true
		}
		return nil
	}
	if nouvelle {
		c.dernier = s
	}
	if t.Before(r.graceFin) || r.exemptes.contient(h, s) || r.examinees.contient(h, s) || r.dejaVue(a) {
		return nil
	}
	return &rotCandidat{adr: a, h: h, cle: cle, hote: sig.hote}
}

func (r *Rotation) dejaVue(a netip.Addr) bool {
	_, att := r.enAttente[a]
	_, jug := r.juges[a]
	return att || jug
}

// Servie ouvre le verdict du candidat : sa page (2xx text/html, avec ressources) vient de partir en entier.
func (r *Rotation) Servie(x *rotCandidat, t time.Time) {
	if r == nil || x == nil || r.memoire.contient(x.h, t.Unix()) || r.exemptes.contient(x.h, t.Unix()) {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.campagnes[x.cle] == nil || r.dejaVue(x.adr) || len(r.attente) >= r.maxAttente {
		return
	}
	ech := t.UnixNano()
	if r.cfg.Verdict == "differe" {
		ech += int64(r.cfg.Delai)
	}
	r.enAttente[x.adr] = struct{}{}
	r.attente = append(r.attente, rotVerdict{rotCandidat: *x, echeance: ech})
}

// Suivre enveloppe la réponse faite à un candidat ; nil (pas de verdict) si trop de réponses sont déjà suivies. À libérer par Liberer.
func (r *Rotation) Suivre(x *rotCandidat) *rotationReponse {
	if r == nil || x == nil {
		return nil
	}
	if r.captures.Add(1) > rotationSuivis {
		r.captures.Add(-1)
		r.abandonnees.Add(1)
		return nil
	}
	return &rotationReponse{}
}

func (r *Rotation) Liberer() { r.captures.Add(-1) }

// signatureSuivie (sous verrou) rend la signature, créée au besoin, placée en tête du LRU.
func (r *Rotation) signatureSuivie(cle [32]byte, host string, ns int64) *rotSignature {
	s := r.sigs[cle]
	if s == nil {
		for len(r.sigs) >= r.cfg.MaxSignatures && r.queue != nil {
			r.oublier(r.queue)
		}
		s = &rotSignature{cle: cle, hote: strings.Clone(host), sources: map[[16]byte]rotSource{}, premier: ns}
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

// noterSource (sous verrou) compte la navigation ; `nouvelle` : source inconnue de la signature ; `comptee` : elle entre dans les statistiques.
func (r *Rotation) noterSource(s *rotSignature, o [16]byte, h uint64, sec int64, campagne bool) (nouvelle, comptee bool) {
	if src, ok := s.sources[o]; ok {
		if src.n < 0xff {
			src.n++
		}
		src.vu = uint32(sec)
		s.sources[o] = src
		return false, true
	}
	for r.nSources >= r.maxSourcesTotal && r.queue != nil && r.queue != s && len(s.sources) < r.maxSourcesSig {
		r.oublier(r.queue)
	}
	if len(s.sources) >= r.maxSourcesSig || r.nSources >= r.maxSourcesTotal {
		r.aEvaluer[s] = struct{}{} // plein : l'évaluation purge les sources sorties de la fenêtre et rend des places
		return true, false
	}
	s.sources[o] = rotSource{cle: h, n: 1, vu: uint32(sec)}
	r.nSources++
	if campagne || len(s.sources) >= r.cfg.SeuilSources {
		r.aEvaluer[s] = struct{}{}
	}
	return true, true
}

// Veiller relance Tick à intervalle régulier.
func (r *Rotation) Veiller(pas time.Duration) {
	for {
		r.Tick(time.Now())
		time.Sleep(pas)
	}
}

// Tick : liste Tor, évaluation des signatures, expirations, verdicts échus, audit, état et mémoire. Un seul appelant à la fois.
func (r *Rotation) Tick(t time.Time) {
	if r == nil || r.cfg.Mode == "off" {
		return
	}
	if !r.dernierTick.IsZero() {
		// Écart d'horloge MURALE (celle des échéances) : un saut en avant ferait tomber d'un coup des verdicts jamais attendus.
		if e := t.UnixNano() - r.dernierTick.UnixNano(); e < 0 || e > int64(rotationTrouTick) {
			r.abandonnerAttente()
		}
	}
	r.dernierTick = t
	r.chargerTor(t)
	r.evaluerTout(t)
	r.expirer(t)
	r.juger(t)

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
	r.entretenirMemoire(t)
}

func (r *Rotation) abandonnerAttente() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if n := len(r.attente); n > 0 {
		log.Printf("sbxwaf: rotation — trou entre deux passes : %d verdict(s) en attente abandonné(s)", n)
	}
	r.attente, r.enAttente = nil, map[netip.Addr]struct{}{}
}

func (r *Rotation) classer(ip string) reseau.Info {
	if r.annu == nil {
		return reseau.Info{Classe: reseau.ClasseInconnu}
	}
	return r.annu.Classer(ip)
}

// ── Évaluation ───────────────────────────────────────────────────────────────────────────────────────────────────────

type rotExamen struct {
	o       [16]byte
	src     rotSource
	apprise bool // classe résolue dans cette passe
}

func (r *Rotation) evaluerTout(t time.Time) {
	ns := t.UnixNano()
	r.mu.Lock()
	var liste []*rotSignature
	for s := range r.aEvaluer {
		if r.campagnes[s.cle] == nil && ns-s.evalue < int64(rotationPasEval) {
			continue
		}
		if liste = append(liste, s); len(liste) >= rotationMaxEval {
			break
		}
	}
	r.mu.Unlock()
	budget := rotationBudgetEval
	for _, s := range liste {
		if budget <= 0 {
			return // reste marquée : au prochain Tick
		}
		budget -= r.evaluer(s, t)
	}
}

// evaluer recalcule la fenêtre d'une signature et établit, met à jour ou finit sa campagne. Rend le nombre de sources lues.
func (r *Rotation) evaluer(s *rotSignature, t time.Time) int {
	limite, sec := t.Add(-r.cfg.Fenetre).Unix(), t.Unix()

	// 1. Purge et copie, sous verrou (au plus maxSourcesSig entrées).
	ex := r.tampon[:0]
	r.mu.Lock()
	if r.sigs[s.cle] != s {
		r.mu.Unlock()
		return 0
	}
	delete(r.aEvaluer, s)
	s.evalue = t.UnixNano()
	for o, src := range s.sources {
		if int64(src.vu) < limite {
			delete(s.sources, o)
			r.nSources--
			continue
		}
		ex = append(ex, rotExamen{o: o, src: src})
	}
	campagne := r.campagnes[s.cle] != nil
	r.mu.Unlock()
	r.tampon = ex

	// 2. Classes, preuves et statistiques, hors verrou.
	var n, sans, une, le3, louee int
	var parClasse [16]int
	var tirees []netip.Addr
	for i := range ex {
		x := &ex[i]
		if x.src.classe == 0 {
			x.src.classe = codeClasse(r.classer(netip.AddrFrom16(x.o).Unmap().String()).Classe)
			x.apprise = true
		}
		n++
		if r.memoire.contient(x.src.cle, sec) {
			continue // un vrai navigateur ne compte jamais EN FAVEUR d'une campagne
		}
		sans++
		if x.src.n == 1 {
			une++
		}
		if x.src.n <= 3 {
			le3++
		}
		parClasse[x.src.classe]++
		if cl := rotationClasses[x.src.classe]; cl == reseau.ClasseProxyLoue || cl == reseau.ClasseHebergeur {
			louee++
		}
		if len(tirees) < rotationRobotsTires {
			tirees = append(tirees, netip.AddrFrom16(x.o).Unmap())
		}
	}
	parts := le3*100 >= r.cfg.PartUneATrois*n && louee*100 >= r.cfg.PartLouee*n
	tient := sans >= r.cfg.SeuilSources && parts
	// Première heure : la fenêtre n'est pas pleine (campagne relue), le nombre ne prouve rien ; les parts, si l'échantillon suffit.
	if campagne && !tient && t.Sub(r.debut) < r.cfg.Fenetre {
		tient = parts || n < rotationEchantillon
	}
	if !campagne && tient && r.robotsParmi(tirees) {
		tient = false // robots d'indexation vérifiés : jamais une campagne (spec 7.1)
	}
	if !campagne && tient {
		for i := range ex {
			r.exemptes.noterGroupe(ex[i].src.cle, sec, groupeDe(s.cle))
		}
	}

	// 3. Résultat, sous verrou.
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.sigs[s.cle] == s {
		for _, x := range ex {
			if x.apprise {
				if src, ok := s.sources[x.o]; ok {
					src.classe = x.src.classe
					s.sources[x.o] = src
				}
			}
		}
	}
	c := r.campagnes[s.cle]
	if !tient {
		if c != nil {
			r.finir(c, t, "seuils")
		}
		return len(ex)
	}
	if c == nil {
		if campagne {
			return len(ex) // sortie entre-temps
		}
		c = r.etablir(s, t)
		for _, src := range s.sources { // arrivées pendant le calcul
			if !r.exemptes.contient(src.cle, sec) {
				r.exemptes.noterGroupe(src.cle, sec, groupeDe(s.cle))
			}
		}
		defer func() {
			r.audits = append(r.audits, map[string]any{"ts": t.UTC().Format("2006-01-02T15:04:05Z"), "module": "waf", "action": "rotation_etablie",
				"detail": "campagne à rotation " + c.signature[:8] + " sur " + c.hote, "signature": c.signature, "hote": c.hote,
				"sources": c.sources, "une": c.une, "le3": c.le3, "classes": c.classes, "mode": r.cfg.Mode, "verdict": r.cfg.Verdict})
			log.Printf("sbxwaf: rotation — campagne %s établie sur %s (%d sources, mode=%s, verdict=%s)", c.signature[:8], c.hote, c.sources,
				r.cfg.Mode, r.cfg.Verdict)
		}()
	}
	if sans > 0 {
		c.sources, c.une, c.le3 = sans, une*100/sans, le3*100/sans
		c.classes = map[string]int{}
		for i, k := range parClasse {
			if k > 0 && i < len(rotationClasses) {
				c.classes[rotationClasses[i]] = k * 100 / sans
			}
		}
	}
	if !campagne && r.temoin != nil {
		r.temoin.etablie(c, s.premier/int64(time.Second))
	}
	r.etatSale = true
	return len(ex)
}

// robotsParmi (hors verrou) : un robot d'indexation VÉRIFIÉ est parmi les sources tirées. S'arrête à la première panne du DNS (chaque ban est de toute
// façon vérifié un par un).
func (r *Rotation) robotsParmi(tirees []netip.Addr) bool {
	if r.robots == nil {
		return false
	}
	for _, a := range tirees {
		nom, sur := r.robots(a.String())
		if nom != "" {
			return true
		}
		if !sur {
			return false
		}
	}
	return false
}

// etablir (sous verrou) crée la campagne ; au-delà de MaxCampagnes, la moins récemment active sort.
func (r *Rotation) etablir(s *rotSignature, t time.Time) *rotCampagne {
	for len(r.campagnes) >= r.cfg.MaxCampagnes {
		var vieille *rotCampagne
		for _, x := range r.campagnes {
			if vieille == nil || x.dernier < vieille.dernier {
				vieille = x
			}
		}
		r.finir(vieille, t, "plafond_campagnes")
	}
	c := &rotCampagne{cle: s.cle, signature: hex.EncodeToString(s.cle[:]), hote: s.hote, etablieLe: t.Unix(), dernier: t.Unix()}
	r.campagnes[s.cle] = c
	return c
}

// finir (sous verrou) retire une campagne et l'écrit dans l'audit. Ses verdicts en attente tombent avec elle (juger ne la trouve plus).
func (r *Rotation) finir(c *rotCampagne, t time.Time, raison string) {
	delete(r.campagnes, c.cle)
	r.etatSale = true
	if r.temoin != nil {
		r.temoin.finie(c, t, raison)
	}
	r.audits = append(r.audits, map[string]any{"ts": t.UTC().Format("2006-01-02T15:04:05Z"), "module": "waf", "action": "rotation_fin",
		"detail": "campagne à rotation " + c.signature[:8] + " terminée (" + raison + ")", "signature": c.signature, "hote": c.hote,
		"raison": raison, "bannies": c.bannies, "epargnees": c.epargnees, "a_bannir": c.aBannir})
	log.Printf("sbxwaf: rotation — campagne %s terminée (%s, %d bannies, %d épargnées)", c.signature[:8], raison, c.bannies, c.epargnees)
}

// expirer : campagnes sans nouvelle source depuis Duree (ou datées du futur : horloge reculée), signatures inactives depuis Fenetre, adresses jugées
// depuis Duree. Travail borné par passe.
func (r *Rotation) expirer(t time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, c := range r.campagnes {
		if t.Unix()-c.dernier > int64(r.cfg.Duree/time.Second) {
			r.finir(c, t, "inactive")
		} else if c.dernier > t.Unix()+rotationToleranceFutur {
			r.finir(c, t, "horloge")
		}
	}
	limite := t.Add(-r.cfg.Fenetre).UnixNano()
	for i := 0; i < rotationMaxPurge && r.queue != nil && r.queue.dernier < limite; i++ {
		r.oublier(r.queue)
	}
	vieux, k := t.Add(-r.cfg.Duree).UnixNano(), 0
	for k < len(r.ordreJuges) && k < rotationMaxPurge && r.juges[r.ordreJuges[k]] < vieux {
		delete(r.juges, r.ordreJuges[k])
		k++
	}
	r.ordreJuges = r.ordreJuges[k:]
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

func (r *Rotation) nbAttente() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.attente)
}
