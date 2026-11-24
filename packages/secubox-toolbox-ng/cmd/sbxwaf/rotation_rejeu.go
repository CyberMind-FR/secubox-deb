// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// See LICENCE-CMSD-1.0.md for terms.

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/CyberMind-FR/secubox-deb/secubox-toolbox-ng/internal/reseau"
)

// REJEU HORS LIGNE du détecteur de rotation (#3919) sur des journaux d'accès nginx : le VRAI détecteur (rotation.go), une horloge simulée, le mode
// `propose`. Il répond, avant tout usage en service, à : quelles campagnes auraient été établies, combien d'adresses auraient été bannies, lesquelles
// ressemblent à de vrais visiteurs.
//
// Ni nft, ni réseau (aucun DNS : aucune vérification de robot), ni écriture : les journaux, la base ASN, le catalogue et la liste Tor sont LUS, le
// rapport JSON part sur `sortie`, l'état ne vit qu'en mémoire. Sans privilège. Par défaut : des comptes, aucune adresse.
//
// Deux lectures : la première rejoue, la seconde cherche, indépendamment du détecteur, ce qui innocenterait les adresses « qui auraient été bannies ».

var rejeuApproximations = []string{
	"MAJORANT pour les requêtes journalisées : les bans mesurés ici sont au plus ce que le détecteur aurait fait de ces mêmes requêtes ; les gardes qui manquent (ci-dessous) ne feraient qu'en retirer",
	"page : GET, statut 2xx, chemin sans extension de ressource, de téléchargement ni de texte brut ; elle est supposée être du HTML appelant des ressources (le détecteur le vérifie dans le corps)",
	"preuves vues : référent, ressource de page, statut 304, compte HTTP ; cookies, Sec-Fetch-*, Authorization sans compte et préchargements ne sont pas journalisés",
	"empreinte TLS (JA4) absente : des clients que le détecteur sépare sont ici dans la même signature ; plus de sources, mais de vrais visiteurs au même navigateur peuvent aussi y diluer une campagne (seul écart connu qui minore)",
	"robots d'indexation : aucune vérification (pas de DNS) ; seuls les robots déclarés sont écartés",
	"fin de la réponse = date de la ligne, à la seconde près ; les lignes d'une même seconde gardent l'ordre des fichiers",
	"mémoire des navigateurs vide au début du journal : un visiteur connu d'avant est jugé comme neuf",
	"requêtes absentes des journaux (refusées par le WAF, servies sans passer par nginx, access_log off) : non vues, ni comme sources ni comme preuves",
	"hôte : celui de la ligne s'il y est, sinon le nom du fichier ; un vhost écrit dans deux journaux donnés ensemble est compté deux fois",
	"première requête d'une campagne : début du suivi ininterrompu (sans trou d'1 h) de sa signature ; un navigateur très répandu peut y précéder l'attaque",
}

const (
	rejeuExemples     = 20
	rejeuVhostsMax    = 2000
	rejeuCampagnesMax = 2000
	rejeuPasTick      = 2 * time.Second // comme en service
	rejeuPasCalme     = 30 * time.Second
	rejeuCalme        = 60             // s sans ligne
	rejeuSommeil      = 26 * time.Hour // au-delà, plus rien ne peut changer (campagnes : 24 h)
	rejeuRetardMax    = 600            // s : ligne plus en retard que cela sur l'horloge simulée : sa navigation ne compte pas
	rejeuInnocente    = 24 * 3600      // s, avant ou après
)

type rejeuRapport struct {
	GenereLe       string   `json:"genere_le"`
	Mode           string   `json:"mode"`
	Verdict        string   `json:"verdict"`
	SansGrace      bool     `json:"sans_grace"`
	Majorant       bool     `json:"majorant"`
	Approximations []string `json:"approximations"`
	Debut          string   `json:"debut"`
	Fin            string   `json:"fin"`
	Reglages       struct {
		SeuilSources  int  `json:"seuil_sources"`
		PartUneATrois int  `json:"part_une_a_trois"`
		PartLouee     int  `json:"part_louee"`
		MaxParHeure   int  `json:"max_par_heure"`
		MaxCampagnes  int  `json:"max_campagnes"`
		TorGarde      bool `json:"tor_garde"`
	} `json:"reglages"`
	Fichiers struct {
		Lus       int           `json:"lus"`
		SansLigne int           `json:"sans_ligne_lisible"`
		EnErreur  []rejeuErreur `json:"en_erreur"`
	} `json:"fichiers"`
	Lignes struct {
		Lues        int `json:"lues"`
		Malformees  int `json:"malformees"`
		Privees     int `json:"adresses_privees"` // ignorées, comme en service
		HorsOrdre   int `json:"hors_ordre"`       // trop en retard : la preuve compte, pas la navigation
		Navigations int `json:"navigations"`
		Preuves     int `json:"preuves"`
	} `json:"lignes"`
	Annuaire struct {
		AvecReseau int `json:"adresses_avec_reseau"` // consultations
		SansReseau int `json:"adresses_sans_reseau"`
	} `json:"annuaire"`
	Campagnes          []*rejeuCampagne `json:"campagnes"`
	CampagnesOubliees  int              `json:"campagnes_non_listees"`
	HotesAvecCampagne  []string         `json:"hotes_avec_campagne"`
	AuraientEteBannies struct {
		Adresses  int            `json:"adresses"` // distinctes
		Verdicts  int            `json:"verdicts"` // une adresse est jugée au plus une fois par jour
		ParClasse map[string]int `json:"par_classe"`
	} `json:"auraient_ete_bannies"`
	Epargnees            map[string]int         `json:"epargnees"` // verdicts ouverts, par raison
	EnAttenteALaFin      int                    `json:"en_attente_a_la_fin"`
	MemoireSaturee       bool                   `json:"memoire_saturee"`
	ParVhost             map[string]*rejeuVhost `json:"par_vhost"`
	SuspectsFauxPositifs rejeuSuspects          `json:"suspects_faux_positifs"`
}

type rejeuCampagne struct {
	Signature       string         `json:"signature"`
	Hote            string         `json:"hote"`
	PremiereRequete string         `json:"premiere_requete"`
	EtablieLe       string         `json:"etablie_le"`
	DelaiS          int64          `json:"delai_s"`
	FinieLe         string         `json:"finie_le"` // vide : encore active à la fin
	FinRaison       string         `json:"fin_raison"`
	Sources         int            `json:"sources"` // à l'établissement, sans preuve ; de même une, le3, classes
	Une             int            `json:"une"`
	Le3             int            `json:"le3"`
	Classes         map[string]int `json:"classes"`
	// verdicts
	AuraientEteBannies int            `json:"auraient_ete_bannies"`
	ParClasse          map[string]int `json:"auraient_ete_bannies_par_classe"`
	Epargnees          int            `json:"epargnees"` // par une preuve (verdicts, et nouvelles sources déjà connues)
	Ecartees           map[string]int `json:"ecartees"`  // par un garde-fou, par raison
	Exemples           []string       `json:"exemples,omitempty"`

	c *rotCampagne
}

type rejeuVhost struct {
	Lignes             int `json:"lignes"`
	Navigations        int `json:"navigations"`
	Preuves            int `json:"preuves"`
	Campagnes          int `json:"campagnes"`
	AuraientEteBannies int `json:"auraient_ete_bannies"`
}

// rejeuSuspects : adresses qui auraient été bannies et qui se sont montrées navigateurs STRICTEMENT APRÈS leur verdict, dans les 24 h. C'est le seul
// compteur qui informe (`adresses` = `preuve_apres`) ; un faux ban n'y est pas prouvé, une adresse louée peut avoir changé de client.
type rejeuSuspects struct {
	Lecture     string           `json:"lecture"`
	Adresses    int              `json:"adresses"`
	PreuveApres int              `json:"preuve_apres"`
	ParPreuve   map[string]int   `json:"par_preuve"`
	Exemples    []string         `json:"exemples,omitempty"`
	Structurels rejeuStructurels `json:"structurels"`
}

// rejeuStructurels : contrôles nuls (ou presque) PAR CONSTRUCTION ; zéro n'y prouve rien, autre chose dénonce un défaut. Jamais comptés dans `adresses`.
type rejeuStructurels struct {
	PreuveAvant      int `json:"preuve_avant"`       // épargnée par le détecteur (epargnees.preuve)
	PriveLanMaillage int `json:"prive_lan_maillage"` // jamais observée, ou garde « protegee »
	RobotsDeclares   int `json:"robots_declares"`    // jamais suivie sous ce nom : seulement une adresse qui en change
}

const rejeuLectureSuspects = "seul preuve_apres informe (preuve de navigateur après le verdict, 24 h au plus, même IPv4 ou même /64) ; structurels : nuls par construction, sans valeur de preuve"

// rejeuBannie : une adresse qui aurait été bannie (bornée par le plafond horaire du détecteur).
type rejeuBannie struct {
	adr              netip.Addr
	premier, dernier int64 // verdicts
	preuves          map[string]bool
	avant, apres     bool
	robot            bool
}

// classeurCompte compte ce que l'annuaire sait (une base absente ne doit pas passer pour « aucune campagne »).
type classeurCompte struct {
	a   classeur
	rap *rejeuRapport
}

func (c classeurCompte) Classer(ip string) reseau.Info {
	i := reseau.Info{Classe: reseau.ClasseInconnu}
	if c.a != nil {
		i = c.a.Classer(ip)
	}
	if i.ASN != 0 {
		c.rap.Annuaire.AvecReseau++
	} else {
		c.rap.Annuaire.SansReseau++
	}
	return i
}

type rejeu struct {
	rap       *rejeuRapport
	cfg       RotationConfig
	a         classeurCompte
	adresses  bool
	r         *Rotation
	horloge   int64 // simulée, monotone
	tick      int64 // dernier Tick
	courantes map[[32]byte]*rejeuCampagne
	bannies   map[netip.Addr]*rejeuBannie
	origines  map[netip.Addr][]*rejeuBannie // par IPv4 ou /64 IPv6 (seconde lecture)
	parti     bool
}

func dateRejeu(s int64) string {
	if s == 0 {
		return ""
	}
	return time.Unix(s, 0).UTC().Format(time.RFC3339)
}

// Rejouer rejoue les journaux et écrit le rapport JSON. Le mode est toujours `propose`, aucun fichier n'est écrit, quelle que soit `cfg` (Grace
// négatif : aucune période sans juger). `adresses` : liste au plus 20 adresses par campagne.
func Rejouer(fichiers []string, cfg RotationConfig, a classeur, adresses bool, sortie io.Writer) error {
	rap := &rejeuRapport{Mode: "propose", SansGrace: cfg.Grace < 0, Majorant: true, Approximations: append([]string(nil), rejeuApproximations...),
		Campagnes: []*rejeuCampagne{}, HotesAvecCampagne: []string{}, Epargnees: map[string]int{}, ParVhost: map[string]*rejeuVhost{}}
	rap.GenereLe = dateRejeu(time.Now().Unix())
	rap.AuraientEteBannies.ParClasse = map[string]int{}
	rap.SuspectsFauxPositifs = rejeuSuspects{Lecture: rejeuLectureSuspects, ParPreuve: map[string]int{}}

	flux, lues, mal, sansLigne, erreurs := reperer(fichiers)
	if len(flux)+sansLigne == 0 {
		return fmt.Errorf("aucun journal lisible (%d erreur(s), dont %s)", len(erreurs), premiereErreur(erreurs))
	}
	cfg.Mode, cfg.Etat, cfg.Navigateurs, cfg.Audit = "propose", "", "", ""
	j := &rejeu{rap: rap, cfg: cfg, a: classeurCompte{a, rap}, adresses: adresses, courantes: map[[32]byte]*rejeuCampagne{}, bannies: map[netip.Addr]*rejeuBannie{}}
	j.demarrer()
	l, m, e := fusionner(flux, j.ligne)
	j.r.Tick(time.Unix(j.horloge, 0)) // rien n'est jugé au-delà de la dernière ligne : les preuves manqueraient
	lues, mal, erreurs = lues+l, mal+m, append(append([]rejeuErreur{}, erreurs...), e...)

	if len(j.bannies) > 0 {
		j.origines = map[netip.Addr][]*rejeuBannie{}
		for a, b := range j.bannies {
			j.origines[origine(a)] = append(j.origines[origine(a)], b)
		}
		fin := j.horloge
		j.horloge = flux[0].premier
		_, _, e = fusionner(flux, j.innocenter)
		j.horloge = fin
		for _, x := range e {
			if !strings.Contains(fmt.Sprint(erreurs), x.Fichier) {
				erreurs = append(erreurs, x)
			}
		}
	}
	rap.Fichiers.Lus, rap.Fichiers.SansLigne, rap.Fichiers.EnErreur = len(flux), sansLigne, erreurs
	rap.Lignes.Lues, rap.Lignes.Malformees = lues, mal
	j.conclure()
	enc := json.NewEncoder(sortie)
	enc.SetIndent("", "  ")
	return enc.Encode(rap)
}

func premiereErreur(e []rejeuErreur) error {
	if len(e) == 0 {
		return errors.New("aucun fichier donné")
	}
	return errors.New(e[0].Fichier + " : " + e[0].Erreur)
}

// demarrer construit le détecteur ; sa vraie date de départ est posée à la première ligne.
func (j *rejeu) demarrer() {
	j.cfg.Horloge = func() time.Time { return time.Unix(j.horloge, 0) }
	j.r = NewRotation(j.cfg, nil, j.a)
	j.r.tempsDecisions = time.Hour // pas de DNS : le temps réel ne doit pas changer le résultat
	j.r.temoin = &rotationTemoin{etablie: j.etablie, finie: j.finie, verdict: j.verdict}
	c := j.r.cfg
	j.rap.Verdict = c.Verdict
	g := &j.rap.Reglages
	g.SeuilSources, g.PartUneATrois, g.PartLouee, g.MaxParHeure, g.MaxCampagnes = c.SeuilSources, c.PartUneATrois, c.PartLouee, c.MaxParHeure, c.MaxCampagnes
}

func (j *rejeu) vhost(h string) *rejeuVhost {
	v := j.rap.ParVhost[h]
	if v == nil {
		if len(j.rap.ParVhost) >= rejeuVhostsMax {
			h = "(autres)"
			if v = j.rap.ParVhost[h]; v != nil {
				return v
			}
		}
		v = &rejeuVhost{}
		j.rap.ParVhost[strings.Clone(h)] = v
	}
	return v
}

// ligne rejoue une ligne.
func (j *rejeu) ligne(hote string, l *rejeuLigne) {
	if !j.parti {
		j.parti, j.horloge, j.tick = true, l.t, l.t
		j.demarrer()
		j.r.Tick(time.Unix(l.t, 0))
		j.rap.Reglages.TorGarde = j.r.tor != nil
		j.rap.Debut = dateRejeu(l.t)
	}
	retard := j.horloge - l.t
	if retard < 0 {
		j.avancer(l.t)
		j.horloge = l.t
	}
	v := j.vhost(hote)
	v.Lignes++
	if privateCIDR(l.ip) {
		j.rap.Lignes.Privees++
		return
	}
	nav, preuve := l.navigation(), l.preuve()
	if preuve {
		v.Preuves++
		j.rap.Lignes.Preuves++
	}
	if retard > rejeuRetardMax {
		j.rap.Lignes.HorsOrdre++
		nav = false
	}
	if nav {
		v.Navigations++
		j.rap.Lignes.Navigations++
	}
	t := time.Unix(j.horloge, 0)
	if x := j.r.Observe(RotationRequete{IP: l.ip, UA: l.ua, Hote: hote, Navigation: nav, Preuve: preuve}, t); x != nil && l.pageServie() {
		j.r.Servie(x, t)
	}
}

// avancer fait passer le temps simulé jusqu'à `a` EXCLU (les preuves de la seconde `a` passent avant les verdicts de cette seconde) : un Tick toutes
// les 2 s, espacés de 30 s quand rien n'est en attente, aucun quand plus rien ne peut changer.
func (j *rejeu) avancer(a int64) {
	for {
		pas := int64(rejeuPasTick / time.Second)
		if j.tick-j.horloge > rejeuCalme && j.r.nbAttente() == 0 {
			if j.tick-j.horloge > int64(rejeuSommeil/time.Second) {
				j.tick = a
				return
			}
			pas = int64(rejeuPasCalme / time.Second)
		}
		if j.tick+pas >= a {
			return
		}
		j.tick += pas
		j.r.Tick(time.Unix(j.tick, 0))
	}
}

// ── Témoin du détecteur (appelé depuis Tick, dans le même fil) ───────────────────────────────────────────────────────

func (j *rejeu) etablie(c *rotCampagne, premier int64) {
	x := &rejeuCampagne{Signature: c.signature, Hote: c.hote, PremiereRequete: dateRejeu(premier), EtablieLe: dateRejeu(c.etablieLe), DelaiS: c.etablieLe - premier,
		Sources: c.sources, Une: c.une, Le3: c.le3, Classes: map[string]int{}, ParClasse: map[string]int{}, Ecartees: map[string]int{}, c: c}
	for k, v := range c.classes {
		x.Classes[k] = v
	}
	j.courantes[c.cle] = x
	j.vhost(c.hote).Campagnes++
	if len(j.rap.Campagnes) >= rejeuCampagnesMax {
		j.rap.CampagnesOubliees++
		return
	}
	j.rap.Campagnes = append(j.rap.Campagnes, x)
}

func (j *rejeu) finie(c *rotCampagne, t time.Time, raison string) {
	if x := j.courantes[c.cle]; x != nil {
		x.FinieLe, x.FinRaison, x.Epargnees, x.c = dateRejeu(t.Unix()), raison, c.epargnees, nil
		delete(j.courantes, c.cle)
	}
}

// verdict : raison vide = l'adresse aurait été bannie.
func (j *rejeu) verdict(v rotVerdict, raison string, t time.Time) {
	x := j.courantes[v.cle]
	if raison != "" {
		j.rap.Epargnees[raison]++
		if x != nil && raison != raisonPreuve {
			x.Ecartees[raison]++
		}
		return
	}
	b := j.bannies[v.adr]
	if b == nil {
		b = &rejeuBannie{adr: v.adr, premier: t.Unix(), preuves: map[string]bool{}}
		j.bannies[v.adr] = b
	}
	b.dernier = t.Unix()
	cl := j.r.classer(v.adr.String()).Classe
	j.rap.AuraientEteBannies.Verdicts++
	j.rap.AuraientEteBannies.ParClasse[cl]++
	j.vhost(v.hote).AuraientEteBannies++
	if x == nil {
		return
	}
	x.AuraientEteBannies++
	x.ParClasse[cl]++
	if j.adresses && len(x.Exemples) < rejeuExemples {
		x.Exemples = append(x.Exemples, v.adr.String())
	}
}

// ── Seconde lecture : ce qui innocente ───────────────────────────────────────────────────────────────────────────────

// innocenter cherche, autour de chaque verdict (± 24 h), les preuves et les robots déclarés venus de la même origine (IPv4, ou /64 IPv6). Une preuve
// AVANT le verdict ne devrait pas exister : ce serait un défaut du détecteur ou du rejeu. Même horloge monotone qu'à la première lecture : une ligne
// écrite en retard vient après.
func (j *rejeu) innocenter(_ string, l *rejeuLigne) {
	j.horloge = max(j.horloge, l.t)
	nature := l.naturePreuve()
	robot := l.ua != "" && (automateDeclare(l.ua) || strings.Contains(l.ua, "://"))
	if nature == "" && !robot {
		return
	}
	a, ok := adresse(l.ip)
	if !ok {
		return
	}
	for _, b := range j.origines[origine(a)] {
		if j.horloge < b.premier-rejeuInnocente || j.horloge > b.dernier+rejeuInnocente {
			continue
		}
		b.robot = b.robot || robot
		switch {
		case nature == "":
		case j.horloge <= b.premier:
			b.avant = true
		default:
			b.apres, b.preuves[nature] = true, true
		}
	}
}

// adresseDeConfiance : privée, locale, CGNAT (maillage) ou plage protégée. Le détecteur ne les juge jamais ; le rejeu le vérifie.
func adresseDeConfiance(a netip.Addr, protegees []*net.IPNet) bool {
	return rejeuCGNAT.Contains(a) || adresseProtegee(a.String(), protegees) || privateCIDR(a.String())
}

var rejeuCGNAT = netip.MustParsePrefix("100.64.0.0/10")

func (j *rejeu) conclure() {
	for _, x := range j.courantes {
		x.Epargnees = x.c.epargnees
	}
	rap := j.rap
	rap.Fin = dateRejeu(j.horloge)
	rap.EnAttenteALaFin = j.r.nbAttente()
	rap.MemoireSaturee = j.r.memoire.satureJusqua > 0
	rap.AuraientEteBannies.Adresses = len(j.bannies)
	for h, v := range rap.ParVhost {
		if v.Campagnes > 0 {
			rap.HotesAvecCampagne = append(rap.HotesAvecCampagne, h)
		}
	}
	sort.Strings(rap.HotesAvecCampagne)
	s := &rap.SuspectsFauxPositifs
	for _, b := range j.bannies {
		prive := adresseDeConfiance(b.adr, j.cfg.Protegees)
		if prive {
			s.Structurels.PriveLanMaillage++
		}
		if b.robot {
			s.Structurels.RobotsDeclares++
		}
		if b.avant {
			s.Structurels.PreuveAvant++
		}
		if b.apres {
			s.Adresses++
			s.PreuveApres++
			if j.adresses {
				s.Exemples = append(s.Exemples, b.adr.String())
			}
		}
		for n := range b.preuves {
			s.ParPreuve[n]++
		}
	}
	sort.Strings(s.Exemples)
	if len(s.Exemples) > rejeuExemples {
		s.Exemples = s.Exemples[:rejeuExemples]
	}
	if rap.Annuaire.AvecReseau == 0 {
		rap.Approximations = append(rap.Approximations, "AUCUNE adresse n'a pu être rattachée à un réseau (base ASN absente, ou pas assez de trafic) : aucune campagne ne peut s'établir")
	}
	if !rap.Reglages.TorGarde {
		rap.Approximations = append(rap.Approximations, "liste des sorties Tor absente : garde Tor inactive pendant le rejeu")
	}
}
