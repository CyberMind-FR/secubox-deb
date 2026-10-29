// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// SecuBox-Deb :: toolbox-ng :: sbxwaf — Phase G : règles adaptatives par vhost (#1080)
//
// LE PROBLÈME. Les signatures de reconnaissance (Phase F : catégories
// `scanners`, `recon_crawler`, `product_absent_probes`) sont des empreintes de
// CHEMIN. Un même chemin est une ATTAQUE hors du vhost qui le possède, mais
// LÉGITIME à l'intérieur du service qui le sert : un clone git chez gitea passe
// par `/owner/repo.git/info/refs` — du smart-http normal qui contient `.git/` ;
// nextcloud sert `/.well-known/carddav` ; peertube sert `/api/v1/…`. Appliquées
// globalement, ces signatures ferraient un faux positif DANS le service.
//
// LA PARADE, déclarative et auditable (contrainte CSPN — jamais de bypass
// silencieux, jamais un défaut qui ouvre) :
//
//   - un PROFIL DE SERVICE déclare, une fois, les chemins légitimes du service
//     (gitea, peertube, nextcloud…) ;
//   - une carte VHOST→SERVICE dit quel hôte fait tourner quel service ;
//   - à la détection, si le Host de la requête fait tourner un service dont le
//     profil légitime CE chemin ET que la catégorie touchée est une empreinte
//     de reconnaissance (jamais une injection : sqli/xss/lfi/rce restent
//     bloquées partout), on SUPPRIME le déclenchement — pour CE vhost
//     uniquement. Partout ailleurs la règle tire normalement.
//
// « Autoadaptatif » : le profil défini une fois, chaque vhost de ce service
// hérite automatiquement des bonnes exceptions, sans réécrire de règle.
//
// CATÉGORIES PROPRES À UN SERVICE (#3193). Un service peut ajouter, pour SES
// seuls `legit_paths`, des catégories à la liste globale (`suppress_categories`
// dans son profil). Cas d'origine : la signalisation LiveKit de la Visio passe
// son jeton dans l'URL (`/rtc/v1?access_token=<JWT>`) par conception du
// protocole ; cred-003 (credential_harvest) la prenait pour une moisson
// d'identifiants et le ban automatique coupait toute la box. La liste GLOBALE ne
// gagne pas credential_harvest : un jeton dans l'URL reste une alerte partout
// ailleurs, y compris sur les chemins légitimes des autres services.
//
// Opt-in : sans `--vhost-profiles`, le récepteur est nil et `doitSupprimer`
// rend toujours false — la Phase F est strictement inchangée.
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"regexp"
	"strings"
	"sync"
)

// serviceProfile est un service connu et l'ensemble de ses chemins légitimes,
// compilés une fois au chargement.
type serviceProfile struct {
	nom   string
	legit []*regexp.Regexp
	// propres : catégories supprimables pour CE service seulement (#3193),
	// en plus de la liste globale. Nil si le service n'en déclare aucune.
	propres map[string]bool
	// exclues : union globale ∪ propres, précalculée au chargement pour la
	// ré-vérification anti-contrebande (immuable ensuite). Nil si le service
	// n'a pas de catégorie propre : la liste globale s'applique telle quelle.
	exclues map[string]bool
}

// VhostProfiles porte la table hôte→service, les profils compilés et les
// catégories dont le déclenchement peut être supprimé sur un chemin légitime.
type VhostProfiles struct {
	mu           sync.RWMutex
	hoteService  map[string]string         // hôte (minuscules, sans port) -> nom de service
	services     map[string]serviceProfile // nom de service -> profil
	supprimables map[string]bool           // id de catégorie -> supprimable
	antirobots   map[string]bool           // hôte -> refuser les robots (#1216)
	phpServices  map[string]bool           // nom de service -> fait tourner PHP (#3257)
	phpHotes     []*regexp.Regexp          // motifs d'hôte PHP (#3257, R15)
	federation   map[string]bool           // hôte -> fédération Nextcloud utilisée (#3273, R-NC1)
}

// fichierProfils est la forme JSON sur disque de vhost_profiles.json.
type fichierProfils struct {
	Services map[string]struct {
		LegitPaths []string `json:"legit_paths"`
		// SuppressCategories (#3193) : catégories supprimables sur les seuls
		// legit_paths de CE service. Clé absente = aucune (fichier antérieur
		// valide tel quel).
		SuppressCategories []string `json:"suppress_categories"`
	} `json:"services"`
	Vhosts             map[string]string `json:"vhosts"`
	SuppressCategories []string          `json:"suppress_categories"`
	// AntiRobots (#1216) : vhosts qui refusent les robots d'indexation.
	// Clé ABSENTE = liste vide = personne n'est filtré : la case est
	// opt-in, un fichier d'avant la fonctionnalité reste valide tel quel.
	AntiRobots []string `json:"anti_robots"`
	// PHPServices (#3257) : services dont les vhosts font tourner PHP ; seuls
	// ces hôtes voient leurs envois multipart analysés (PHP2Shell). Clé absente
	// = aucun vhost PHP.
	PHPServices []string `json:"php_services"`
	// PHPHotes (#3257, R15) : expressions régulières sur le nom d'hôte
	// normalisé ; un hôte qui correspond est PHP même sans vhost déclaré. Lues
	// une à une : un motif invalide (ou qui n'est pas une chaîne) est rejeté
	// seul, journalisé, sans refuser le fichier.
	PHPHotes []json.RawMessage `json:"php_hotes"`
	// FederationVhosts (#3273, R-NC1) : vhosts Nextcloud qui utilisent la
	// fédération (partages entre serveurs). Sur eux, un partage fédéré anonyme
	// n'est signalé qu'en rafale ; ailleurs, à chaque appel. Clé absente =
	// aucun (une box unique ne fédère pas).
	FederationVhosts []string `json:"federation_vhosts"`
}

// chargerVhostProfiles lit et compile le fichier déclaratif. Une erreur de
// lecture ou une regex invalide échoue FRANCHEMENT : un profil à moitié
// compilé laisserait des faux positifs qu'on croyait couverts.
func chargerVhostProfiles(path string) (*VhostProfiles, error) {
	brut, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return chargerVhostProfilesDepuis(brut)
}

func chargerVhostProfilesDepuis(brut []byte) (*VhostProfiles, error) {
	var f fichierProfils
	if err := json.Unmarshal(brut, &f); err != nil {
		return nil, fmt.Errorf("vhost_profiles illisible : %w", err)
	}
	vp := &VhostProfiles{
		hoteService:  make(map[string]string, len(f.Vhosts)),
		services:     make(map[string]serviceProfile, len(f.Services)),
		supprimables: make(map[string]bool, len(f.SuppressCategories)),
		antirobots:   make(map[string]bool, len(f.AntiRobots)),
		phpServices:  make(map[string]bool, len(f.PHPServices)),
		federation:   make(map[string]bool, len(f.FederationVhosts)),
	}
	for _, cat := range f.SuppressCategories {
		vp.supprimables[cat] = true
	}
	for nom, s := range f.Services {
		prof := serviceProfile{nom: nom}
		for _, motif := range s.LegitPaths {
			re, err := regexp.Compile(motif)
			if err != nil {
				return nil, fmt.Errorf("service %q : motif %q invalide : %w", nom, motif, err)
			}
			prof.legit = append(prof.legit, re)
		}
		if len(s.SuppressCategories) > 0 {
			prof.propres = make(map[string]bool, len(s.SuppressCategories))
			prof.exclues = make(map[string]bool, len(vp.supprimables)+len(s.SuppressCategories))
			for cat := range vp.supprimables {
				prof.exclues[cat] = true
			}
			for _, cat := range s.SuppressCategories {
				prof.propres[cat] = true
				prof.exclues[cat] = true
			}
		}
		vp.services[nom] = prof
	}
	for hote, service := range f.Vhosts {
		// On ne garde pas un vhost qui pointe vers un service absent : le
		// silence serait pire qu'un refus, il ferait croire à une couverture.
		if _, ok := vp.services[service]; !ok {
			return nil, fmt.Errorf("vhost %q renvoie au service inconnu %q", hote, service)
		}
		vp.hoteService[normaliserHote(hote)] = service
	}
	// Un hôte coché anti-robots n'a PAS besoin d'un profil de service : on
	// peut vouloir épargner un site vitrine sans lui décrire de chemins
	// légitimes. On normalise seulement, sans exiger d'appartenance.
	for _, hote := range f.AntiRobots {
		vp.antirobots[normaliserHote(hote)] = true
	}
	// Un service PHP inconnu est ignoré, pas fatal : le fichier reste valide.
	for _, nom := range f.PHPServices {
		if _, ok := vp.services[nom]; !ok {
			log.Printf("vhost_profiles : php_services nomme le service inconnu %q, ignoré", nom)
			continue
		}
		vp.phpServices[nom] = true
	}
	// Comme anti_robots : normalisé, sans exiger un vhost déclaré.
	for _, hote := range f.FederationVhosts {
		vp.federation[normaliserHote(hote)] = true
	}
	for i, brutMotif := range f.PHPHotes {
		var motif string
		if err := json.Unmarshal(brutMotif, &motif); err != nil {
			log.Printf("vhost_profiles : php_hotes #%d n'est pas une chaîne, rejeté : %v", i, err)
			continue
		}
		re, err := regexp.Compile(motif)
		if err != nil {
			log.Printf("vhost_profiles : php_hotes %q invalide, rejeté : %v", motif, err)
			continue
		}
		vp.phpHotes = append(vp.phpHotes, re)
	}
	return vp, nil
}

// normaliserHote met en minuscules et retire un éventuel port : l'en-tête Host
// peut arriver « gitea.gk2.secubox.in:443 », la carte est indexée sans port.
func normaliserHote(host string) string {
	host = strings.ToLower(strings.TrimSpace(host))
	if i := strings.LastIndexByte(host, ':'); i >= 0 {
		// Un ':' final n'est un port que s'il ne s'agit pas d'un IPv6 nu ;
		// les hôtes SecuBox sont des noms, ce cas simple suffit.
		host = host[:i]
	}
	return host
}

// catSupprimable dit si une catégorie touchée figure dans la liste GLOBALE des
// catégories supprimables. Récepteur nil-safe : Phase G est opt-in.
func (v *VhostProfiles) catSupprimable(cat string) bool {
	if v == nil {
		return false
	}
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.supprimables[cat]
}

// catSupprimablePour dit si une catégorie peut être annulée sur cet hôte :
// liste globale, OU catégorie propre au service que fait tourner CET hôte
// (#3193). Hôte inconnu → liste globale seule. Nil-safe.
func (v *VhostProfiles) catSupprimablePour(host, cat string) bool {
	if v == nil {
		return false
	}
	v.mu.RLock()
	defer v.mu.RUnlock()
	if v.supprimables[cat] {
		return true
	}
	service, ok := v.hoteService[normaliserHote(host)]
	if !ok {
		return false
	}
	return v.services[service].propres[cat]
}

// estLegitime dit si le service qui tourne sur cet hôte déclare ce chemin comme
// légitime. Hôte inconnu → false (comportement Phase F inchangé). Nil-safe.
func (v *VhostProfiles) estLegitime(host, chemin string) bool {
	if v == nil {
		return false
	}
	v.mu.RLock()
	defer v.mu.RUnlock()
	service, ok := v.hoteService[normaliserHote(host)]
	if !ok {
		return false
	}
	prof, ok := v.services[service]
	if !ok {
		return false
	}
	for _, re := range prof.legit {
		if re.MatchString(chemin) {
			return true
		}
	}
	return false
}

// categoriesSupprimablesPour rend l'ensemble des catégories supprimables POUR
// CET HÔTE — liste globale ∪ catégories propres à son service (#3193) — pour la
// ré-vérification de sécurité côté détection (voir Rules.MatchExcept).
//
// PAR HÔTE, et c'est la garde : une union de TOUS les services ferait exclure
// credential_harvest (propre à livekit) de la ré-vérification d'un autre vhost,
// et l'exemption de livekit affaiblirait la détection partout. Les ensembles
// sont immuables après chargement ; on rend la référence. Nil-safe.
func (v *VhostProfiles) categoriesSupprimablesPour(host string) map[string]bool {
	if v == nil {
		return nil
	}
	v.mu.RLock()
	defer v.mu.RUnlock()
	if service, ok := v.hoteService[normaliserHote(host)]; ok {
		if ex := v.services[service].exclues; ex != nil {
			return ex
		}
	}
	return v.supprimables
}

// antiRobots dit si ce vhost est coché « refuser les robots » (#1216).
// Nil-safe et faux par défaut : sans fichier, sans clé, ou pour un hôte non
// coché, on ne filtre rien.
func (v *VhostProfiles) antiRobots(host string) bool {
	if v == nil {
		return false
	}
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.antirobots[normaliserHote(host)]
}

// doitSupprimer combine les deux gardes : on n'annule un déclenchement que si
// la catégorie est supprimable POUR CET HÔTE (liste globale ou catégorie propre
// à son service, #3193) ET que le chemin est légitime pour le service de ce
// vhost. Point d'intégration unique dans le chemin de détection. Nil-safe
// (opt-in).
func (v *VhostProfiles) doitSupprimer(host, chemin, cat string) bool {
	return v != nil && v.catSupprimablePour(host, cat) && v.estLegitime(host, chemin)
}

// estPHP dit si cet hôte fait tourner PHP (#3257) : voir servicePHP.
// Récepteur nil → false.
func (v *VhostProfiles) estPHP(host string) bool {
	_, ok := v.servicePHP(host)
	return ok
}

// servicePHP dit si cet hôte fait tourner PHP et sous quel service (#3273) :
// son service est déclaré dans php_services (service = ce nom), OU l'hôte
// normalisé correspond à un motif de php_hotes (R15 : un alias nextcloud.* ou
// une box sans liste propre reste couvert ; service = "", et toutes les
// familles de signatures s'appliquent). Récepteur nil → ("", false).
func (v *VhostProfiles) servicePHP(host string) (service string, php bool) {
	if v == nil {
		return "", false
	}
	v.mu.RLock()
	defer v.mu.RUnlock()
	h := normaliserHote(host)
	if service, ok := v.hoteService[h]; ok && v.phpServices[service] {
		return service, true
	}
	for _, re := range v.phpHotes {
		if re.MatchString(h) {
			return "", true
		}
	}
	return "", false
}

// federationUtilisee dit si cet hôte (normalisé) utilise la fédération
// Nextcloud (federation_vhosts, #3273 R-NC1). Récepteur nil → false.
func (v *VhostProfiles) federationUtilisee(host string) bool {
	if v == nil {
		return false
	}
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.federation[normaliserHote(host)]
}

// armementPHP rend le nombre de vhosts PHP explicites (vhost dont le service
// est déclaré PHP) et de motifs d'hôte PHP armés. Nil-safe.
func (v *VhostProfiles) armementPHP() (explicites, motifs int) {
	if v == nil {
		return 0, 0
	}
	v.mu.RLock()
	defer v.mu.RUnlock()
	for _, service := range v.hoteService {
		if v.phpServices[service] {
			explicites++
		}
	}
	return explicites, len(v.phpHotes)
}

// ligneArmementPHP est la ligne de démarrage qui dit ce que la capture PHP2Shell
// couvre (relecture finale I3) : une box où rien n'est armé se voit au journal,
// au lieu de passer pour une box sans faux positif.
func ligneArmementPHP(v *VhostProfiles) string {
	n, m := v.armementPHP()
	l := fmt.Sprintf("sbxwaf: vhosts PHP armés : %d explicites, %d motifs", n, m)
	if v == nil {
		l += " (vhost-profiles absent ou illisible : capture PHP2Shell coupée)"
	}
	return l
}
