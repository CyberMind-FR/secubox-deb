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
// Opt-in : sans `--vhost-profiles`, le récepteur est nil et `doitSupprimer`
// rend toujours false — la Phase F est strictement inchangée.
package main

import (
	"encoding/json"
	"fmt"
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
}

// VhostProfiles porte la table hôte→service, les profils compilés et les
// catégories dont le déclenchement peut être supprimé sur un chemin légitime.
type VhostProfiles struct {
	mu           sync.RWMutex
	hoteService  map[string]string         // hôte (minuscules, sans port) -> nom de service
	services     map[string]serviceProfile // nom de service -> profil
	supprimables map[string]bool           // id de catégorie -> supprimable
}

// fichierProfils est la forme JSON sur disque de vhost_profiles.json.
type fichierProfils struct {
	Services map[string]struct {
		LegitPaths []string `json:"legit_paths"`
	} `json:"services"`
	Vhosts             map[string]string `json:"vhosts"`
	SuppressCategories []string          `json:"suppress_categories"`
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
	for _, cat := range f.SuppressCategories {
		vp.supprimables[cat] = true
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

// catSupprimable dit si une catégorie touchée peut être annulée sur un chemin
// légitime. Récepteur nil-safe : Phase G est opt-in.
func (v *VhostProfiles) catSupprimable(cat string) bool {
	if v == nil {
		return false
	}
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.supprimables[cat]
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

// categoriesSupprimables rend l'ensemble des catégories supprimables, pour la
// ré-vérification de sécurité côté détection (voir Rules.MatchExcept). Le set
// est immuable après chargement ; on rend la référence. Nil-safe.
func (v *VhostProfiles) categoriesSupprimables() map[string]bool {
	if v == nil {
		return nil
	}
	return v.supprimables
}

// doitSupprimer combine les deux gardes : on n'annule un déclenchement que si
// la catégorie est une empreinte de reconnaissance ET que le chemin est
// légitime pour le service de ce vhost. Point d'intégration unique dans le
// chemin de détection. Nil-safe (opt-in).
func (v *VhostProfiles) doitSupprimer(host, chemin, cat string) bool {
	return v != nil && v.catSupprimable(cat) && v.estLegitime(host, chemin)
}
