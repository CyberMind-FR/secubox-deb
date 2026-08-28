// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// See LICENCE-CMSD-1.0.md for terms.

package main

import "strings"

// Lecture « negative space » (#1240, phase P0-A).
//
// L'idée du brief : transformer les accès à des ressources qui N'EXISTENT
// VOLONTAIREMENT PAS en signaux de reconnaissance — MAIS sans considérer
// naïvement toute 404 comme une attaque. Un navigateur qui tombe sur une URL
// périmée n'est pas un scanner ; une sonde vers `/.env` ou `/.git/HEAD`, si.
//
// Ce fichier ne DÉCIDE de rien (ni ban, ni blocage) : il CLASSE. Le verdict
// nourrit l'observation (journal de menaces, profileur). C'est un indice, pas
// une condamnation — la décision reste au pipeline d'action existant.
//
// Quatre classes, du plus anodin au plus parlant :
//   - known_real       : chemin réellement servi par un vhost → aucun signal.
//   - unknown          : 404 quelconque, non appât → aucun signal (le point clé
//                        du brief : ne pas crier au loup sur chaque 404).
//   - known_negative   : appât connu — ressource qui n'existe sur AUCUNE conf
//                        SecuBox normale (matché par une catégorie WAF de
//                        reconnaissance) → signal d'observation.
//   - high_value_probe : sous-ensemble FORT de known_negative — sonde de secret,
//                        d'exécution ou d'administration → signal d'observation
//                        appuyé.

// PathVerdict — verdict de classification « negative space » d'un chemin.
type PathVerdict struct {
	Class  string // "known_real" | "unknown" | "known_negative" | "high_value_probe"
	Signal bool   // true → observation de reconnaissance ; false → 404 banal
}

// Classes de la classification, exposées pour le journal/les tests.
const (
	pathKnownReal      = "known_real"
	pathUnknown        = "unknown"
	pathKnownNegative  = "known_negative"
	pathHighValueProbe = "high_value_probe"
)

// categoriesNegatives : les catégories WAF (waf-rules.json) qui décrivent des
// sondes de reconnaissance — un chemin non routé qu'elles matchent est un appât,
// pas une simple 404. On les nomme ici plutôt que de deviner : une catégorie
// métier (ex. injection) n'est pas du « negative space ».
var categoriesNegatives = map[string]bool{
	"honeypot":              true,
	"scanners":              true,
	"recon_crawler":         true,
	"credential_harvest":    true,
	"product_absent_probes": true,
	"waf_fingerprint":       true,
}

// categoriesHauteValeur : parmi les catégories négatives, celles qui sont, par
// nature, des sondes fortes (secrets, produit absent = exploit ciblé).
var categoriesHauteValeur = map[string]bool{
	"credential_harvest":    true,
	"product_absent_probes": true,
}

// marqueursHauteValeur : fragments de chemin qui, à eux seuls, dénoncent une
// sonde de secret / d'exécution / d'administration. Ils n'existent sur AUCUNE
// configuration normale : les reconnaître même sans règle rend le classifieur
// autonome. Liste volontairement ÉTROITE — jamais de chemin générique — pour ne
// pas requalifier une 404 anodine en attaque.
var marqueursHauteValeur = []string{
	// secrets & dépôts
	"/.env", "/.git", "/.aws", "/.ssh", "/.htpasswd", "/.npmrc",
	"id_rsa", "wp-config", "credentials", "secrets.json",
	// introspection & exécution
	"/actuator/env", "/actuator/gateway", "/server-status", "/cgi-bin/",
	"/_ignition/execute-solution", "/console",
	// administration de bases
	"/phpmyadmin", "/adminer",
}

// estHauteValeur teste les marqueurs intrinsèques sur un chemin déjà décodé et
// mis en minuscules par l'appelant.
func estHauteValeur(pathLower string) bool {
	for _, m := range marqueursHauteValeur {
		if strings.Contains(pathLower, m) {
			return true
		}
	}
	return false
}

// classifyPath classe un chemin pour la lecture « negative space ».
//
//   - routed  : le chemin est servi par un vhost/route réel (KNOWN_REAL).
//   - ruleCat : la catégorie WAF qui a matché ce chemin ("" si aucune).
//
// La fonction est PURE (aucun effet de bord) : elle est le cœur testable de la
// phase, câblée ensuite en mode observation dans le handler.
func classifyPath(path string, routed bool, ruleCat string) PathVerdict {
	if routed {
		return PathVerdict{Class: pathKnownReal, Signal: false}
	}
	p := strings.ToLower(path)
	// Sonde forte : marqueur intrinsèque OU catégorie haute-valeur.
	if estHauteValeur(p) || categoriesHauteValeur[ruleCat] {
		return PathVerdict{Class: pathHighValueProbe, Signal: true}
	}
	// Appât connu : matché par une catégorie de reconnaissance.
	if categoriesNegatives[ruleCat] {
		return PathVerdict{Class: pathKnownNegative, Signal: true}
	}
	// Sinon : 404 banale — surtout PAS un signal.
	return PathVerdict{Class: pathUnknown, Signal: false}
}
