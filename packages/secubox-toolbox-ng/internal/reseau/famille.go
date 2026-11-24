// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package reseau

import "strings"

// Familles de campagne (#3919) : ce que l'opérateur lit sur une carte de
// campagne, au lieu d'une catégorie de règle.
const (
	FamilleMessagerie   = "messagerie"
	FamilleAccesDistant = "acces_distant"
	FamilleCollecte     = "collecte"
	FamilleBalayageWeb  = "balayage_web"
	FamilleAutre        = "autre"
)

// regleFamille : une catégorie exacte, ou un préfixe quand prefixe est vrai.
type regleFamille struct {
	motif   string
	prefixe bool
	famille string
}

// reglesFamille est la table, lue dans l'ordre, la première règle gagnant.
// LISTE PLATE VOLONTAIRE : elle est recopiée telle quelle côté Python
// (tâche 5 de #3919) et testée sur les mêmes cas ; toute modification ici se
// reporte là-bas.
var reglesFamille = []regleFamille{
	{"auth_smtp", true, FamilleMessagerie},
	{"auth_imap", true, FamilleMessagerie},
	{"auth_ssh", true, FamilleAccesDistant},
	{"leurre", true, FamilleAccesDistant},
	{"aspirateur_ua", false, FamilleCollecte},
	{"recon_crawler", false, FamilleCollecte},
	{"robots", false, FamilleCollecte},
	{"scanners", false, FamilleBalayageWeb},
	{"honeypot", false, FamilleBalayageWeb},
	{"lfi", false, FamilleBalayageWeb},
	{"api_abuse", false, FamilleBalayageWeb},
	{"waf_fingerprint", false, FamilleBalayageWeb},
	{"host_anomaly:", true, FamilleBalayageWeb},
	{"rotation:", true, FamilleCollecte},
}

// Famille rend la famille d'une catégorie de règle ; « autre » si aucune
// règle ne s'applique.
func Famille(categorie string) string {
	for _, r := range reglesFamille {
		if r.prefixe && strings.HasPrefix(categorie, r.motif) ||
			!r.prefixe && categorie == r.motif {
			return r.famille
		}
	}
	return FamilleAutre
}
