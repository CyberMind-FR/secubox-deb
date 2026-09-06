// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// Package knowledge calcule le KnowledgeScore d'Actor Intelligence
// (RFC-0002, RFC-0013 §4). Le score 0..100 dit « combien d'information
// spécifique le comportement semble posséder », JAMAIS « qui » : il ne
// nomme ni ne désigne aucune personne, il mesure seulement la profondeur
// de connaissance que trahissent les identifiants et chemins sollicités.
//
// Taxonomie (RFC-0002), chaque niveau porte sa bande de score :
//
//	K0 générique   (0..5)    admin, root, test, chemins standards
//	K1 public      (5..20)   domaine, techno fingerprintable, comptes publics
//	K2 contextuel  (20..45)  structure/identifiant cohérent avec l'organisation
//	K3 historique  (45..75)  login/alias/hostname jadis utilisé, inutile au service actuel
//	K4 sentinelle  (75..100) donnée canari créée uniquement pour détecter une fuite
//
// Le score final tombe TOUJOURS dans la bande du niveau le plus élevé
// réellement observé ; des observations supplémentaires (même niveau ou
// inférieur) l'accroissent par incréments décroissants, sans jamais quitter
// la bande ni dépasser 100. La séparation des bandes garantit qu'un cumul
// d'observations de bas niveau ne rattrape jamais une seule observation de
// niveau supérieur — cinq logins génériques restent moins « savants » qu'un
// seul canari touché.
//
// Une observation marquée PubliclyExposed est rétrogradée au rang public
// (RFC-0002 : « pénalité si l'info est largement présente dans des fuites
// publiques ») : on ne surévalue jamais un login qui traîne dans une fuite,
// fût-il en apparence historique ou sentinelle.
package knowledge

import (
	"math"

	"github.com/CyberMind-FR/secubox-deb/secubox-toolbox-ng/internal/actor/score"
)

// Niveaux de la taxonomie K0..K4 (RFC-0002).
const (
	K0Generic    = 0 // générique : admin, root, test, chemins standards
	K1Public     = 1 // public : domaine, techno fingerprintable, comptes publics
	K2Contextual = 2 // contextuel : cohérent avec l'organisation
	K3Historical = 3 // historique/spécifique : jadis utilisé, inutile au service actuel
	K4Sentinel   = 4 // sentinelle/canari : créé uniquement pour détecter une fuite
)

// Observation : un signal de connaissance observé, classé K0..K4.
type Observation struct {
	Level           int    // 0=générique .. 4=sentinelle/canari
	Detail          string // description humaine, reportée en Label de la contribution
	EvidenceID      string // preuve traçable (evidence ledger, RFC-0007)
	PubliclyExposed bool   // l'info est largement présente dans des fuites publiques → pénalité
}

// Bandes de score par niveau (RFC-0002). Index = niveau K0..K4.
var (
	bandFloor = [5]int{0, 5, 20, 45, 75}
	bandCeil  = [5]int{5, 20, 45, 75, 100}
	// levelUnit pondère l'« intensité » qu'apporte une observation selon son
	// niveau : plus une connaissance est spécifique, plus elle remplit vite sa
	// bande. Sert au calcul des rendements décroissants, pas au plancher.
	levelUnit = [5]int{1, 3, 5, 8, 12}
)

// clampLevel borne un niveau brut à [K0,K4] : un capteur bavard ne peut pas
// inventer un niveau hors taxonomie.
func clampLevel(l int) int {
	if l < K0Generic {
		return K0Generic
	}
	if l > K4Sentinel {
		return K4Sentinel
	}
	return l
}

// effectiveLevel rend le niveau RÉELLEMENT retenu pour une observation. Une
// info exposée publiquement est ramenée au rang public (K1) : sa présence dans
// une fuite prouve qu'elle n'a rien de confidentiel, on ne la surévalue pas.
func effectiveLevel(o Observation) int {
	l := clampLevel(o.Level)
	if o.PubliclyExposed && l > K1Public {
		return K1Public
	}
	return l
}

// Score calcule le KnowledgeScore d'un ensemble d'observations. Le résultat est
// explicable : chaque Observation devient une score.Contribution traçable à sa
// preuve, et la somme des poids retombe dans la bande du niveau le plus élevé
// réellement observé. Score(nil) rend une valeur 0 (aucune connaissance).
func Score(obs []Observation) score.Score {
	if len(obs) == 0 {
		return score.New()
	}

	// Niveaux effectifs (après rétrogradation des infos exposées) et niveau max.
	eff := make([]int, len(obs))
	maxLevel := K0Generic
	rawIntensity := 0
	for i, o := range obs {
		eff[i] = effectiveLevel(o)
		rawIntensity += levelUnit[eff[i]]
		if eff[i] > maxLevel {
			maxLevel = eff[i]
		}
	}

	base := bandFloor[maxLevel]
	span := bandCeil[maxLevel] - base

	// Rendements décroissants : une seule observation place déjà le score dans
	// le premier tiers de la bande ; les suivantes le poussent vers le haut sans
	// jamais atteindre le plafond de la bande (fraction strictement < 1).
	sat := 2 * levelUnit[maxLevel]
	fraction := float64(rawIntensity) / float64(rawIntensity+sat)
	value := base + int(math.Round(float64(span)*fraction))
	if value > bandCeil[maxLevel] {
		value = bandCeil[maxLevel]
	}

	// Répartition des poids : chaque observation reçoit une part de l'excédent
	// (value - base) proportionnelle à son intensité ; l'observation dominante
	// porte en plus le plancher de la bande. La somme des poids vaut exactement
	// value, si bien que score.New la restitue telle quelle.
	extra := value - base
	dom := 0
	for i, l := range eff {
		if l == maxLevel {
			dom = i
			break
		}
	}

	weights := make([]int, len(obs))
	assigned := 0
	for i, l := range eff {
		w := int(math.Round(float64(extra) * float64(levelUnit[l]) / float64(rawIntensity)))
		weights[i] = w
		assigned += w
	}
	weights[dom] += base
	assigned += base
	// Corrige la dérive d'arrondi pour que la somme colle pile à value.
	weights[dom] += value - assigned

	contribs := make([]score.Contribution, len(obs))
	for i, o := range obs {
		contribs[i] = score.Contribution{
			Label:      o.Detail,
			Weight:     weights[i],
			EvidenceID: o.EvidenceID,
		}
	}
	return score.New(contribs...)
}
