// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// Package intent porte les trois axes de lecture d'un acteur (RFC-0013 §6,
// RFC-0003) : IntentScore (ciblage/intention), AutomationScore (degré
// d'automatisation) et PersistenceScore (ténacité dans le temps). Les axes sont
// INDÉPENDANTS : la RFC-0003 rappelle qu'« un acteur peut être simultanément
// très automatisé ET très ciblé » — un signal d'automatisation ne déplace donc
// jamais l'axe d'intention, et réciproquement. Chaque score reste EXPLICABLE :
// il se construit par score.New à partir des contributions pondérées des seuls
// signaux observés, et reste borné 0..100.
package intent

import "github.com/CyberMind-FR/secubox-deb/secubox-toolbox-ng/internal/actor/score"

// Signals regroupe les signaux booléens/compteurs observés pour un acteur.
// Ils sont classés par axe, mais chaque axe est calculé isolément (cf. Scores).
type Signals struct {
	// Automation (RFC-0003 « signaux d'automatisation »)
	RegularCadence          bool // cadence extrêmement régulière
	IPRotationStablePayload bool // rotation d'IP sans changement de payload
	IdenticalTestOrder      bool // ordre de tests identique
	StableOrIncoherentUA    bool // user-agent incohérent ou très stable
	HighParallelism         bool // parallélisme élevé
	ExactOffsetResume       bool // reprise exactement au même offset après changement de source
	// Intent / ciblage (RFC-0003 « signaux de ciblage »)
	AdaptsToResponses      bool // adaptation aux réponses de la box
	ServicePivot           bool // passage d'un service à un autre après découverte
	SpecificIdentifier     bool // utilisation d'un identifiant spécifique
	ReturnAfterDNSIPChange bool // retour après changement de DNS/IP
	ReconAuthEndpointChain bool // séquence recon → auth → endpoint précis
	LowVolumeHighRelevance bool // faible volume mais forte pertinence
	// Persistence
	ReemergenceWindows       int // nombre de fenêtres distinctes où l'acteur réapparaît
	ReturnsAfterSourceChange bool
	SpansMultipleDays        bool
}

// Poids par signal. Les signaux les plus discriminants pèsent plus : une cadence
// machine ou une rotation d'IP à payload constant trahissent l'outillage bien
// plus qu'un simple UA stable ; une adaptation aux réponses ou une chaîne
// recon→auth→endpoint trahissent l'intention bien plus qu'un retour opportuniste.
const (
	// Axe automation.
	wRegularCadence          = 25
	wIPRotationStablePayload = 25
	wIdenticalTestOrder      = 20
	wStableOrIncoherentUA    = 15
	wHighParallelism         = 20
	wExactOffsetResume       = 20

	// Axe intention/ciblage.
	wAdaptsToResponses      = 25
	wReconAuthEndpointChain = 25
	wSpecificIdentifier     = 20
	wServicePivot           = 20
	wReturnAfterDNSIPChange = 15
	wLowVolumeHighRelevance = 20

	// Axe persistence.
	wReemergenceWindow        = 15 // par fenêtre de réapparition observée
	wReturnsAfterSourceChange = 25
	wSpansMultipleDays        = 20
)

// add pousse une contribution pondérée dans acc si le signal est actif.
func add(acc *[]score.Contribution, on bool, label string, weight int) {
	if on {
		*acc = append(*acc, score.Contribution{Label: label, Weight: weight})
	}
}

// Scores calcule les trois axes de manière strictement indépendante à partir
// des signaux observés. Aucun axe n'emprunte de contribution à un autre :
// Scores(Signals{}) rend donc (0, 0, 0), et un acteur peut culminer sur
// plusieurs axes à la fois.
func Scores(s Signals) (intent, automation, persistence score.Score) {
	// --- Axe automation ---
	var auto []score.Contribution
	add(&auto, s.RegularCadence, "cadence extrêmement régulière", wRegularCadence)
	add(&auto, s.IPRotationStablePayload, "rotation d'IP sans changement de payload", wIPRotationStablePayload)
	add(&auto, s.IdenticalTestOrder, "ordre de tests identique", wIdenticalTestOrder)
	add(&auto, s.StableOrIncoherentUA, "user-agent incohérent ou très stable", wStableOrIncoherentUA)
	add(&auto, s.HighParallelism, "parallélisme élevé", wHighParallelism)
	add(&auto, s.ExactOffsetResume, "reprise au même offset après changement de source", wExactOffsetResume)

	// --- Axe intention/ciblage ---
	var intt []score.Contribution
	add(&intt, s.AdaptsToResponses, "adaptation aux réponses de la box", wAdaptsToResponses)
	add(&intt, s.ReconAuthEndpointChain, "séquence recon → auth → endpoint précis", wReconAuthEndpointChain)
	add(&intt, s.SpecificIdentifier, "utilisation d'un identifiant spécifique", wSpecificIdentifier)
	add(&intt, s.ServicePivot, "pivot d'un service à un autre après découverte", wServicePivot)
	add(&intt, s.ReturnAfterDNSIPChange, "retour après changement de DNS/IP", wReturnAfterDNSIPChange)
	add(&intt, s.LowVolumeHighRelevance, "faible volume mais forte pertinence", wLowVolumeHighRelevance)

	// --- Axe persistence ---
	var pers []score.Contribution
	// Chaque fenêtre de réapparition compte : la persistence croît avec leur nombre.
	for i := 0; i < s.ReemergenceWindows; i++ {
		pers = append(pers, score.Contribution{Label: "fenêtre de réapparition distincte", Weight: wReemergenceWindow})
	}
	add(&pers, s.ReturnsAfterSourceChange, "retour après changement de source", wReturnsAfterSourceChange)
	add(&pers, s.SpansMultipleDays, "activité étalée sur plusieurs jours", wSpansMultipleDays)

	return score.New(intt...), score.New(auto...), score.New(pers...)
}
