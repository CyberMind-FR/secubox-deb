// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package main

import (
	"fmt"
	"log"
	"time"

	"github.com/CyberMind-FR/secubox-deb/secubox-toolbox-ng/internal/actor/envelope"
	"github.com/CyberMind-FR/secubox-deb/secubox-toolbox-ng/internal/actor/evidence"
	"github.com/CyberMind-FR/secubox-deb/secubox-toolbox-ng/internal/actor/graph"
	"github.com/CyberMind-FR/secubox-deb/secubox-toolbox-ng/internal/actor/intent"
	"github.com/CyberMind-FR/secubox-deb/secubox-toolbox-ng/internal/actor/knowledge"
	"github.com/CyberMind-FR/secubox-deb/secubox-toolbox-ng/internal/actor/score"
	"github.com/CyberMind-FR/secubox-deb/secubox-toolbox-ng/internal/actor/similarity"
)

// actorSignals accumule, PAR acteur, les signaux de connaissance et
// d'intention/automation/persistance observés au fil de ses événements, pour
// recalculer les scores sur l'historique agrégé (et non le seul dernier event).
type actorSignals struct {
	know    []knowledge.Observation
	sig     intent.Signals
	windows map[int64]bool // fenêtres (jours) distinctes -> ReemergenceWindows
	days    map[string]bool
}

// signatureDe dérive la Signature de corrélation d'une enveloppe (RFC-0013 §3).
func signatureDe(e *envelope.Envelope) similarity.Signature {
	return similarity.Signature{
		CredentialHash: e.CredentialTokenHash,
		PathSig:        e.PathShape,
		UAFamily:       e.UserAgentFamily,
		TLSFingerprint: e.TLSFingerprint,
		CadenceBucket:  e.RequestRateBucket,
		IP:             e.SrcIP,
		ASN:            e.ASN,
		Country:        e.GeoCountry,
		SeenAt:         e.Timestamp,
	}
}

// DefaultRebuildMax borne le rejeu de demarrage a ~11 s sur la cible (mesure :
// ~220 us par evenement). Au-dela, l'API resterait fermee trop longtemps — et
// une API fermee, c'est une page vide pour l'operateur.
const DefaultRebuildMax = 50000

// rebuild reconstruit le graphe en mémoire au démarrage en rejouant les
// événements persistés du plus ancien au plus récent. N'écrit AUCUNE preuve : le
// ledger reflète le flux live, jamais les rejeux (pas de doublon d'evidence_id).
func (s *Server) rebuild() {
	// PLAFOND DE REJEU, DISTINCT DE LA RETENTION (#1240). Le rejeu est LINEAIRE :
	// mesure sur la cible, 708 ms pour 3187 evenements, soit ~220 us l'unite. A
	// 100 000 evenements par jour, rejouer quinze jours demanderait plusieurs
	// minutes pendant lesquelles l'API reste FERMEE — c'est exactement ce qui a
	// fait passer la carte Renseignement pour vide, systemd finissant par tuer le
	// demon sur expiration du delai d'arret.
	//
	// La retention (ce qu'on GARDE, pour la preuve et les requetes) et le rejeu
	// (ce qu'on RECHARGE en memoire au demarrage) n'ont pas les memes contraintes
	// et ne doivent donc pas partager le meme chiffre. On peut etre genereux sur
	// la premiere sans payer la seconde : les acteurs les plus anciens
	// reapparaissent d'eux-memes des qu'ils se manifestent a nouveau.
	n := s.rebuildMax
	if n <= 0 {
		n = DefaultRebuildMax
	}
	evs, err := s.store.Recent(n)
	if err != nil {
		log.Printf("actord: rebuild: %v", err)
		return
	}
	for i := len(evs) - 1; i >= 0; i-- { // Recent = plus récent d'abord
		e := evs[i]
		s.observe(&e)
	}
	log.Printf("actord: graphe reconstruit (%d événements → %d acteurs)", len(evs), s.graph.Len())
}

// observe est le cœur du warm-path (RFC-0013 §6) : rattache l'événement à un
// acteur et met à jour ses scores agrégés (connaissance/intention/automation/
// persistance). Pur (graphe + scores), sans effet de bord ledger — réutilisé au
// rebuild du graphe au démarrage. Retourne l'acteur, sa continuité et sa priorité.
func (s *Server) observe(e *envelope.Envelope) (id string, cont, prio int) {
	obs := graph.Obs{Sig: signatureDe(e), Severity: e.Severity, Target: e.DstService,
		Tags: e.BehaviorTags, Timestamp: e.Timestamp}
	s.mu.Lock()
	defer s.mu.Unlock()
	// On APPREND les noms qui n'existent pas, au fil des etiquettes.
	for _, t := range e.BehaviorTags {
		if t == graph.EtiquetteInexistant && e.DstService != "" {
			if s.inexistants == nil {
				s.inexistants = map[string]bool{}
			}
			s.inexistants[e.DstService] = true
		}
	}
	a := s.graph.Observe(obs)
	acc := s.accum[a.ID]
	if acc == nil {
		acc = &actorSignals{windows: map[int64]bool{}, days: map[string]bool{}}
		s.accum[a.ID] = acc
	}
	mergeTags(acc, e)
	iScore, aScore, pScore := intent.Scores(acc.sig)
	kScore := knowledge.Score(acc.know)
	s.graph.SetScores(a.ID, kScore.Value, iScore.Value, aScore.Value, pScore.Value)
	return a.ID, a.Vector.Continuity, a.Priority
}

// correlate : observe + fige une preuve inviolable. Aucune décision appliquée
// (shadow). Utilisé sur le flux d'ingestion live.
func (s *Server) correlate(e *envelope.Envelope) {
	defer s.correlated.Add(1)
	actorID, cont, prio := s.observe(e)

	// Preuve inviolable : chaque événement lie sa source à un acteur + sa priorité,
	// horodaté et chaîné (RFC-0013 §7/§14). Best-effort : une preuve manquée ne
	// bloque jamais l'ingestion.
	if s.ledger != nil {
		_, err := s.ledger.Append(evidence.Record{
			ID:               e.EventID,
			Timestamp:        e.Timestamp,
			Sensor:           e.Sensor,
			Observation:      fmt.Sprintf("%s → %s (%s)", e.Sensor, actorID, similarity.Band(cont)),
			Weight:           prio,
			Explanation:      fmt.Sprintf("continuité=%d priorité=%d", cont, prio),
			AlgorithmVersion: score.AlgoVersion,
		})
		if err != nil {
			log.Printf("actord: evidence: %v", err)
		}
	}
}

// mergeTags fusionne les behavior_tags d'un événement dans les signaux accumulés
// de l'acteur. Convention de tags (émise par les capteurs une fois instrumentés) :
// connaissance k0..k4 / canary / public-leak ; automation & ciblage : jetons
// documentés ci-dessous. Tant que les capteurs n'émettent pas ces tags, les
// scores restent honnêtement à 0 (pas de valeur inventée).
func mergeTags(acc *actorSignals, e *envelope.Envelope) {
	// Une fenêtre = un jour calendaire (UTC) où l'acteur a été vu.
	day := e.Timestamp / 86400
	if !acc.windows[day] {
		acc.windows[day] = true
		acc.sig.ReemergenceWindows = len(acc.windows)
		if len(acc.windows) >= 2 {
			acc.sig.SpansMultipleDays = true
		}
	}
	publicLeak := false
	for _, t := range e.BehaviorTags {
		if t == "public-leak" {
			publicLeak = true
		}
	}
	for _, t := range e.BehaviorTags {
		switch t {
		case "k0":
			acc.know = append(acc.know, knowledge.Observation{Level: knowledge.K0Generic, Detail: "signal générique", EvidenceID: e.EventID, PubliclyExposed: publicLeak})
		case "k1":
			acc.know = append(acc.know, knowledge.Observation{Level: knowledge.K1Public, Detail: "donnée publique", EvidenceID: e.EventID, PubliclyExposed: publicLeak})
		case "k2":
			acc.know = append(acc.know, knowledge.Observation{Level: knowledge.K2Contextual, Detail: "donnée contextuelle", EvidenceID: e.EventID, PubliclyExposed: publicLeak})
		case "k3":
			acc.know = append(acc.know, knowledge.Observation{Level: knowledge.K3Historical, Detail: "identifiant historique", EvidenceID: e.EventID, PubliclyExposed: publicLeak})
		case "k4", "canary":
			acc.know = append(acc.know, knowledge.Observation{Level: knowledge.K4Sentinel, Detail: "touche de canari", EvidenceID: e.EventID})
		case "regular-cadence":
			acc.sig.RegularCadence = true
		case "ip-rotation-stable":
			acc.sig.IPRotationStablePayload = true
		case "identical-order":
			acc.sig.IdenticalTestOrder = true
		case "stable-ua":
			acc.sig.StableOrIncoherentUA = true
		case "high-parallelism":
			acc.sig.HighParallelism = true
		case "exact-offset-resume":
			acc.sig.ExactOffsetResume = true
		case "adapts":
			acc.sig.AdaptsToResponses = true
		case "service-pivot":
			acc.sig.ServicePivot = true
		case "specific-id":
			acc.sig.SpecificIdentifier = true
		case "return-after-dns":
			acc.sig.ReturnAfterDNSIPChange = true
		case "recon-chain":
			acc.sig.ReconAuthEndpointChain = true
		case "low-vol-high-rel":
			acc.sig.LowVolumeHighRelevance = true
		case "returns-after-source":
			acc.sig.ReturnsAfterSourceChange = true
		}
	}
}

// consolidationLoop reunit periodiquement les acteurs qui se revelent etre le
// meme. POURQUOI PERIODIQUE ET PAS A CHAQUE EVENEMENT : la preuve qui autorise
// une fusion — deux mots de dictionnaire, une adresse commune — n'apparait
// qu'une fois les deux profils suffisamment nourris. La verifier a chaque
// observation couterait un balayage complet pour un resultat qui ne change
// qu'au bout de plusieurs minutes.
func (s *Server) consolidationLoop() {
	t := time.NewTicker(2 * time.Minute)
	defer t.Stop()
	for range t.C {
		s.mu.Lock()
		inex := make(map[string]bool, len(s.inexistants))
		for k := range s.inexistants {
			inex[k] = true
		}
		n := s.graph.Consolider(inex)
		restants := s.graph.Len()
		s.mu.Unlock()
		if n > 0 {
			log.Printf("actord: consolidation — %d acteur(s) fusionne(s), %d restants", n, restants)
		}
	}
}
