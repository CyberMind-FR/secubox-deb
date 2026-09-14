// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// Package similarity calcule la CONTINUITÉ multi-signal entre deux observations
// (RFC-0013 §3 / RFC-0001). Le score ne repose JAMAIS sur un seul attribut :
// c'est la somme pondérée et explicable de signaux indépendants concordants.
// Une IP n'est pas une identité — elle décroît dans le temps ; le pays seul ne
// peut jamais provoquer une décision (poids 1). Le résultat est une « continuité
// de campagne probable », jamais « même personne » (RFC-0007).
package similarity

import (
	"math"

	"github.com/CyberMind-FR/secubox-deb/secubox-toolbox-ng/internal/actor/score"
)

// Poids de départ à calibrer (RFC-0013 §3). Versionnés via score.WeightsVersion.
const (
	WCredential = 30 // credential/token rare réutilisé
	WPathSeq    = 18 // même séquence de chemins
	WTool       = 12 // même famille d'outillage HTTP
	WTLS        = 12 // même empreinte TLS (JA4)
	WCadence    = 8  // même cadence temporelle
	WIP         = 10 // IP identique, AVEC décroissance
	WASN        = 5  // même ASN
	WCountry    = 1  // même pays — jamais décisif à lui seul

	ipHalfLifeSec = 6 * 3600 // demi-vie de la contribution IP identique
)

// Signature est l'empreinte comparée d'une observation (event ou agrégat).
// Les champs vides ne contribuent pas (pas de faux pivot sur une valeur absente).
type Signature struct {
	CredentialHash string // HMAC (envelope.CredentialTokenHash)
	PathSig        string // signature de la séquence de chemins normalisés (path_shape)
	UAFamily       string
	TLSFingerprint string // JA4
	CadenceBucket  string
	IP             string
	ASN            uint32
	Country        string
	SeenAt         int64 // horodatage, pour la décroissance de l'IP
}

// Seuils de continuité (RFC-0013 §3).
const (
	BandNonRelated = "non relié"             // 0–29
	BandWeak       = "ressemblance faible"   // 30–49
	BandProbable   = "campagne probable"     // 50–69
	BandStrong     = "forte continuité"      // 70–84
	BandVeryStrong = "très forte continuité" // 85–100
)

// Band nomme la bande d'un score de continuité. Même à 85–100, c'est « probable »,
// jamais une identité certaine.
func Band(v int) string {
	switch {
	case v >= 85:
		return BandVeryStrong
	case v >= 70:
		return BandStrong
	case v >= 50:
		return BandProbable
	case v >= 30:
		return BandWeak
	default:
		return BandNonRelated
	}
}

// ipDecay renvoie le facteur [0,1] appliqué à la contribution IP identique selon
// l'écart temporel entre les deux observations (demi-vie ipHalfLifeSec).
func ipDecay(t1, t2 int64) float64 {
	gap := t1 - t2
	if gap < 0 {
		gap = -gap
	}
	return math.Exp(-float64(gap) / float64(ipHalfLifeSec))
}

// Similarity calcule la continuité entre deux signatures : somme pondérée et
// explicable des signaux concordants, bornée 0..100. Chaque signal concordant
// devient une contribution traçable.
// discriminant refuse les valeurs UBIQUITAIRES. Une signature n'a de valeur de
// preuve que si la partager est improbable : « / » est le chemin le plus frequent
// du web, et le partager ne rapproche personne de personne.
//
// SANS CE FILTRE, le moteur fusionnait deux scanners etrangers des lors qu'ils
// visaient « / » avec une famille d'outillage banale — 18 + 12 points pour deux
// coincidences qui n'en sont pas. C'est exactement le faux positif qu'un
// operateur ne pardonne pas : deux inconnus presentes comme un seul acteur.
func discriminant(v string) bool {
	switch v {
	case "", "/", "/*", "*":
		return false
	}
	return true
}

func Similarity(a, b Signature) score.Score {
	var c []score.Contribution
	add := func(label string, w int) {
		if w > 0 {
			c = append(c, score.Contribution{Label: label, Weight: w})
		}
	}
	if a.CredentialHash != "" && a.CredentialHash == b.CredentialHash {
		add("credential/token rare réutilisé", WCredential)
	}
	if discriminant(a.PathSig) && a.PathSig == b.PathSig {
		add("même séquence de chemins", WPathSeq)
	}
	if a.UAFamily != "" && a.UAFamily == b.UAFamily {
		add("même famille d'outillage HTTP", WTool)
	}
	if a.TLSFingerprint != "" && a.TLSFingerprint == b.TLSFingerprint {
		add("même empreinte TLS", WTLS)
	}
	if a.CadenceBucket != "" && a.CadenceBucket == b.CadenceBucket {
		add("même cadence temporelle", WCadence)
	}
	if a.IP != "" && a.IP == b.IP {
		w := int(math.Round(float64(WIP) * ipDecay(a.SeenAt, b.SeenAt)))
		if w > 0 {
			add("IP identique (décroissante)", w)
		}
	}
	if a.ASN != 0 && a.ASN == b.ASN {
		add("même ASN", WASN)
	}
	if a.Country != "" && a.Country == b.Country {
		add("même pays", WCountry)
	}
	return score.New(c...)
}

// PoidsTotal est la somme de TOUS les axes : la masse de preuve qu'une
// comparaison pourrait produire si chaque capteur etait alimente.
const PoidsTotal = WCredential + WPathSeq + WTool + WTLS + WCadence + WIP + WASN + WCountry

// MasseMin est la masse ABSOLUE de concordance exigee pour qu'un rattachement
// soit envisageable, quel que soit le nombre de capteurs deployes. Sans elle,
// un deploiement ne portant qu'un seul axe faible rattacherait sur ce seul axe.
const MasseMin = 20

// Comparable rend la masse de preuve que ces deux signatures pouvaient produire :
// la somme des poids des axes RENSEIGNES DES DEUX COTES, concordants ou non.
//
// POURQUOI CETTE MESURE EXISTE (2026-09-14). Le bareme a ete calibre pour huit
// capteurs et compare a un seuil fixe de 50. Sur une box ou seuls trois sont
// alimentes — ni identifiant reutilise (30), ni empreinte TLS (12), ni ASN, ni
// pays — le plafond atteignable est 40 : le seuil ne POUVAIT PAS etre franchi,
// et le moteur creait un acteur par evenement. Le score reste une mesure
// ABSOLUE, donc comparable dans le temps et non falsifiable ; c'est la DECISION
// de rattachement qui doit tenir compte de ce qu'on pouvait observer.
func Comparable(a, b Signature) int {
	m := 0
	deux := func(gauche, droite bool, poids int) {
		if gauche && droite {
			m += poids
		}
	}
	deux(a.CredentialHash != "", b.CredentialHash != "", WCredential)
	deux(discriminant(a.PathSig), discriminant(b.PathSig), WPathSeq)
	deux(a.UAFamily != "", b.UAFamily != "", WTool)
	deux(a.TLSFingerprint != "", b.TLSFingerprint != "", WTLS)
	deux(a.CadenceBucket != "", b.CadenceBucket != "", WCadence)
	if a.IP != "" && b.IP != "" {
		// L'IP decroit avec le temps : ce qu'elle pouvait prouver decroit aussi.
		m += int(math.Round(float64(WIP) * ipDecay(a.SeenAt, b.SeenAt)))
	}
	deux(a.ASN != 0, b.ASN != 0, WASN)
	deux(a.Country != "", b.Country != "", WCountry)
	return m
}

// SeuilEffectif ramene un seuil calibre sur PoidsTotal a la masse reellement
// comparable. « Tout ce qu'on pouvait comparer concorde » doit pouvoir suffire,
// sans jamais descendre sous MasseMin : une concordance legere ne devient pas
// une preuve parce qu'on n'avait rien d'autre a comparer.
func SeuilEffectif(seuilNominal, comparable int) int {
	if comparable <= 0 {
		return seuilNominal
	}
	s := int(math.Round(float64(seuilNominal) * float64(comparable) / float64(PoidsTotal)))
	if s < MasseMin {
		s = MasseMin
	}
	if s > seuilNominal {
		s = seuilNominal
	}
	return s
}
