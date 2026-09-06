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
	if a.PathSig != "" && a.PathSig == b.PathSig {
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
