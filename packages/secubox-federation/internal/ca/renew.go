// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package ca

import (
	"errors"
	"time"

	"github.com/CyberMind-FR/secubox-deb/secubox-federation/internal/sbxcert"
)

// Renouvellement : la box présente son certificat et PROUVE qu'elle en tient
// la clé (signature de sa clé de nœud sur une charge datée).
type Renouvellement struct {
	Certificat string `json:"certificat"` // YAML
	Horodatage string `json:"horodatage"`
	Signature  string `json:"signature"`
}

func ChargeRenouvellement(serial, boxID, horodatage string) map[string]any {
	return map[string]any{"action": "renew", "serial": serial, "box_id": boxID, "horodatage": horodatage}
}

// Grace : un certificat expiré depuis moins longtemps se renouvelle encore.
// Au-delà, la box refait une demande d'adhésion — décision humaine.
const Grace = 30 * 24 * time.Hour

// Renouvelle émet un nouveau certificat, AUX CONDITIONS ACTUELLES du tier
// (la politique a pu changer depuis la dernière émission).
func (a *Autorite) Renouvelle(r *Renouvellement, p Politique, jours int, maintenant time.Time, revoques map[string]bool) (*sbxcert.Certificat, error) {
	c, err := sbxcert.Lit([]byte(r.Certificat))
	if err != nil {
		return nil, err
	}
	// Vérifié comme si l'on était encore dans la période de grâce : un
	// certificat expiré hier doit pouvoir être renouvelé aujourd'hui.
	e := c.Verification(a.Pub, maintenant.Add(-Grace), revoques)
	if !e.Valide {
		return nil, errors.New("certificat non renouvelable : " + e.Motif)
	}
	if _, err := VerifiePreuve(c.BoxID, c.Pubkey, r.Horodatage, r.Signature,
		ChargeRenouvellement(c.Serial, c.BoxID, r.Horodatage), maintenant); err != nil {
		return nil, err
	}
	return a.Emet(c.Pubkey, c.Owner, c.Tier, p, jours, maintenant)
}
