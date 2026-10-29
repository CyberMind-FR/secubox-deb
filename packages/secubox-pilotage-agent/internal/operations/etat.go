// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package operations

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/CyberMind-FR/secubox-deb/secubox-pilotage-agent/internal/notifs"
)

var (
	etatsConsentement = map[string]bool{"en_attente": true, "accepte": true, "refuse": true, "utilise": true,
		"expire": true, "annule": true}
	etatsSupport = map[string]bool{"en_attente": true, "ouvert": true, "refuse": true, "ferme": true, "annule": true,
		"expire": true}
)

// LireEtat interprète la sortie du verbe de lecture `etat` du ctl : un seul objet JSON, ok vrai, mains_liees booléen,
// consentements et support aux identifiants et états de la liste fermée. Toute autre forme est une erreur (fermé par
// défaut : aucune notification plutôt qu'une notification inventée).
func LireEtat(b []byte) (notifs.EtatLocal, error) {
	var r struct {
		OK            *bool `json:"ok"`
		MainsLiees    *bool `json:"mains_liees"`
		Consentements []struct {
			ID   string `json:"id"`
			Etat string `json:"etat"`
		} `json:"consentements"`
		Support *struct {
			ID   string `json:"id"`
			Etat string `json:"etat"`
		} `json:"support"`
	}
	incoherent := fmt.Errorf("état du ctl incohérent")
	dec := json.NewDecoder(bytes.NewReader(b))
	if err := dec.Decode(&r); err != nil || dec.More() || r.OK == nil || !*r.OK || r.MainsLiees == nil ||
		r.Consentements == nil {
		return notifs.EtatLocal{}, incoherent
	}
	e := notifs.EtatLocal{MainsLiees: *r.MainsLiees, Consentements: make([]notifs.Consentement, 0, len(r.Consentements))}
	for _, c := range r.Consentements {
		if !reJob.MatchString(c.ID) || !etatsConsentement[c.Etat] {
			return notifs.EtatLocal{}, incoherent
		}
		e.Consentements = append(e.Consentements, notifs.Consentement{ID: c.ID, Etat: c.Etat})
	}
	if r.Support != nil {
		if !reSupport.MatchString(r.Support.ID) || !etatsSupport[r.Support.Etat] {
			return notifs.EtatLocal{}, incoherent
		}
		e.Support = &notifs.Support{ID: r.Support.ID, Etat: r.Support.Etat}
	}
	return e, nil
}
