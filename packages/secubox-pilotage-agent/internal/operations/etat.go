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
	type support struct {
		ID   string `json:"id"`
		Etat string `json:"etat"`
		Fin  *int64 `json:"fin"`
	}
	var r struct {
		OK            *bool           `json:"ok"`
		MainsLiees    *bool           `json:"mains_liees"`
		Consentements json.RawMessage `json:"consentements"`
		Support       json.RawMessage `json:"support"`
	}
	incoherent := fmt.Errorf("état du ctl incohérent")
	dec := json.NewDecoder(bytes.NewReader(b))
	if err := dec.Decode(&r); err != nil || dec.More() || r.OK == nil || !*r.OK || r.MainsLiees == nil ||
		r.Consentements == nil {
		return notifs.EtatLocal{}, incoherent
	}
	e := notifs.EtatLocal{MainsLiees: *r.MainsLiees}
	// M2 : une section que le ctl n'a pu lire est marquée « illisible » ; mains_liees reste lu.
	if string(r.Consentements) == `"illisible"` {
		e.ConsentementsIllisibles = true
	} else {
		var liste []struct {
			ID   string `json:"id"`
			Etat string `json:"etat"`
		}
		if json.Unmarshal(r.Consentements, &liste) != nil || liste == nil {
			return notifs.EtatLocal{}, incoherent
		}
		e.Consentements = make([]notifs.Consentement, 0, len(liste))
		for _, c := range liste {
			if !reJob.MatchString(c.ID) || !etatsConsentement[c.Etat] {
				return notifs.EtatLocal{}, incoherent
			}
			e.Consentements = append(e.Consentements, notifs.Consentement{ID: c.ID, Etat: c.Etat})
		}
	}
	switch string(r.Support) {
	case `"illisible"`:
		e.SupportIllisible = true
	case "", "null":
	default:
		var s support
		if json.Unmarshal(r.Support, &s) != nil || !reSupport.MatchString(s.ID) || !etatsSupport[s.Etat] ||
			(s.Fin != nil && *s.Fin <= 0) {
			return notifs.EtatLocal{}, incoherent
		}
		e.Support = &notifs.Support{ID: s.ID, Etat: s.Etat}
		if s.Fin != nil {
			e.Support.Fin = *s.Fin
		}
	}
	return e, nil
}
