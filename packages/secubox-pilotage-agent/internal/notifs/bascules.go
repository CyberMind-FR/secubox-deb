// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package notifs

import "time"

// Bascules locales (L2, tâche 4) : décidées en root sur la box par `secubox-pilotage`, lues par l'agent dans le verbe
// `etat` du ctl, puis notifiées au maître.
const (
	TypeMainsLiees   = "X_SECUBOX_HandsTied" // {etat: on|off}
	TypeConsentement = "X_SECUBOX_Consent"   // {id, decision: accepte|refuse|expire|annule}
	TypeSupport      = "X_SECUBOX_Support"   // {id, etat: en_attente|ouvert|refuse|ferme|annule|expire}
)

// decisions : états d'un consentement qui se notifient (« utilise » n'est pas une décision du détenteur).
var decisions = map[string]bool{"accepte": true, "refuse": true, "expire": true, "annule": true}

// Consentement et Support : identifiant et état, rien d'autre ne sort de la box.
type Consentement struct{ ID, Etat string }

// Support : la session de support (une seule à la fois).
type Support struct{ ID, Etat string }

// EtatLocal est l'état lu au ctl.
type EtatLocal struct {
	MainsLiees    bool
	Consentements []Consentement
	Support       *Support
}

// Bascules compare chaque état lu au précédent ; le premier sert de référence (rien n'est notifié : le maître lit
// l'état courant par Get). Non sûr en concurrence (une seule veille).
type Bascules struct {
	horloge  func() time.Time
	vu       bool
	liees    bool
	consents map[string]string
	support  Support
}

// NouvellesBascules ; horloge nil = time.Now.
func NouvellesBascules(horloge func() time.Time) *Bascules {
	if horloge == nil {
		horloge = time.Now
	}
	return &Bascules{horloge: horloge}
}

// Observer rend les notifications du passage de l'état précédent à e : mains liées, puis décisions de consentement
// (dans l'ordre du ctl), puis support.
func (b *Bascules) Observer(e EtatLocal) []Evenement {
	ts := b.horloge().Unix()
	consents := make(map[string]string, len(e.Consentements))
	for _, c := range e.Consentements {
		consents[c.ID] = c.Etat
	}
	support := Support{}
	if e.Support != nil {
		support = *e.Support
	}
	var ev []Evenement
	if b.vu {
		if e.MainsLiees != b.liees {
			etat := "off"
			if e.MainsLiees {
				etat = "on"
			}
			ev = append(ev, Evenement{Type: TypeMainsLiees, Etat: etat, Instant: ts})
		}
		for _, c := range e.Consentements {
			if avant, ok := b.consents[c.ID]; decisions[c.Etat] && (!ok || avant != c.Etat) {
				ev = append(ev, Evenement{Type: TypeConsentement, ID: c.ID, Decision: c.Etat, Instant: ts})
			}
		}
		if support.ID != "" && support != b.support {
			ev = append(ev, Evenement{Type: TypeSupport, ID: support.ID, Etat: support.Etat, Instant: ts})
		}
	}
	b.vu, b.liees, b.consents, b.support = true, e.MainsLiees, consents, support
	return ev
}
