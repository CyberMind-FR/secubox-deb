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
type Support struct {
	ID, Etat string
	Fin      int64
}

// EtatLocal est l'état lu au ctl.
type EtatLocal struct {
	MainsLiees              bool
	Consentements           []Consentement
	Support                 *Support
	ConsentementsIllisibles bool
	SupportIllisible        bool
}

// Bascules compare chaque état lu au précédent. Au premier état lu (démarrage de l'agent), l'état des mains liées et la
// session de support en cours (en attente ou ouverte, avec sa fin) sont notifiés (R-L2-33 b) : un agent qui redémarre
// pendant une session la renotifie ; les consentements ne le sont pas (le maître lit l'état par Get). Le maître
// dédoublonne par id et état (une renotification est sans conséquence). Une section illisible ne produit rien et garde
// la mémoire précédente. Non sûr en concurrence (une seule veille).
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

// evSupport : X_SECUBOX_Support {id, etat, fin} ; fin (RFC 3339, UTC) dès qu'elle est connue (session ouverte), pour
// que le maître expire la session lui-même à sa borne (R-L2-33 a).
func evSupport(s Support, ts int64) Evenement {
	e := Evenement{Type: TypeSupport, ID: s.ID, Etat: s.Etat, Instant: ts}
	if s.Fin > 0 {
		e.Fin = time.Unix(s.Fin, 0).UTC().Format(time.RFC3339)
	}
	return e
}

// Observer rend les notifications du passage de l'état précédent à e : mains liées, puis décisions de consentement
// (dans l'ordre du ctl), puis support.
func (b *Bascules) Observer(e EtatLocal) []Evenement {
	ts := b.horloge().Unix()
	var ev []Evenement
	if !b.vu || e.MainsLiees != b.liees {
		etat := "off"
		if e.MainsLiees {
			etat = "on"
		}
		ev = append(ev, Evenement{Type: TypeMainsLiees, Etat: etat, Instant: ts})
	}
	b.liees = e.MainsLiees
	if !e.ConsentementsIllisibles {
		consents := make(map[string]string, len(e.Consentements))
		for _, c := range e.Consentements {
			consents[c.ID] = c.Etat
			if avant, ok := b.consents[c.ID]; b.vu && decisions[c.Etat] && (!ok || avant != c.Etat) {
				ev = append(ev, Evenement{Type: TypeConsentement, ID: c.ID, Decision: c.Etat, Instant: ts})
			}
		}
		b.consents = consents
	}
	if !e.SupportIllisible {
		support := Support{}
		if e.Support != nil {
			support = *e.Support
		}
		enCours := support.Etat == "en_attente" || support.Etat == "ouvert"
		if support.ID != "" && ((b.vu && support != b.support) || (!b.vu && enCours)) {
			ev = append(ev, evSupport(support, ts))
		}
		b.support = support
	}
	b.vu = true
	return ev
}
