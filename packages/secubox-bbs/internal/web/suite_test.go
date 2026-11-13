// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package web

import (
	"testing"

	"github.com/CyberMind-FR/secubox-deb/secubox-bbs/internal/store"
)

func pv(auteur, quand int64) postView {
	return postView{Post: store.Post{AuthorID: auteur, CreatedAt: quand}}
}

// #3713 : une série du même auteur à moins de 30 min n'a qu'un en-tête.
func TestMarquerSuites(t *testing.T) {
	posts := []postView{
		pv(1, 1000),                 // ouvre une série
		pv(1, 1000+60),              // suite
		pv(1, 1000+60+SuiteMax),     // suite : pile la borne
		pv(1, 1000+60+2*SuiteMax+1), // trop tard : nouvelle série
		pv(2, 1000+60+2*SuiteMax+2), // autre auteur
		pv(1, 1000+60+2*SuiteMax+3), // l'auteur revient après un autre : nouvelle série
	}
	marquerSuites(posts)
	attendu := []bool{false, true, true, false, false, false}
	for i, p := range posts {
		if p.Suite != attendu[i] {
			t.Fatalf("message %d : Suite=%v, attendu %v", i, p.Suite, attendu[i])
		}
	}
}

// Un horodatage qui recule (import, horloge) n'est jamais une suite.
func TestMarquerSuitesHorlogeQuiRecule(t *testing.T) {
	posts := []postView{pv(1, 5000), pv(1, 4000)}
	marquerSuites(posts)
	if posts[1].Suite {
		t.Fatal("un message antérieur au précédent ne prolonge pas sa série")
	}
	marquerSuites(nil)
}
