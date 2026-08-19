// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package store

import (
	"testing"

	"github.com/CyberMind-FR/secubox-deb/secubox-bbs/internal/gateway"
)

// La mosaïque (#1049) lit les Contenu DÉJÀ ingérés, ordonnés par le temps et
// bornés — elle ne re-contacte aucune source au rendu. GatewayRecents est ce
// robinet : les plus récents d'abord, quel que soit le connecteur, borné.
func TestGatewayRecentsRendLesPlusRecentsBornes(t *testing.T) {
	s := ouvre(t)
	mk := func(ref string, publie int64, conn string) {
		c := contenuTest(func(c *gateway.Contenu) {
			c.RefNative = ref
			c.SourceURL = "https://ex.example/" + ref
			c.PublieLe = publie
			c.Connecteur = conn
		})
		if _, err := s.GatewayEnregistrer(c); err != nil {
			t.Fatal(err)
		}
	}
	mk("a", 100, "billets")
	mk("b", 300, "mastodon")
	mk("c", 200, "peertube")

	recents, err := s.GatewayRecents(2)
	if err != nil {
		t.Fatal(err)
	}
	if len(recents) != 2 {
		t.Fatalf("len = %d, veut 2 (borne)", len(recents))
	}
	if recents[0].PublieLe != 300 || recents[1].PublieLe != 200 {
		t.Fatalf("ordre = [%d, %d], veut [300, 200]", recents[0].PublieLe, recents[1].PublieLe)
	}
}
