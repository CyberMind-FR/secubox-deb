// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package web

import (
	"strings"
	"testing"
)

// Le marqueur « 🖼 <url> » d'un fil-passerelle (SocialRelay) doit être EXTRAIT
// comme média, et ne JAMAIS polluer l'aperçu texte de la carte.
func TestMarqueImageRelaisExtraiteEtNettoie(t *testing.T) {
	corps := "Un joli coucher de soleil sur la vallée\n\n— alice\n" +
		"Source : https://pixelfed.fr/p/alice/123\n" +
		"🖼 https://socialrelay.gk2.secubox.in/api/v1/socialrelay/media/abc123\n"

	ms := marqueImageRelais.FindAllStringSubmatch(corps, -1)
	if len(ms) != 1 {
		t.Fatalf("attendu 1 marqueur image, obtenu %d : %v", len(ms), ms)
	}
	if got := ms[0][1]; got != "https://socialrelay.gk2.secubox.in/api/v1/socialrelay/media/abc123" {
		t.Fatalf("URL extraite = %q", got)
	}
	// L'aperçu ne doit contenir ni le marqueur ni l'URL du média.
	r := resumeDeCorps(corps, "")
	if strings.Contains(r, "🖼") || strings.Contains(r, "socialrelay.gk2") {
		t.Fatalf("l'aperçu contient le marqueur média : %q", r)
	}
	if !strings.Contains(r, "coucher de soleil") {
		t.Fatalf("l'aperçu a perdu le texte : %q", r)
	}
}
