// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package pipeline

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// titreDe ne doit jamais paniquer, même quand le texte fait plus de 90
// octets mais moins de 90 runes (emoji / accents), et doit tronquer sur
// les runes, pas sur les octets.
func TestTitreDeMultibyteNePanique(t *testing.T) {
	texte := strings.Repeat("🌍", 40) // 40 runes, 160 octets : >90 octets mais <90 runes
	titre := titreDe("moi", texte)
	if !utf8.ValidString(titre) {
		t.Fatalf("titre non-UTF8 valide : %q", titre)
	}
	if strings.Contains(titre, "�") {
		t.Fatalf("troncature au milieu d'une rune : %q", titre)
	}
}

func TestTitreDeTronqueSurRunes(t *testing.T) {
	texte := strings.Repeat("é", 200) // 200 runes, 400 octets
	titre := titreDe("", texte)
	// 90 runes + l'ellipse
	if n := utf8.RuneCountInString(titre); n != 91 {
		t.Fatalf("attendu 91 runes (90 + …), obtenu %d : %q", n, titre)
	}
	if !strings.HasSuffix(titre, "…") {
		t.Fatalf("ellipse manquante : %q", titre)
	}
}

func TestTitreDeVide(t *testing.T) {
	if got := titreDe("", "   \n  "); got != "Publication" {
		t.Fatalf("attendu \"Publication\", obtenu %q", got)
	}
}
