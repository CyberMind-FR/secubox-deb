// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package ytid

import "testing"

func TestVideoIDWatch(t *testing.T) {
	if id := VideoID("https://www.youtube.com/watch?v=dQw4w9WgXcQ"); id != "dQw4w9WgXcQ" {
		t.Fatalf("watch : id %q", id)
	}
}

func TestVideoIDYoutuBeAvecQuery(t *testing.T) {
	if id := VideoID("https://youtu.be/kFuf9xUInzA?si=7DvT2wtSMprn4NHI"); id != "kFuf9xUInzA" {
		t.Fatalf("youtu.be : id %q", id)
	}
}

func TestVideoIDShorts(t *testing.T) {
	if id := VideoID("https://www.youtube.com/shorts/dQw4w9WgXcQ"); id != "dQw4w9WgXcQ" {
		t.Fatalf("shorts : id %q", id)
	}
}

func TestVideoIDNonYoutube(t *testing.T) {
	if id := VideoID("https://exemple.org/x"); id != "" {
		t.Fatalf("non-YouTube : id %q attendu vide", id)
	}
}

// M2 : `youtu.be//ID` (double barre) doit rendre l'id, comme le
// `lstrip("/")` de ytid.py côté ytsas — un simple TrimPrefix laisserait un
// premier "/" résiduel et casserait la validation.
func TestVideoIDYoutuBeDoubleBarre(t *testing.T) {
	if id := VideoID("https://youtu.be//dQw4w9WgXcQ"); id != "dQw4w9WgXcQ" {
		t.Fatalf("youtu.be double barre : id %q attendu dQw4w9WgXcQ", id)
	}
}
