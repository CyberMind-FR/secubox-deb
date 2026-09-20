// SPDX-License-Identifier: LicenseRef-CMSD-1.0
package pairing

import (
	"strings"
	"testing"
)

func TestSVGContientUnTrace(t *testing.T) {
	svg, err := SVG("sgnl://linkdevice?uuid=abc&pub_key=def", 320)
	if err != nil {
		t.Fatal(err)
	}
	for _, attendu := range []string{"<svg", "viewBox", "<path", "</svg>"} {
		if !strings.Contains(svg, attendu) {
			t.Errorf("SVG sans %q", attendu)
		}
	}
}

// L'URI d'appairage est un SECRET : elle ne doit apparaitre NULLE PART dans
// la sortie. C'est tout l'interet de tracer cote serveur.
func TestLURIneFuitPasDansLeSVG(t *testing.T) {
	const uri = "sgnl://linkdevice?uuid=SECRET-UUID&pub_key=SECRET-KEY"
	svg, err := SVG(uri, 320)
	if err != nil {
		t.Fatal(err)
	}
	for _, fuite := range []string{"SECRET-UUID", "SECRET-KEY", "sgnl://"} {
		if strings.Contains(svg, fuite) {
			t.Fatalf("l'URI d'appairage fuit dans le SVG : %q trouve", fuite)
		}
	}
}

func TestURIVideEchoue(t *testing.T) {
	if _, err := SVG("", 320); err == nil {
		t.Fatal("une URI vide doit etre refusee")
	}
}
