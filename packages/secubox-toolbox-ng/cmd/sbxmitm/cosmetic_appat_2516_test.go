// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package main

import (
	"strings"
	"testing"
)

// #2516 : le détecteur d'anti-adblock du thème Foxiz (zataz) crée un appât
// #rb-adcheck > #google_ads_iframe_test (300x250) et mesure s'il est masqué.
// Nos règles ([id^="google_ads"]…) le masquaient : le mur « bloqueur de
// publicités détecté » apparaissait. La règle de protection, après la règle de
// masquage et plus spécifique, doit le laisser visible.
func TestCosmeticLaisseVisibleLAppatDesDetecteurs(t *testing.T) {
	style := string(cosmeticStyleFor("www.zataz.com"))
	hide := strings.Index(style, "display:none!important")
	if hide < 0 {
		t.Fatal("règle de masquage absente")
	}
	for _, sel := range []string{`#rb-adcheck`, `#google_ads_iframe_test`} {
		i := strings.LastIndex(style, sel)
		if i < 0 {
			t.Fatalf("appât %q non protégé", sel)
		}
		if i < hide {
			t.Errorf("protection de %q placée avant la règle de masquage : elle serait écrasée", sel)
		}
	}
	rule := style[strings.Index(style, `#rb-adcheck`):]
	if !strings.Contains(rule, "display:block!important") || !strings.Contains(rule, "visibility:visible!important") {
		t.Error("l'appât doit être forcé visible (display + visibility)")
	}
	if !strings.Contains(rule, "height:250px!important") {
		t.Error("l'appât doit garder sa taille (une feuille qui fixe height:0 le ferait juger masqué)")
	}
}
