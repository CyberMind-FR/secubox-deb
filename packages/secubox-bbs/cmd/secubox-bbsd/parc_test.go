// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package main

import (
	"os"
	"path/filepath"
	"testing"
)

// boxDe simule une box : son domaine et les paquets installés.
func boxDe(t *testing.T, domaine string, paquets ...string) {
	t.Helper()
	d := t.TempDir()
	for _, p := range paquets {
		if err := os.WriteFile(filepath.Join(d, p+".list"), nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	ancienD, ancienO := dpkgInfo, origineBox
	dpkgInfo = d
	origineBox = func(p string) string {
		if domaine == "" {
			return ""
		}
		return "https://" + p + "." + domaine
	}
	t.Cleanup(func() { dpkgInfo, origineBox = ancienD, ancienO })
}

func opts() (map[string]*string, map[string]string) {
	v := map[string]string{"peertube-origine": "", "radio-base": "", "billets-base": "",
		"metanews-base": "https://metanews.gk2.secubox.in", "media-origines": "", "frame-origines": ""}
	o := map[string]*string{}
	for k := range v {
		s := v[k]
		o[k] = &s
	}
	return o, v
}

// gk3 : radio et billets installés, pas peertube → radio.gk3, billets.gk3,
// peertube de la référence ; les listes gardent aussi gk2.
func TestParcSurGk3(t *testing.T) {
	boxDe(t, "gk3.secubox.in", "secubox-radio", "secubox-billets")
	o, _ := opts()
	appliquerParc(map[string]bool{}, o)
	attendu := map[string]string{
		"radio-base":       "https://radio.gk3.secubox.in",
		"billets-base":     "https://billets.gk3.secubox.in",
		"peertube-origine": "https://peertube.gk2.secubox.in",
		"metanews-base":    "https://metanews.gk2.secubox.in",
		"frame-origines":   "https://radio.gk3.secubox.in,https://radio.gk2.secubox.in,https://podcaster.gk2.secubox.in",
	}
	for k, v := range attendu {
		if *o[k] != v {
			t.Errorf("%s = %q, attendu %q", k, *o[k], v)
		}
	}
}

// gk2 : tout installé → exactement les valeurs que l'unité figeait.
func TestParcSurGk2IdentiqueALUniteDAvant(t *testing.T) {
	boxDe(t, "gk2.secubox.in", "secubox-radio", "secubox-billets", "secubox-peertube",
		"secubox-podcaster", "secubox-socialrelay", "secubox-metanews")
	o, _ := opts()
	appliquerParc(map[string]bool{}, o)
	if got := *o["media-origines"]; got != "https://peertube.gk2.secubox.in,https://radio.gk2.secubox.in,https://podcaster.gk2.secubox.in,https://billets.gk2.secubox.in,https://socialrelay.gk2.secubox.in" {
		t.Errorf("media-origines = %q", got)
	}
	if got := *o["frame-origines"]; got != "https://radio.gk2.secubox.in,https://podcaster.gk2.secubox.in" {
		t.Errorf("frame-origines = %q", got)
	}
}

// Une option explicite de l'unité prime ; domaine inconnu → la référence.
func TestParcRespecteLesOptionsDonneesEtLeDomaineInconnu(t *testing.T) {
	boxDe(t, "", "secubox-radio")
	o, _ := opts()
	*o["radio-base"] = "https://radio.ailleurs.example"
	appliquerParc(map[string]bool{"radio-base": true}, o)
	if *o["radio-base"] != "https://radio.ailleurs.example" {
		t.Errorf("option explicite écrasée : %q", *o["radio-base"])
	}
	if *o["billets-base"] != "https://billets.gk2.secubox.in" {
		t.Errorf("sans domaine : %q", *o["billets-base"])
	}
}
