// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// SecuBox-Deb :: toolbox-ng :: sbxwaf — tests de la normalisation PHP des noms (#3273)

package main

import (
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func TestNomPHP(t *testing.T) {
	cas := []struct {
		brut string
		nom  string
		ok   bool
	}{
		{"_from", "_from", true},
		{".from", "_from", true},
		{" _from", "_from", true},
		{"a.b c", "a_b_c", true},
		{"_from[]", "_from", true},
		{"_from[x]", "_from", true},
		{"_[Host-x", "__Host-x", true},
		// php_variables.c:236-240 : sans « ] », la suite convertit aussi
		// « », « . » et « [ » en « _ » (le brief disait « telle quelle »).
		{"a[b.c", "a_b_c", true},
		{"a[b[c d", "a_b_c_d", true},
		// R-W2 : php_variables.c:149-153 + 156, base vide après « [ » initial.
		{"[from", "", false},
		{"_fr\x00om", "_fr", true},
		{"", "", false},
		{"   ", "", false},
		// Seul l'octet « ' ' » est sauté en tête (php_variables.c:133), pas la tabulation.
		{"\t_x", "\t_x", true},
		// Un « ] » situé plus loin suffit, même après un espace (l. 227-232).
		{"a[ ]", "a", true},
		{"a[x.y]z", "a", true},
	}
	for _, c := range cas {
		nom, ok := nomPHP(c.brut)
		if nom != c.nom || ok != c.ok {
			t.Errorf("nomPHP(%q) = (%q,%v), attendu (%q,%v)", c.brut, nom, ok, c.nom, c.ok)
		}
	}
}

func TestURLDecodePHP(t *testing.T) {
	cas := map[string]string{
		"a+b":     "a b",
		"%41":     "A",
		"%zz":     "%zz",
		"%4":      "%4",
		"%0d%0a":  "\r\n",
		"%00":     "\x00",
		"%4g":     "%4g",
		"%%41":    "%A",
		"":        "",
		"%C3%a9+": "\xc3\xa9 ",
	}
	for in, want := range cas {
		if got := urldecodePHP(in); got != want {
			t.Errorf("urldecodePHP(%q) = %q, attendu %q", in, got, want)
		}
	}
}

func TestLireParametresPHP(t *testing.T) {
	p := lireParametresPHP("_task=settings&.from=edit-%21x&&q=1&_uid")
	if p.Variables != 4 {
		t.Errorf("Variables = %d, attendu 4", p.Variables)
	}
	if got := p.Valeurs("_from"); !reflect.DeepEqual(got, []string{"edit-!x"}) {
		t.Errorf("Valeurs(_from) = %q", got)
	}
	if got := p.Valeurs("_task"); !reflect.DeepEqual(got, []string{"settings"}) {
		t.Errorf("Valeurs(_task) = %q", got)
	}
	if got := p.Valeurs("q"); got != nil {
		t.Errorf("Valeurs(q) = %q, attendu nil (non retenu)", got)
	}
	if got := p.Valeurs("_uid"); !reflect.DeepEqual(got, []string{""}) {
		t.Errorf("Valeurs(_uid) = %q, attendu [\"\"]", got)
	}

	p = lireParametresPHP("_uid=1&_uid=2")
	if got := p.Valeurs("_uid"); !reflect.DeepEqual(got, []string{"1", "2"}) {
		t.Errorf("Valeurs(_uid) = %q", got)
	}

	// Le nom est décodé puis normalisé : %5Ffrom, %2Efrom, _from[] et « %5B » orphelin.
	p = lireParametresPHP("%5Ffrom=a&%2Efrom=b&_from%5B%5D=c")
	if got := p.Valeurs("_from"); !reflect.DeepEqual(got, []string{"a", "b", "c"}) {
		t.Errorf("Valeurs(_from) = %q", got)
	}
}

func TestLireParametresPHPPlafond(t *testing.T) {
	p := lireParametresPHP(strings.Repeat("_uid=1&", 99) + "_uid=1")
	if len(p.Retenus) != 64 || p.Variables != 100 {
		t.Errorf("Retenus=%d Variables=%d, attendu 64 et 100", len(p.Retenus), p.Variables)
	}
}

func TestParcourirCookiesPHP(t *testing.T) {
	type paire struct{ brut, nom string }
	collecte := func(lignes []string) []paire {
		var r []paire
		parcourirCookiesPHP(lignes, func(brut, nom string) { r = append(r, paire{brut, nom}) })
		return r
	}
	got := collecte([]string{"a=1; _[Host-x=y", " b.c=2"})
	want := []paire{{"a", "a"}, {"_[Host-x", "__Host-x"}, {"b.c", "b_c"}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("cookies = %v, attendu %v", got, want)
	}
	// Nom non décodé (PHP >= 8.0).
	got = collecte([]string{"%5F%5BHost-x=1"})
	want = []paire{{"%5F%5BHost-x", "%5F%5BHost-x"}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("cookies = %v, attendu %v", got, want)
	}
	// Sans « = » : la ligne entière est le nom ; nom vide, séparateurs répétés et
	// nom ignoré par PHP ([x) : rien.
	got = collecte([]string{"seul;; =v; \t;=w; [x=1; d\x00e=2"})
	want = []paire{{"seul", "seul"}, {"d", "d"}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("cookies = %v, attendu %v", got, want)
	}
}

func FuzzLireParametresPHP(f *testing.F) {
	for _, s := range []string{"", "_uid=1&_uid=2", "%zz=%4&&[=]", "_from[=%00&.q", "a=b&" + strings.Repeat("_uid=1&", 80)} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		p := lireParametresPHP(s)
		if len(p.Retenus) > parametresRetenusMax {
			t.Fatalf("trop de retenus : %d", len(p.Retenus))
		}
		if p.Variables < len(p.Retenus) {
			t.Fatalf("Variables %d < Retenus %d", p.Variables, len(p.Retenus))
		}
		for _, r := range p.Retenus {
			if !nomsRetenusPHP[r.Nom] {
				t.Fatalf("nom non retenu conservé : %q", r.Nom)
			}
		}
	})
}

// octetsAlloues mesure les octets alloués par f (TotalAlloc), sur un seul appel.
func octetsAlloues(f func()) uint64 {
	var avant, apres runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&avant)
	f()
	runtime.ReadMemStats(&apres)
	return apres.TotalAlloc - avant.TotalAlloc
}

// I1 (relecture de la tâche 2) : un corps de 1 Mio fait de séparateurs ne
// doit pas allouer une tranche par segment (strings.Split : ~16 Mo).
func TestLireParametresPHPAllocationsBornees(t *testing.T) {
	cas := map[string]string{
		"& x 1 Mi":    strings.Repeat("&", 1<<20),
		"a& x 512 Ki": strings.Repeat("a&", 512<<10),
	}
	for nom, brut := range cas {
		if n := testing.AllocsPerRun(5, func() { lireParametresPHP(brut) }); n != 0 {
			t.Errorf("%s : %v allocation(s) par appel, attendu 0", nom, n)
		}
		if o := octetsAlloues(func() { lireParametresPHP(brut) }); o > 64<<10 {
			t.Errorf("%s : %d octets alloués, attendu au plus 64 Kio", nom, o)
		}
	}
}

// I1 : ni urldecodePHP ni nomPHP n'allouent quand il n'y a rien à changer, et
// nomPHP ne copie qu'une fois quand il change le nom.
func TestNomPHPAllocations(t *testing.T) {
	cas := []struct {
		nom    string
		f      func()
		maxAll float64
	}{
		{"urldecode sans % ni +", func() { urldecodePHP("_from") }, 0},
		{"nomPHP inchangé", func() { nomPHP("_from") }, 0},
		{"nomPHP index", func() { nomPHP("_from[x]") }, 0},
		{"nomPHP point", func() { nomPHP(".from") }, 1},
		{"nomPHP crochet orphelin", func() { nomPHP("a[b.c") }, 1},
	}
	for _, c := range cas {
		if n := testing.AllocsPerRun(20, c.f); n > c.maxAll {
			t.Errorf("%s : %v allocation(s), attendu au plus %v", c.nom, n, c.maxAll)
		}
	}
}

// I1 : la normalisation travaille octet par octet, comme PHP : un octet non
// UTF-8 n'est jamais réécrit (strings.Map le remplacerait par U+FFFD).
func TestNomPHPOctetsNonUTF8(t *testing.T) {
	cas := map[string]string{
		"a\xff.b":    "a\xff_b",
		"\xfe[x]":    "\xfe",
		"a\xff[b.c":  "a\xff_b_c",
		"\xc3\xa9.x": "\xc3\xa9_x",
	}
	for brut, attendu := range cas {
		if nom, ok := nomPHP(brut); !ok || nom != attendu {
			t.Errorf("nomPHP(%q) = (%q, %v), attendu (%q, true)", brut, nom, ok, attendu)
		}
	}
}
