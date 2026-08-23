// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
package linker

import "testing"

const rssXML = `<?xml version="1.0"?><rss version="2.0"><channel><title>T</title>
<item><title>Incendie près de Marseille</title><link>https://ex.fr/a</link>
<guid>ex-1</guid><description>&lt;p&gt;Un &lt;b&gt;feu&lt;/b&gt; important.&lt;/p&gt;</description>
<pubDate>Sat, 23 Aug 2026 10:00:00 +0200</pubDate></item></channel></rss>`

const atomXML = `<?xml version="1.0"?><feed xmlns="http://www.w3.org/2005/Atom"><title>T</title>
<entry><title>Wildfire near Marseille</title><id>atom-1</id>
<link rel="alternate" href="https://ex.com/b"/><summary>Evacuations reported.</summary>
<published>2026-08-23T08:00:00Z</published></entry></feed>`

func TestAnalyserRSS(t *testing.T) {
	items, err := Analyser([]byte(rssXML))
	if err != nil || len(items) != 1 {
		t.Fatalf("rss : %v / %d", err, len(items))
	}
	it := items[0]
	if it.Titre != "Incendie près de Marseille" || it.URL != "https://ex.fr/a" || it.Ref != "ex-1" {
		t.Errorf("champs rss inattendus : %+v", it)
	}
	if it.Corps != "Un feu important." { // HTML retiré, espaces compactés
		t.Errorf("corps mal nettoyé : %q", it.Corps)
	}
	if it.PublieLe == 0 {
		t.Errorf("date non analysée")
	}
}

func TestAnalyserAtom(t *testing.T) {
	items, err := Analyser([]byte(atomXML))
	if err != nil || len(items) != 1 {
		t.Fatalf("atom : %v / %d", err, len(items))
	}
	if items[0].URL != "https://ex.com/b" || items[0].Ref != "atom-1" || items[0].PublieLe == 0 {
		t.Errorf("atom inattendu : %+v", items[0])
	}
}

func TestEmpreinteClones(t *testing.T) {
	// même contenu, titres à la ponctuation près → même empreinte (clone).
	a := Empreinte("Incendie près de Marseille", "Un feu important")
	b := Empreinte("incendie près de marseille.", "un  feu   important")
	if a != b {
		t.Errorf("clones devraient partager l'empreinte : %s != %s", a, b)
	}
	c := Empreinte("Autre sujet", "rien à voir")
	if a == c {
		t.Errorf("sujets distincts ne devraient pas partager l'empreinte")
	}
}

func TestPokeLectureSeule(t *testing.T) {
	if _, err := NewRSS(nil).Poke(OutMsg{}); err != ErrLectureSeule {
		t.Errorf("RSS doit refuser Poke")
	}
}
