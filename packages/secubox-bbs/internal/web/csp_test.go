// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package web

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func csp(t *testing.T, opt Options) string {
	t.Helper()
	srv, _ := banc(t)
	srv.opt.BanniereOrigine = opt.BanniereOrigine
	srv.opt.BanniereHash = opt.BanniereHash
	srv.opt.BanniereStyle = opt.BanniereStyle
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/", nil))
	return w.Header().Get("Content-Security-Policy")
}

// ── CE QUE LA POLITIQUE INTERDIT VRAIMENT (#1329) ──────────────────────────
//
// Ce test exigeait « jamais `unsafe-inline`, nulle part ». La politique ne le
// respecte plus VOLONTAIREMENT depuis #1238-suite : `style-src` le porte, parce
// que la carte /micro embarque le style « spicy » et la lib partagée SBXAide,
// qui injectent un <style> et des styles en ligne.
//
// Le test est donc resté rouge sur master, et c'est le vrai coût : une suite
// dont deux tests échouent en permanence est une suite dont on n'apprend plus
// rien. Au prochain relâchement — un vrai, celui-là — personne ne le verrait.
//
// ON NE RELÂCHE PAS LA RÈGLE, ON LA REND EXACTE. Ce qui compte n'a jamais été
// « unsafe-inline » comme mot, mais ce qu'il autorise :
//
//   * dans `script-src`, il autorise l'EXÉCUTION de code arbitraire injecté —
//     c'est la faille que toute la politique existe pour fermer, et c'est
//     interdit quelle que soit la configuration ;
//   * `unsafe-eval` et `unsafe-hashes` restent interdits PARTOUT ;
//   * dans `style-src`, il autorise des styles. Un style n'exécute pas de code.
//
// RISQUE RÉSIDUEL, QUI N'EST PAS NUL ET QU'ON N'ESCAMOTE PAS : du CSS peut
// exfiltrer (sélecteurs d'attribut + `background-image`) et servir à un
// habillage trompeur. C'est sans commune mesure avec `script-src`, mais c'est
// une décision, pas une neutralité. La sortie propre serait un `nonce` sur
// `style-src` — elle demande que SBXAide sache le lire.

func TestScriptSrcNAutoriseJamaisLInline(t *testing.T) {
	for _, o := range []Options{
		{},
		{BanniereOrigine: "https://admin.example", BanniereHash: "sha256-abc"},
	} {
		p := csp(t, o)
		// On isole `script-src` : chercher la chaîne dans la politique entière
		// retomberait sur le `style-src` autorisé, et le test ne prouverait
		// plus rien de ce qu'il prétend prouver.
		d := directive(p, "script-src")
		if strings.Contains(d, "unsafe-inline") {
			t.Errorf("script-src autorise l'inline : %q (politique : %s)", d, p)
		}
	}
}

func TestNiEvalNiUnsafeHashesNullePart(t *testing.T) {
	for _, o := range []Options{
		{},
		{BanniereOrigine: "https://admin.example", BanniereHash: "sha256-abc"},
		{BanniereStyle: "sha256-2HVN0jyg43/7tFpU8UVAi4XD067D/50XDOJYznR2CIo="},
	} {
		p := csp(t, o)
		for _, interdit := range []string{"unsafe-eval", "unsafe-hashes"} {
			if strings.Contains(p, interdit) {
				t.Errorf("politique contenant %s : %s", interdit, p)
			}
		}
	}
}

// L'EXCEPTION EST NOMMÉE, ET ELLE EST SEULE. Si un jour `unsafe-inline`
// apparaît ailleurs que dans `style-src`, ce test le dit — c'est exactement le
// service que l'ancien rendait, sans le faux positif qui l'avait éteint.
func TestUnsafeInlineNEstTolereQueDansStyleSrc(t *testing.T) {
	p := csp(t, Options{BanniereOrigine: "https://admin.example"})
	for _, d := range strings.Split(p, ";") {
		d = strings.TrimSpace(d)
		if !strings.Contains(d, "unsafe-inline") {
			continue
		}
		if !strings.HasPrefix(d, "style-src ") {
			t.Errorf("unsafe-inline hors de style-src : %q", d)
		}
	}
}

// directive extrait une directive nommée de la politique.
func directive(politique, nom string) string {
	for _, d := range strings.Split(politique, ";") {
		d = strings.TrimSpace(d)
		if strings.HasPrefix(d, nom+" ") || d == nom {
			return d
		}
	}
	return ""
}

func TestSansBanniereLaPolitiqueResteFermee(t *testing.T) {
	p := csp(t, Options{})
	if !strings.Contains(p, "script-src 'self';") {
		t.Errorf("script-src elargi sans raison : %s", p)
	}
	// #1056 : frame-src autorise youtube-nocookie par conception (la board
	// integre YouTube). C'est la SEULE origine externe par defaut, et elle ne
	// peut ni executer de script ni exfiltrer de donnees. L'invariant « fermee »
	// porte donc desormais sur les directives sensibles : script/style/connect.
	for _, dir := range []string{"script-src 'self' http", "style-src 'self' http", "connect-src 'self' http"} {
		if strings.Contains(p, dir) {
			t.Errorf("une origine externe de code/style/connexion est autorisee par defaut : %s", p)
		}
	}
}

func TestAvecBanniereSeulesLOrigineEtLEmpreinteSontAjoutees(t *testing.T) {
	// La banniere de sante est injectee par le WAF de la board dans toutes les
	// pages. On l'autorise PRECISEMENT — une origine nommee et l'empreinte
	// exacte du chargeur — plutot que d'ouvrir la porte a tout script en ligne.
	p := csp(t, Options{
		BanniereOrigine: "https://admin.gk2.secubox.in",
		BanniereHash:    "sha256-eDTYsncfrGT/tlGmdDgSPq9JNg8lg8MeoFWIUtAxVHs=",
	})
	if !strings.Contains(p, "https://admin.gk2.secubox.in") {
		t.Errorf("origine de la banniere absente : %s", p)
	}
	if !strings.Contains(p, "'sha256-eDTYsncfrGT/tlGmdDgSPq9JNg8lg8MeoFWIUtAxVHs='") {
		t.Errorf("empreinte du chargeur absente : %s", p)
	}
	// L'elargissement ne doit toucher QUE les scripts et les connexions.
	if strings.Contains(p, "style-src 'self' https://") {
		t.Errorf("style-src elargi sans raison : %s", p)
	}
}

func TestUneEmpreinteMalFormeeEstIgnoree(t *testing.T) {
	// Une valeur de configuration erronee ne doit pas produire une politique
	// invalide — un navigateur qui n'arrive pas a lire la politique peut
	// l'ignorer ENTIEREMENT, ce qui est le pire resultat possible.
	p := csp(t, Options{BanniereOrigine: "https://a.example", BanniereHash: "n importe quoi"})
	if strings.Contains(p, "n importe quoi") {
		t.Errorf("empreinte non validee reprise telle quelle : %s", p)
	}
}

// L'EMPREINTE DE STYLE N'EST PAS AJOUTÉE, ET C'EST VOULU (#1329).
//
// Ce test l'exigeait dans `style-src`. Le code la retire exprès, et il a
// raison : par la spécification CSP, la présence d'une empreinte (ou d'un
// nonce) dans une directive ANNULE `unsafe-inline` pour cette directive.
// L'ajouter casserait donc les styles de la carte /micro — précisément ce que
// `unsafe-inline` est là pour permettre.
//
// On garde le test, en inversant ce qu'il vérifie : sans quoi quelqu'un
// « corrigera » un jour l'oubli apparent, et cassera l'affichage sans
// comprendre pourquoi.
func TestLEmpreinteDeStyleNEstPasAjouteeTantQueLInlineEstLa(t *testing.T) {
	p := csp(t, Options{
		BanniereOrigine: "https://admin.gk2.secubox.in",
		BanniereStyle:   "sha256-2HVN0jyg43/7tFpU8UVAi4XD067D/50XDOJYznR2CIo=",
	})
	d := directive(p, "style-src")
	if !strings.Contains(d, "unsafe-inline") {
		t.Fatalf("style-src ne porte plus l'inline : le reste de ce test ne "+
			"veut plus rien dire, et l'empreinte devrait alors revenir (%q)", d)
	}
	if strings.Contains(d, "sha256-2HVN0jyg43") {
		t.Errorf("empreinte ajoutée À CÔTÉ de unsafe-inline : elle l'annule, "+
			"et les styles de la carte /micro cesseront de s'appliquer (%q)", d)
	}
	if strings.Contains(p, "unsafe-hashes") {
		t.Errorf("unsafe-hashes ajoute : %s", p)
	}
}

func TestUneEmpreinteDeStyleMalFormeeEstIgnoree(t *testing.T) {
	p := csp(t, Options{BanniereStyle: "pas-une-empreinte"})
	if strings.Contains(p, "pas-une-empreinte") {
		t.Errorf("empreinte non validee reprise : %s", p)
	}
}

// La board integre YouTube par conception : frame-src doit TOUJOURS autoriser
// l'hote cookieless, meme sans autre configuration (#1056).
func TestFrameSrcAutoriseToujoursYoutubeNocookie(t *testing.T) {
	if f := (&Server{}).frameSrc(); !strings.Contains(f, "https://www.youtube-nocookie.com") {
		t.Fatalf("frame-src doit autoriser youtube-nocookie : %s", f)
	}
}

// L'origine ytsas alimente media-src pour le <video> du cas « cache » (#1056).
func TestPolitiqueMediaSrcInclutYtsas(t *testing.T) {
	p := politique("'self'", "'self'", "'self'", "'none'", "http://10.100.0.180:8091")
	if !strings.Contains(p, "media-src 'self' http://10.100.0.180:8091") {
		t.Fatalf("media-src doit inclure l'origine ytsas : %s", p)
	}
}
