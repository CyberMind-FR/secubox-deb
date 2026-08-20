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

func TestLaPolitiqueNAutoriseJamaisUnsafeInline(t *testing.T) {
	// `unsafe-inline` rendrait la politique decorative : c'est exactement ce
	// contre quoi elle protege. Quelle que soit la configuration, elle ne doit
	// jamais apparaitre.
	for _, o := range []Options{
		{},
		{BanniereOrigine: "https://admin.example", BanniereHash: "sha256-abc"},
	} {
		p := csp(t, o)
		for _, interdit := range []string{"unsafe-inline", "unsafe-eval", "unsafe-hashes"} {
			if strings.Contains(p, interdit) {
				t.Errorf("politique contenant %s : %s", interdit, p)
			}
		}
	}
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

func TestLEmpreinteDeStyleNAutorisePasUnsafeHashes(t *testing.T) {
	// La banniere injecte aussi une balise <style>. C'est un ELEMENT, pas un
	// attribut : une empreinte simple suffit. `unsafe-hashes` — que le message
	// du navigateur suggere — ne sert qu'aux attributs `style=`, et l'ajouter
	// ici autoriserait d'un coup tous les styles en ligne dont on vient
	// justement de debarrasser les gabarits.
	p := csp(t, Options{
		BanniereOrigine: "https://admin.gk2.secubox.in",
		BanniereStyle:   "sha256-2HVN0jyg43/7tFpU8UVAi4XD067D/50XDOJYznR2CIo=",
	})
	if !strings.Contains(p, "style-src 'self' 'sha256-2HVN0jyg43") {
		t.Errorf("empreinte de style absente de style-src : %s", p)
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
