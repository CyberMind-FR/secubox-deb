// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>

// Revalidation conditionnelle du cache media (#1031).
//
// Le defaut d origine : un `app.js` remplace sur disque restait servi dans sa
// version d avant jusqu a la fin de son TTL d une heure.
package main

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

func amontEssai(t *testing.T, h http.HandlerFunc) (string, int, func()) {
	t.Helper()
	srv := httptest.NewServer(h)
	u := strings.TrimPrefix(srv.URL, "http://")
	hote, p, err := net.SplitHostPort(u)
	if err != nil {
		t.Fatalf("adresse : %v", err)
	}
	n, _ := strconv.Atoi(p)
	return hote, n, srv.Close
}

func requete(chemin, hote string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "http://x"+chemin, nil)
	r.Host = hote
	return r
}

func TestUn304SignifieInchange(t *testing.T) {
	ip, port, stop := amontEssai(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("If-None-Match") == `"abc"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	defer stop()
	if !amontInchange(ip, port, requete("/app.js", "site.example"), `"abc"`, "") {
		t.Fatal("un 304 doit valoir « inchange »")
	}
}

func TestUn200SignifieChange(t *testing.T) {
	// LE CAS DU DEFAUT : le fichier a ete remplace, l ETag ne correspond plus.
	ip, port, stop := amontEssai(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("nouveau contenu"))
	})
	defer stop()
	if amontInchange(ip, port, requete("/app.js", "site.example"), `"vieux"`, "") {
		t.Fatal("un 200 doit valoir « change »")
	}
}


func TestSansValidateurOnNeSupposeRien(t *testing.T) {
	// L ignorance doit conduire a redemander, jamais a servir du perime.
	appele := false
	ip, port, stop := amontEssai(t, func(w http.ResponseWriter, r *http.Request) {
		appele = true
		w.WriteHeader(http.StatusNotModified)
	})
	defer stop()
	if amontInchange(ip, port, requete("/a.png", "site.example"), "", "") {
		t.Fatal("sans validateur, on ne peut pas conclure « inchange »")
	}
	if appele {
		t.Error("sans validateur, l amont ne doit meme pas etre interroge")
	}
}

func TestAmontMuetVautChange(t *testing.T) {
	// Un amont injoignable ne prouve pas que le cache est bon. Servir du
	// perime est invisible et dure des heures ; un aller-retour de trop coute
	// une milliseconde.
	if amontInchange("127.0.0.1", 1, requete("/a.png", "site.example"), `"abc"`, "") {
		t.Fatal("un amont muet ne doit jamais valoir « inchange »")
	}
}

func TestLHoteEstTransmis(t *testing.T) {
	// L amont sert plusieurs vhosts sur le meme port : sans l en-tete Host, on
	// revaliderait contre le fichier d un autre site.
	var vu string
	ip, port, stop := amontEssai(t, func(w http.ResponseWriter, r *http.Request) {
		vu = r.Host
		w.WriteHeader(http.StatusNotModified)
	})
	defer stop()
	amontInchange(ip, port, requete("/a.png", "anibal-amiot.fr"), `"abc"`, "")
	if vu != "anibal-amiot.fr" {
		t.Errorf("Host transmis = %q, veut anibal-amiot.fr", vu)
	}
}

func TestUneRedirectionNEstPasUneFraicheur(t *testing.T) {
	// Un 301 vers un autre chemin n est pas « ce fichier n a pas change » :
	// le suivre masquerait le changement qu on cherche a detecter.
	ip, port, stop := amontEssai(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/ailleurs", http.StatusMovedPermanently)
	})
	defer stop()
	if amontInchange(ip, port, requete("/a.png", "site.example"), `"abc"`, "") {
		t.Fatal("une redirection ne doit pas valoir « inchange »")
	}
}

// ── Le defaut de bout en bout ────────────────────────────────────────────

// Une entree VALIDEE dont l amont a change ne doit plus etre servie : c est
// exactement anibal-amiot.fr, ou un app.js remplace par `git pull` restait
// masque par le cache pendant une heure.
func TestEntreeValideeEtAmontChangeNEstPasServie(t *testing.T) {
	dir := t.TempDir()
	mc := NewMediaCache(dir)
	const u = "https://site.example/app.js"

	// On memorise « ancien contenu », avec un validateur.
	req := httptest.NewRequest(http.MethodGet, u, nil)
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Header: http.Header{
			"Content-Type": []string{"application/javascript"},
			"Etag":         []string{`"ancien"`},
		},
		Request: req,
	}
	mc.MaybeStore(req, resp, []byte("ancien contenu"), u)

	etag, lm := mc.Validateurs(u)
	if etag != `"ancien"` {
		t.Fatalf("validateur non memorise : %q / %q", etag, lm)
	}

	// L amont repond 200 : le fichier a change.
	ip, port, stop := amontEssai(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", `"neuf"`)
		w.WriteHeader(http.StatusOK)
	})
	defer stop()

	if amontInchange(ip, port, requete("/app.js", "site.example"), etag, lm) {
		t.Fatal("l amont a change : la revalidation doit le dire")
	}

	mc.Invalide(u)
	if _, _, ok := mc.Get(u, ""); ok {
		t.Fatal("apres invalidation, l entree ne doit plus etre servie")
	}
}

// Et l inverse : une entree validee dont l amont n a PAS change reste servie —
// sans quoi la correction couterait le cache tout entier.
func TestEntreeValideeEtAmontInchangeResteServie(t *testing.T) {
	dir := t.TempDir()
	mc := NewMediaCache(dir)
	const u = "https://site.example/logo.png"

	req := httptest.NewRequest(http.MethodGet, u, nil)
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Header: http.Header{
			"Content-Type": []string{"image/png"},
			"Etag":         []string{`"stable"`},
		},
		Request: req,
	}
	mc.MaybeStore(req, resp, []byte("des pixels"), u)

	ip, port, stop := amontEssai(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("If-None-Match") == `"stable"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	defer stop()

	etag, lm := mc.Validateurs(u)
	if !amontInchange(ip, port, requete("/logo.png", "site.example"), etag, lm) {
		t.Fatal("l amont n a pas change : le cache doit rester valable")
	}
	body, _, ok := mc.Get(u, "")
	if !ok || string(body) != "des pixels" {
		t.Fatalf("l entree doit toujours etre servie, got ok=%v", ok)
	}
}
