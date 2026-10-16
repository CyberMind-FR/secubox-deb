// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
//
// #2804 — cache de réponses des CDN statiques (proxypac étape 2).
package main

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func newTestCDN(t *testing.T, hotes ...string) (*cdnCache, string) {
	t.Helper()
	dir := t.TempDir()
	liste := filepath.Join(dir, "hotes.txt")
	if err := os.WriteFile(liste, []byte(strings.Join(hotes, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return newCDNCache(filepath.Join(dir, "cache"), liste), dir
}

func get(t *testing.T, url string, h map[string]string) *http.Request {
	t.Helper()
	r, err := http.NewRequest("GET", url, nil)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range h {
		r.Header.Set(k, v)
	}
	return r
}

func rep(code int, h map[string]string) *http.Response {
	r := &http.Response{StatusCode: code, Status: "200 OK", Header: http.Header{}}
	for k, v := range h {
		r.Header.Set(k, v)
	}
	return r
}

func TestCDNEligible_ListeFermeeEtListeOperateur(t *testing.T) {
	c, _ := newTestCDN(t, "cdnjs.cloudflare.com", "optimizationguide-pa.googleapis.com", "evil.cdnjs.cloudflare.com", "d111.cloudfront.net")
	if !c.Eligible("cdnjs.cloudflare.com", get(t, "https://cdnjs.cloudflare.com/a.js", nil)) {
		t.Fatal("hôte statique accepté : éligible")
	}
	for _, h := range []string{"optimizationguide-pa.googleapis.com", "evil.cdnjs.cloudflare.com", "d111.cloudfront.net"} {
		if c.Eligible(h, get(t, "https://"+h+"/x", nil)) {
			t.Fatalf("%s : hors liste fermée, jamais mis en cache même si l'opérateur l'a listé", h)
		}
	}
	if c.Eligible("unpkg.com", get(t, "https://unpkg.com/x", nil)) {
		t.Fatal("hôte statique mais non accepté par l'opérateur : non éligible")
	}
}

func TestCDNEligible_MethodeEtEntetes(t *testing.T) {
	c, _ := newTestCDN(t, "cdn.jsdelivr.net")
	u := "https://cdn.jsdelivr.net/npm/x.js"
	post, _ := http.NewRequest("POST", u, nil)
	for nom, r := range map[string]*http.Request{
		"POST": post, "Range": get(t, u, map[string]string{"Range": "bytes=0-9"}), "Authorization": get(t, u, map[string]string{"Authorization": "Bearer x"}),
	} {
		if c.Eligible("cdn.jsdelivr.net", r) {
			t.Fatalf("%s : non éligible", nom)
		}
	}
	var nul *cdnCache
	if nul.Eligible("cdn.jsdelivr.net", get(t, u, nil)) {
		t.Fatal("cache nil : jamais éligible")
	}
}

func TestCDNStoreGet_AllerRetour(t *testing.T) {
	c, _ := newTestCDN(t, "cdnjs.cloudflare.com")
	req := get(t, "https://cdnjs.cloudflare.com/ajax/libs/x/1/x.min.js", map[string]string{"Accept-Encoding": "gzip"})
	resp := rep(200, map[string]string{"Content-Type": "application/javascript", "Content-Encoding": "gzip", "Cache-Control": "public, max-age=3600", "Etag": `"abc"`})
	if _, ok := c.Get("cdnjs.cloudflare.com", req); ok {
		t.Fatal("rien en cache au départ")
	}
	c.Store("cdnjs.cloudflare.com", req, resp, []byte("CORPS"))
	e, ok := c.Get("cdnjs.cloudflare.com", req)
	if !ok || string(e.body) != "CORPS" || e.header.Get("Content-Type") != "application/javascript" || e.header.Get("Content-Encoding") != "gzip" || e.header.Get("Etag") != `"abc"` {
		t.Fatalf("aller-retour incorrect : %+v ok=%v", e, ok)
	}
}

func TestCDNStore_RefuseCeQuiNeSeCachePas(t *testing.T) {
	c, _ := newTestCDN(t, "cdnjs.cloudflare.com")
	req := get(t, "https://cdnjs.cloudflare.com/a.js", nil)
	cas := map[string]*http.Response{
		"404":        rep(404, nil),
		"set-cookie": rep(200, map[string]string{"Content-Type": "text/css", "Set-Cookie": "a=b"}),
		"no-store":   rep(200, map[string]string{"Content-Type": "text/css", "Cache-Control": "no-store"}),
		"private":    rep(200, map[string]string{"Content-Type": "text/css", "Cache-Control": "private, max-age=60"}),
		"vary-*":     rep(200, map[string]string{"Content-Type": "text/css", "Vary": "*"}),
		"sans-type":  rep(200, nil),
	}
	for nom, r := range cas {
		c.Store("cdnjs.cloudflare.com", req, r, []byte("x"))
		if _, ok := c.Get("cdnjs.cloudflare.com", req); ok {
			t.Fatalf("%s : ne doit pas être mis en cache", nom)
		}
	}
	c.Store("cdnjs.cloudflare.com", req, rep(200, map[string]string{"Content-Type": "text/css"}), make([]byte, cdnMaxEntree+1))
	if _, ok := c.Get("cdnjs.cloudflare.com", req); ok {
		t.Fatal("trop gros : non mis en cache")
	}
}

func TestCDNGet_Expiration(t *testing.T) {
	c, _ := newTestCDN(t, "unpkg.com")
	maintenant := time.Unix(1_000_000, 0)
	c.now = func() time.Time { return maintenant }
	req := get(t, "https://unpkg.com/x@1/x.js", nil)
	c.Store("unpkg.com", req, rep(200, map[string]string{"Content-Type": "text/javascript", "Cache-Control": "max-age=60"}), []byte("v1"))
	// max-age=60 est relevé au plancher (1 h) : toujours là après 30 min
	c.now = func() time.Time { return maintenant.Add(30 * time.Minute) }
	if _, ok := c.Get("unpkg.com", req); !ok {
		t.Fatal("plancher d'une heure : encore valide")
	}
	c.now = func() time.Time { return maintenant.Add(61 * time.Minute) }
	if _, ok := c.Get("unpkg.com", req); ok {
		t.Fatal("expiré après le plancher")
	}
	// plafond : max-age d'un an -> 7 jours
	c.now = func() time.Time { return maintenant }
	c.Store("unpkg.com", req, rep(200, map[string]string{"Content-Type": "text/javascript", "Cache-Control": "max-age=31536000"}), []byte("v2"))
	c.now = func() time.Time { return maintenant.Add(7*24*time.Hour + time.Minute) }
	if _, ok := c.Get("unpkg.com", req); ok {
		t.Fatal("plafonné à 7 jours")
	}
}

func TestCDNCle_EncodageEtAgentUtilisateur(t *testing.T) {
	c, _ := newTestCDN(t, "fonts.googleapis.com", "cdnjs.cloudflare.com")
	css := "https://fonts.googleapis.com/css2?family=Inter"
	a := get(t, css, map[string]string{"User-Agent": "Chrome/124", "Accept-Encoding": "gzip"})
	c.Store("fonts.googleapis.com", a, rep(200, map[string]string{"Content-Type": "text/css"}), []byte("woff2"))
	if _, ok := c.Get("fonts.googleapis.com", get(t, css, map[string]string{"User-Agent": "Firefox/120", "Accept-Encoding": "gzip"})); ok {
		t.Fatal("Google varie le CSS selon l'agent : clé par agent pour fonts.googleapis.com")
	}
	if _, ok := c.Get("fonts.googleapis.com", get(t, css, map[string]string{"User-Agent": "Chrome/124", "Accept-Encoding": "br"})); ok {
		t.Fatal("encodage différent : autre variante")
	}
	js := "https://cdnjs.cloudflare.com/a.js"
	c.Store("cdnjs.cloudflare.com", get(t, js, map[string]string{"User-Agent": "A", "Accept-Encoding": "gzip"}), rep(200, map[string]string{"Content-Type": "text/javascript"}), []byte("js"))
	if _, ok := c.Get("cdnjs.cloudflare.com", get(t, js, map[string]string{"User-Agent": "B", "Accept-Encoding": "gzip"})); !ok {
		t.Fatal("hors polices, l'agent n'entre pas dans la clé")
	}
}

func TestCDNJanitor_EvinceLesPlusAnciens(t *testing.T) {
	c, _ := newTestCDN(t, "unpkg.com")
	c.maxTotal = 300
	for i, n := range []string{"a", "b", "c"} {
		req := get(t, "https://unpkg.com/"+n+".js", nil)
		c.Store("unpkg.com", req, rep(200, map[string]string{"Content-Type": "text/javascript"}), make([]byte, 200))
		ancien := time.Now().Add(time.Duration(i-10) * time.Minute)
		_ = os.Chtimes(c.chemin(c.cle("unpkg.com", req)), ancien, ancien)
	}
	c.nettoyer()
	var restes int
	_ = filepath.Walk(c.dir, func(p string, i os.FileInfo, err error) error {
		if err == nil && !i.IsDir() {
			restes++
		}
		return nil
	})
	if restes > 1 {
		t.Fatalf("le plafond de 300 octets ne tient pas : %d entrées restent", restes)
	}
}

type corpsEspion struct {
	*strings.Reader
	ferme int
}

func (c *corpsEspion) Close() error { c.ferme++; return nil }

func TestCDNCapturer_RestitueLeCorpsEtLeMetEnCache(t *testing.T) {
	c, _ := newTestCDN(t, "cdnjs.cloudflare.com")
	req := get(t, "https://cdnjs.cloudflare.com/a.js", nil)
	src := &corpsEspion{Reader: strings.NewReader("contenu")}
	resp := rep(200, map[string]string{"Content-Type": "text/javascript"})
	resp.Body = src
	c.capturer("cdnjs.cloudflare.com", req, resp)
	lu := make([]byte, 64)
	n, _ := resp.Body.Read(lu)
	if string(lu[:n]) != "contenu" {
		t.Fatalf("le client doit recevoir le corps intact : %q", lu[:n])
	}
	_ = resp.Body.Close()
	if src.ferme != 1 {
		t.Fatalf("le corps d'origine doit être fermé une fois (fuite sinon) : %d", src.ferme)
	}
	if e, ok := c.Get("cdnjs.cloudflare.com", req); !ok || string(e.body) != "contenu" {
		t.Fatal("la réponse doit être en cache")
	}
}

func TestCDNCapturer_TropGrosEstRelayeSansPerte(t *testing.T) {
	c, _ := newTestCDN(t, "cdnjs.cloudflare.com")
	req := get(t, "https://cdnjs.cloudflare.com/gros.js", nil)
	gros := strings.Repeat("x", cdnMaxEntree+10)
	resp := rep(200, map[string]string{"Content-Type": "text/javascript"})
	resp.Body = &corpsEspion{Reader: strings.NewReader(gros)}
	c.capturer("cdnjs.cloudflare.com", req, resp)
	tout := new(strings.Builder)
	buf := make([]byte, 1<<16)
	for {
		n, err := resp.Body.Read(buf)
		tout.Write(buf[:n])
		if err != nil {
			break
		}
	}
	if tout.Len() != len(gros) {
		t.Fatalf("le client doit recevoir TOUT le corps : %d / %d", tout.Len(), len(gros))
	}
	if _, ok := c.Get("cdnjs.cloudflare.com", req); ok {
		t.Fatal("trop gros : pas en cache")
	}
}

func TestCDNCapturer_IgnoreLesReponsesNon200(t *testing.T) {
	c, _ := newTestCDN(t, "cdnjs.cloudflare.com")
	req := get(t, "https://cdnjs.cloudflare.com/absent.js", nil)
	resp := rep(404, map[string]string{"Content-Type": "text/plain"})
	src := &corpsEspion{Reader: strings.NewReader("introuvable")}
	resp.Body = src
	c.capturer("cdnjs.cloudflare.com", req, resp)
	if resp.Body != src {
		t.Fatal("un non-200 n'est ni lu ni remplacé")
	}
}

func TestCDNReponse_EnTeteDeServiceDepuisLeCache(t *testing.T) {
	c, _ := newTestCDN(t, "unpkg.com")
	req := get(t, "https://unpkg.com/x.js", nil)
	c.Store("unpkg.com", req, rep(200, map[string]string{"Content-Type": "text/javascript", "Etag": `"e"`}), []byte("js"))
	e, _ := c.Get("unpkg.com", req)
	r := e.reponse()
	if r.StatusCode != 200 || r.Header.Get("X-SecuBox-Cache") != "HIT" || r.Header.Get("Content-Type") != "text/javascript" {
		t.Fatalf("réponse de cache incorrecte : %+v", r.Header)
	}
}
