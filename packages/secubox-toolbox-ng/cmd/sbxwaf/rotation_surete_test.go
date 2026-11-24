// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// See LICENCE-CMSD-1.0.md for terms.

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/CyberMind-FR/secubox-deb/secubox-toolbox-ng/internal/reseau"
)

// Sûreté du détecteur de rotation (#3919, relecture de la tâche 9) : jamais un vrai visiteur ni un client légitime. Un test par constat (C1-C3, I1-I8).
// Adresses de documentation, signatures fictives, horloge injectée.

func surete(t *testing.T, mode string) (*Rotation, *banFactice, time.Time) {
	b := &banFactice{}
	return NewRotation(cfgEssai(t, mode), b, &classesFactices{defaut: reseau.ClasseProxyLoue}), b, time.Now()
}

// temoin : une adresse neuve et muette est bien bannie (le détecteur vit, le test ne passe pas à vide).
func temoin(t *testing.T, r *Rotation, b *banFactice, i int, tt time.Time) {
	t.Helper()
	page(r, adressePublique(i), tt)
	avancer(r, tt, tt.Add(11*time.Second))
	if !b.banni(adressePublique(i)) {
		t.Fatalf("témoin : une adresse neuve et muette doit être bannie")
	}
}

// ── C1 : mémoire des navigateurs ─────────────────────────────────────────────────────────────────────────────────────

func TestC1VisiteurRevenuAvecRessourcesEnCache(t *testing.T) {
	r, b, t0 := surete(t, "auto")
	x := adressePublique(0)
	voir(r, x, uaFictif, t0)
	ressource(r, x, uaFictif, t0.Add(time.Second)) // avant l'établissement
	etablir(r, 1, 60, t0.Add(time.Minute))
	page(r, x, t0.Add(2*time.Minute)) // favori, tout en cache, aucun cookie
	avancer(r, t0.Add(2*time.Minute), t0.Add(3*time.Minute))
	if b.banni(x) {
		t.Fatalf("visiteur revenu avec ses ressources en cache : jamais banni")
	}
	temoin(t, r, b, 200, t0.Add(4*time.Minute))
}

func TestC1PreuveIndependanteDeLaSignature(t *testing.T) {
	r, b, t0 := surete(t, "auto")
	x, y, v6 := adressePublique(101), adressePublique(102), "2001:db8:77:1::aaaa"
	r.NoterPreuve(x, t0)                                                                      // requête non suivie (hôte de confiance, autre navigateur…)
	r.Observe(RotationRequete{IP: y, UA: "git/2.45.0", Hote: "autre.test", Preuve: true}, t0) // autre client, autre hôte
	r.NoterPreuve(v6, t0)
	etablir(r, 0, 50, t0)
	for _, ip := range []string{x, y, "2001:db8:77:1::bbbb"} { // adresse temporaire IPv6 du même /64
		page(r, ip, t0.Add(6*24*time.Hour-time.Minute))
	}
	if n := r.nbAttente(); n != 0 {
		t.Fatalf("une preuve de moins de 7 jours dispense de verdict, %d en attente", n)
	}
	if b.banni(x) || b.banni(y) {
		t.Fatal("banni malgré une preuve")
	}
}

func TestC1MemoireExpire(t *testing.T) {
	m := nouvelleMemoire(10, rotationMemoireTTL)
	m.noter(1, 1000)
	ttl := int64(rotationMemoireTTL / time.Second)
	if !m.contient(1, 1000+ttl-1) || m.contient(1, 1000+ttl) || m.contient(2, 1000) {
		t.Fatal("7 jours, pas plus, pas moins")
	}
}

func TestC1SourcesDEtablissementJamaisJugees(t *testing.T) {
	r, b, t0 := surete(t, "auto")
	etablir(r, 0, 50, t0)
	for i := 0; i < 50; i++ {
		page(r, adressePublique(i), t0.Add(time.Minute))
	}
	avancer(r, t0.Add(time.Minute), t0.Add(2*time.Minute))
	if len(b.liste()) != 0 {
		t.Fatalf("les sources qui ont établi la campagne ne sont pas jugées : %v", b.liste())
	}
	// Plus tard, sorties de la fenêtre, pendant que la campagne continue.
	for i := 200; i < 260; i++ {
		voir(r, adressePublique(i), uaFictif, t0.Add(90*time.Minute))
	}
	avancer(r, t0.Add(90*time.Minute), t0.Add(91*time.Minute))
	page(r, adressePublique(0), t0.Add(92*time.Minute))
	avancer(r, t0.Add(92*time.Minute), t0.Add(93*time.Minute))
	if b.banni(adressePublique(0)) {
		t.Fatal("source d'établissement jugée après sa sortie de la fenêtre")
	}
	temoin(t, r, b, 300, t0.Add(94*time.Minute))
}

func TestC1RedemarragePuisVisiteurRevenu(t *testing.T) {
	cfg := cfgEssai(t, "auto")
	b := &banFactice{}
	cl := &classesFactices{defaut: reseau.ClasseProxyLoue}
	t0 := time.Now()
	r := NewRotation(cfg, b, cl)
	etablir(r, 0, 50, t0)
	x := adressePublique(100)
	page(r, x, t0.Add(2*time.Second))
	ressource(r, x, uaFictif, t0.Add(3*time.Second))
	avancer(r, t0.Add(5*time.Second), t0.Add(3*time.Minute)) // la mémoire est écrite par le ticker
	f, err := os.Stat(filepath.Join(filepath.Dir(cfg.Etat), "rotation-navigateurs.bin"))
	if err != nil || f.Mode().Perm() != 0o640 {
		t.Fatalf("mémoire écrite en 0640 à côté de l'état : %v %v", f, err)
	}
	brut, _ := os.ReadFile(filepath.Join(filepath.Dir(cfg.Etat), "rotation-navigateurs.bin"))
	a16 := netip.MustParseAddr(x).As4()
	if strings.Contains(string(brut), x) || strings.Contains(string(brut), string(a16[:])) {
		t.Fatal("l'adresse n'est jamais écrite, seulement un condensé salé")
	}
	t1 := t0.Add(4 * time.Minute)
	cfg.Horloge = func() time.Time { return t1 }
	r2 := NewRotation(cfg, b, cl)
	if len(r2.campagnesActives()) != 1 {
		t.Fatal("campagne relue attendue")
	}
	page(r2, x, t1.Add(time.Minute))                  // visiteur revenu
	page(r2, adressePublique(0), t1.Add(time.Minute)) // source d'établissement
	avancer(r2, t1.Add(time.Minute), t1.Add(2*time.Minute))
	if len(b.liste()) != 0 {
		t.Fatalf("après redémarrage, visiteur connu et source d'établissement ne sont pas bannis : %v", b.liste())
	}
	temoin(t, r2, b, 101, t1.Add(3*time.Minute))
}

func TestC1GraceApresDemarrage(t *testing.T) {
	cfg := cfgEssai(t, "propose")
	cfg.Grace = 0 // défaut : 10 min
	t0 := time.Now().Truncate(time.Second)
	cfg.Horloge = func() time.Time { return t0 }
	b := &banFactice{}
	r := NewRotation(cfg, b, &classesFactices{defaut: reseau.ClasseProxyLoue})
	etablir(r, 0, 50, t0)
	page(r, adressePublique(100), t0.Add(9*time.Minute))
	avancer(r, t0.Add(9*time.Minute), t0.Add(9*time.Minute+30*time.Second))
	if c := r.campagnesActives(); len(c) != 1 || c[0].ABannir != 0 || !lireEtatRotation(t, cfg.Etat).EnGrace {
		t.Fatalf("pendant la grâce : campagne établie, rien de jugé : %+v", c)
	}
	avancer(r, t0.Add(9*time.Minute+30*time.Second), t0.Add(11*time.Minute))
	page(r, adressePublique(101), t0.Add(11*time.Minute))
	avancer(r, t0.Add(11*time.Minute), t0.Add(12*time.Minute))
	if c := r.campagnesActives(); c[0].ABannir != 1 || lireEtatRotation(t, cfg.Etat).EnGrace {
		t.Fatalf("après la grâce, le verdict tombe : %+v", c)
	}
	// En auto, sans mémoire à reprendre (première mise en service, fichier perdu) : 24 h.
	cfg2 := cfgEssai(t, "auto")
	cfg2.Grace, cfg2.Horloge = 0, cfg.Horloge
	if g := NewRotation(cfg2, b, nil).graceFin.Sub(t0); g != 24*time.Hour {
		t.Fatalf("auto sans mémoire : 24 h de grâce, %s", g)
	}
	// Mémoire continue depuis plus de 24 h (48 h en propose) : 10 min. Jeune, ou trouée (service arrêté 2 h) : le reste des 24 h, redémarrages compris.
	graceA := func(d time.Duration) time.Duration {
		c := cfg
		c.Mode, c.Horloge = "auto", func() time.Time { return t0.Add(d) }
		return NewRotation(c, b, nil).graceFin.Sub(t0)
	}
	r.EcrireMemoire(t0.Add(time.Hour))
	if g := graceA(time.Hour); g != 24*time.Hour {
		t.Fatalf("mémoire jeune d'une heure : le reste des 24 h, %s", g)
	}
	r.EcrireMemoire(t0.Add(48 * time.Hour))
	if g := graceA(48*time.Hour + time.Minute); g != 48*time.Hour+11*time.Minute {
		t.Fatalf("mémoire continue depuis 48 h : 10 min, %s", g)
	}
	if g := graceA(50*time.Hour + time.Minute); g != 74*time.Hour+time.Minute {
		t.Fatalf("mémoire trouée de deux heures : 24 h, %s", g)
	}
}

func TestC1MemoireSatureeNeBannitPlus(t *testing.T) {
	cfg := cfgEssai(t, "auto")
	b := &banFactice{}
	cl := &classesFactices{defaut: reseau.ClasseProxyLoue}
	t0 := time.Now()
	r := NewRotation(cfg, b, cl)
	r.memoire = nouvelleMemoire(20, rotationMemoireTTL)
	for i := 1000; i < 1021; i++ { // 21 navigateurs pour 20 places : un vrai visiteur vient d'être oublié
		r.NoterPreuve(adressePublique(i), t0)
	}
	if r.memoire.nb() != 20 {
		t.Fatalf("mémoire bornée à 20, %d", r.memoire.nb())
	}
	etablir(r, 0, 50, t0)
	page(r, adressePublique(100), t0.Add(2*time.Second))
	avancer(r, t0.Add(2*time.Second), t0.Add(3*time.Minute))
	if len(b.liste()) != 0 || !lireEtatRotation(t, cfg.Etat).MemoireSaturee {
		t.Fatalf("mémoire saturée : aucun ban, et l'état le dit : %v", b.liste())
	}
	// La saturation survit au redémarrage et cesse quand l'entrée oubliée aurait expiré.
	cfg.Horloge = func() time.Time { return t0.Add(time.Minute) }
	r2 := NewRotation(cfg, b, cl)
	if !r2.memoire.saturee(t0.Add(time.Hour).Unix()) || r2.memoire.saturee(t0.Add(rotationMemoireTTL+time.Second).Unix()) {
		t.Fatal("saturation reprise jusqu'à l'échéance de l'entrée oubliée")
	}
	// Remplacer une entrée déjà expirée n'est pas une saturation.
	m := nouvelleMemoire(1, time.Hour)
	m.noter(1, 1000)
	m.noter(2, 1000+3601)
	if m.saturee(1000 + 3601) {
		t.Fatal("une entrée expirée remplacée n'est pas une perte")
	}
}

func TestC1FichierMemoireCorrompu(t *testing.T) {
	ch := filepath.Join(t.TempDir(), "m.bin")
	t0 := time.Now()
	m, e := nouvelleMemoire(100, rotationMemoireTTL), nouvelleMemoire(100, rotationMemoireTTL)
	for i := uint64(0); i < 50; i++ {
		m.noter(i, t0.Unix()+int64(i))
	}
	sel := nouveauSel()
	if err := ecrireMemoires(ch, sel, 42, t0, m, e); err != nil {
		t.Fatal(err)
	}
	lu, le := nouvelleMemoire(100, rotationMemoireTTL), nouvelleMemoire(100, rotationMemoireTTL)
	if s2, dep, ecrit, err := lireMemoires(ch, t0, lu, le); err != nil || s2 != sel || dep != 42 || ecrit != t0.Unix() || lu.nb() != 50 || !lu.contient(49, t0.Unix()) {
		t.Fatalf("relecture : %v, %d entrées", err, lu.nb())
	}
	bon, _ := os.ReadFile(ch)
	for nom, b := range map[string][]byte{"tronqué": bon[:len(bon)-5], "vide": {}, "altéré": append(append([]byte{}, bon[:60]...), append([]byte{bon[60] ^ 1}, bon[61:]...)...)} {
		_ = os.WriteFile(ch, b, 0o640)
		x, y := nouvelleMemoire(100, rotationMemoireTTL), nouvelleMemoire(100, rotationMemoireTTL)
		if _, _, _, err := lireMemoires(ch, t0, x, y); err == nil || x.nb() != 0 {
			t.Errorf("fichier %s : refusé, rien de repris (%v, %d)", nom, err, x.nb())
		}
	}
}

// ── C2 : clients légitimes ───────────────────────────────────────────────────────────────────────────────────────────

func TestC2ClientsNonNavigateursJamaisSuivis(t *testing.T) {
	for _, ua := range []string{"git/2.45.0", "Debian APT-HTTP/1.3 (2.9.8)", "MoniteurFictif/1.0", "FluxFictif/2.0 (+https://exemple.test)", "curl/8.5.0",
		"okhttp/4.12.0", "Go-http-client/2.0", "Mozilla/5.0 (compatible; RobotFictif/1.0; +https://exemple.test) Chrome/120.0",
		"Mozilla/5.0 (Linux) MoteurFictif/1.0 Chrome/120.0 Safari/537.36 (ExempleBot/2.1)", "Mozilla/5.0 SPIDERfictif Chrome/1.0", "Mozilla/5.0 Crawler Firefox/1.0",
		"Mozilla/5.0 (Linux) mirall/3.13", "Mozilla/5.0 MoteurFictif Chrome/120.0 (contact https://exemple.test)", "Mozilla/5.0 Chrome/1.0" + strings.Repeat("x", 2000)} {
		r, b, t0 := surete(t, "auto")
		for i := 0; i < 60; i++ {
			voir(r, adressePublique(i), ua, t0)
		}
		r.Tick(t0.Add(time.Second))
		for i := 100; i < 110; i++ {
			r.Servie(r.Observe(nav(adressePublique(i), ua), t0.Add(2*time.Second)), t0.Add(2*time.Second))
		}
		avancer(r, t0.Add(2*time.Second), t0.Add(30*time.Second))
		if r.nbSignatures() != 0 || len(r.campagnesActives()) != 0 || len(b.liste()) != 0 {
			t.Errorf("%.60q : suivi ou banni", ua)
		}
	}
	for _, ua := range []string{uaFictif, uaVariante(3), "Mozilla/5.0 (Macintosh) Version/17 Safari/605.1.15", "Mozilla/5.0 Edg/120.0"} {
		if !navigateurInteractif(ua) {
			t.Errorf("%q se dit navigateur interactif", ua)
		}
	}
}

func TestC2SeulesLesNavigations(t *testing.T) {
	h := func(kv ...string) http.Header {
		x := http.Header{}
		for i := 0; i < len(kv); i += 2 {
			x.Set(kv[i], kv[i+1])
		}
		return x
	}
	oui := []string{"/", "/utilisateur/depot", "/utilisateur/depot/src/commit/abc/fichier.go", "/status", "/health"}
	non := []string{"/.well-known/acme-challenge/jeton", "/u/d.git/info/refs", "/u/d.git/git-upload-pack", "/u/d.git/git-receive-pack",
		"/u/d.git/info/lfs/objects/batch", "/robots.txt", "/static/app.css", "/img/a.WEBP"}
	for _, p := range oui {
		if !estNavigation("GET", p, h()) || !estNavigation("GET", p, h("Sec-Fetch-Dest", "document")) {
			t.Errorf("%s est une navigation", p)
		}
	}
	for _, p := range non {
		if estNavigation("GET", p, h()) {
			t.Errorf("%s n'est pas une navigation", p)
		}
	}
	for _, m := range []string{"POST", "HEAD", "OPTIONS", "PROPFIND"} {
		if estNavigation(m, "/", h()) {
			t.Errorf("%s n'est pas une navigation", m)
		}
	}
	for _, x := range []http.Header{h("Sec-Fetch-Dest", "iframe"), h("Sec-Fetch-Dest", "empty"), h("Sec-Purpose", "prefetch"), h("Purpose", "prefetch"),
		h("X-Moz", "prefetch"), h("Connection", "Upgrade", "Upgrade", "websocket")} {
		if estNavigation("GET", "/", x) {
			t.Errorf("%v : pas une navigation (préchargement, cadre, websocket…)", x)
		}
	}
	// Une requête qui n'est pas une navigation n'est ni comptée ni jugée.
	r, _, t0 := surete(t, "auto")
	for i := 0; i < 80; i++ {
		q := nav(adressePublique(i), uaFictif)
		q.Navigation = false
		r.Observe(q, t0)
	}
	if r.nbSignatures() != 0 {
		t.Fatal("suivi d'une requête qui n'est pas une navigation")
	}
}

// ── C3 : durée et sanctions ──────────────────────────────────────────────────────────────────────────────────────────

func TestC3JamaisProlonge(t *testing.T) {
	for _, cat := range []string{"rotation:0011aabb", "rotation:0011aabb|prolonge"} {
		if d := Reevaluer(cat, 5000, true, 3, 24*time.Hour, 10); d.Action != "RELEASE" || d.Duree != 0 {
			t.Errorf("%s : toujours RELEASE : %+v", cat, d)
		}
	}
	if d := Reevaluer("campagne:abc", 5000, true, 0, 4*time.Hour, 10); d.Action != "EXTEND" {
		t.Errorf("les autres catégories ne changent pas : %+v", d)
	}
}

func TestC3PasUneSanctionLocale(t *testing.T) {
	st := NewBanStore(filepath.Join(t.TempDir(), "bans.jsonl"))
	for _, c := range []string{"rotation:0011aabb", "rotation:0011aabb|prolonge", "actor:ACT-1", "scanners"} {
		_ = st.Append(BanRecord{IP: "203.0.113.5", Category: c, At: 100, Action: "ban"})
	}
	if n := (&ActorBan{store: st}).sanctions(0)["203.0.113.5"]; n != 1 {
		t.Fatalf("seul « scanners » est une sanction locale : %d", n)
	}
}

func TestC3LigneDeRotationPasUneSonde(t *testing.T) {
	p := construireProfils(strings.NewReader(`{"client_ip":"203.0.113.5","category":"rotation:0011aabb","action":"detect","path":""}
{"client_ip":"203.0.113.6","category":"scanners","action":"detect","path":"/.env","negative_space":"high_value_probe"}
`))
	if p["203.0.113.5"] != nil || p["203.0.113.6"] == nil {
		t.Fatalf("un verdict de rotation ne nourrit pas le ban de campagne : %v", p)
	}
}

// ── I2 : preuves ─────────────────────────────────────────────────────────────────────────────────────────────────────

func TestI2Preuves(t *testing.T) {
	for _, p := range []string{"/a.css", "/a.js", "/a.mjs", "/a.webp", "/a.avif", "/m.webmanifest", "/f.woff2", "/f.otf", "/v.mp4", "/s.mp3", "/favicon.ico", "/A.PNG"} {
		if !ressourceDePage(p) || !preuveNavigateur(p, http.Header{}) {
			t.Errorf("%s est une ressource de page", p)
		}
	}
	for _, p := range []string{"/health", "/api/health", "/status", "/u/status/x", "/system_health", "/a.html", "/x.jsp", "/sans", "/v1.2", "/a.json"} {
		if preuveNavigateur(p, http.Header{}) {
			t.Errorf("%s n'est pas une preuve", p)
		}
	}
	for _, kv := range [][2]string{{"Cookie", "s=1"}, {"Referer", "https://exemple.test/"}, {"Authorization", "Basic eA=="}, {"If-None-Match", `"x"`},
		{"If-Modified-Since", "Mon, 23 Nov 2026 10:00:00 GMT"}, {"Sec-Fetch-Dest", "image"}, {"Sec-Fetch-Dest", "empty"}, {"Sec-Fetch-Site", "same-origin"}} {
		x := http.Header{}
		x.Set(kv[0], kv[1])
		if !preuveNavigateur("/", x) {
			t.Errorf("%v est une preuve", kv)
		}
	}
	for _, kv := range [][2]string{{"Sec-Fetch-Dest", "document"}, {"Sec-Fetch-Site", "none"}, {"Accept", "*/*"}, {"Cookie", ""}} {
		x := http.Header{}
		x.Set(kv[0], kv[1])
		if preuveNavigateur("/", x) {
			t.Errorf("%v n'est pas une preuve", kv)
		}
	}
}

func TestI2PageAvecRessource(t *testing.T) {
	h := "forge.exemple.test"
	for _, s := range []string{`<link rel="stylesheet" href="/a.css">`, `<LINK REL=stylesheet HREF=a.css>`, `<img src='x.png'>`,
		`<link href="https://forge.exemple.test/a.css" rel="stylesheet" media="all">`, `<link rel="stylesheet" href="//Forge.Exemple.test:443/a.css">`,
		`<base href="/app/"><img src="x.png">`, `<script>var a="</b>"</script><img src=/x.png>`} {
		if !pageAvecRessource([]byte("<html><head>"+s), h) {
			t.Errorf("%s : ressource locale attendue", s)
		}
	}
	for _, s := range []string{``, `<p>texte</p>`, `<script src="/a.js"></script>`, `<link rel="icon" href="/f.ico">`, `<img src="data:image/png;base64,xx">`,
		`<img loading="lazy" src="/x.png">`, `<img src="https://ailleurs.test/x.png">`, `<link rel="stylesheet" href="https://cdn.test/a.css">`,
		`<link rel="stylesheet" media="print" href="/a.css">`, `<!-- <img src="/x.png"> -->`, `<noscript><img src="/x.png"></noscript>`,
		`<script>document.write('<img src="/x.png">')</script>`, `<base href="https://cdn.test/"><img src="x.png">`, `<template><img src="/x.png"></template>`} {
		if pageAvecRessource([]byte("<html><head>"+s), h) {
			t.Errorf("%s : aucun navigateur n'y chargerait de ressource de cet hôte", s)
		}
	}
}

// ── I3 : travail et file bornés ──────────────────────────────────────────────────────────────────────────────────────

func TestI3FileEtDecisionsBornees(t *testing.T) {
	r, b, t0 := surete(t, "auto")
	etablir(r, 0, 50, t0)
	tx := t0.Add(2 * time.Second)
	for i := 1000; i < 6000; i++ {
		page(r, adressePublique(i), tx)
	}
	if n := r.nbAttente(); n != 3000 {
		t.Fatalf("3 000 verdicts en attente au plus, %d", n)
	}
	r.Tick(tx.Add(11 * time.Second))
	if n := len(b.liste()); n != rotationMaxDecisions {
		t.Fatalf("%d verdicts par Tick au plus, %d", rotationMaxDecisions, n)
	}
	for s := 13; s < 120; s += 2 {
		r.Tick(tx.Add(time.Duration(s) * time.Second))
	}
	if n := len(b.liste()); n > 1500 || n < 1400 {
		t.Fatalf("plafond horaire tenu, %d", n)
	}
	if r.nbAttente() != 0 || len(r.enAttente) != 0 {
		t.Fatal("file vidée : le surplus est abandonné, jamais banni")
	}
}

func TestI3VerdictPerimeAbandonne(t *testing.T) {
	r, b, t0 := surete(t, "auto")
	etablir(r, 0, 50, t0)
	tx := t0.Add(2 * time.Second)
	for i := 1000; i < 1300; i++ {
		page(r, adressePublique(i), tx)
	}
	for s := 2; s < 12; s += 2 {
		r.Tick(tx.Add(time.Duration(s-2) * time.Second))
	}
	for _, s := range []int{11, 60, 110} { // Tick lents (moins d'une minute d'écart) : le reliquat dépasse une minute de retard
		r.Tick(tx.Add(time.Duration(s) * time.Second))
	}
	if n := len(b.liste()); n != 200 {
		t.Fatalf("100 + 100 bans, le reliquat échu depuis plus d'une minute est abandonné : %d", n)
	}
	if c := r.campagnesActives(); c[0].Ecartees != 100 {
		t.Fatalf("100 écartées : %+v", c)
	}
}

func TestI3PlafondAvantLeDNS(t *testing.T) {
	for _, mode := range []string{"auto", "propose"} {
		cfg := cfgEssai(t, mode)
		cfg.MaxParHeure = 3
		r := NewRotation(cfg, &banFactice{}, &classesFactices{defaut: reseau.ClasseProxyLoue})
		var dns atomic.Int32
		r.SetRobots(func(string) (string, bool) { dns.Add(1); return "", true })
		t0 := time.Now()
		etablir(r, 0, 50, t0)
		dns.Store(0)
		for i := 100; i < 150; i++ {
			page(r, adressePublique(i), t0.Add(2*time.Second))
		}
		avancer(r, t0.Add(2*time.Second), t0.Add(40*time.Second))
		c := r.campagnesActives()[0]
		if dns.Load() != 3 || c.Bannies+c.ABannir != 3 || c.Ecartees != 47 {
			t.Errorf("%s : 3 recherches DNS, pas une de plus (%d) : %+v", mode, dns.Load(), c)
		}
	}
}

func TestI3DNSLentNeBloquePasLeTick(t *testing.T) {
	r, b, t0 := surete(t, "auto")
	etablir(r, 0, 50, t0)
	r.SetRobots(func(string) (string, bool) {
		time.Sleep(rotationTempsDecisions + 100*time.Millisecond)
		return "", false
	})
	for i := 100; i < 140; i++ {
		page(r, adressePublique(i), t0.Add(2*time.Second))
	}
	r.tempsDecisions = 100 * time.Millisecond
	r.Tick(t0.Add(13 * time.Second))
	if len(b.liste()) != 0 || r.nbAttente() != 39 {
		t.Fatalf("un Tick s'arrête au bout de son temps, le reste attend : %d en attente", r.nbAttente())
	}
}

// ── I4 : robots à trois états ────────────────────────────────────────────────────────────────────────────────────────

func TestI4PanneDNSNeBannitPas(t *testing.T) {
	r, b, t0 := surete(t, "auto")
	c := NewCrawlers()
	c.inverse = func(string) ([]string, error) { return nil, errors.New("résolveur en panne") }
	r.SetRobots(c.VerifieSur)
	etablir(r, 0, 50, t0)
	page(r, adressePublique(100), t0.Add(2*time.Second))
	avancer(r, t0.Add(2*time.Second), t0.Add(30*time.Second))
	if len(b.liste()) != 0 {
		t.Fatal("DNS en panne : on ne bannit pas")
	}
	c.inverse = func(string) ([]string, error) { return nil, &net.DNSError{Err: "no such host", IsNotFound: true} }
	temoin(t, r, b, 101, t0.Add(40*time.Second))
}

func TestI4VerifieSur(t *testing.T) {
	const ip = "203.0.113.50"
	nx := &net.DNSError{Err: "no such host", IsNotFound: true}
	panne := &net.DNSError{Err: "i/o timeout", IsTimeout: true}
	cas := []struct {
		nom          string
		inv          []string
		errInv, errD error
		dir          []string
		attendu      string
		sur          bool
	}{
		{"robot vérifié", []string{"a.googlebot.com."}, nil, nil, []string{ip}, "googlebot.com", true},
		{"usurpé", []string{"a.googlebot.com."}, nil, nil, []string{"198.51.100.1"}, "", true},
		{"pas d'inverse", nil, nx, nil, nil, "", true},
		{"inverse en panne", nil, panne, nil, nil, "", false},
		{"direct en panne", []string{"a.googlebot.com."}, nil, panne, nil, "", false},
		{"direct absent", []string{"a.googlebot.com."}, nil, nx, nil, "", true},
		{"autre nom", []string{"hote.exemple.test."}, nil, panne, nil, "", true},
	}
	for _, x := range cas {
		c := NewCrawlers()
		c.inverse = func(string) ([]string, error) { return x.inv, x.errInv }
		c.direct = func(string) ([]string, error) { return x.dir, x.errD }
		if n, sur := c.VerifieSur(ip); n != x.attendu || sur != x.sur {
			t.Errorf("%s : %q %t", x.nom, n, sur)
		}
		// Verifie inchangé : le doute n'y vaut pas exemption, et il est mémorisé ; VerifieSur ne se fie pas à cette mémoire.
		if n := c.Verifie(ip); n != x.attendu || !c.Resolu(ip) {
			t.Errorf("%s : Verifie %q", x.nom, n)
		}
		if _, sur := c.VerifieSur(ip); sur != x.sur {
			t.Errorf("%s : après Verifie, sur=%t", x.nom, sur)
		}
	}
	if _, sur := NewCrawlers().VerifieSur("pas-une-adresse"); sur {
		t.Error("adresse invalide : on ne sait pas")
	}
}

func TestI4RobotsVerifiesNEtablissentPasDeCampagne(t *testing.T) {
	r, _, t0 := surete(t, "auto")
	r.SetRobots(func(string) (string, bool) { return "googlebot.com", true })
	etablir(r, 0, 80, t0)
	if len(r.campagnesActives()) != 0 {
		t.Fatal("des robots vérifiés ne font pas une campagne")
	}
}

// ── I5 : hôte ────────────────────────────────────────────────────────────────────────────────────────────────────────

func TestI5Hote(t *testing.T) {
	r, _, t0 := surete(t, "auto")
	for _, h := range []string{"forge.exemple.test", "Forge.EXEMPLE.Test", "forge.exemple.test:443", "forge.exemple.test.", " forge.exemple.test.:8443"} {
		q := nav("203.0.113.9", uaFictif)
		q.Hote = h
		r.Observe(q, t0)
	}
	if n := r.nbSignatures(); n != 1 {
		t.Fatalf("un hôte, une signature : %d", n)
	}
	for _, h := range []string{"", ".", strings.Repeat("a", 254)} {
		q := nav("203.0.113.9", uaFictif)
		q.Hote = h
		r.Observe(q, t0)
	}
	if n := r.nbSignatures(); n != 1 {
		t.Fatalf("hôte vide ou trop long : non suivi, %d signatures", n)
	}
	q := nav("203.0.113.9", uaFictif)
	q.JA4 = strings.Repeat("x", 200)
	if r.Observe(q, t0); r.nbSignatures() != 1 {
		t.Fatal("empreinte démesurée : non suivie")
	}
}

// ── I6 : plafond de sources ──────────────────────────────────────────────────────────────────────────────────────────

func TestI6PlafondDeSourcesNAveuglePas(t *testing.T) {
	cl := &classesFactices{defaut: reseau.ClasseProxyLoue}
	r := NewRotation(cfgEssai(t, "auto"), &banFactice{}, cl)
	r.maxSourcesSig = 60
	t0 := time.Now()
	for i := 0; i < 60; i++ {
		cl.poser(adressePublique(i), reseau.ClasseAcces)
		voir(r, adressePublique(i), uaFictif, t0)
	}
	vue := false
	for i := 0; i < 500; i++ {
		tt := t0.Add(time.Duration(i) * 29 * time.Second)
		voir(r, adressePublique(1000+i), uaFictif, tt)
		r.Tick(tt)
		vue = vue || len(r.campagnesActives()) == 1
		if n := r.nbSources(); n > 60 {
			t.Fatalf("plafond dépassé : %d", n)
		}
	}
	if !vue {
		t.Fatal("inondation d'une heure puis campagne : jamais vue")
	}
	// Même chose au plafond total.
	r2 := NewRotation(cfgEssai(t, "auto"), &banFactice{}, cl)
	r2.maxSourcesTotal = 60
	for i := 0; i < 60; i++ {
		voir(r2, adressePublique(i), uaFictif, t0)
	}
	voir(r2, adressePublique(2000), uaFictif, t0.Add(2*time.Hour))
	r2.Tick(t0.Add(2 * time.Hour))
	if n := r2.nbSources(); n != 0 {
		t.Fatalf("plafond total : les sources sorties de la fenêtre sont purgées, %d", n)
	}
}

// ── I7 : IPv6 ────────────────────────────────────────────────────────────────────────────────────────────────────────

func TestI7SourcesIPv6ParPrefixe64(t *testing.T) {
	r, b, t0 := surete(t, "auto")
	for i := 0; i < 80; i++ {
		voir(r, fmt.Sprintf("2001:db8:1:2::%x", i+1), uaFictif, t0)
	}
	r.Tick(t0.Add(time.Second))
	if len(r.campagnesActives()) != 0 || r.nbSources() != 1 {
		t.Fatalf("un seul /64 est UNE source : %d", r.nbSources())
	}
	for i := 0; i < 60; i++ { // 60 /64 distincts
		voir(r, adressePublique(600+i), uaFictif, t0.Add(20*time.Second))
	}
	r.Tick(t0.Add(21 * time.Second))
	if len(r.campagnesActives()) != 1 {
		t.Fatal("60 /64 distincts : campagne")
	}
	page(r, "2001:db8:9:9::1", t0.Add(30*time.Second))
	avancer(r, t0.Add(30*time.Second), t0.Add(50*time.Second))
	if a := b.liste(); len(a) != 1 || a[0].ip != "2001:db8:9:9::1" {
		t.Fatalf("le ban reste par adresse : %v", a)
	}
}

// ── I8 : fin de campagne ─────────────────────────────────────────────────────────────────────────────────────────────

func TestI8NavigateursNEntretiennentPas(t *testing.T) {
	r, _, t0 := surete(t, "auto")
	etablir(r, 0, 50, t0)
	dernier := r.campagnesActives()[0].Dernier
	for i := 100; i < 110; i++ { // peu de vrais navigateurs : les parts tiennent encore
		q := nav(adressePublique(i), uaFictif)
		q.Preuve = true
		r.Observe(q, t0.Add(time.Minute))
	}
	r.Tick(t0.Add(time.Minute))
	if c := r.campagnesActives(); len(c) != 1 || c[0].Dernier != dernier || c[0].Epargnees != 10 {
		t.Fatalf("des navigateurs n'entretiennent pas la campagne : %+v", c)
	}
	// Une source déjà connue qui revient n'est pas une NOUVELLE source.
	voir(r, adressePublique(0), uaFictif, t0.Add(90*time.Second))
	if c := r.campagnesActives(); c[0].Dernier != dernier {
		t.Fatalf("une source connue n'entretient pas la campagne : %+v", c)
	}
	// Ils deviennent majoritaires : les parts ne tiennent plus, la campagne finit.
	for i := 110; i < 200; i++ {
		q := nav(adressePublique(i), uaFictif)
		q.Preuve = true
		r.Observe(q, t0.Add(2*time.Minute))
	}
	r.Tick(t0.Add(2 * time.Minute))
	if c := r.campagnesActives(); len(c) != 0 {
		t.Fatalf("signature partagée avec de vrais visiteurs : campagne finie, %+v", c)
	}
}

func TestI8CampagneFinitQuandLaFenetreSeVide(t *testing.T) {
	r, b, t0 := surete(t, "auto")
	etablir(r, 0, 50, t0)
	// L'attaque s'arrête ; trois heures plus tard, un visiteur isolé porte la même signature (navigateur courant) : pas de verdict pour lui.
	tv := t0.Add(3 * time.Hour)
	page(r, adressePublique(100), tv)
	avancer(r, tv.Add(time.Second), tv.Add(30*time.Second))
	if len(b.liste()) != 0 || len(r.campagnesActives()) != 0 {
		t.Fatalf("fenêtre vidée : campagne finie, personne de banni : %v", b.liste())
	}
}

// ── Mineurs ──────────────────────────────────────────────────────────────────────────────────────────────────────────

func TestMineurEtatDuFuturRefuse(t *testing.T) {
	for _, dec := range []rotationEtat{
		{GenereLe: time.Now().Add(48 * time.Hour).Unix()},
		{GenereLe: time.Now().Unix(), Campagnes: []rotationCampagneEtat{{Signature: Signature("a", "", "b"), EtablieLe: time.Now().Unix(), Dernier: time.Now().Add(time.Hour).Unix()}}},
		{GenereLe: time.Now().Unix(), Campagnes: []rotationCampagneEtat{{Signature: Signature("a", "", "b"), EtablieLe: time.Now().Add(time.Hour).Unix(), Dernier: time.Now().Unix()}}},
	} {
		cfg := cfgEssai(t, "auto")
		if len(dec.Campagnes) == 0 {
			dec.Campagnes = []rotationCampagneEtat{{Signature: Signature("a", "", "b"), EtablieLe: time.Now().Unix(), Dernier: time.Now().Unix()}}
		}
		j, _ := json.Marshal(dec)
		_ = os.WriteFile(cfg.Etat, j, 0o640)
		if c := NewRotation(cfg, &banFactice{}, nil).campagnesActives(); len(c) != 0 {
			t.Errorf("date du futur acceptée : %+v", c)
		}
	}
}

func TestMineurTrouDeTickAbandonneLesVerdicts(t *testing.T) {
	for _, saut := range []time.Duration{62 * time.Second, 10 * time.Minute, -time.Minute} {
		r, b, t0 := surete(t, "auto")
		etablir(r, 0, 50, t0)
		page(r, adressePublique(100), t0.Add(2*time.Second))
		r.Tick(t0.Add(4 * time.Second))
		r.Tick(t0.Add(4*time.Second + saut))
		avancer(r, t0.Add(4*time.Second+saut), t0.Add(30*time.Second+saut))
		if len(b.liste()) != 0 {
			t.Errorf("saut de %s : verdict en attente abandonné attendu", saut)
		}
	}
}

func TestMineurMobilePartageJamaisBanni(t *testing.T) {
	r, b, t0 := surete(t, "auto")
	r.annu.(*classesFactices).poser(adressePublique(100), reseau.ClasseMobilePartage)
	etablir(r, 0, 50, t0)
	page(r, adressePublique(100), t0.Add(2*time.Second))
	temoin(t, r, b, 101, t0.Add(2*time.Second))
	if b.banni(adressePublique(100)) {
		t.Fatal("adresse partagée (satellite, CGNAT) : jamais bannie")
	}
}

func TestJournalDesVerdicts(t *testing.T) {
	for mode, action := range map[string]string{"auto": "banned", "propose": "detect"} {
		r, _, t0 := surete(t, mode)
		var lignes []ThreatRecord
		r.SetJournal(func(x ThreatRecord) { lignes = append(lignes, x) })
		etablir(r, 0, 50, t0)
		x := adressePublique(100)
		page(r, x, t0.Add(2*time.Second))
		page(r, adressePublique(101), t0.Add(2*time.Second))
		ressource(r, adressePublique(101), uaFictif, t0.Add(3*time.Second)) // épargnée : aucune ligne
		if len(lignes) != 0 {
			t.Fatal("rien n'est écrit depuis la requête")
		}
		avancer(r, t0.Add(4*time.Second), t0.Add(30*time.Second))
		if len(lignes) != 1 {
			t.Fatalf("%s : une ligne par verdict robot : %+v", mode, lignes)
		}
		l := lignes[0]
		if l.ClientIP != x || l.Category != catAttendue() || l.Severity != "high" || l.Action != action || l.RuleID != "rotation" || l.Host != hoteFictif || !l.HorsActeur {
			t.Fatalf("%s : ligne inattendue : %+v", mode, l)
		}
	}
}
