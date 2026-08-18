// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package main

import (
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// ── marqueur d'armement ──────────────────────────────────────────────────

func ecrisMarqueur(t *testing.T, contenu string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "armed")
	if err := os.WriteFile(p, []byte(contenu), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestSansMarqueurLaCaptureEstFermee(t *testing.T) {
	c := &captureArm{chemin: filepath.Join(t.TempDir(), "absent")}
	if c.arme("www.youtube.com") {
		t.Fatal("capture ouverte sans marqueur — le silence doit rester fermé")
	}
}

func TestUnMarqueurDansLaFenetreOuvreLaCapture(t *testing.T) {
	deadline := time.Now().Add(time.Minute).Unix()
	p := ecrisMarqueur(t, `{"deadline":`+itoa64(deadline)+`,"profil":"perso"}`)
	c := &captureArm{chemin: p}
	if !c.arme("www.youtube.com") {
		t.Fatal("un marqueur dans la fenêtre devrait ouvrir la capture")
	}
	if c.profil() != "perso" {
		t.Fatalf("profil = %q, attendu perso", c.profil())
	}
}

func TestUnMarqueurExpireResteFerme(t *testing.T) {
	p := ecrisMarqueur(t, `{"deadline":`+itoa64(time.Now().Add(-time.Minute).Unix())+`}`)
	c := &captureArm{chemin: p}
	if c.arme("www.youtube.com") {
		t.Fatal("un marqueur expiré ne doit pas ouvrir la capture")
	}
}

func TestLaListeBlancheLimiteLesHotes(t *testing.T) {
	// Si le marqueur nomme des hôtes, on ne capture QUE ceux-là : la fenêtre
	// suit ce que l'utilisateur relie, pas tout ce qu'il visite en même temps.
	deadline := itoa64(time.Now().Add(time.Minute).Unix())
	p := ecrisMarqueur(t, `{"deadline":`+deadline+`,"hotes":["youtube.com","google.com"]}`)
	c := &captureArm{chemin: p}
	if !c.arme("www.youtube.com") {
		t.Fatal("un hôte de la liste devrait être capturé")
	}
	if c.arme("www.mabanque.fr") {
		t.Fatal("un hôte hors liste ne doit jamais être capturé")
	}
}

func TestSansListeToutHoteVisiteEstCapture(t *testing.T) {
	// Liste vide = le périmètre est la navigation : tout hôte visité pendant
	// la fenêtre entre.
	deadline := itoa64(time.Now().Add(time.Minute).Unix())
	p := ecrisMarqueur(t, `{"deadline":`+deadline+`}`)
	c := &captureArm{chemin: p}
	if !c.arme("n-importe-quoi.example") {
		t.Fatal("sans liste, tout hôte visité devrait entrer")
	}
}

// ── extraction des valeurs ────────────────────────────────────────────────

func TestExtraireLesValeursDunEnteteCookie(t *testing.T) {
	req, _ := http.NewRequest("GET", "https://www.youtube.com/", nil)
	req.Header.Set("Cookie", "SID=abc123; HSID=def456; SSID=ghi")
	cs := valeursCookieEnvoye(req)
	if len(cs) != 3 {
		t.Fatalf("%d cookies, attendu 3", len(cs))
	}
	if cs[0].Name != "SID" || cs[0].Value != "abc123" {
		t.Fatalf("premier cookie mal lu : %+v", cs[0])
	}
}

func TestExtraireLesAttributsDunSetCookie(t *testing.T) {
	c := valeurSetCookie(
		"SID=xyz789; Domain=.youtube.com; Path=/; Secure; HttpOnly; Max-Age=3600")
	if c == nil {
		t.Fatal("Set-Cookie valable non lu")
	}
	if c.Name != "SID" || c.Value != "xyz789" {
		t.Fatalf("nom/valeur mal lus : %+v", c)
	}
	if c.Domain != ".youtube.com" || c.Path != "/" {
		t.Fatalf("attributs mal lus : %+v", c)
	}
	if !c.Secure || !c.HTTPOnly {
		t.Fatal("drapeaux Secure/HttpOnly perdus")
	}
	if c.Expires == 0 {
		t.Fatal("Max-Age devrait donner une échéance")
	}
}

func TestUnSetCookieSansValeurEstIgnore(t *testing.T) {
	if valeurSetCookie("; Path=/; Secure") != nil {
		t.Fatal("une ligne d'attributs seuls ne devrait pas donner de cookie")
	}
}

func TestLeDomaineParDefautEstLHote(t *testing.T) {
	// Un cookie de l'en-tête Cookie n'a pas d'attribut Domain : on lui donne
	// l'hôte, sinon le cookies.txt ne se rattacherait à rien.
	req, _ := http.NewRequest("GET", "https://www.youtube.com/", nil)
	req.Header.Set("Cookie", "PREF=ok")
	cs := capturerFlux("www.youtube.com", req, nil)
	if len(cs) != 1 || cs[0].Domain == "" {
		t.Fatalf("domaine par défaut manquant : %+v", cs)
	}
}

// ── assemblage du flux ────────────────────────────────────────────────────

func TestCapturerFluxReunitEnvoiEtReponse(t *testing.T) {
	req, _ := http.NewRequest("GET", "https://www.youtube.com/", nil)
	req.Header.Set("Cookie", "SID=envoye")
	resp := &http.Response{Header: http.Header{}}
	resp.Header.Add("Set-Cookie", "YSC=pose; Domain=.youtube.com; Path=/; HttpOnly")
	cs := capturerFlux("www.youtube.com", req, resp)
	noms := map[string]string{}
	for _, c := range cs {
		noms[c.Name] = c.Value
	}
	if noms["SID"] != "envoye" || noms["YSC"] != "pose" {
		t.Fatalf("flux incomplet : %+v", noms)
	}
}

func TestLeSetCookieEnrichitLeCookieEnvoye(t *testing.T) {
	// Le même cookie vu à l'envoi (valeur) ET posé en réponse (attributs) :
	// on garde la valeur ET les attributs, pas l'un sans l'autre.
	req, _ := http.NewRequest("GET", "https://www.youtube.com/", nil)
	req.Header.Set("Cookie", "SID=valeur-courante")
	resp := &http.Response{Header: http.Header{}}
	resp.Header.Add("Set-Cookie", "SID=valeur-courante; Domain=.youtube.com; Secure")
	cs := capturerFlux("www.youtube.com", req, resp)
	var sid *capturedCookie
	for i := range cs {
		if cs[i].Name == "SID" {
			sid = &cs[i]
		}
	}
	if sid == nil {
		t.Fatal("SID absent")
	}
	if sid.Domain != ".youtube.com" || !sid.Secure {
		t.Fatalf("attributs du Set-Cookie non repris : %+v", sid)
	}
}

func TestSansMarqueurLeConstructeurRendNil(t *testing.T) {
	// Le defaut (chemin vide) doit donner nil : emitCapture devient alors un
	// no-op total, et le proxy se comporte exactement comme sans capture.
	if newCaptureArm("") != nil {
		t.Fatal("un chemin vide devrait donner nil (capture jamais active)")
	}
	if newCaptureArm("/x/y") == nil {
		t.Fatal("un chemin non-vide devrait donner un lecteur")
	}
}

func TestEmitCaptureAvecCaptureNilNeFaitRien(t *testing.T) {
	// La garde qui protege le chemin par defaut : px.capture == nil ne doit ni
	// paniquer, ni rien emettre.
	px := &Proxy{capture: nil}
	req, _ := http.NewRequest("GET", "https://www.youtube.com/", nil)
	req.Header.Set("Cookie", "SID=x")
	px.emitCapture(req, nil) // ne doit pas paniquer
}
