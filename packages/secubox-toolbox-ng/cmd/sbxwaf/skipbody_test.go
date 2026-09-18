// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>

// Corps non inspecte par hote (#1027).
//
// Le defaut d'origine : un depot d'archive de 210 Mio etait refuse en 403
// parce qu'une regle LFI filait sur les octets COMPRESSES du zip. Dans un
// mebioctet de donnees compressees, une sequence ressemblant a `../` finit par
// apparaitre par hasard.
package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// serveurSansCorps : comme newDetectTestServer, plus la liste d'hotes dont le
// corps n'est pas inspecte.
func serveurSansCorps(t *testing.T, backendURL, rulesPath, hotes string) *Server {
	t.Helper()
	s := newDetectTestServer(t, backendURL, rulesPath)
	s.skipBodyHosts = parseTrustedHosts(hotes)
	s.maxBodyInspect = 1 << 20
	return s
}

// requetePOST : un envoi depuis une adresse PUBLIQUE — sans quoi privateCIDR
// sauterait l'inspection et le test ne prouverait rien.
func requetePOST(hote, chemin, corps, ip string) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "http://"+hote+chemin,
		strings.NewReader(corps))
	req.Host = hote
	req.RemoteAddr = ip + ":12345"
	return req
}

const reglesLFI = `{"lfi":{"name":"LFI","severity":"critical","mode":"block",
	"patterns":[{"id":"lfi-1","pattern":"../../../etc/passwd","desc":"traversee"}]}}`

// LE DEFAUT REPRODUIT : un corps binaire portant par hasard le motif est
// bloque, alors que la requete est legitime.
func TestCorpsBinaireBloqueSansLaListe(t *testing.T) {
	rules := writeRulesFile(t, reglesLFI)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("l'amont ne doit pas etre atteint : le WAF bloque")
	}))
	defer backend.Close()

	s := serveurSansCorps(t, backend.URL, rules, "") // liste VIDE
	rec := httptest.NewRecorder()
	s.handler().ServeHTTP(rec, requetePOST("depot.example.com",
		"/api/v1/droplet/depot", "PK\x03\x04....../../../etc/passwd....", "203.0.113.90"))

	if rec.Code != http.StatusForbidden {
		t.Fatalf("sans la liste, le corps doit rester inspecte : got %d, want 403", rec.Code)
	}
}

// LA CORRECTION : le meme envoi passe quand l'hote est declare.
func TestCorpsNonInspectePourLHoteDeclare(t *testing.T) {
	rules := writeRulesFile(t, reglesLFI)
	atteint := false
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atteint = true
		// LE CORPS ARRIVE ENTIER. Sauter l'inspection ne doit rien consommer :
		// si le WAF avalait les octets, le depot recevrait un fichier tronque
		// — une corruption silencieuse, pire que le refus qu'on corrige.
		b, _ := io.ReadAll(r.Body)
		if !strings.Contains(string(b), "/etc/passwd") {
			t.Errorf("le corps est arrive ampute : %q", string(b))
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	s := serveurSansCorps(t, backend.URL, rules, "depot.example.com")
	rec := httptest.NewRecorder()
	s.handler().ServeHTTP(rec, requetePOST("depot.example.com",
		"/api/v1/droplet/depot", "PK\x03\x04....../../../etc/passwd....", "203.0.113.91"))

	if rec.Code == http.StatusForbidden {
		t.Fatalf("l'hote declare ne doit plus etre bloque sur son corps")
	}
	if !atteint {
		t.Fatal("l'amont n'a pas ete atteint")
	}
}

// CE QUI NE DOIT PAS ETRE SAUTE : le chemin reste inspecte, regles bloquantes
// comprises. Sauter le corps est une renonciation ETROITE — si elle emportait
// l'URL, ce serait un contournement du WAF, pas un ajustement.
func TestLeCheminResteInspecteMalgreLaListe(t *testing.T) {
	rules := writeRulesFile(t, reglesLFI)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("une attaque dans l'URL doit rester bloquee")
	}))
	defer backend.Close()

	s := serveurSansCorps(t, backend.URL, rules, "depot.example.com")
	rec := httptest.NewRecorder()
	s.handler().ServeHTTP(rec, requetePOST("depot.example.com",
		"/api/v1/droplet/depot?f=../../../etc/passwd", "corps anodin", "203.0.113.92"))

	if rec.Code != http.StatusForbidden {
		t.Fatalf("le chemin et la requete doivent rester inspectes : got %d, want 403", rec.Code)
	}
}

// UN AUTRE HOTE N'HERITE DE RIEN. La renonciation est nominative.
func TestUnAutreHoteResteInspecte(t *testing.T) {
	rules := writeRulesFile(t, reglesLFI)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("un hote non declare doit rester inspecte")
	}))
	defer backend.Close()

	s := serveurSansCorps(t, backend.URL, rules, "depot.example.com")
	rec := httptest.NewRecorder()
	s.handler().ServeHTTP(rec, requetePOST("autre.example.com",
		"/rien", "PK\x03\x04../../../etc/passwd", "203.0.113.93"))

	if rec.Code != http.StatusForbidden {
		t.Fatalf("hote non declare : got %d, want 403", rec.Code)
	}
}

// La correspondance d'hote suit celle des hotes de confiance : casse ignoree,
// port toleré. Deux comparateurs differents finiraient par diverger.
func TestCorrespondanceDHote(t *testing.T) {
	m := parseTrustedHosts("Depot.Example.COM, autre.fr")
	for _, h := range []string{"depot.example.com", "DEPOT.EXAMPLE.COM",
		"depot.example.com:9080", "autre.fr"} {
		if !hostDans(m, h) {
			t.Errorf("hostDans(%q) = false, veut true", h)
		}
	}
	for _, h := range []string{"", "ailleurs.fr", "depot.example.com.evil.fr"} {
		if hostDans(m, h) {
			t.Errorf("hostDans(%q) = true, veut false", h)
		}
	}
}

// Une liste vide ne saute rien — le defaut est l'inspection.
func TestListeVideNeSauteRien(t *testing.T) {
	s := &Server{skipBodyHosts: parseTrustedHosts("")}
	if s.isSkipBodyHost("depot.example.com") {
		t.Error("liste vide : aucun hote ne doit etre saute")
	}
	_ = time.Second
}
