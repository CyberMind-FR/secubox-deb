// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package relais

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// moduleFactice : un module FastAPI vu de sa socket /run/secubox/<m>.sock (un serveur HTTP sur socket Unix).
type moduleFactice struct {
	mu      sync.Mutex
	recues  []*http.Request
	corps   [][]byte
	reponse func(w http.ResponseWriter, r *http.Request)
	serveur *http.Server
}

func (m *moduleFactice) appels() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.recues)
}

func (m *moduleFactice) derniere(t *testing.T) (*http.Request, []byte) {
	t.Helper()
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.recues) == 0 {
		t.Fatal("le module n'a reçu aucun appel")
	}
	return m.recues[len(m.recues)-1], m.corps[len(m.corps)-1]
}

func demarrerModule(t *testing.T, dossier, nom string) *moduleFactice {
	t.Helper()
	m := &moduleFactice{}
	ln, err := net.Listen("unix", filepath.Join(dossier, nom+".sock"))
	if err != nil {
		t.Fatal(err)
	}
	m.serveur = &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		m.mu.Lock()
		m.recues = append(m.recues, r)
		m.corps = append(m.corps, b)
		rep := m.reponse
		m.mu.Unlock()
		if rep != nil {
			rep(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Set-Cookie", "sbx_token=fuite")
		_, _ = w.Write([]byte(`{"ok":true}`))
	})}
	go func() { _ = m.serveur.Serve(ln) }()
	t.Cleanup(func() { _ = m.serveur.Close() })
	return m
}

type banc struct {
	r       *Relais
	dossier string
	socket  string
	cle     ed25519.PrivateKey
}

// court : les sockets Unix sont bornées à 108 octets ; t.TempDir() peut être long.
func court(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp("", "rel")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(d) })
	return d
}

func nouveauBanc(t *testing.T, uid uint32) *banc {
	t.Helper()
	d := court(t)
	_, cle, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(d, "etc-secubox-pilotage"), 0o755); err != nil {
		t.Fatal(err)
	}
	r := &Relais{
		Cle:               cle,
		UIDAgent:          uid,
		DossierSockets:    d,
		DossierMainsLiees: filepath.Join(d, "etc-secubox-pilotage"),
		UIDRoot:           uid0Test,
		CheminAudit:       filepath.Join(d, "audit.log"),
		NomBox:            func() string { return "gk5" },
		Delai:             DelaiDefaut,
	}
	// audit.log existe (compte secubox en production) : le relais n'y fait qu'ajouter, jamais créer.
	if err := os.WriteFile(r.CheminAudit, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(d, "pilotage-relais.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	ctx, fin := context.WithCancel(context.Background())
	go func() { _ = r.Servir(ctx, ln) }()
	t.Cleanup(func() { fin(); ln.Close() })
	return &banc{r: r, dossier: d, socket: sock, cle: cle}
}

func uidCourant() uint32 { return uint32(os.Getuid()) }

// uid0Test : en test, le « root » attendu du drapeau des mains liées est le compte qui lance les tests.
var uid0Test = uint32(os.Getuid())

// appeler envoie une demande au relais et rend la réponse brute (vide si le relais a fermé sans répondre).
func (b *banc) appelerBrut(t *testing.T, demande any) []byte {
	t.Helper()
	c, err := net.Dial("unix", b.socket)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(20 * time.Second))
	var donnees []byte
	if s, ok := demande.(string); ok {
		donnees = []byte(s)
	} else if donnees, err = json.Marshal(demande); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write(donnees); err != nil && !strings.Contains(err.Error(), "broken pipe") &&
		!strings.Contains(err.Error(), "reset by peer") {
		t.Fatal(err)
	}
	brut, _ := io.ReadAll(c)
	return brut
}

func (b *banc) appeler(t *testing.T, demande any) Reponse {
	t.Helper()
	brut := b.appelerBrut(t, demande)
	var rep Reponse
	if err := json.Unmarshal(brut, &rep); err != nil {
		t.Fatalf("réponse illisible %q : %v", brut, err)
	}
	return rep
}

func demande(methode, chemin string) map[string]any {
	return map[string]any{"methode": methode, "chemin": chemin, "entetes": map[string]string{},
		"corps_b64": "", "acteur": "gerald", "maitre": "gk2", "portee": "admin", "version_page": "1.2.3"}
}

func decouper(t *testing.T, jeton string) (entete, charge map[string]any, brutEntete []byte) {
	t.Helper()
	parts := strings.Split(jeton, ".")
	if len(parts) != 3 {
		t.Fatalf("jeton %q : %d parties", jeton, len(parts))
	}
	e, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatal(err)
	}
	p, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(e, &entete); err != nil {
		t.Fatal(err)
	}
	dec := json.NewDecoder(bytes.NewReader(p))
	dec.UseNumber()
	if err := dec.Decode(&charge); err != nil {
		t.Fatal(err)
	}
	return entete, charge, e
}

func jetonRecu(t *testing.T, r *http.Request) string {
	t.Helper()
	a := r.Header.Get("Authorization")
	if !strings.HasPrefix(a, "Bearer ") {
		t.Fatalf("Authorization = %q", a)
	}
	return strings.TrimPrefix(a, "Bearer ")
}

func TestRelaisFrappeUnJetonCourt(t *testing.T) {
	b := nouveauBanc(t, uidCourant())
	m := demarrerModule(t, b.dossier, "demo")
	rep := b.appeler(t, demande("GET", "/api/v1/demo/status?vue=1"))
	if rep.Statut != 200 {
		t.Fatalf("statut %d", rep.Statut)
	}
	corps, _ := base64.StdEncoding.DecodeString(rep.CorpsB64)
	if string(corps) != `{"ok":true}` {
		t.Fatalf("corps %q", corps)
	}
	r, _ := m.derniere(t)
	// Comme nginx (`proxy_pass …:/`) et l'agrégateur : le préfixe /api/v1/<module> est retiré, la requête gardée.
	if r.URL.Path != "/status" || r.URL.RawQuery != "vue=1" {
		t.Fatalf("chemin transmis %q ? %q", r.URL.Path, r.URL.RawQuery)
	}
	if r.Host != "localhost" {
		t.Fatalf("Host %q", r.Host)
	}
	if strings.TrimSpace(r.Header.Get("X-SecuBox-Pilotage-Relais")) == "" {
		t.Fatal("en-tête du relais absent")
	}
	jeton := jetonRecu(t, r)
	entete, charge, brutEntete := decouper(t, jeton)
	if string(brutEntete) != `{"alg":"EdDSA","typ":"JWT"}` {
		t.Fatalf("en-tête du jeton %s", brutEntete)
	}
	_ = entete
	parts := strings.Split(jeton, ".")
	sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
	if !ed25519.Verify(b.cle.Public().(ed25519.PublicKey), []byte(parts[0]+"."+parts[1]), sig) {
		t.Fatal("signature Ed25519 invalide")
	}
	cles := map[string]bool{}
	for k := range charge {
		cles[k] = true
	}
	for _, k := range []string{"sub", "aud", "iat", "exp", "cible", "pilotage"} {
		if !cles[k] {
			t.Fatalf("réclamation %q absente", k)
		}
		delete(cles, k)
	}
	if len(cles) != 0 {
		t.Fatalf("réclamations en trop : %v", cles)
	}
	iat, _ := charge["iat"].(json.Number).Int64()
	exp, _ := charge["exp"].(json.Number).Int64()
	if exp-iat != 30 || iat > time.Now().Unix()+1 || iat < time.Now().Unix()-5 {
		t.Fatalf("iat %d exp %d", iat, exp)
	}
	if charge["aud"] != "gk5" || charge["sub"] != "pilotage:gerald@gk2" || charge["cible"] != "demo" {
		t.Fatalf("charge %v", charge)
	}
	p, _ := charge["pilotage"].(map[string]any)
	if len(p) != 3 || p["acteur"] != "gerald" || p["maitre"] != "gk2" || p["portee"] != "admin" {
		t.Fatalf("réclamation pilotage %v", p)
	}
	// Jamais un cookie du module vers le maître.
	for k := range rep.Entetes {
		if strings.EqualFold(k, "Set-Cookie") {
			t.Fatal("Set-Cookie relayé")
		}
	}
	if rep.Entetes["Content-Type"] != "application/json" {
		t.Fatalf("en-têtes de réponse %v", rep.Entetes)
	}
}

func TestRelaisRefuseUnAutreUid(t *testing.T) {
	b := nouveauBanc(t, uidCourant()+1)
	m := demarrerModule(t, b.dossier, "demo")
	brut := b.appelerBrut(t, demande("GET", "/api/v1/demo/status"))
	if len(brut) != 0 {
		t.Fatalf("le relais a répondu à un autre compte : %q", brut)
	}
	if m.appels() != 0 {
		t.Fatal("module appelé pour un autre compte")
	}
	// Le refus est audité : connexion d'un compte qui n'est pas celui de l'agent.
	audit, err := os.ReadFile(b.r.CheminAudit)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(audit), `"motif":"compte du pair refuse"`) {
		t.Fatalf("audit : %s", audit)
	}
}

func TestRelaisRefuseUnModuleInconnu(t *testing.T) {
	b := nouveauBanc(t, uidCourant())
	m := demarrerModule(t, b.dossier, "demo")
	if rep := b.appeler(t, demande("GET", "/api/v1/absent/status")); rep.Statut != 404 {
		t.Fatalf("module sans socket : statut %d", rep.Statut)
	}
	// Un fichier ordinaire au nom de socket n'est pas une socket.
	if err := os.WriteFile(filepath.Join(b.dossier, "faux.sock"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if rep := b.appeler(t, demande("GET", "/api/v1/faux/status")); rep.Statut != 404 {
		t.Fatalf("faux.sock régulier : statut %d", rep.Statut)
	}
	// Modules qui ne reconnaissent jamais le porteur délégué : refusés avant tout appel, même avec une socket.
	for _, nom := range []string{"auth", "vault", "pilotage", "pilotage-relais", "pilotage-x", "aggregator"} {
		if nom != "pilotage-relais" { // celle-là existe déjà : c'est la socket du relais lui-même
			demarrerModule(t, b.dossier, nom)
		}
		if rep := b.appeler(t, demande("GET", "/api/v1/"+nom+"/status")); rep.Statut != 403 {
			t.Fatalf("module exclu %s : statut %d", nom, rep.Statut)
		}
	}
	if m.appels() != 0 {
		t.Fatal("module appelé")
	}
}

func TestRelaisBorneLeCorps(t *testing.T) {
	b := nouveauBanc(t, uidCourant())
	m := demarrerModule(t, b.dossier, "demo")
	d := demande("POST", "/api/v1/demo/regler")
	d["corps_b64"] = base64.StdEncoding.EncodeToString(make([]byte, CorpsMax+1))
	if rep := b.appeler(t, d); rep.Statut != 413 {
		t.Fatalf("corps de demande trop gros : statut %d", rep.Statut)
	}
	if m.appels() != 0 {
		t.Fatal("module appelé avec un corps trop gros")
	}
	// Exactement 8 Mio passe.
	d["corps_b64"] = base64.StdEncoding.EncodeToString(make([]byte, CorpsMax))
	if rep := b.appeler(t, d); rep.Statut != 200 {
		t.Fatalf("8 Mio : statut %d", rep.Statut)
	}
	if _, corps := m.derniere(t); len(corps) != CorpsMax {
		t.Fatalf("corps transmis : %d octets", len(corps))
	}
	// Réponse du module trop grosse : 413, rien de relayé.
	m.mu.Lock()
	m.reponse = func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(make([]byte, CorpsMax+1)) }
	m.mu.Unlock()
	rep := b.appeler(t, demande("GET", "/api/v1/demo/gros"))
	if rep.Statut != 413 {
		t.Fatalf("réponse trop grosse : statut %d", rep.Statut)
	}
	if c, _ := base64.StdEncoding.DecodeString(rep.CorpsB64); len(c) > 1024 {
		t.Fatalf("corps relayé : %d octets", len(c))
	}
	// Une demande JSON trop longue (avant même le décodage) : 413.
	enorme := `{"methode":"POST","chemin":"/api/v1/demo/x","corps_b64":"` + strings.Repeat("A", tailleDemandeMax) + `"}`
	if rep := b.appeler(t, enorme); rep.Statut != 413 {
		t.Fatalf("demande JSON trop longue : statut %d", rep.Statut)
	}
}

func TestRelaisMainsLieesEnCours(t *testing.T) {
	b := nouveauBanc(t, uidCourant())
	m := demarrerModule(t, b.dossier, "demo")
	for _, methode := range []string{"POST", "PUT", "PATCH", "DELETE"} {
		d := demande(methode, "/api/v1/demo/regler")
		d["portee"] = "lecture"
		if rep := b.appeler(t, d); rep.Statut != 423 {
			t.Fatalf("portée lecture, %s : statut %d", methode, rep.Statut)
		}
	}
	if m.appels() != 0 {
		t.Fatal("module appelé en portée lecture pour une écriture")
	}
	d := demande("GET", "/api/v1/demo/status")
	d["portee"] = "lecture"
	if rep := b.appeler(t, d); rep.Statut != 200 {
		t.Fatalf("lecture en portée lecture : statut %d", rep.Statut)
	}
	r, _ := m.derniere(t)
	if _, charge, _ := decouper(t, jetonRecu(t, r)); charge["pilotage"].(map[string]any)["portee"] != "lecture" {
		t.Fatalf("portée frappée %v", charge["pilotage"])
	}
	// Drapeau des mains liées posé sur la box : même une portée admin est ramenée à la lecture.
	if err := os.WriteFile(filepath.Join(b.r.DossierMainsLiees, "mains-liees"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if rep := b.appeler(t, demande("POST", "/api/v1/demo/regler")); rep.Statut != 423 {
		t.Fatalf("mains liées, portée admin, POST : statut %d", rep.Statut)
	}
	if rep := b.appeler(t, demande("GET", "/api/v1/demo/status")); rep.Statut != 200 {
		t.Fatalf("mains liées, GET : statut %d", rep.Statut)
	}
	r, _ = m.derniere(t)
	if _, charge, _ := decouper(t, jetonRecu(t, r)); charge["pilotage"].(map[string]any)["portee"] != "lecture" {
		t.Fatalf("mains liées : portée frappée %v", charge["pilotage"])
	}
	if m.appels() != 2 {
		t.Fatalf("%d appels", m.appels())
	}
	// Chaque refus est audité (sans jeton ni corps).
	audit, err := os.ReadFile(b.r.CheminAudit)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(audit), `"motif":"mains liees`) || strings.Contains(string(audit), "Bearer") {
		t.Fatalf("audit : %s", audit)
	}
}

func TestRelaisNormaliseLActeur(t *testing.T) {
	b := nouveauBanc(t, uidCourant())
	m := demarrerModule(t, b.dossier, "demo")
	d := demande("GET", "/api/v1/demo/status")
	d["acteur"] = "Gerald.K"
	d["maitre"] = "GK2"
	if rep := b.appeler(t, d); rep.Statut != 200 {
		t.Fatalf("statut %d", rep.Statut)
	}
	r, _ := m.derniere(t)
	_, charge, _ := decouper(t, jetonRecu(t, r))
	if charge["sub"] != "pilotage:gerald.k@gk2" {
		t.Fatalf("sub %v", charge["sub"])
	}
	p := charge["pilotage"].(map[string]any)
	if p["acteur"] != "gerald.k" || p["maitre"] != "gk2" {
		t.Fatalf("pilotage %v", p)
	}
}

func TestRelaisRefuseUnActeurInvalide(t *testing.T) {
	b := nouveauBanc(t, uidCourant())
	m := demarrerModule(t, b.dossier, "demo")
	for _, cas := range []struct{ acteur, maitre, portee string }{
		{"gé rald", "gk2", "admin"}, {"", "gk2", "admin"}, {strings.Repeat("a", 65), "gk2", "admin"},
		{"gerald@x", "gk2", "admin"}, {"gerald", "gk2.lan", "admin"}, {"gerald", "", "admin"},
		{"gerald", strings.Repeat("g", 64), "admin"}, {"gerald", "gk_2", "admin"}, {"gerald", "gk2", "root"},
		{"gerald", "gk2", ""}, {"ge\nrald", "gk2", "admin"}, {"Kelvin", "gk2", "admin"},
	} {
		d := demande("GET", "/api/v1/demo/status")
		d["acteur"], d["maitre"], d["portee"] = cas.acteur, cas.maitre, cas.portee
		if rep := b.appeler(t, d); rep.Statut != 400 {
			t.Fatalf("%+v : statut %d", cas, rep.Statut)
		}
	}
	if m.appels() != 0 {
		t.Fatal("module appelé pour un acteur invalide")
	}
}

func TestRelaisEffaceLesEntetesInterdits(t *testing.T) {
	b := nouveauBanc(t, uidCourant())
	m := demarrerModule(t, b.dossier, "demo")
	d := demande("POST", "/api/v1/demo/regler")
	d["corps_b64"] = base64.StdEncoding.EncodeToString([]byte(`{"a":1}`))
	d["entetes"] = map[string]string{
		"Authorization": "Bearer jeton-du-maitre", "Cookie": "sbx_token=vole", "X-SecuBox-LAN": "1",
		"X-SecuBox-Pilotage-Relais": "falsifie", "x-secubox-maillage": "1", "X-Forwarded-For": "1.2.3.4",
		"X-Real-IP": "1.2.3.4", "Host": "evil", "Content-Type": "application/json", "Accept": "application/json",
		"If-None-Match": `"v1"`, "if-modified-since": "Mon, 01 Jan 2026 00:00:00 GMT", "Transfer-Encoding": "chunked",
	}
	if rep := b.appeler(t, d); rep.Statut != 200 {
		t.Fatalf("statut %d", rep.Statut)
	}
	r, corps := m.derniere(t)
	if string(corps) != `{"a":1}` {
		t.Fatalf("corps %q", corps)
	}
	permis := map[string]bool{"Authorization": true, "Content-Type": true, "Accept": true, "If-None-Match": true,
		"If-Modified-Since": true, "X-Secubox-Pilotage-Relais": true, "Content-Length": true,
		"Accept-Encoding": true, "User-Agent": true, "Connection": true}
	for k := range r.Header {
		if !permis[k] {
			t.Fatalf("en-tête %q transmis au module", k)
		}
	}
	if r.Header.Get("Cookie") != "" || r.Host != "localhost" {
		t.Fatal("Cookie ou Host transmis")
	}
	if r.Header.Get("X-SecuBox-Pilotage-Relais") == "falsifie" || len(r.Header.Values("X-SecuBox-Pilotage-Relais")) != 1 {
		t.Fatalf("en-tête du relais falsifiable : %v", r.Header.Values("X-SecuBox-Pilotage-Relais"))
	}
	if strings.Contains(r.Header.Get("Authorization"), "jeton-du-maitre") || len(r.Header.Values("Authorization")) != 1 {
		t.Fatal("Authorization du maître transmis")
	}
	if r.Header.Get("If-None-Match") != `"v1"` || r.Header.Get("Content-Type") != "application/json" {
		t.Fatalf("en-têtes permis perdus : %v", r.Header)
	}
}

func TestRelaisRefuseUnCheminHorsAPI(t *testing.T) {
	b := nouveauBanc(t, uidCourant())
	m := demarrerModule(t, b.dossier, "demo")
	demarrerModule(t, b.dossier, "auth")
	for _, chemin := range []string{
		"/etc/passwd", "/api/v1/demo", "/api/v1/demo?x=1", "api/v1/demo/status", "/api/v2/demo/status",
		"/api/v1/demo/../auth/login", "/api/v1/demo/%2e%2e/auth/login", "/api/v1/demo/%2E%2e/x",
		"/api/v1/demo/a%2fb", "/api/v1/demo/a%5cb", "/api/v1/../demo/status", "/api/v1/Demo/status",
		"/api/v1/demo/a\\b", "/api/v1/demo/a\nb", "/api/v1/demo/./status", "/api/v1/demo//status",
		"/api/v1/demo/a b", "/api/v1/demo/%00", "/api/v1/demo/x#frag", "/api/v1//demo/status",
		"/api/v1/de.mo/status", "/api/v1/demo/" + strings.Repeat("a", 5000), "//api/v1/demo/status",
		"/api/v1/demo/%zz", "/api/v1/demo/x?a=%00", "/api/v1/demo/x?%00=1", "/api/v1/demo/x?a=b%0Ac",
	} {
		if rep := b.appeler(t, demande("GET", chemin)); rep.Statut != 400 {
			t.Fatalf("chemin %q : statut %d", chemin, rep.Statut)
		}
	}
	for _, methode := range []string{"OPTIONS", "TRACE", "CONNECT", "get", "G ET", ""} {
		if rep := b.appeler(t, demande(methode, "/api/v1/demo/status")); rep.Statut != 400 {
			t.Fatalf("méthode %q : statut %d", methode, rep.Statut)
		}
	}
	if m.appels() != 0 {
		t.Fatal("module appelé")
	}
	// Un chemin simple, avec segments et requête, passe ; `/api/v1/demo/` vise la racine du module.
	if rep := b.appeler(t, demande("GET", "/api/v1/demo/a-b/c_d.json?x=1&y=%2F")); rep.Statut != 200 {
		t.Fatalf("chemin simple : statut %d", rep.Statut)
	}
	r, _ := m.derniere(t)
	if r.URL.Path != "/a-b/c_d.json" || r.URL.RawQuery != "x=1&y=%2F" {
		t.Fatalf("transmis %q ? %q", r.URL.Path, r.URL.RawQuery)
	}
	if rep := b.appeler(t, demande("HEAD", "/api/v1/demo/")); rep.Statut != 200 {
		t.Fatalf("racine du module : statut %d", rep.Statut)
	}
	if r, _ := m.derniere(t); r.URL.Path != "/" || r.Method != "HEAD" {
		t.Fatalf("racine transmise %q %s", r.URL.Path, r.Method)
	}
}

func TestRelaisRefuseUneDemandeMalFormee(t *testing.T) {
	b := nouveauBanc(t, uidCourant())
	m := demarrerModule(t, b.dossier, "demo")
	inconnu := demande("GET", "/api/v1/demo/status")
	inconnu["jeton"] = "x"
	for _, d := range []any{"pas du json", `{"methode":"GET"}{"methode":"GET"}`, inconnu,
		`{"methode":"GET","chemin":"/api/v1/demo/x","acteur":"a","maitre":"b","portee":"admin","corps_b64":"!!"}`,
		`{"methode":"GET","chemin":"/api/v1/demo/x","acteur":"a","maitre":"b","portee":"admin","entetes":{"Accept":"a\r\nX: y"}}`,
	} {
		if rep := b.appeler(t, d); rep.Statut != 400 {
			t.Fatalf("%v : statut %d", d, rep.Statut)
		}
	}
	if m.appels() != 0 {
		t.Fatal("module appelé")
	}
}

func TestRelaisDelaiDuModule(t *testing.T) {
	b := nouveauBanc(t, uidCourant())
	b.r.Delai = 200 * time.Millisecond
	m := demarrerModule(t, b.dossier, "demo")
	m.reponse = func(w http.ResponseWriter, r *http.Request) { time.Sleep(time.Second) }
	if rep := b.appeler(t, demande("GET", "/api/v1/demo/lent")); rep.Statut != 504 {
		t.Fatalf("statut %d", rep.Statut)
	}
	if DelaiDefaut != 30*time.Second {
		t.Fatalf("délai par défaut %v", DelaiDefaut)
	}
}

func TestRelaisAliasDeSocket(t *testing.T) {
	// secubox-profiles sert `waker` sur /run/secubox/waker.sock depuis /usr/lib/secubox/profiles/ :
	// module_courant (secubox_core.auth) y voit `profiles`, la cible du jeton doit l'être aussi.
	b := nouveauBanc(t, uidCourant())
	m := demarrerModule(t, b.dossier, "waker")
	if rep := b.appeler(t, demande("GET", "/api/v1/waker/status")); rep.Statut != 200 {
		t.Fatalf("statut %d", rep.Statut)
	}
	r, _ := m.derniere(t)
	if _, charge, _ := decouper(t, jetonRecu(t, r)); charge["cible"] != "profiles" {
		t.Fatalf("cible %v", charge["cible"])
	}
}

func TestRelaisSansNomDeBox(t *testing.T) {
	b := nouveauBanc(t, uidCourant())
	b.r.NomBox = func() string { return "" }
	m := demarrerModule(t, b.dossier, "demo")
	if rep := b.appeler(t, demande("GET", "/api/v1/demo/status")); rep.Statut != 503 {
		t.Fatalf("statut %d", rep.Statut)
	}
	if m.appels() != 0 {
		t.Fatal("module appelé sans nom de box")
	}
}

func TestNomDeBox(t *testing.T) {
	for entree, attendu := range map[string]string{
		"gk5": "gk5", "GK5.secubox.in": "gk5", " gk-5 ": "gk-5", "-gk": "", "gk_5": "", "": "",
		strings.Repeat("a", 64): "", strings.Repeat("a", 63): strings.Repeat("a", 63), "gk5-": "",
	} {
		if n := nomDeBox(entree); n != attendu {
			t.Fatalf("nomDeBox(%q) = %q, attendu %q", entree, n, attendu)
		}
	}
}

func TestRelaisCorpsMaxQuatreMio(t *testing.T) {
	// R-L5-19 (I2) : 4 Mio au lieu des 8 du brief — deux appels simultanés tiennent sous MemoryMax=64M.
	if CorpsMax != 4<<20 {
		t.Fatalf("CorpsMax = %d", CorpsMax)
	}
}

func TestRelaisLectureAvecCorpsRefusee(t *testing.T) {
	b := nouveauBanc(t, uidCourant())
	m := demarrerModule(t, b.dossier, "demo")
	for _, methode := range []string{"GET", "HEAD"} {
		d := demande(methode, "/api/v1/demo/status")
		d["corps_b64"] = base64.StdEncoding.EncodeToString([]byte("x"))
		if rep := b.appeler(t, d); rep.Statut != 400 {
			t.Fatalf("%s avec corps : statut %d", methode, rep.Statut)
		}
	}
	if m.appels() != 0 {
		t.Fatal("module appelé")
	}
}

func TestRelaisUidIllisibleAudite(t *testing.T) {
	b := nouveauBanc(t, uidCourant())
	a, c := net.Pipe() // pas une socket Unix : SO_PEERCRED impossible
	defer c.Close()
	b.r.traiter(a)
	audit, _ := os.ReadFile(b.r.CheminAudit)
	if !strings.Contains(string(audit), `"detail":"uid=?"`) {
		t.Fatalf("audit : %s", audit)
	}
}

// drapeau : (re)pose l'état du dossier root des mains liées pour un cas.
func TestRelaisDrapeauMainsLieesDeConfiance(t *testing.T) {
	cas := []struct {
		nom   string
		poser func(t *testing.T, dossier string, r *Relais)
		liees bool
	}{
		{"absent", func(t *testing.T, d string, r *Relais) {}, false},
		{"valide", func(t *testing.T, d string, r *Relais) {
			_ = os.WriteFile(filepath.Join(d, "mains-liees"), nil, 0o644)
		}, true},
		{"non root", func(t *testing.T, d string, r *Relais) {
			_ = os.WriteFile(filepath.Join(d, "mains-liees"), nil, 0o644)
			r.UIDRoot = uid0Test + 1
		}, true},
		{"dossier non root, drapeau absent", func(t *testing.T, d string, r *Relais) { r.UIDRoot = uid0Test + 1 }, true},
		{"lien symbolique", func(t *testing.T, d string, r *Relais) {
			cible := filepath.Join(filepath.Dir(d), "ailleurs")
			_ = os.WriteFile(cible, nil, 0o644)
			_ = os.Symlink(cible, filepath.Join(d, "mains-liees"))
		}, true},
		{"droits larges", func(t *testing.T, d string, r *Relais) {
			f := filepath.Join(d, "mains-liees")
			_ = os.WriteFile(f, nil, 0o644)
			_ = os.Chmod(f, 0o666)
		}, true},
		{"dossier inscriptible par tous", func(t *testing.T, d string, r *Relais) { _ = os.Chmod(d, 0o777) }, true},
		{"dossier absent", func(t *testing.T, d string, r *Relais) { _ = os.Remove(d) }, true},
		{"dossier lien symbolique", func(t *testing.T, d string, r *Relais) {
			vrai := d + "-vrai"
			_ = os.Mkdir(vrai, 0o755)
			_ = os.Remove(d)
			_ = os.Symlink(vrai, d)
		}, true},
		{"pas un fichier régulier", func(t *testing.T, d string, r *Relais) {
			_ = os.Mkdir(filepath.Join(d, "mains-liees"), 0o755)
		}, true},
	}
	for _, c := range cas {
		t.Run(c.nom, func(t *testing.T) {
			b := nouveauBanc(t, uidCourant())
			m := demarrerModule(t, b.dossier, "demo")
			c.poser(t, b.r.DossierMainsLiees, b.r)
			rep := b.appeler(t, demande("POST", "/api/v1/demo/regler"))
			if c.liees && rep.Statut != 423 {
				t.Fatalf("mains liées attendues : statut %d", rep.Statut)
			}
			if !c.liees && (rep.Statut != 200 || m.appels() != 1) {
				t.Fatalf("mains libres attendues : statut %d", rep.Statut)
			}
		})
	}
}

func TestRelaisConnexionsEnAttenteBornees(t *testing.T) {
	if connexionsMax != 8 {
		t.Fatalf("connexionsMax = %d", connexionsMax)
	}
	b := nouveauBanc(t, uidCourant())
	b.r.DelaiLecture = 400 * time.Millisecond
	demarrerModule(t, b.dossier, "demo")
	var oisives []net.Conn
	for i := 0; i < connexionsMax; i++ {
		c, err := net.Dial("unix", b.socket)
		if err != nil {
			t.Fatal(err)
		}
		oisives = append(oisives, c)
	}
	defer func() {
		for _, c := range oisives {
			c.Close()
		}
	}()
	time.Sleep(50 * time.Millisecond)
	debut := time.Now()
	rep := b.appeler(t, demande("GET", "/api/v1/demo/status"))
	if rep.Statut != 200 {
		t.Fatalf("statut %d", rep.Statut)
	}
	// Servie seulement quand les connexions oisives ont expiré (DelaiLecture) : la neuvième a attendu.
	if attente := time.Since(debut); attente < 300*time.Millisecond {
		t.Fatalf("neuvième connexion servie en %v : aucune borne", attente)
	}
}

// TestRelaisMemoireBornee : deux appels simultanés de taille maximale (4 Mio à l'aller ET au retour).
// Mesure : le relais tourne SEUL dans un processus enfant (ce binaire de test relancé), avec GOGC=10 pour
// que le tas alloué suive de près le tas vivant ; runtime.MemStats.HeapAlloc y est échantillonné toutes
// les 200 µs. Le client et le module factice restent dans le parent : leurs tampons ne sont pas comptés.
// Plafond 40 Mio : sous GOMEMLIMIT=48MiB / MemoryMax=64M de l'unité.
func TestRelaisMemoireBornee(t *testing.T) {
	d := court(t)
	m := demarrerModule(t, d, "demo")
	retour := make([]byte, CorpsMax)
	m.reponse = func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", strconv.Itoa(len(retour)))
		_, _ = w.Write(retour)
	}
	sock := filepath.Join(d, "pilotage-relais.sock")
	enfant := exec.Command(os.Args[0], "-test.run=^TestAideRelaisEnfant$")
	enfant.Env = append(os.Environ(), "SBX_RELAIS_ENFANT="+d, "GOGC=10")
	entree, err := enfant.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	var sortie bytes.Buffer
	enfant.Stdout = &sortie
	if err := enfant.Start(); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 500; i++ {
		if _, err := os.Stat(sock); err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	b := &banc{socket: sock}
	corps := base64.StdEncoding.EncodeToString(make([]byte, CorpsMax))
	var g sync.WaitGroup
	for i := 0; i < 2; i++ {
		g.Add(1)
		go func() {
			defer g.Done()
			dm := demande("POST", "/api/v1/demo/regler")
			dm["corps_b64"] = corps
			if rep := b.appeler(t, dm); rep.Statut != 200 || len(rep.CorpsB64) != len(corps) {
				t.Errorf("statut %d, corps %d", rep.Statut, len(rep.CorpsB64))
			}
		}()
	}
	g.Wait()
	entree.Close()
	if err := enfant.Wait(); err != nil {
		t.Fatalf("enfant : %v\n%s", err, sortie.String())
	}
	var pic uint64
	if _, err := fmt.Sscanf(sortie.String()[strings.Index(sortie.String(), "PIC=")+4:], "%d", &pic); err != nil {
		t.Fatalf("sortie de l'enfant : %q", sortie.String())
	}
	t.Logf("pic de tas du relais seul : %.1f Mio", float64(pic)/(1<<20))
	if pic > 40<<20 {
		t.Fatalf("pic de tas %.1f Mio > 40 Mio", float64(pic)/(1<<20))
	}
}

// TestAideRelaisEnfant : le relais seul, pour TestRelaisMemoireBornee (sans effet hors de ce test).
func TestAideRelaisEnfant(t *testing.T) {
	d := os.Getenv("SBX_RELAIS_ENFANT")
	if d == "" {
		t.Skip("processus enfant de TestRelaisMemoireBornee seulement")
	}
	_, cle, _ := ed25519.GenerateKey(nil)
	dossierMains := filepath.Join(d, "etc-secubox-pilotage")
	_ = os.Mkdir(dossierMains, 0o755)
	r := &Relais{Cle: cle, UIDAgent: uidCourant(), DossierSockets: d, DossierMainsLiees: dossierMains,
		UIDRoot: uid0Test, NomBox: func() string { return "gk5" }, Journal: log.New(io.Discard, "", 0)}
	ln, err := net.Listen("unix", filepath.Join(d, "pilotage-relais.sock"))
	if err != nil {
		t.Fatal(err)
	}
	ctx, fin := context.WithCancel(context.Background())
	go func() { _ = r.Servir(ctx, ln) }()
	var pic atomic.Uint64
	arret := make(chan struct{})
	go func() {
		var ms runtime.MemStats
		for {
			select {
			case <-arret:
				return
			default:
			}
			runtime.ReadMemStats(&ms)
			if ms.HeapAlloc > pic.Load() {
				pic.Store(ms.HeapAlloc)
			}
			time.Sleep(200 * time.Microsecond)
		}
	}()
	_, _ = io.Copy(io.Discard, os.Stdin) // le parent ferme l'entrée quand les appels sont finis
	close(arret)
	fin()
	fmt.Printf("PIC=%d\n", pic.Load())
}
