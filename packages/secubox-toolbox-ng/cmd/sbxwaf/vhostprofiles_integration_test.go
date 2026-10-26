// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
//
// Phase G (#1080) — preuve d'INTÉGRATION : la suppression par vhost est bien
// câblée dans le chemin de détection (main.go, après MatchModes), pas seulement
// dans doitSupprimer. On pilote une vraie requête au travers de srv.handler().
package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// buildScannerRulesFile écrit un waf-rules.json minimal : une catégorie
// `scanners` (block) qui matche un chemin de sonde, et une `sqli` (block) qui
// matche une injection. La sonde sert à démontrer la suppression ; l'injection
// à démontrer qu'elle n'est JAMAIS supprimée.
func buildScannerRulesFile(t *testing.T) string {
	t.Helper()
	doc := map[string]any{
		"categories": map[string]any{
			"scanners": map[string]any{
				"name": "Scanners", "severity": "high", "enabled": true,
				"patterns": []any{
					map[string]any{"id": "scanG", "pattern": `/probe-path`},
				},
			},
			"sqli": map[string]any{
				"name": "SQLi", "severity": "high", "enabled": true,
				"patterns": []any{
					map[string]any{"id": "sqli1", "pattern": `union\s+select`},
				},
			},
		},
	}
	f, err := os.CreateTemp(t.TempDir(), "waf-rules*.json")
	if err != nil {
		t.Fatalf("temp rules: %v", err)
	}
	if err := json.NewEncoder(f).Encode(doc); err != nil {
		t.Fatalf("encode: %v", err)
	}
	f.Close()
	return f.Name()
}

// profilG construit des profils : le vhost "profiled.example" fait tourner un
// service dont "/probe-path" est légitime ; scanners est supprimable.
func profilG(t *testing.T) *VhostProfiles {
	t.Helper()
	vp, err := chargerVhostProfilesDepuis([]byte(`{
	  "services": { "svc": { "legit_paths": ["^/probe-path"] } },
	  "vhosts": { "profiled.example": "svc" },
	  "suppress_categories": ["scanners"]
	}`))
	if err != nil {
		t.Fatalf("profils: %v", err)
	}
	return vp
}

func serveurG(t *testing.T, backendAddr string, vp *VhostProfiles) *Server {
	t.Helper()
	return &Server{
		routeLookup: func(host string) (string, int, bool) {
			h, p, err := splitHostPort(backendAddr)
			if err != nil {
				return "", 0, false
			}
			return h, p, true
		},
		rules:         LoadRules(buildScannerRulesFile(t)),
		vhostProfiles: vp,
	}
}

func TestPhaseG_SondeLegitimeDansSonServiceEstProxifiee(t *testing.T) {
	const corps = "backend ok"
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, corps)
	}))
	defer backend.Close()

	srv := serveurG(t, backend.URL[len("http://"):], profilG(t))
	req := httptest.NewRequest(http.MethodGet, "http://profiled.example/probe-path", nil)
	req.Host = "profiled.example"
	req.RemoteAddr = "1.2.3.4:5555" // IP publique : pas de bypass de confiance
	rec := httptest.NewRecorder()
	srv.handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("chemin légitime du service : attendu 200 (supprimé+proxifié), obtenu %d", rec.Code)
	}
	if body, _ := io.ReadAll(rec.Result().Body); string(body) != corps {
		t.Fatalf("le backend n'a pas été atteint : corps=%q", string(body))
	}
}

func TestPhaseG_MemeSondeHorsServiceEstBloquee(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ne devrait pas être atteint")
	}))
	defer backend.Close()

	srv := serveurG(t, backend.URL[len("http://"):], profilG(t))
	// Host NON profilé : la même sonde doit tirer normalement (Phase F).
	req := httptest.NewRequest(http.MethodGet, "http://autre.example/probe-path", nil)
	req.Host = "autre.example"
	req.RemoteAddr = "1.2.3.4:5555"
	rec := httptest.NewRecorder()
	srv.handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("sonde hors de son service : attendu 403 (bloqué), obtenu %d", rec.Code)
	}
}

func TestPhaseG_InjectionJamaisSupprimeeMemeSurCheminLegitime(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ne devrait pas être atteint")
	}))
	defer backend.Close()

	srv := serveurG(t, backend.URL[len("http://"):], profilG(t))
	// Chemin légitime du service MAIS injection sqli en query : sqli n'est pas
	// dans suppress_categories → doit bloquer, la légitimité du chemin ne
	// protège jamais une injection.
	req := httptest.NewRequest(http.MethodGet,
		"http://profiled.example/probe-path?q=1+union+select+1,2", nil)
	req.Host = "profiled.example"
	req.RemoteAddr = "1.2.3.4:5555"
	rec := httptest.NewRecorder()
	srv.handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("injection sur chemin légitime : attendu 403 (jamais supprimée), obtenu %d", rec.Code)
	}
}

// ── #3193 : signalisation LiveKit de la Visio ──────────────────────────────
//
// Preuve de bout en bout, sur les fichiers RÉELLEMENT LIVRÉS par
// secubox-waf-ng (profils de vhost + règles) : la connexion LiveKit
// `GET /rtc/v1?access_token=<JWT>` sur livekit.gk1 n'est ni une menace ni un
// ban ; la même URL sur un autre vhost lève toujours credential_harvest.

// jetonLivekit est un jeton de 40 caractères alphanumériques : la règle réelle
// cred-003 exige `access_token=[A-Za-z0-9]{16,}`.
const jetonLivekit = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9abcd"

// fichierLivreWafNg rend le chemin d'un fichier de configuration livré par le
// paquet secubox-waf-ng (même dépôt) — pas une copie de test qui pourrait
// diverger de ce qui part sur la box.
func fichierLivreWafNg(t *testing.T, nom string) string {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	p := filepath.Join(filepath.Dir(file), "..", "..", "..",
		"secubox-waf-ng", "composants", "waf", "config", nom)
	if _, err := os.Stat(p); err != nil {
		t.Fatalf("fichier livré introuvable : %v", err)
	}
	return p
}

// serveurLivre monte le handler sur les règles et les profils LIVRÉS, avec un
// vrai compteur de ban et un vrai journal de menaces.
func serveurLivre(t *testing.T, backendAddr string) (*Server, string) {
	t.Helper()
	vp, err := chargerVhostProfiles(fichierLivreWafNg(t, "vhost_profiles.json"))
	if err != nil {
		t.Fatalf("vhost_profiles.json livré illisible : %v", err)
	}
	journal := filepath.Join(t.TempDir(), "waf-threats.log")
	return &Server{
		routeLookup: func(host string) (string, int, bool) {
			h, p, err := splitHostPort(backendAddr)
			if err != nil {
				return "", 0, false
			}
			return h, p, true
		},
		rules:         LoadRules(fichierLivreWafNg(t, "waf-rules.json")),
		vhostProfiles: vp,
		ban:           NewBan(300*time.Second, 3),
		threatLog:     NewThreatLog(journal),
	}, journal
}

func backendOK(t *testing.T) *httptest.Server {
	t.Helper()
	b := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "backend ok")
	}))
	t.Cleanup(b.Close)
	return b
}

func requeteLivekit(host, chemin, ip string, websocket bool) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "http://"+host+chemin, nil)
	req.Host = host
	req.RemoteAddr = ip + ":5555" // adresse publique : aucun contournement LAN
	req.Header.Set("User-Agent", "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 Safari/604.1")
	if websocket {
		req.Header.Set("Connection", "Upgrade")
		req.Header.Set("Upgrade", "websocket")
		req.Header.Set("Sec-WebSocket-Version", "13")
		req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
	}
	return req
}

func lireJournal(t *testing.T, chemin string) string {
	t.Helper()
	b, err := os.ReadFile(chemin)
	if err != nil {
		if os.IsNotExist(err) {
			return ""
		}
		t.Fatalf("journal : %v", err)
	}
	return string(b)
}

func TestLivekit3193_SignalisationNiMenaceNiBan(t *testing.T) {
	backend := backendOK(t)
	srv, journal := serveurLivre(t, backend.URL[len("http://"):])
	const ip = "203.0.113.193"
	cas := []struct {
		chemin    string
		websocket bool
	}{
		{"/rtc/v1?access_token=" + jetonLivekit + "&auto_subscribe=1&sdk=js&protocol=16", true},
		{"/rtc/v1/validate?access_token=" + jetonLivekit + "&auto_subscribe=1&sdk=js&protocol=16", false},
	}
	// Cinq connexions de suite : au-delà du seuil de ban (3), comme les essais
	// répétés du téléphone le 2026-10-26.
	for i := 0; i < 5; i++ {
		for _, c := range cas {
			rec := httptest.NewRecorder()
			srv.handler().ServeHTTP(rec, requeteLivekit("livekit.gk1.secubox.in", c.chemin, ip, c.websocket))
			if rec.Code != http.StatusOK {
				t.Fatalf("%s : attendu 200 (signalisation légitime), obtenu %d", c.chemin, rec.Code)
			}
		}
	}
	if n := srv.ban.Count(ip); n != 0 {
		t.Fatalf("la signalisation LiveKit ne doit rien compter au ban : %d", n)
	}
	if j := lireJournal(t, journal); j != "" {
		t.Fatalf("aucune ligne de menace attendue, journal :\n%s", j)
	}
}

func TestLivekit3193_MemeURLSurUnAutreVhostToujoursCredentialHarvest(t *testing.T) {
	backend := backendOK(t)
	srv, journal := serveurLivre(t, backend.URL[len("http://"):])
	const ip = "203.0.113.194"
	rec := httptest.NewRecorder()
	srv.handler().ServeHTTP(rec, requeteLivekit("hall.gk2.secubox.in",
		"/rtc/v1?access_token="+jetonLivekit, ip, false))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("même URL sur le hall : attendu 403, obtenu %d", rec.Code)
	}
	if n := srv.ban.Count(ip); n != 1 {
		t.Fatalf("le coup doit compter au ban : %d", n)
	}
	j := lireJournal(t, journal)
	if !strings.Contains(j, `"credential_harvest"`) || !strings.Contains(j, `"cred-003"`) {
		t.Fatalf("credential_harvest / cred-003 attendus au journal :\n%s", j)
	}
}

func TestLivekit3193_CheminHorsProfilSurLivekitToujoursCredentialHarvest(t *testing.T) {
	backend := backendOK(t)
	srv, journal := serveurLivre(t, backend.URL[len("http://"):])
	const ip = "203.0.113.195"
	rec := httptest.NewRecorder()
	srv.handler().ServeHTTP(rec, requeteLivekit("livekit.gk1.secubox.in",
		"/admin?access_token="+jetonLivekit, ip, false))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("/admin sur livekit : attendu 403, obtenu %d", rec.Code)
	}
	if j := lireJournal(t, journal); !strings.Contains(j, `"credential_harvest"`) {
		t.Fatalf("credential_harvest attendu au journal :\n%s", j)
	}
}

func TestLivekit3193_PasDeFuiteVersUnAutreService(t *testing.T) {
	backend := backendOK(t)
	srv, _ := serveurLivre(t, backend.URL[len("http://"):])
	// /api/v1/ est un chemin LÉGITIME de gitea, mais credential_harvest n'est
	// supprimable que pour livekit : la règle tire chez gitea.
	rec := httptest.NewRecorder()
	srv.handler().ServeHTTP(rec, requeteLivekit("gitea.gk2.secubox.in",
		"/api/v1/repos/x?access_token="+jetonLivekit, "203.0.113.196", false))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("credential_harvest chez gitea : attendu 403, obtenu %d", rec.Code)
	}
}

func TestLivekit3193_ProfilsLivresDeclarentLesTroisBoxes(t *testing.T) {
	vp, err := chargerVhostProfiles(fichierLivreWafNg(t, "vhost_profiles.json"))
	if err != nil {
		t.Fatalf("vhost_profiles.json livré : %v", err)
	}
	for _, h := range []string{"livekit.gk1.secubox.in", "livekit.gk2.secubox.in", "livekit.gk3.secubox.in"} {
		if !vp.doitSupprimer(h, "/rtc/v1", "credential_harvest") ||
			!vp.doitSupprimer(h, "/rtc/v1/validate", "credential_harvest") {
			t.Errorf("%s : la signalisation LiveKit doit être exemptée de credential_harvest", h)
		}
	}
	if vp.catSupprimable("credential_harvest") {
		t.Fatal("credential_harvest ne doit JAMAIS entrer dans la liste globale suppress_categories")
	}
}

// GARDE ANTI-CONTREBANDE par hôte : sur un vhost qui n'est PAS livekit, une
// requête dont le premier déclenchement est une empreinte supprimable (scanners
// sur un chemin légitime) mais qui porte AUSSI un jeton dans l'URL doit être
// rattrapée par la ré-vérification. Si celle-ci excluait les catégories de
// TOUS les services (credential_harvest de livekit compris), la requête
// passerait : l'exemption de livekit affaiblirait les autres vhosts.
func TestLivekit3193_ReverificationExclutSeulementLesCategoriesDeCetHote(t *testing.T) {
	regles := `{"categories": {
	  "scanners": {"name": "Scanners", "severity": "high", "enabled": true,
	    "patterns": [{"id": "scanG", "pattern": "/probe-path"}]},
	  "credential_harvest": {"name": "Cred", "severity": "critical", "enabled": true,
	    "patterns": [{"id": "cred-003", "pattern": "(api_?key|apikey|access_?token)=[A-Za-z0-9]{16,}"}]},
	  "sqli": {"name": "SQLi", "severity": "high", "enabled": true,
	    "patterns": [{"id": "sqli1", "pattern": "union\\s+select"}]}
	}}`
	f := filepath.Join(t.TempDir(), "waf-rules.json")
	if err := os.WriteFile(f, []byte(regles), 0o600); err != nil {
		t.Fatal(err)
	}
	vp, err := chargerVhostProfilesDepuis([]byte(`{
	  "services": {
	    "svc": {"legit_paths": ["^/probe-path"]},
	    "livekit": {"legit_paths": ["^/rtc(/v1)?(/validate)?$", "^/probe-path"],
	                "suppress_categories": ["credential_harvest"]}
	  },
	  "vhosts": {"profiled.example": "svc", "livekit.example": "livekit"},
	  "suppress_categories": ["scanners"]
	}`))
	if err != nil {
		t.Fatalf("profils : %v", err)
	}
	backend := backendOK(t)
	addr := backend.URL[len("http://"):]
	srv := &Server{
		routeLookup: func(string) (string, int, bool) {
			h, p, err := splitHostPort(addr)
			return h, p, err == nil
		},
		rules:         LoadRules(f),
		vhostProfiles: vp,
	}
	envoyer := func(host, chemin string) int {
		rec := httptest.NewRecorder()
		srv.handler().ServeHTTP(rec, requeteLivekit(host, chemin, "203.0.113.197", false))
		return rec.Code
	}
	// Vhost svc : scanners supprimé, mais le jeton reste une moisson → 403.
	if c := envoyer("profiled.example", "/probe-path?access_token="+jetonLivekit); c != http.StatusForbidden {
		t.Fatalf("svc : la ré-vérification doit rattraper credential_harvest, obtenu %d", c)
	}
	// Vhost livekit, même requête : les deux catégories sont supprimables ICI.
	if c := envoyer("livekit.example", "/probe-path?access_token="+jetonLivekit); c != http.StatusOK {
		t.Fatalf("livekit : attendu 200, obtenu %d", c)
	}
	// Vhost livekit, chemin légitime + injection : jamais supprimée.
	if c := envoyer("livekit.example", "/rtc/v1?access_token="+jetonLivekit+"&q=1+union+select+1,2"); c != http.StatusForbidden {
		t.Fatalf("livekit : une injection n'est jamais supprimée, obtenu %d", c)
	}
}
