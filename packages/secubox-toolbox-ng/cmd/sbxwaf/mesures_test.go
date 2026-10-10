// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type banFaux struct {
	mu   sync.Mutex
	pris []string
	durs []time.Duration
}

func (b *banFaux) BanFor(ip, cat, sev string, d time.Duration) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.pris = append(b.pris, ip+"|"+cat)
	b.durs = append(b.durs, d)
}

type bancMesures struct {
	m   *MesuresWAF
	ban *banFaux
	dir string
	t   time.Time
}

func ecrireMesures(t *testing.T, chemin string, genere time.Time, ms ...map[string]any) {
	t.Helper()
	b, _ := json.Marshal(map[string]any{"genere_le": genere.Unix(), "shadow": true, "mesures": ms})
	if err := os.WriteFile(chemin, b, 0o640); err != nil {
		t.Fatal(err)
	}
}

func mesureFichier(actor, ip, niveau string, expire time.Time, lan bool) map[string]any {
	return map[string]any{"actor": actor, "ips": []string{ip}, "niveau": niveau, "ttl_s": 300, "depuis": expire.Add(-5 * time.Minute).Unix(), "expire": expire.Unix(),
		"risque": 70, "confiance": 70, "capteurs": []string{"waf"}, "hostiles": 30, "lan": lan, "raison": "test"}
}

func banc(t *testing.T, mode string) *bancMesures {
	t.Helper()
	dir := t.TempDir()
	b := &bancMesures{ban: &banFaux{}, dir: dir, t: time.Unix(1_800_000_000, 0)}
	store := NewBanStore(filepath.Join(dir, "bans.jsonl"))
	m := NewMesuresWAF(filepath.Join(dir, "mesures.json"), mode, store, b.ban)
	m.now = func() time.Time { return b.t }
	m.preuves = filepath.Join(dir, "mesures.jsonl")
	m.etat = filepath.Join(dir, "mesures-etat.json")
	m.delai = 30 * time.Millisecond
	b.m = m
	return b
}

func (b *bancMesures) requete(ip, chemin, accept string) (*httptest.ResponseRecorder, bool) {
	r := httptest.NewRequest("GET", "http://exemple.org"+chemin, nil)
	r.RemoteAddr = ip + ":4444"
	if accept != "" {
		r.Header.Set("Accept", accept)
	}
	w := httptest.NewRecorder()
	traite := b.m.Intercepte(w, r)
	return w, traite
}

func TestDelayRalentitSansBloquer(t *testing.T) {
	b := banc(t, "auto")
	ecrireMesures(t, b.m.chemin, b.t, mesureFichier("ACT-1", "203.0.113.5", "DELAY", b.t.Add(5*time.Minute), false))
	b.m.Tick()
	debut := time.Now()
	_, traite := b.requete("203.0.113.5", "/page", "text/html")
	if traite || time.Since(debut) < 25*time.Millisecond {
		t.Fatalf("le délai attend puis laisse passer : traite=%v durée=%s", traite, time.Since(debut))
	}
	if _, traite := b.requete("203.0.113.99", "/page", "text/html"); traite {
		t.Fatal("une autre adresse n'est pas touchée")
	}
}

func TestChallengeSertLaPageDeDefiAuxNavigateursEtRalentitLesAPI(t *testing.T) {
	b := banc(t, "auto")
	ecrireMesures(t, b.m.chemin, b.t, mesureFichier("ACT-1", "203.0.113.5", "CHALLENGE", b.t.Add(15*time.Minute), false))
	b.m.Tick()
	w, traite := b.requete("203.0.113.5", "/admin", "text/html,application/xhtml+xml")
	if !traite || !strings.Contains(w.Body.String(), "sbx-defi") || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("page de défi : traite=%v corps=%q", traite, w.Body.String())
	}
	// une requête d'API n'est pas cassée par une page HTML : elle est seulement ralentie
	debut := time.Now()
	_, traite = b.requete("203.0.113.5", "/api/v1/x", "application/json")
	if traite || time.Since(debut) < 25*time.Millisecond {
		t.Fatalf("API : ralentie, jamais bloquée par une page HTML (%v)", traite)
	}
}

func resoudre(seed string) string {
	for n := 0; ; n++ {
		nonce := fmt.Sprint(n)
		h := sha256.Sum256([]byte(seed + nonce))
		if strings.HasPrefix(hex.EncodeToString(h[:]), "0000") {
			return nonce
		}
	}
}

func TestLaPreuveDeTravailOuvreUnLaissezPasserLieAL_adresse(t *testing.T) {
	b := banc(t, "auto")
	ecrireMesures(t, b.m.chemin, b.t, mesureFichier("ACT-1", "203.0.113.5", "CHALLENGE", b.t.Add(15*time.Minute), false))
	b.m.Tick()
	w, _ := b.requete("203.0.113.5", "/admin?x=1", "text/html")
	seed := between(w.Body.String(), `data-seed="`, `"`)
	if seed == "" {
		t.Fatalf("la page porte sa graine : %q", w.Body.String())
	}
	// mauvaise preuve : refusée
	post := func(nonce, ip, retour string) *httptest.ResponseRecorder {
		f := url.Values{"seed": {seed}, "nonce": {nonce}, "retour": {retour}}
		r := httptest.NewRequest("POST", "http://exemple.org/__sbx/defi", strings.NewReader(f.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.RemoteAddr = ip + ":1"
		rec := httptest.NewRecorder()
		if !b.m.Intercepte(rec, r) {
			t.Fatal("le point d'entrée du défi est traité par le WAF")
		}
		return rec
	}
	if rec := post("0", "203.0.113.5", "/admin?x=1"); rec.Code != http.StatusForbidden {
		t.Fatalf("une mauvaise preuve est refusée : %d", rec.Code)
	}
	rec := post(resoudre(seed), "203.0.113.5", "/admin?x=1")
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/admin?x=1" {
		t.Fatalf("bonne preuve : retour à la page demandée : %d %q", rec.Code, rec.Header().Get("Location"))
	}
	cookie := rec.Result().Cookies()[0]
	// avec le laissez-passer, la page passe
	r := httptest.NewRequest("GET", "http://exemple.org/admin", nil)
	r.RemoteAddr = "203.0.113.5:9"
	r.Header.Set("Accept", "text/html")
	r.AddCookie(cookie)
	if b.m.Intercepte(httptest.NewRecorder(), r) {
		t.Fatal("le laissez-passer ouvre la page")
	}
	// mais il est lié à l'adresse : un autre client avec le même cookie n'est pas dispensé
	r2 := httptest.NewRequest("GET", "http://exemple.org/admin", nil)
	r2.RemoteAddr = "203.0.113.77:9"
	r2.Header.Set("Accept", "text/html")
	r2.AddCookie(cookie)
	ecrireMesures(t, b.m.chemin, b.t, mesureFichier("ACT-2", "203.0.113.77", "CHALLENGE", b.t.Add(15*time.Minute), false))
	b.m.Tick()
	if !b.m.Intercepte(httptest.NewRecorder(), r2) {
		t.Fatal("un laissez-passer volé ne sert pas à une autre adresse")
	}
}

func TestLeRetourDuDefiNeSortJamaisDuSite(t *testing.T) {
	b := banc(t, "auto")
	ecrireMesures(t, b.m.chemin, b.t, mesureFichier("ACT-1", "203.0.113.5", "CHALLENGE", b.t.Add(15*time.Minute), false))
	b.m.Tick()
	w, _ := b.requete("203.0.113.5", "/", "text/html")
	seed := between(w.Body.String(), `data-seed="`, `"`)
	for _, mauvais := range []string{"https://evil.example/", "//evil.example/", "javascript:alert(1)", "http://x"} {
		f := url.Values{"seed": {seed}, "nonce": {resoudre(seed)}, "retour": {mauvais}}
		r := httptest.NewRequest("POST", "http://exemple.org/__sbx/defi", strings.NewReader(f.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.RemoteAddr = "203.0.113.5:1"
		rec := httptest.NewRecorder()
		b.m.Intercepte(rec, r)
		if loc := rec.Header().Get("Location"); loc != "/" {
			t.Fatalf("retour %q → %q : jamais de redirection ouverte", mauvais, loc)
		}
	}
}

func TestTarpitRetientLaConnexionEtRespecteLeContexte(t *testing.T) {
	b := banc(t, "auto")
	b.m.tarpitPas, b.m.tarpitMax = 10*time.Millisecond, 120*time.Millisecond
	ecrireMesures(t, b.m.chemin, b.t, mesureFichier("ACT-1", "203.0.113.5", "TARPIT", b.t.Add(30*time.Minute), false))
	b.m.Tick()
	debut := time.Now()
	w, traite := b.requete("203.0.113.5", "/wp-login.php", "")
	d := time.Since(debut)
	if !traite || d < 100*time.Millisecond || d > 2*time.Second {
		t.Fatalf("tarpit : traite=%v durée=%s", traite, d)
	}
	if w.Body.Len() < 3 {
		t.Fatalf("le corps arrive au compte-gouttes : %d octets", w.Body.Len())
	}
}

func TestLeTarpitPlafonneSesConnexionsSimultanees(t *testing.T) {
	b := banc(t, "auto")
	b.m.tarpitPas, b.m.tarpitMax = 10*time.Millisecond, 400*time.Millisecond
	b.m.tarpitSlots = make(chan struct{}, 2)
	ecrireMesures(t, b.m.chemin, b.t, mesureFichier("ACT-1", "203.0.113.5", "TARPIT", b.t.Add(30*time.Minute), false))
	b.m.Tick()
	var wg sync.WaitGroup
	var mu sync.Mutex
	retenues := 0
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			debut := time.Now()
			b.requete("203.0.113.5", "/x", "")
			if time.Since(debut) > 300*time.Millisecond {
				mu.Lock()
				retenues++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if retenues != 2 {
		t.Fatalf("au plus 2 connexions retenues, les autres retombent sur un simple délai : %d", retenues)
	}
}

func TestDenyBannitViaNftAvecDureeGraduee(t *testing.T) {
	b := banc(t, "auto")
	ecrireMesures(t, b.m.chemin, b.t, mesureFichier("ACT-7", "203.0.113.5", "DENY", b.t.Add(time.Hour), false))
	b.m.Tick()
	if len(b.ban.pris) != 1 || !strings.HasPrefix(b.ban.pris[0], "203.0.113.5|mesure:ACT-7") || b.ban.durs[0] != time.Hour {
		t.Fatalf("premier ban : 1 h : %v %v", b.ban.pris, b.ban.durs)
	}
	b.m.Tick() // même mesure, deuxième lecture : pas de second ban
	if len(b.ban.pris) != 1 {
		t.Fatalf("une mesure = un ban : %v", b.ban.pris)
	}
}

func TestLesGardeFousNeLaissentJamaisAgirSurUneAdressePrivee(t *testing.T) {
	b := banc(t, "auto")
	b.m.protegees = parseCIDRs("203.0.113.200/32")
	ecrireMesures(t, b.m.chemin, b.t,
		mesureFichier("ACT-1", "192.168.1.50", "DENY", b.t.Add(time.Hour), false),
		mesureFichier("ACT-2", "203.0.113.200", "DENY", b.t.Add(time.Hour), false),
		mesureFichier("ACT-3", "10.0.0.8", "TARPIT", b.t.Add(time.Hour), false))
	b.m.Tick()
	if len(b.ban.pris) != 0 {
		t.Fatalf("ni privée ni protégée : %v", b.ban.pris)
	}
	if _, traite := b.requete("192.168.1.50", "/x", "text/html"); traite {
		t.Fatal("aucune mesure HTTP sur le LAN")
	}
}

func TestUnRobotDIndexationVerifieN_estJamaisTouche(t *testing.T) {
	b := banc(t, "auto")
	d := &dns{inv: map[string][]string{"203.0.113.5": {"crawl.googlebot.com."}}, dir: map[string][]string{"crawl.googlebot.com": {"203.0.113.5"}}}
	c := NewCrawlers()
	d.install(c)
	b.m.robots = c
	ecrireMesures(t, b.m.chemin, b.t, mesureFichier("ACT-1", "203.0.113.5", "DENY", b.t.Add(time.Hour), false), mesureFichier("ACT-2", "203.0.113.5", "TARPIT", b.t.Add(time.Hour), false))
	b.m.Tick()
	if len(b.ban.pris) != 0 {
		t.Fatalf("on ne bannit pas Googlebot : %v", b.ban.pris)
	}
	if _, traite := b.requete("203.0.113.5", "/x", ""); traite {
		t.Fatal("ni de tarpit")
	}
}

func TestLePlafondHoraireDeBansTient(t *testing.T) {
	b := banc(t, "auto")
	b.m.maxBansHeure = 2
	var ms []map[string]any
	for i := 0; i < 5; i++ {
		ms = append(ms, mesureFichier(fmt.Sprintf("ACT-%d", i), fmt.Sprintf("203.0.113.%d", 10+i), "DENY", b.t.Add(time.Hour), false))
	}
	ecrireMesures(t, b.m.chemin, b.t, ms...)
	b.m.Tick()
	if len(b.ban.pris) != 2 {
		t.Fatalf("plafond de 2 bans par heure : %d", len(b.ban.pris))
	}
}

func TestLeModeProposeNAppliqueRienMaisConsigne(t *testing.T) {
	b := banc(t, "propose")
	ecrireMesures(t, b.m.chemin, b.t, mesureFichier("ACT-1", "203.0.113.5", "TARPIT", b.t.Add(time.Hour), false), mesureFichier("ACT-2", "203.0.113.6", "DENY", b.t.Add(time.Hour), false))
	b.m.Tick()
	if len(b.ban.pris) != 0 {
		t.Fatal("propose ne bannit pas")
	}
	if _, traite := b.requete("203.0.113.5", "/x", "text/html"); traite {
		t.Fatal("propose ne retient rien")
	}
	lignes := lignesFichier(t, b.m.preuves)
	if len(lignes) != 2 || lignes[0]["applique"] != false {
		t.Fatalf("les mesures sont consignées avec applique=false : %v", lignes)
	}
}

func TestUnFichierPerimeOuAbsentNeLaisseAucuneMesure(t *testing.T) {
	b := banc(t, "auto")
	ecrireMesures(t, b.m.chemin, b.t, mesureFichier("ACT-1", "203.0.113.5", "TARPIT", b.t.Add(time.Hour), false))
	b.m.Tick()
	b.t = b.t.Add(10 * time.Minute) // actord figé ou arrêté depuis 10 minutes
	b.m.Tick()
	if _, traite := b.requete("203.0.113.5", "/x", ""); traite {
		t.Fatal("fichier périmé : plus de mesure (jamais d'effet sans actord)")
	}
}

func TestUneMesureExpireeNeSAppliquePlus(t *testing.T) {
	b := banc(t, "auto")
	b.m.delai = 80 * time.Millisecond
	ecrireMesures(t, b.m.chemin, b.t, mesureFichier("ACT-1", "203.0.113.5", "DELAY", b.t.Add(2*time.Minute), false))
	b.m.Tick()
	b.t = b.t.Add(3 * time.Minute)
	debut := time.Now()
	b.requete("203.0.113.5", "/x", "text/html")
	if time.Since(debut) > 40*time.Millisecond {
		t.Fatal("la mesure a expiré")
	}
}

func TestLesCheminsVitauxNeSontJamaisTouches(t *testing.T) {
	b := banc(t, "auto")
	ecrireMesures(t, b.m.chemin, b.t, mesureFichier("ACT-1", "203.0.113.5", "TARPIT", b.t.Add(time.Hour), false))
	b.m.Tick()
	for _, c := range []string{"/.well-known/acme-challenge/abc", "/robots.txt"} {
		debut := time.Now()
		if _, traite := b.requete("203.0.113.5", c, ""); traite || time.Since(debut) > 50*time.Millisecond {
			t.Fatalf("%s : ni retenu ni bloqué", c)
		}
	}
}

func TestSbxwafNIsoleJamaisUnAppareilDuLan(t *testing.T) {
	b := banc(t, "auto")
	ecrireMesures(t, b.m.chemin, b.t, mesureFichier("ACT-1", "192.168.1.50", "QUARANTINE", b.t.Add(6*time.Hour), true))
	b.m.Tick()
	if len(b.ban.pris) != 0 {
		t.Fatal("la quarantaine du LAN appartient au NAC : sbxwaf ne pose aucun ban")
	}
	if _, traite := b.requete("192.168.1.50", "/x", "text/html"); traite {
		t.Fatal("ni de mesure HTTP")
	}
}

func TestLEtatPourLePanneauEstEcrit(t *testing.T) {
	b := banc(t, "auto")
	ecrireMesures(t, b.m.chemin, b.t, mesureFichier("ACT-1", "203.0.113.5", "TARPIT", b.t.Add(time.Hour), false))
	b.m.Tick()
	var e map[string]any
	raw, _ := os.ReadFile(b.m.etat)
	if json.Unmarshal(raw, &e) != nil || e["mode"] != "auto" || len(e["actives"].([]any)) != 1 {
		t.Fatalf("état : %s", raw)
	}
}

func lignesFichier(t *testing.T, chemin string) []map[string]any {
	t.Helper()
	b, _ := os.ReadFile(chemin)
	var out []map[string]any
	for _, l := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		if l == "" {
			continue
		}
		var m map[string]any
		if json.Unmarshal([]byte(l), &m) == nil {
			out = append(out, m)
		}
	}
	return out
}

func between(s, a, b string) string {
	i := strings.Index(s, a)
	if i < 0 {
		return ""
	}
	s = s[i+len(a):]
	j := strings.Index(s, b)
	if j < 0 {
		return ""
	}
	return s[:j]
}
