// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>

package main

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ÉCHELLE DE RÉPONSE APPLIQUÉE (#2274). actord décide le cran de chaque acteur et publie les mesures actives ; ce fichier les APPLIQUE :
//
//	DELAY      : la requête attend avant d'être servie (ralentit le bruit automatisé) ;
//	CHALLENGE  : un navigateur reçoit une page de défi (preuve de travail en JavaScript, sans service tiers) et un laissez-passer lié à son adresse ; une
//	             requête d'API est seulement ralentie — on ne casse pas un client qui ne sait pas lire une page ;
//	TARPIT     : la connexion est retenue et nourrie au compte-gouttes, avec un plafond de connexions retenues ;
//	DENY       : ban nft de durée graduée (1 h, 24 h, 7 j), dans la limite d'un plafond horaire ;
//	QUARANTINE : appareil du LAN — isolé par le NAC, qui lit lui-même les mesures d'actord (zone de quarantaine ; DNS et le reste comme aujourd'hui).
//	             sbxwaf ne l'applique JAMAIS : il n'a ni le secret de flotte ni de raison de toucher au LAN.
//
// GARDE-FOUS : jamais une adresse privée côté HTTP, ni une plage protégée, ni un moteur de recherche vérifié ; fichier périmé = aucune mesure ; chaque mesure a
// une échéance ; mode `propose` = consigné, rien d'appliqué ; chaque première application est une ligne de preuve (mesures.jsonl).

const (
	cheminDefi       = "/__sbx/defi"
	cookieDefi       = "sbx_defi"
	zerosDefi        = "0000"
	fenetreGraine    = 5 * time.Minute
	validiteLaissez  = 15 * time.Minute
	mesuresFraicheur = 3 * time.Minute
)

type mesureLue struct {
	Actor     string   `json:"actor"`
	IPs       []string `json:"ips"`
	Niveau    string   `json:"niveau"`
	Depuis    int64    `json:"depuis"`
	Expire    int64    `json:"expire"`
	Raison    string   `json:"raison"`
	LAN       bool     `json:"lan"`
	Risque    int      `json:"risque"`
	Confiance int      `json:"confiance"`
}

type mesuresFichierRacine struct {
	GenereLe int64       `json:"genere_le"`
	Mesures  []mesureLue `json:"mesures"`
}

type mesureActive struct {
	Niveau string `json:"niveau"`
	Expire int64  `json:"expire"`
	Actor  string `json:"actor"`
	Raison string `json:"raison"`
	IP     string `json:"ip"`
}

type MesuresWAF struct {
	chemin        string
	mode          string // off | propose | auto
	store         *BanStore
	banneur       banneurDuree
	protegees     []*net.IPNet
	robots        *Crawlers
	preuves, etat string
	now           func() time.Time

	delai        time.Duration
	tarpitPas    time.Duration
	tarpitMax    time.Duration
	tarpitSlots  chan struct{}
	maxBansHeure int
	secret       []byte

	mu       sync.RWMutex
	actives  map[string]mesureActive
	vus      map[string]int64 // ip|niveau|depuis → vu (preuve déjà écrite)
	bannis   map[string]bool  // ip|depuis → ban déjà posé
	recents  []time.Time
	plafonne bool
}

func NewMesuresWAF(chemin, mode string, store *BanStore, b banneurDuree) *MesuresWAF {
	sec := make([]byte, 32)
	_, _ = rand.Read(sec)
	return &MesuresWAF{chemin: chemin, mode: mode, store: store, banneur: b, now: time.Now,
		delai: 1500 * time.Millisecond, tarpitPas: 2 * time.Second, tarpitMax: 60 * time.Second, tarpitSlots: make(chan struct{}, 64),
		maxBansHeure: 20, secret: sec, actives: map[string]mesureActive{}, vus: map[string]int64{}, bannis: map[string]bool{}}
}

var rangMesure = map[string]int{"DELAY": 1, "CHALLENGE": 2, "TARPIT": 3, "DENY": 4}

func (m *MesuresWAF) lire() (mesuresFichierRacine, bool) {
	var f mesuresFichierRacine
	b, err := os.ReadFile(m.chemin)
	if err != nil || json.Unmarshal(b, &f) != nil {
		return f, false
	}
	if m.now().Sub(time.Unix(f.GenereLe, 0)) > mesuresFraicheur {
		return f, false // actord arrêté ou figé : jamais de mesure sans lui
	}
	return f, true
}

func (m *MesuresWAF) ecrireLigne(chemin string, v any) {
	if chemin == "" {
		return
	}
	b, err := json.Marshal(v)
	if err != nil {
		return
	}
	_ = os.MkdirAll(filepath.Dir(chemin), 0o755)
	f, err := os.OpenFile(chemin, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o640)
	if err != nil {
		log.Printf("sbxwaf: mesures — écriture %s impossible : %v", chemin, err)
		return
	}
	defer f.Close()
	_, _ = f.Write(append(b, '\n'))
}

func (m *MesuresWAF) preuve(x mesureLue, ip, decision string, applique bool, now time.Time) {
	cle := fmt.Sprintf("%s|%s|%s|%d|%v", ip, x.Niveau, decision, x.Depuis, applique)
	if _, deja := m.vus[cle]; deja {
		return
	}
	m.vus[cle] = now.Unix()
	m.ecrireLigne(m.preuves, map[string]any{"ts": now.Unix(), "ip": ip, "actor": x.Actor, "niveau": x.Niveau, "decision": decision, "applique": applique,
		"risque": x.Risque, "confiance": x.Confiance, "raison": x.Raison, "mode": m.mode, "expire": x.Expire, "version": "v1"})
	if applique {
		log.Printf("sbxwaf: mesure %s %s ← %s (%s)", x.Niveau, ip, x.Actor, decision)
	}
}

// Tick relit les mesures d'actord et met à jour ce qui est appliqué.
func (m *MesuresWAF) Tick() {
	if m.mode != "propose" && m.mode != "auto" {
		return
	}
	now := m.now()
	f, ok := m.lire()
	if !ok {
		m.mu.Lock()
		m.actives = map[string]mesureActive{}
		m.mu.Unlock()
		m.ecrireEtat(now)
		return
	}
	nouv := map[string]mesureActive{}
	m.mu.Lock()
	garde := m.recents[:0]
	for _, t := range m.recents {
		if now.Sub(t) < time.Hour {
			garde = append(garde, t)
		}
	}
	m.recents = garde
	for k, t := range m.vus { // les lignes de preuve déjà écrites ne sont retenues qu'une journée
		if now.Unix()-t > 86400 {
			delete(m.vus, k)
		}
	}
	m.plafonne = false
	m.mu.Unlock()

	var bans []demandeBan
	for _, x := range f.Mesures {
		if x.Expire <= now.Unix() {
			continue
		}
		for _, ip := range x.IPs {
			m.traiter(x, ip, now, nouv, &bans)
		}
	}
	m.mu.Lock()
	m.actives = nouv
	m.mu.Unlock()
	for _, b := range bans {
		m.banneur.BanFor(b.ip, b.cat, "high", b.d)
	}
	m.ecrireEtat(now)
}

type demandeBan struct {
	ip, cat string
	d       time.Duration
}

func (m *MesuresWAF) traiter(x mesureLue, ip string, now time.Time, nouv map[string]mesureActive, bans *[]demandeBan) {
	rang := rangMesure[x.Niveau]
	if rang == 0 {
		return // QUARANTINE et OBSERVE : pas des mesures de sbxwaf
	}
	switch {
	case adresseProtegee(ip, m.protegees):
		m.mu.Lock()
		m.preuve(x, ip, "ecarte:protegee", false, now)
		m.mu.Unlock()
		return
	case m.robots != nil && m.robots.Verifie(ip) != "":
		m.mu.Lock()
		m.preuve(x, ip, "ecarte:robot_verifie", false, now)
		m.mu.Unlock()
		return
	}
	auto := m.mode == "auto"
	m.mu.Lock()
	defer m.mu.Unlock()
	if auto {
		if cur, ok := nouv[ip]; !ok || rangMesure[cur.Niveau] < rang {
			nouv[ip] = mesureActive{Niveau: x.Niveau, Expire: x.Expire, Actor: x.Actor, Raison: x.Raison, IP: ip}
		}
	}
	if x.Niveau != "DENY" {
		m.preuve(x, ip, "appliquee", auto, now)
		return
	}
	cle := fmt.Sprintf("%s|%d", ip, x.Depuis)
	if !auto {
		m.preuve(x, ip, "a_bannir", false, now)
		return
	}
	if m.bannis[cle] {
		return
	}
	if len(m.recents) >= m.maxBansHeure {
		m.plafonne = true
		m.preuve(x, ip, "ecarte:plafond_horaire", false, now)
		return
	}
	n := 0
	if m.store != nil {
		n = m.store.CompteCategorie(ip, "mesure:", now.Add(-plafondChaine).Unix())
	}
	d := dureeLeurre(n)
	m.bannis[cle] = true
	m.recents = append(m.recents, now)
	m.preuve(x, ip, "banni", true, now)
	*bans = append(*bans, demandeBan{ip, "mesure:" + x.Actor, d}) // posé APRÈS la libération du verrou : nft peut prendre du temps
}

func (m *MesuresWAF) ecrireEtat(now time.Time) {
	if m.etat == "" {
		return
	}
	m.mu.RLock()
	act := make([]mesureActive, 0, len(m.actives))
	for _, a := range m.actives {
		act = append(act, a)
	}
	e := map[string]any{"genere_le": now.Unix(), "mode": m.mode, "actives": act, "bans_derniere_heure": len(m.recents), "plafond_atteint": m.plafonne}
	m.mu.RUnlock()
	b, err := json.Marshal(e)
	if err != nil {
		return
	}
	_ = os.MkdirAll(filepath.Dir(m.etat), 0o755)
	tmp := m.etat + ".tmp"
	if os.WriteFile(tmp, b, 0o640) == nil {
		_ = os.Rename(tmp, m.etat)
	}
}

// Veiller relance Tick à intervalle régulier.
func (m *MesuresWAF) Veiller(pas time.Duration) {
	for {
		m.Tick()
		time.Sleep(pas)
	}
}

func (m *MesuresWAF) active(ip string) (mesureActive, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	a, ok := m.actives[ip]
	if !ok || a.Expire <= m.now().Unix() {
		return a, false
	}
	return a, true
}

func (m *MesuresWAF) attendre(ctx context.Context, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}

func cheminExempte(p string) bool {
	return strings.HasPrefix(p, "/.well-known/acme-challenge/") || p == "/robots.txt"
}

// Intercepte applique la mesure de l'adresse à la requête. Rend true quand la réponse est déjà écrite (défi, tarpit, refus) ; false pour laisser passer.
func (m *MesuresWAF) Intercepte(w http.ResponseWriter, r *http.Request) bool {
	if m == nil || m.mode != "auto" {
		return false
	}
	ip := clientIP(r)
	a, ok := m.active(ip)
	if !ok || cheminExempte(r.URL.Path) {
		return false
	}
	if a.Niveau == "CHALLENGE" && r.URL.Path == cheminDefi && r.Method == http.MethodPost {
		m.repondreDefi(w, r, ip, a)
		return true
	}
	switch a.Niveau {
	case "DELAY":
		m.attendre(r.Context(), m.delai)
		return false
	case "CHALLENGE":
		if m.laissezPasserValide(r, ip) {
			return false
		}
		if (r.Method == http.MethodGet || r.Method == http.MethodHead) && strings.Contains(r.Header.Get("Accept"), "text/html") {
			m.servirDefi(w, r, ip)
			return true
		}
		m.attendre(r.Context(), m.delai) // client sans page : ralenti, jamais cassé
		return false
	case "TARPIT":
		select {
		case m.tarpitSlots <- struct{}{}:
			defer func() { <-m.tarpitSlots }()
		default:
			m.attendre(r.Context(), m.delai) // trop de connexions déjà retenues : simple délai
			return false
		}
		m.retenir(w, r)
		return true
	case "DENY":
		// Le ban nft est l'effet ; en attendant qu'il soit posé (délai anti-tempête), la requête est refusée.
		http.Error(w, "accès suspendu", http.StatusForbidden)
		return true
	}
	return false
}

func (m *MesuresWAF) retenir(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	fl, _ := w.(http.Flusher)
	fin := time.NewTimer(m.tarpitMax)
	tk := time.NewTicker(m.tarpitPas)
	defer fin.Stop()
	defer tk.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-fin.C:
			return
		case <-tk.C:
			if _, err := w.Write([]byte(" ")); err != nil {
				return
			}
			if fl != nil {
				fl.Flush()
			}
		}
	}
}

// ── défi par preuve de travail ───────────────────────────────────────────────────────────────────────────────────────────────────────────────
func (m *MesuresWAF) mac(parts ...string) string {
	h := hmac.New(sha256.New, m.secret)
	h.Write([]byte(strings.Join(parts, "|")))
	return hex.EncodeToString(h.Sum(nil))
}

func (m *MesuresWAF) graine(ip string, decalage int) string {
	w := m.now().Unix()/int64(fenetreGraine.Seconds()) - int64(decalage)
	return m.mac("graine", ip, strconv.FormatInt(w, 10))[:32]
}

func (m *MesuresWAF) graineValide(ip, g string) bool {
	return g != "" && (hmac.Equal([]byte(g), []byte(m.graine(ip, 0))) || hmac.Equal([]byte(g), []byte(m.graine(ip, 1))))
}

func (m *MesuresWAF) laissezPasserValide(r *http.Request, ip string) bool {
	c, err := r.Cookie(cookieDefi)
	if err != nil {
		return false
	}
	exp, sig, ok := strings.Cut(c.Value, ".")
	if !ok {
		return false
	}
	e, err := strconv.ParseInt(exp, 10, 64)
	if err != nil || e <= m.now().Unix() {
		return false
	}
	return hmac.Equal([]byte(sig), []byte(m.mac("laissez", ip, exp)))
}

func retourSur(s string) string {
	if !strings.HasPrefix(s, "/") || strings.HasPrefix(s, "//") || strings.ContainsAny(s, "\\\r\n") || len(s) > 2048 {
		return "/"
	}
	return s
}

func (m *MesuresWAF) servirDefi(w http.ResponseWriter, r *http.Request, ip string) {
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodHead {
		return
	}
	fmt.Fprintf(w, pageDefi, html.EscapeString(m.graine(ip, 0)), html.EscapeString(retourSur(r.URL.RequestURI())), cheminDefi)
}

func (m *MesuresWAF) repondreDefi(w http.ResponseWriter, r *http.Request, ip string, a mesureActive) {
	_ = r.ParseForm()
	seed, nonce, retour := r.PostForm.Get("seed"), r.PostForm.Get("nonce"), retourSur(r.PostForm.Get("retour"))
	somme := sha256.Sum256([]byte(seed + nonce))
	if !m.graineValide(ip, seed) || len(nonce) > 32 || !strings.HasPrefix(hex.EncodeToString(somme[:]), zerosDefi) {
		http.Error(w, "preuve invalide", http.StatusForbidden)
		return
	}
	exp := m.now().Add(validiteLaissez).Unix()
	if a.Expire < exp {
		exp = a.Expire
	}
	e := strconv.FormatInt(exp, 10)
	http.SetCookie(w, &http.Cookie{Name: cookieDefi, Value: e + "." + m.mac("laissez", ip, e), Path: "/", Expires: time.Unix(exp, 0), HttpOnly: true, Secure: r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https", SameSite: http.SameSiteLaxMode})
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, retour, http.StatusSeeOther)
}

const pageDefi = `<!doctype html><html lang="fr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex">
<title>Vérification</title><style>body{font:16px system-ui,sans-serif;display:grid;place-items:center;min-height:100vh;margin:0;background:#101418;color:#e8ecf1}main{max-width:26rem;padding:1.5rem;text-align:center}
.b{height:6px;background:#27303a;border-radius:3px;overflow:hidden;margin-top:1rem}.b i{display:block;height:100%%;width:30%%;background:#c9a84c;animation:m 1.2s ease-in-out infinite}@keyframes m{50%%{margin-left:70%%}}</style></head>
<body><main id="sbx-defi" data-seed="%s" data-retour="%s"><h1>Vérification en cours…</h1><p>Un instant, votre navigateur prouve qu'il n'est pas un robot.</p><div class="b"><i></i></div>
<noscript><p>JavaScript est nécessaire pour cette vérification.</p></noscript>
<form id="f" method="post" action="%s" hidden><input name="seed"><input name="nonce"><input name="retour"></form></main>
<script>(async function(){var m=document.getElementById("sbx-defi"),s=m.dataset.seed,enc=new TextEncoder(),n=0;
for(;;n++){var h=new Uint8Array(await crypto.subtle.digest("SHA-256",enc.encode(s+n)));if(h[0]===0&&h[1]===0)break;}
var f=document.getElementById("f");f.seed.value=s;f.nonce.value=n;f.retour.value=m.dataset.retour;f.submit();})();</script></body></html>`
