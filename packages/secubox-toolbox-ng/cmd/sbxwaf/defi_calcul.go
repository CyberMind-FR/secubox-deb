// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>

package main

// DÉFI DE CALCUL PAR VHOST ET PAR CHEMIN (#4021).
//
// Avant un chemin coûteux déclaré (gitea : src/commit, blame, raw, commits, compare, archive…), un navigateur sans laissez-passer reçoit une
// page minimale qui résout une preuve de travail SHA-256 (quelques dizaines de millisecondes) puis repose la requête d'origine. La réponse
// porte un cookie `sbx_calcul` signé HMAC, valable quelques heures, lié à une EMPREINTE du client (User-Agent + préfixe réseau /24 ou /48,
// condensés : jamais l'adresse en clair). Le défi est un jeton signé et horodaté : aucun état par visiteur, sauf la mémoire bornée des
// jetons déjà utilisés (usage unique) et celle des insistants.
//
// QUI EST BANNI : seulement qui INSISTE — N requêtes sur des chemins défiés sans solution valide dans une fenêtre (20 / 10 min par défaut)
// → ban gradué (24 h, puis 7 j) par la pose existante, qui épargne plages protégées et robots vérifiés (Epargne, #4008). L'empreinte
// d'automatisation collectée par la page (navigator.webdriver, navigateur sans interface, incohérences) n'est qu'un INDICE : journalisée
// (champ `indice`) et versée à actord, jamais motif de ban seule.
//
// JAMAIS DÉFIÉS : méthodes autres que GET/HEAD, API (Accept JSON, /api/), clients git en HTTP, APT et agents SecuBox, webhooks, robots
// vérifiés, LAN/maillage/plages protégées, chemins exclus déclarés par vhost. Placé APRÈS l'inspection des règles : la catégorie
// aspirateur_ua (ban à la 1re requête) garde son comportement.
//
// COMPROMIS DE L'EMPREINTE : un mobile qui change d'antenne (autre /24) ou un navigateur mis à jour (autre UA) est redéfié — une page de
// ~100 ms, rare. À l'inverse, deux clients derrière le même NAT/CGNAT avec le même UA partagent l'empreinte : un cookie volé y resterait
// valable. Lier à l'adresse exacte casserait les mobiles et l'IPv6 à adresses temporaires ; le préfixe est le moindre mal.

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	cheminCalcul        = "/__sbx/calcul"
	cookieCalcul        = "sbx_calcul"
	categorieIndice     = "defi_calcul_indice"
	categorieInsistance = "defi_calcul_insistance"
	maxJetonsUtilises   = 200000
	maxInsistants       = 200000
)

// DefiCalculFichier est la forme de /etc/secubox/waf/defi-calcul.json (conffile de secubox-waf-ng).
type DefiCalculFichier struct {
	DifficulteBits int                  `json:"difficulte_bits"` // bits nuls en tête du condensé (14 ≈ 16 000 essais en moyenne)
	DureeCookie    string               `json:"duree_cookie"`    // durée du laissez-passer (6h)
	ValiditeDefi   string               `json:"validite_defi"`   // durée de vie d'un jeton de défi (5m)
	Insistance     DefiInsistance       `json:"insistance"`
	Vhosts         map[string]DefiVhost `json:"vhosts"`
}

type DefiInsistance struct {
	Seuil   int      `json:"seuil"`   // requêtes défiées sans solution avant ban (20)
	Fenetre string   `json:"fenetre"` // fenêtre de comptage (10m)
	Durees  []string `json:"durees"`  // ban gradué : 1er, 2e et suivants (24h, 168h)
}

type DefiVhost struct {
	Etat          string   `json:"etat"`           // desarme | observe | arme
	Chemins       []string `json:"chemins"`        // expressions régulières des chemins défiés
	Exclus        []string `json:"exclus"`         // expressions régulières jamais défiées
	NonNavigateur string   `json:"non_navigateur"` // laisser (défaut) | compter : requête sans Accept text/html
}

type defiVhostCompile struct {
	etat          string
	chemins       []*regexp.Regexp
	exclus        []*regexp.Regexp
	compterNonNav bool
}

type defiConfig struct {
	bits     int
	cookie   time.Duration
	validite time.Duration
	seuil    int
	fenetre  time.Duration
	durees   []time.Duration
	vhosts   map[string]*defiVhostCompile
}

type insistant struct {
	debut int64
	n     int
	banni bool
}

type bansInsistance struct {
	n    int
	last int64
}

// DefiCalcul applique le défi de calcul. nil = désactivé.
type DefiCalcul struct {
	chemin string
	cle    []byte
	now    func() time.Time

	protegees []*net.IPNet
	robots    interface{ Verifie(string) string }
	banneur   banneurDuree
	epargne   func(ip string) string
	journal   func(ThreatRecord)
	ja4       func(*http.Request) string

	cfgMu sync.RWMutex
	cfg   *defiConfig
	mtime time.Time
	vuLe  time.Time

	mu       sync.Mutex
	utilises map[string]int64 // aléa du jeton → échéance
	insistes map[string]*insistant
	bans     map[string]bansInsistance
}

// Valeurs par défaut d'un fichier incomplet.
func defiDefauts() *defiConfig {
	return &defiConfig{bits: 14, cookie: 6 * time.Hour, validite: 5 * time.Minute, seuil: 20, fenetre: 10 * time.Minute,
		durees: []time.Duration{24 * time.Hour, 7 * 24 * time.Hour}, vhosts: map[string]*defiVhostCompile{}}
}

func dureeOu(s string, d time.Duration) time.Duration {
	if v, err := time.ParseDuration(strings.TrimSpace(s)); err == nil && v > 0 {
		return v
	}
	return d
}

// compilerDefi valide le fichier. Une expression invalide rejette TOUT le fichier : la config précédente reste en place.
func compilerDefi(b []byte) (*defiConfig, error) {
	var f DefiCalculFichier
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, err
	}
	c := defiDefauts()
	if f.DifficulteBits > 0 {
		if f.DifficulteBits > 24 {
			return nil, fmt.Errorf("difficulte_bits %d > 24 : un téléphone ne suivrait pas", f.DifficulteBits)
		}
		c.bits = f.DifficulteBits
	}
	c.cookie = dureeOu(f.DureeCookie, c.cookie)
	c.validite = dureeOu(f.ValiditeDefi, c.validite)
	if f.Insistance.Seuil > 0 {
		c.seuil = f.Insistance.Seuil
	}
	c.fenetre = dureeOu(f.Insistance.Fenetre, c.fenetre)
	if len(f.Insistance.Durees) > 0 {
		c.durees = nil
		for _, s := range f.Insistance.Durees {
			d, err := time.ParseDuration(s)
			if err != nil || d <= 0 {
				return nil, fmt.Errorf("durée de ban %q invalide", s)
			}
			c.durees = append(c.durees, d)
		}
	}
	for h, v := range f.Vhosts {
		vc := &defiVhostCompile{etat: v.Etat, compterNonNav: v.NonNavigateur == "compter"}
		switch v.Etat {
		case "desarme", "observe", "arme":
		case "":
			vc.etat = "desarme"
		default:
			return nil, fmt.Errorf("vhost %s : état %q inconnu (desarme|observe|arme)", h, v.Etat)
		}
		for _, e := range v.Chemins {
			re, err := regexp.Compile(e)
			if err != nil {
				return nil, fmt.Errorf("vhost %s : chemin %q : %v", h, e, err)
			}
			vc.chemins = append(vc.chemins, re)
		}
		for _, e := range v.Exclus {
			re, err := regexp.Compile(e)
			if err != nil {
				return nil, fmt.Errorf("vhost %s : exclu %q : %v", h, e, err)
			}
			vc.exclus = append(vc.exclus, re)
		}
		c.vhosts[strings.ToLower(h)] = vc
	}
	return c, nil
}

// lireCleDefi lit la clé HMAC (créée par le postinst). Absente ou trop courte : clé aléatoire en mémoire (les cookies ne survivent pas au
// redémarrage) — signalé sans jamais écrire la clé.
func lireCleDefi(chemin string) []byte {
	if b, err := os.ReadFile(chemin); err == nil {
		k := []byte(strings.TrimSpace(string(b)))
		if len(k) >= 32 {
			return k
		}
	}
	log.Printf("sbxwaf: défi de calcul : clé %s absente ou trop courte — clé éphémère en mémoire (laissez-passer perdus au redémarrage)", chemin)
	k := make([]byte, 32)
	_, _ = rand.Read(k)
	return k
}

func NewDefiCalcul(chemin string, cle []byte) *DefiCalcul {
	d := &DefiCalcul{chemin: chemin, cle: cle, now: time.Now, cfg: defiDefauts(),
		utilises: map[string]int64{}, insistes: map[string]*insistant{}, bans: map[string]bansInsistance{}}
	d.recharger(true)
	return d
}

// recharger relit le fichier au plus toutes les 5 s, et seulement s'il a changé.
func (d *DefiCalcul) recharger(force bool) {
	now := d.now()
	d.cfgMu.RLock()
	trop := !force && now.Sub(d.vuLe) < 5*time.Second
	d.cfgMu.RUnlock()
	if trop {
		return
	}
	d.cfgMu.Lock()
	defer d.cfgMu.Unlock()
	d.vuLe = now
	st, err := os.Stat(d.chemin)
	if err != nil {
		if !d.mtime.IsZero() {
			log.Printf("sbxwaf: défi de calcul : %s disparu — désarmé partout", d.chemin)
		}
		d.cfg, d.mtime = defiDefauts(), time.Time{}
		return
	}
	if st.ModTime().Equal(d.mtime) {
		return
	}
	b, err := os.ReadFile(d.chemin)
	if err != nil {
		return
	}
	c, err := compilerDefi(b)
	if err != nil {
		log.Printf("sbxwaf: défi de calcul : %s rejeté (%v) — configuration précédente gardée", d.chemin, err)
		d.mtime = st.ModTime()
		return
	}
	d.cfg, d.mtime = c, st.ModTime()
	armes := 0
	for _, v := range c.vhosts {
		if v.etat != "desarme" {
			armes++
		}
	}
	log.Printf("sbxwaf: défi de calcul : %d vhost(s) déclaré(s), %d armé(s) ou observé(s), %d bits, cookie %s, insistance %d/%s",
		len(c.vhosts), armes, c.bits, c.cookie, c.seuil, c.fenetre)
}

func (d *DefiCalcul) config() *defiConfig {
	d.recharger(false)
	d.cfgMu.RLock()
	defer d.cfgMu.RUnlock()
	return d.cfg
}

// ── empreinte, jetons, cookie ─────────────────────────────────────────────────────────────────────────────────────────────────────────────

func (d *DefiCalcul) mac(n int, parts ...string) string {
	h := hmac.New(sha256.New, d.cle)
	h.Write([]byte(strings.Join(parts, "|")))
	return hex.EncodeToString(h.Sum(nil))[:n]
}

// prefixeReseau : /24 en IPv4, /48 en IPv6 (jamais l'adresse entière).
func prefixeReseau(ip string) string {
	p := net.ParseIP(ip)
	if p == nil {
		return ""
	}
	if v4 := p.To4(); v4 != nil {
		return v4.Mask(net.CIDRMask(24, 32)).String() + "/24"
	}
	return p.Mask(net.CIDRMask(48, 128)).String() + "/48"
}

func (d *DefiCalcul) empreinte(r *http.Request) string {
	return d.mac(32, "empreinte", r.Header.Get("User-Agent"), prefixeReseau(clientIP(r)))
}

// jeton : <émis>.<aléa>.<bits>.<signature>, 47 caractères : jeton + ":" + nonce tient dans UN bloc SHA-256 côté page.
func (d *DefiCalcul) jeton(host, fp string, bits int) string {
	a := make([]byte, 4)
	_, _ = rand.Read(a)
	e := strconv.FormatInt(d.now().Unix(), 10)
	al := hex.EncodeToString(a)
	b := strconv.Itoa(bits)
	return e + "." + al + "." + b + "." + d.mac(24, "defi", host, fp, e, al, b)
}

// bitsNuls compte les bits nuls en tête du condensé.
func bitsNuls(s [32]byte) int {
	n := 0
	for _, o := range s {
		if o == 0 {
			n += 8
			continue
		}
		for o&0x80 == 0 {
			n++
			o <<= 1
		}
		break
	}
	return n
}

// verifierSolution : signature, fraîcheur, difficulté, usage unique. Rend une raison d'échec, "" si valide.
func (d *DefiCalcul) verifierSolution(c *defiConfig, host, fp, tok, nonce string) string {
	p := strings.Split(tok, ".")
	if len(p) != 4 || len(nonce) == 0 || len(nonce) > 12 {
		return "forme"
	}
	if !hmac.Equal([]byte(p[3]), []byte(d.mac(24, "defi", host, fp, p[0], p[1], p[2]))) {
		return "signature" // autre client, autre vhost, ou jeton forgé
	}
	e, err1 := strconv.ParseInt(p[0], 10, 64)
	bits, err2 := strconv.Atoi(p[2])
	now := d.now().Unix()
	if err1 != nil || err2 != nil || now-e > int64(c.validite.Seconds()) || e > now+30 {
		return "perime"
	}
	if bits < 1 {
		return "forme"
	}
	if bitsNuls(sha256.Sum256([]byte(tok+":"+nonce))) < bits {
		return "calcul"
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if _, vu := d.utilises[p[1]+p[0]]; vu {
		return "rejoue"
	}
	if len(d.utilises) >= maxJetonsUtilises {
		for k, exp := range d.utilises {
			if exp <= now {
				delete(d.utilises, k)
			}
		}
		if len(d.utilises) >= maxJetonsUtilises {
			return "sature" // mémoire pleine : refus (le client est redéfié), jamais d'acceptation sans contrôle
		}
	}
	d.utilises[p[1]+p[0]] = e + int64(c.validite.Seconds()) + 60
	return ""
}

func (d *DefiCalcul) valeurCookie(host, fp string, exp int64) string {
	e := strconv.FormatInt(exp, 10)
	return "1." + e + "." + d.mac(32, "laissez", host, e, fp)
}

// CookieValide dit si la requête porte un laissez-passer valable pour ce vhost et cette empreinte.
func (d *DefiCalcul) CookieValide(r *http.Request, host string) bool {
	if d == nil {
		return false
	}
	ck, err := r.Cookie(cookieCalcul)
	if err != nil {
		return false
	}
	p := strings.Split(ck.Value, ".")
	if len(p) != 3 || p[0] != "1" {
		return false
	}
	e, err := strconv.ParseInt(p[1], 10, 64)
	if err != nil || e <= d.now().Unix() {
		return false
	}
	return hmac.Equal([]byte(p[2]), []byte(d.mac(32, "laissez", host, p[1], d.empreinte(r))))
}

// ── exclusions ────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────

// exclusionDefi rend la raison pour laquelle la requête n'est JAMAIS défiée, "" sinon (avant la vérification coûteuse des robots).
func exclusionDefi(r *http.Request, chemin string) string {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		return "methode"
	}
	ua := strings.ToLower(r.Header.Get("User-Agent"))
	acc := strings.ToLower(r.Header.Get("Accept"))
	lc := strings.ToLower(chemin)
	switch {
	case strings.HasPrefix(ua, "git/"), strings.HasPrefix(ua, "jgit/"), strings.HasPrefix(ua, "go-git"),
		strings.HasSuffix(lc, "/info/refs"), strings.Contains(lc, "/git-upload-pack"), strings.Contains(lc, "/git-receive-pack"),
		r.Header.Get("Git-Protocol") != "":
		return "git"
	case strings.HasPrefix(ua, "debian apt-http"), strings.HasPrefix(ua, "secubox"):
		return "agent"
	case strings.Contains(acc, "application/json"), strings.HasPrefix(lc, "/api/"), strings.Contains(lc, "/api/v1/"):
		return "api"
	case strings.Contains(lc, "/hooks/"), strings.Contains(lc, "webhook"), r.Header.Get("X-Gitea-Event") != "",
		r.Header.Get("X-GitHub-Event") != "", r.Header.Get("X-Gitlab-Event") != "":
		return "webhook"
	case lc == "/robots.txt", strings.HasPrefix(lc, "/.well-known/"):
		return "public"
	}
	return ""
}

// hoteNu : Host sans port, en minuscules (clé des vhosts).
func hoteNu(h string) string {
	if b, _, err := net.SplitHostPort(h); err == nil {
		h = b
	}
	return strings.ToLower(strings.TrimSpace(h))
}

func uaRobot(ua string) bool {
	u := strings.ToLower(ua)
	return strings.Contains(u, "bot") || strings.Contains(u, "crawl") || strings.Contains(u, "spider") || strings.Contains(u, "slurp")
}

func navigateurAccepte(r *http.Request) bool {
	return strings.Contains(strings.ToLower(r.Header.Get("Accept")), "text/html")
}

// ── interception ──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────

// Intercepte : appelé après l'inspection des règles, avant le proxy. true = réponse écrite (page de défi, solution, refus).
func (d *DefiCalcul) Intercepte(w http.ResponseWriter, r *http.Request, host string) bool {
	if d == nil {
		return false
	}
	c := d.config()
	v := c.vhosts[host]
	if v == nil || v.etat == "desarme" {
		return false
	}
	ip := clientIP(r)
	if privateCIDR(ip) || adresseProtegee(ip, d.protegees) {
		return false // LAN, maillage, plages protégées : jamais défiés ni comptés
	}
	chemin := r.URL.Path
	if chemin == cheminCalcul && r.Method == http.MethodPost && v.etat == "arme" {
		d.repondre(w, r, c, host, ip)
		return true
	}
	if !d.defie(v, chemin) || exclusionDefi(r, chemin) != "" {
		return false
	}
	if d.CookieValide(r, host) {
		return false
	}
	if uaRobot(r.Header.Get("User-Agent")) && d.robots != nil && d.robots.Verifie(ip) != "" {
		return false // robot d'indexation vérifié (DNS inverse + direct)
	}
	nav := navigateurAccepte(r)
	if !nav && !v.compterNonNav {
		return false // image d'un README, curl d'un fichier brut : laissés (non_navigateur = laisser)
	}
	d.compter(r, c, v, host, ip)
	if !nav || v.etat != "arme" {
		return false // observe : rien de servi ; non-navigateur compté mais servi
	}
	d.servir(w, r, c, host)
	return true
}

func (d *DefiCalcul) defie(v *defiVhostCompile, chemin string) bool {
	for _, re := range v.exclus {
		if re.MatchString(chemin) {
			return false
		}
	}
	for _, re := range v.chemins {
		if re.MatchString(chemin) {
			return true
		}
	}
	return false
}

// compter note une requête défiée sans solution ; au seuil, ban gradué (une seule fois par fenêtre).
func (d *DefiCalcul) compter(r *http.Request, c *defiConfig, v *defiVhostCompile, host, ip string) {
	now := d.now().Unix()
	fen := int64(c.fenetre.Seconds())
	d.mu.Lock()
	if len(d.insistes) >= maxInsistants {
		for k, x := range d.insistes {
			if now-x.debut > fen {
				delete(d.insistes, k)
			}
		}
		if len(d.insistes) >= maxInsistants {
			d.insistes = map[string]*insistant{} // vague hors norme : on repart de zéro plutôt que de grossir sans fin
		}
	}
	x := d.insistes[ip]
	if x == nil || now-x.debut > fen {
		x = &insistant{debut: now}
		d.insistes[ip] = x
	}
	x.n++
	declenche := x.n >= c.seuil && !x.banni
	var duree time.Duration
	if declenche {
		x.banni = true
		b := d.bans[ip]
		if now-b.last > 30*24*3600 {
			b.n = 0
		}
		i := b.n
		if i >= len(c.durees) {
			i = len(c.durees) - 1
		}
		duree = c.durees[i]
		if v.etat == "arme" {
			b.n++
			b.last = now
			d.bans[ip] = b
		}
	}
	n := x.n
	d.mu.Unlock()
	if !declenche {
		return
	}
	action := "propose"
	if v.etat == "arme" {
		action = "banned"
		if d.epargne != nil && d.epargne(ip) != "" {
			action = "epargne"
		}
	}
	if d.journal != nil {
		d.journal(ThreatRecord{ClientIP: ip, Host: r.Host, Method: r.Method, Path: r.URL.Path, Category: categorieInsistance,
			Severity: "medium", RuleID: "defi-calcul:insistance", Action: action, UA: r.Header.Get("User-Agent"), JA4: d.lireJA4(r),
			Signaux: map[string]int{"requetes_sans_solution": n, "fenetre_s": int(c.fenetre.Seconds()), "duree_ban_s": int(duree.Seconds())}})
	}
	if action == "banned" && d.banneur != nil {
		go d.banneur.BanFor(ip, categorieInsistance, "medium", duree)
	}
}

func (d *DefiCalcul) lireJA4(r *http.Request) string {
	if d.ja4 == nil {
		return ""
	}
	return d.ja4(r)
}

func (d *DefiCalcul) servir(w http.ResponseWriter, r *http.Request, c *defiConfig, host string) {
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Robots-Tag", "noindex")
	h.Set("Content-Security-Policy", cspDefi)
	h.Set("X-SecuBox-WAF", "defi-calcul")
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodHead {
		return
	}
	fmt.Fprintf(w, entetePage, html.EscapeString(d.jeton(host, d.empreinte(r), c.bits)), c.bits,
		html.EscapeString(retourSur(r.URL.RequestURI())), cheminCalcul)
	_, _ = io.WriteString(w, piedPage)
}

// traitsAutomatisation : seuls les noms connus passent, le reste de ce que renvoie la page est ignoré.
var traitsAutomatisation = map[string]bool{"webdriver": true, "headless_ua": true, "sans_plugins": true, "sans_langues": true,
	"plateforme_incoherente": true, "chrome_incoherent": true, "fenetre_nulle": true, "notifications_incoherentes": true}

func traitsLus(s string) []string {
	var out []string
	vus := map[string]bool{}
	for _, t := range strings.Split(s, ",") {
		t = strings.TrimSpace(t)
		if traitsAutomatisation[t] && !vus[t] {
			vus[t] = true
			out = append(out, "automatisation:"+t)
		}
	}
	return out
}

func (d *DefiCalcul) repondre(w http.ResponseWriter, r *http.Request, c *defiConfig, host, ip string) {
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "solution illisible", http.StatusBadRequest)
		return
	}
	tok, nonce, retour := r.PostForm.Get("t"), r.PostForm.Get("n"), retourSur(r.PostForm.Get("r"))
	fp := d.empreinte(r)
	if raison := d.verifierSolution(c, host, fp, tok, nonce); raison != "" {
		if v := c.vhosts[host]; v != nil {
			d.compter(r, c, v, host, ip) // une solution fausse compte comme une requête sans solution
		}
		w.Header().Set("Cache-Control", "no-store")
		http.Redirect(w, r, retour, http.StatusSeeOther) // redéfié au retour
		return
	}
	if traits := traitsLus(r.PostForm.Get("e")); len(traits) > 0 && d.journal != nil {
		// INDICE seulement : action detect, sévérité audit, aucun ban ni compteur.
		ms, _ := strconv.Atoi(r.PostForm.Get("ms"))
		d.journal(ThreatRecord{ClientIP: ip, Host: r.Host, Method: r.Method, Path: retour, Category: categorieIndice, Severity: "audit",
			RuleID: "defi-calcul:empreinte", Action: "detect", Mode: "detect", UA: r.Header.Get("User-Agent"), JA4: d.lireJA4(r),
			Indice: traits, Signaux: map[string]int{"resolution_ms": ms}})
	}
	d.mu.Lock()
	delete(d.insistes, ip) // a résolu : son compteur repart de zéro
	d.mu.Unlock()
	exp := d.now().Add(c.cookie).Unix()
	http.SetCookie(w, &http.Cookie{Name: cookieCalcul, Value: d.valeurCookie(host, fp, exp), Path: "/", Expires: time.Unix(exp, 0),
		HttpOnly: true, Secure: r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https", SameSite: http.SameSiteLaxMode})
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, retour, http.StatusSeeOther)
}

// ── page ──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────

// Script constant (les données passent par les attributs data-*) : la CSP l'autorise par son condensé, sans 'unsafe-inline'.
// SHA-256 synchrone en JS pur (crypto.subtle est asynchrone et ~10x plus lent par essai).
const scriptCalcul = `(function(){var m=document.getElementById("d"),t=m.dataset.t,b=+m.dataset.b,K=[],H=[],i,j,n,k=0;
for(i=2;k<64;i++){for(j=2;j*j<=i&&i%j;j++);if(j*j>i){if(k<8)H[k]=(Math.pow(i,.5)*4294967296)|0;K[k++]=(Math.pow(i,1/3)*4294967296)|0}}
function h0(s){var w=[],a,c,e,g,l,o,p,q,x,y,z,L=s.length,M=((L+8)>>6)+1,W=new Array(M*16).fill(0),r=H.slice(0,8),u;
for(i=0;i<L;i++)W[i>>2]|=s.charCodeAt(i)<<(24-(i&3)*8);W[L>>2]|=128<<(24-(L&3)*8);W[M*16-1]=L*8;
for(u=0;u<M*16;u+=16){a=r[0];c=r[1];e=r[2];g=r[3];l=r[4];o=r[5];p=r[6];q=r[7];
for(j=0;j<64;j++){if(j<16)w[j]=W[u+j];else{x=w[j-15];y=w[j-2];w[j]=(((x>>>7|x<<25)^(x>>>18|x<<14)^(x>>>3))+w[j-7]+((y>>>17|y<<15)^(y>>>19|y<<13)^(y>>>10))+w[j-16])|0}
x=(q+((l>>>6|l<<26)^(l>>>11|l<<21)^(l>>>25|l<<7))+((l&o)^(~l&p))+K[j]+w[j])|0;y=(((a>>>2|a<<30)^(a>>>13|a<<19)^(a>>>22|a<<10))+((a&c)^(a&e)^(c&e)))|0;
q=p;p=o;o=l;l=(g+x)|0;g=e;e=c;c=a;a=(x+y)|0}
r[0]=r[0]+a|0;r[1]=r[1]+c|0;r[2]=r[2]+e|0;r[3]=r[3]+g|0;r[4]=r[4]+l|0;r[5]=r[5]+o|0;r[6]=r[6]+p|0;r[7]=r[7]+q|0}return r}
var d0=Date.now(),z=t+":";for(n=0;;n++){if((h0(z+n)[0]>>>(32-b))===0)break}
var N=navigator,U=N.userAgent||"",P=N.platform||"",e=[];
if(N.webdriver)e.push("webdriver");if(/HeadlessChrome|PhantomJS|Electron/.test(U))e.push("headless_ua");
if(/Chrome|Firefox/.test(U)&&!/Mobile|Android/.test(U)&&N.plugins&&N.plugins.length===0)e.push("sans_plugins");
if(!N.languages||N.languages.length===0)e.push("sans_langues");
if((/Windows/.test(U)&&!/Win/.test(P))||(/Mac OS X/.test(U)&&!/Mac|iP/.test(P))||(/Linux/.test(U)&&!/Android/.test(U)&&/Win|Mac/.test(P)))e.push("plateforme_incoherente");
if(/Chrome\//.test(U)&&!/Edg|OPR|Mobile/.test(U)&&!window.chrome)e.push("chrome_incoherent");
if(window.outerWidth===0||window.outerHeight===0)e.push("fenetre_nulle");
try{if(window.Notification&&Notification.permission==="denied"&&N.permissions===undefined)e.push("notifications_incoherentes")}catch(_){}
var F=document.getElementById("f");F.t.value=t;F.n.value=n;F.r.value=m.dataset.r;F.e.value=e.join(",");F.ms.value=Date.now()-d0;F.submit()})();`

const styleCalcul = `body{font:16px system-ui,sans-serif;display:grid;place-items:center;min-height:100vh;margin:0;background:#101418;color:#e8ecf1}main{max-width:26rem;padding:1.5rem;text-align:center}h1{font-size:1.2rem;font-weight:600}p{color:#aab4bf}`

func condenseCSP(s string) string {
	h := sha256.Sum256([]byte(s))
	return "'sha256-" + base64.StdEncoding.EncodeToString(h[:]) + "'"
}

var cspDefi = "default-src 'none'; script-src " + condenseCSP(scriptCalcul) + "; style-src " + condenseCSP(styleCalcul) +
	"; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"

// entetePage : modèle Printf (jeton, bits, retour, action) ; le script, qui contient des %, est écrit à la suite tel quel.
const entetePage = `<!doctype html><html lang="fr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex">
<title>Vérification</title><style>` + styleCalcul + `</style></head>
<body><main id="d" data-t="%s" data-b="%d" data-r="%s"><h1>Vérification de votre navigateur…</h1><p>Un calcul de quelques instants, une fois toutes les quelques heures.</p>
<noscript><p>JavaScript est nécessaire pour cette vérification.</p></noscript>
<form id="f" method="post" action="%s" hidden><input name="t"><input name="n"><input name="r"><input name="e"><input name="ms"></form></main>
<script>`

const piedPage = scriptCalcul + `</script></body></html>`
