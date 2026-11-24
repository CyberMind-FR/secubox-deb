// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// See LICENCE-CMSD-1.0.md for terms.

package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/CyberMind-FR/secubox-deb/secubox-toolbox-ng/internal/reseau"
)

// Détecteur de rotation (#3919, tâche 9). Signatures FICTIVES, adresses de documentation (RFC 5737 / RFC 3849).

const uaFictif = "Mozilla/5.0 (X11; SystemeFictif) MoteurFictif/1.0 Chrome/120.0 Safari/537.36"
const hoteFictif = "forge.exemple.test"

// adressePublique rend la i-ème adresse neutre : 203.0.113.0/24, 198.51.100.0/24, puis 2001:db8::/32 (un /64 par adresse).
func adressePublique(i int) string {
	switch {
	case i < 250:
		return fmt.Sprintf("203.0.113.%d", i+1)
	case i < 500:
		return fmt.Sprintf("198.51.100.%d", i-250+1)
	default:
		return fmt.Sprintf("2001:db8:%x:%x::1", i>>16, i&0xffff)
	}
}

type banFactice struct {
	mu     sync.Mutex
	appels []appelBan
}

type appelBan struct {
	ip, cat, sev string
	d            time.Duration
}

func (b *banFactice) BanFor(ip, cat, sev string, d time.Duration) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.appels = append(b.appels, appelBan{ip, cat, sev, d})
}

func (b *banFactice) liste() []appelBan {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]appelBan(nil), b.appels...)
}

func (b *banFactice) banni(ip string) bool {
	for _, a := range b.liste() {
		if a.ip == ip {
			return true
		}
	}
	return false
}

// classesFactices : classe par adresse, `defaut` sinon.
type classesFactices struct {
	mu     sync.Mutex
	defaut string
	par    map[string]string
}

func (c *classesFactices) Classer(ip string) reseau.Info {
	c.mu.Lock()
	defer c.mu.Unlock()
	if cl, ok := c.par[ip]; ok {
		return reseau.Info{ASN: 64500, Org: "Réseau fictif", Classe: cl}
	}
	return reseau.Info{ASN: 64501, Org: "Réseau fictif", Classe: c.defaut}
}

func (c *classesFactices) poser(ip, cl string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.par == nil {
		c.par = map[string]string{}
	}
	c.par[ip] = cl
}

func cfgEssai(t *testing.T, mode string) RotationConfig {
	d := t.TempDir()
	return RotationConfig{Mode: mode, Verdict: "differe", Grace: -1, Etat: filepath.Join(d, "rotation-etat.json"),
		Audit: filepath.Join(d, "audit.log"), SortiesTor: filepath.Join(d, "absent-tor.txt")}
}

// uaVariante : navigateurs fictifs distincts (signatures distinctes).
func uaVariante(k int) string {
	return fmt.Sprintf("Mozilla/5.0 (X11; SystemeFictif) MoteurFictif/%d.0 Firefox/100.0", k)
}

func nav(ip, ua string) RotationRequete {
	return RotationRequete{IP: ip, UA: ua, Hote: hoteFictif, Navigation: true}
}

// voir : une navigation, sans suite.
func voir(r *Rotation, ip, ua string, t time.Time) { r.Observe(nav(ip, ua), t) }

// page : une navigation dont la page (2xx text/html avec ressources) est partie en entier à l'instant t.
func page(r *Rotation, ip string, t time.Time) { r.Servie(r.Observe(nav(ip, uaFictif), t), t) }

// ressource : le chargement d'une ressource par cette adresse, quel que soit le navigateur déclaré.
func ressource(r *Rotation, ip, ua string, t time.Time) {
	r.Observe(RotationRequete{IP: ip, UA: ua, Hote: hoteFictif, Preuve: true}, t)
}

// avancer : un Tick toutes les 20 s de `de` à `a` (inclus), comme en service.
func avancer(r *Rotation, de, a time.Time) {
	for t := de; t.Before(a); t = t.Add(20 * time.Second) {
		r.Tick(t)
	}
	r.Tick(a)
}

// etablir : n adresses (à partir de l'indice `depart`), une requête chacune sur la signature fictive, puis un Tick.
func etablir(r *Rotation, depart, n int, t0 time.Time) {
	for i := depart; i < depart+n; i++ {
		voir(r, adressePublique(i), uaFictif, t0)
	}
	r.Tick(t0.Add(time.Second))
}

func lireEtatRotation(t *testing.T, chemin string) rotationEtat {
	t.Helper()
	b, err := os.ReadFile(chemin)
	if err != nil {
		t.Fatalf("état illisible : %v", err)
	}
	var e rotationEtat
	if err := json.Unmarshal(b, &e); err != nil {
		t.Fatalf("état invalide : %v", err)
	}
	return e
}

func catAttendue() string { return "rotation:" + Signature(uaFictif, "", hoteFictif)[:8] }

func TestRotationSignature(t *testing.T) {
	s := Signature("a", "b", "c")
	if len(s) != 64 || s != Signature("a", "b", "c") || s == Signature("a", "", "bc") {
		t.Fatalf("signature inattendue : %s", s)
	}
}

func TestPasDeSuiviSansUA(t *testing.T) {
	r := NewRotation(cfgEssai(t, "auto"), &banFactice{}, &classesFactices{defaut: reseau.ClasseProxyLoue})
	t0 := time.Now()
	for i := 0; i < 60; i++ {
		voir(r, adressePublique(i), "", t0)
	}
	r.Tick(t0.Add(time.Second))
	if n := r.nbSignatures(); n != 0 {
		t.Fatalf("aucune signature ne doit être suivie sans navigateur déclaré, %d suivies", n)
	}
	if n := len(r.campagnesActives()); n != 0 {
		t.Fatalf("aucune campagne attendue, %d", n)
	}
}

func TestCampagneEtablie(t *testing.T) {
	t0 := time.Now()
	r := NewRotation(cfgEssai(t, "auto"), &banFactice{}, &classesFactices{defaut: reseau.ClasseProxyLoue})
	etablir(r, 0, 50, t0)
	if c := r.campagnesActives(); len(c) != 1 || c[0].Signature != Signature(uaFictif, "", hoteFictif) || c[0].Sources != 50 {
		t.Fatalf("campagne attendue sur 50 sources : %+v", c)
	}
	r2 := NewRotation(cfgEssai(t, "auto"), &banFactice{}, &classesFactices{defaut: reseau.ClasseProxyLoue})
	etablir(r2, 0, 49, t0)
	if c := r2.campagnesActives(); len(c) != 0 {
		t.Fatalf("49 sources ne suffisent pas : %+v", c)
	}
}

func TestInconnuNeComptePas(t *testing.T) {
	t0 := time.Now()
	r := NewRotation(cfgEssai(t, "auto"), &banFactice{}, &classesFactices{defaut: reseau.ClasseInconnu})
	etablir(r, 0, 80, t0)
	if c := r.campagnesActives(); len(c) != 0 {
		t.Fatalf("des adresses de classe inconnue ne font pas une campagne : %+v", c)
	}
	// Sans annuaire du tout : jamais de campagne.
	r2 := NewRotation(cfgEssai(t, "auto"), &banFactice{}, nil)
	etablir(r2, 0, 80, t0)
	if c := r2.campagnesActives(); len(c) != 0 {
		t.Fatalf("sans annuaire, aucune campagne : %+v", c)
	}
}

func TestAccesNeComptePas(t *testing.T) {
	t0 := time.Now()
	essai := func(louees, acces int) int {
		cl := &classesFactices{defaut: reseau.ClasseProxyLoue}
		for i := louees; i < louees+acces; i++ {
			cl.poser(adressePublique(i), reseau.ClasseAcces)
		}
		r := NewRotation(cfgEssai(t, "auto"), &banFactice{}, cl)
		etablir(r, 0, louees+acces, t0)
		return len(r.campagnesActives())
	}
	if n := essai(30, 20); n != 1 {
		t.Fatalf("30 proxy loué + 20 accès (60 %%) : campagne attendue, %d", n)
	}
	if n := essai(29, 21); n != 0 {
		t.Fatalf("29 proxy loué + 21 accès (58 %%) : pas de campagne, %d", n)
	}
	// Hébergeur compte comme proxy loué.
	cl := &classesFactices{defaut: reseau.ClasseHebergeur}
	r := NewRotation(cfgEssai(t, "auto"), &banFactice{}, cl)
	etablir(r, 0, 50, t0)
	if len(r.campagnesActives()) != 1 {
		t.Fatalf("50 hébergeurs : campagne attendue")
	}
}

func TestRotationPartUneATrois(t *testing.T) {
	// 50 sources, dont 11 à 4 requêtes (78 % à ≤ 3) : pas de campagne.
	t0 := time.Now()
	r := NewRotation(cfgEssai(t, "auto"), &banFactice{}, &classesFactices{defaut: reseau.ClasseProxyLoue})
	for i := 0; i < 50; i++ {
		k := 1
		if i < 11 {
			k = 4
		}
		for j := 0; j < k; j++ {
			voir(r, adressePublique(i), uaFictif, t0)
		}
	}
	r.Tick(t0.Add(time.Second))
	if c := r.campagnesActives(); len(c) != 0 {
		t.Fatalf("78 %% à ≤ 3 requêtes : pas de campagne, %+v", c)
	}
}

func TestVerdictDiffereRobot(t *testing.T) {
	t0 := time.Now()
	b := &banFactice{}
	r := NewRotation(cfgEssai(t, "auto"), b, &classesFactices{defaut: reseau.ClasseProxyLoue})
	etablir(r, 0, 50, t0)
	x := adressePublique(100)
	tx := t0.Add(2 * time.Second)
	page(r, x, tx)
	r.Tick(tx.Add(5 * time.Second))
	if len(b.liste()) != 0 {
		t.Fatalf("aucun ban avant le délai : %+v", b.liste())
	}
	r.Tick(tx.Add(11 * time.Second))
	a := b.liste()
	if len(a) != 1 || a[0].ip != x || a[0].cat != catAttendue() || a[0].sev != "high" || a[0].d != 24*time.Hour {
		t.Fatalf("ban attendu de %s en %s : %+v", x, catAttendue(), a)
	}
	// Une seule fois : pas de second verdict pour la même adresse.
	page(r, x, tx.Add(12*time.Second))
	r.Tick(tx.Add(30 * time.Second))
	if len(b.liste()) != 1 {
		t.Fatalf("un seul ban attendu : %+v", b.liste())
	}
	if c := r.campagnesActives(); len(c) != 1 || c[0].Bannies != 1 {
		t.Fatalf("bannies=1 attendu : %+v", c)
	}
}

func TestVerdictDiffereNavigateur(t *testing.T) {
	t0 := time.Now()
	b := &banFactice{}
	r := NewRotation(cfgEssai(t, "auto"), b, &classesFactices{defaut: reseau.ClasseProxyLoue})
	etablir(r, 0, 50, t0)
	tx := t0.Add(2 * time.Second)

	// X : la page, puis sa feuille de style à t+1 s, sous un navigateur déclaré différent (aucune importance).
	x := adressePublique(100)
	page(r, x, tx)
	ressource(r, x, "AutreNavigateurFictif/2.0", tx.Add(time.Second))
	// Y : la ressource arrive SANS navigateur déclaré (NAT, client minimal) : épargnée quand même.
	y := adressePublique(101)
	page(r, y, tx)
	ressource(r, y, "", tx.Add(time.Second))
	// Z : revient avec un cookie de session.
	z := adressePublique(102)
	page(r, z, tx)
	r.Observe(RotationRequete{IP: z, UA: uaFictif, Hote: hoteFictif, Navigation: true, Preuve: true}, tx.Add(3*time.Second))
	// W : la page elle-même porte un référent.
	w := adressePublique(103)
	r.Observe(RotationRequete{IP: w, UA: uaFictif, Hote: hoteFictif, Navigation: true, Preuve: true}, tx)

	avancer(r, tx.Add(11*time.Second), tx.Add(40*time.Second))
	if a := b.liste(); len(a) != 0 {
		t.Fatalf("un client qui se comporte en navigateur n'est jamais banni : %+v", a)
	}
	c := r.campagnesActives()
	if len(c) != 1 || c[0].Epargnees != 4 {
		t.Fatalf("4 adresses épargnées attendues : %+v", c)
	}
	// Épargnée = mémorisée : une nouvelle page sans ressource (cache du navigateur) ne relance pas de verdict.
	page(r, x, tx.Add(5*time.Minute))
	avancer(r, tx.Add(5*time.Minute), tx.Add(6*time.Minute))
	if a := b.liste(); len(a) != 0 {
		t.Fatalf("une adresse épargnée n'est pas rejugée : %+v", a)
	}
}

func TestVerdictImmediat(t *testing.T) {
	t0 := time.Now()
	b := &banFactice{}
	cfg := cfgEssai(t, "auto")
	cfg.Verdict = "immediat"
	r := NewRotation(cfg, b, &classesFactices{defaut: reseau.ClasseProxyLoue})
	etablir(r, 0, 50, t0)
	x := adressePublique(100)
	tx := t0.Add(2 * time.Second)
	page(r, x, tx)
	if len(b.liste()) != 0 {
		t.Fatalf("Observe ne bannit jamais lui-même (aucune E/S sur le chemin de la requête)")
	}
	r.Tick(tx)
	if a := b.liste(); len(a) != 1 || a[0].ip != x {
		t.Fatalf("ban immédiat attendu au premier Tick : %+v", a)
	}
	if e := lireEtatRotation(t, cfg.Etat); e.Verdict != "immediat" {
		t.Fatalf("le verdict figure dans l'état : %+v", e)
	}
}

func TestModePropose(t *testing.T) {
	t0 := time.Now()
	b := &banFactice{}
	cfg := cfgEssai(t, "propose")
	r := NewRotation(cfg, b, &classesFactices{defaut: reseau.ClasseProxyLoue})
	etablir(r, 0, 50, t0)
	x := adressePublique(100)
	tx := t0.Add(2 * time.Second)
	page(r, x, tx)
	r.Tick(tx.Add(11 * time.Second))
	if a := b.liste(); len(a) != 0 {
		t.Fatalf("mode propose : aucun ban, %+v", a)
	}
	e := lireEtatRotation(t, cfg.Etat)
	if e.Mode != "propose" || len(e.Campagnes) != 1 {
		t.Fatalf("campagne attendue dans l'état : %+v", e)
	}
	c := e.Campagnes[0]
	if c.Signature != Signature(uaFictif, "", hoteFictif) || c.Hote != hoteFictif || c.Sources != 51 /* 50 + X, réévaluée après 10 s */ || c.Une != 100 || c.Le3 != 100 ||
		c.Classes[reseau.ClasseProxyLoue] != 100 || c.Bannies != 0 || c.ABannir != 1 || c.EtablieLe == 0 || c.Dernier == 0 {
		t.Fatalf("champs de l'état inattendus : %+v", c)
	}
}

func TestGardeFous(t *testing.T) {
	t0 := time.Now()
	b := &banFactice{}
	cfg := cfgEssai(t, "auto")
	protegee := adressePublique(110)
	_, n, _ := net.ParseCIDR(protegee + "/32")
	cfg.Protegees = []*net.IPNet{n}
	r := NewRotation(cfg, b, &classesFactices{defaut: reseau.ClasseProxyLoue})
	robot := adressePublique(111)
	r.SetRobots(func(ip string) (string, bool) {
		if ip == robot {
			return "moteur.exemple.test", true
		}
		return "", true
	})
	etablir(r, 0, 50, t0)
	tx := t0.Add(2 * time.Second)
	temoin := adressePublique(112)
	for _, ip := range []string{"10.1.2.3", "192.168.1.20", "127.0.0.1", "fe80::1", protegee, robot, temoin} {
		page(r, ip, tx)
	}
	r.Tick(tx.Add(11 * time.Second))
	a := b.liste()
	if len(a) != 1 || a[0].ip != temoin {
		t.Fatalf("seul le témoin public est banni : %+v", a)
	}
}

func TestRelaisJamaisBanni(t *testing.T) {
	t0 := time.Now()
	b := &banFactice{}
	cfg := cfgEssai(t, "auto")
	tor := adressePublique(121)
	cfg.SortiesTor = filepath.Join(t.TempDir(), "sorties-tor.txt")
	if err := os.WriteFile(cfg.SortiesTor, []byte("# sorties Tor (fictives)\n\n"+tor+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cl := &classesFactices{defaut: reseau.ClasseProxyLoue}
	relais := adressePublique(120)
	cl.poser(relais, reseau.ClasseRelaisViePrivee)
	r := NewRotation(cfg, b, cl)
	etablir(r, 0, 50, t0)
	tx := t0.Add(2 * time.Second)
	temoin := adressePublique(122)
	for _, ip := range []string{relais, tor, temoin} {
		page(r, ip, tx)
	}
	r.Tick(tx.Add(11 * time.Second))
	if a := b.liste(); len(a) != 1 || a[0].ip != temoin {
		t.Fatalf("relais de vie privée et sortie Tor jamais bannis : %+v", a)
	}
	if e := lireEtatRotation(t, cfg.Etat); !e.TorGarde {
		t.Fatalf("liste Tor lue : tor_garde=true attendu")
	}

	// Sans liste Tor : garde signalée inactive.
	cfg2 := cfgEssai(t, "auto")
	r2 := NewRotation(cfg2, &banFactice{}, cl)
	r2.Tick(t0)
	b2, _ := os.ReadFile(cfg2.Etat)
	if !strings.Contains(string(b2), `"tor_garde":false`) {
		t.Fatalf("sans liste Tor, l'état porte \"tor_garde\": false : %s", b2)
	}
}

func TestPlafondHoraire(t *testing.T) {
	t0 := time.Now()
	b := &banFactice{}
	cfg := cfgEssai(t, "auto")
	cfg.MaxParHeure = 3
	r := NewRotation(cfg, b, &classesFactices{defaut: reseau.ClasseProxyLoue})
	etablir(r, 0, 50, t0)
	tx := t0.Add(2 * time.Second)
	for i := 100; i < 106; i++ {
		page(r, adressePublique(i), tx)
	}
	r.Tick(tx.Add(11 * time.Second))
	for i := 106; i < 110; i++ {
		page(r, adressePublique(i), tx.Add(20*time.Minute))
	}
	avancer(r, tx.Add(20*time.Minute), tx.Add(21*time.Minute))
	if n := len(b.liste()); n != 3 {
		t.Fatalf("3 bans au plus dans l'heure, %d", n)
	}
	// L'heure passée, le plafond se libère (l'attaque continue : la campagne tient ses seuils).
	for i := 200; i < 260; i++ {
		voir(r, adressePublique(i), uaFictif, tx.Add(50*time.Minute))
	}
	avancer(r, tx.Add(50*time.Minute), tx.Add(61*time.Minute))
	page(r, adressePublique(110), tx.Add(61*time.Minute))
	avancer(r, tx.Add(61*time.Minute), tx.Add(62*time.Minute))
	if n := len(b.liste()); n != 4 {
		t.Fatalf("plafond libéré après une heure : 4 bans attendus, %d", n)
	}
	if !strings.Contains(lireFichier(t, cfg.Audit), `"rotation_plafond"`) {
		t.Fatalf("le plafond atteint est écrit dans l'audit")
	}
}

func lireFichier(t *testing.T, chemin string) string {
	t.Helper()
	b, err := os.ReadFile(chemin)
	if err != nil {
		t.Fatalf("lecture %s : %v", chemin, err)
	}
	return string(b)
}

func TestExpiration(t *testing.T) {
	t0 := time.Now()
	cfg := cfgEssai(t, "auto")
	r := NewRotation(cfg, &banFactice{}, &classesFactices{defaut: reseau.ClasseProxyLoue})
	etablir(r, 0, 50, t0)
	r.Tick(t0.Add(23 * time.Hour))
	if len(r.campagnesActives()) != 1 {
		t.Fatalf("campagne encore active avant 24 h")
	}
	r.Tick(t0.Add(24*time.Hour + 2*time.Second))
	if len(r.campagnesActives()) != 0 {
		t.Fatalf("campagne retirée après 24 h sans nouvelle source")
	}
	if e := lireEtatRotation(t, cfg.Etat); len(e.Campagnes) != 0 {
		t.Fatalf("campagne retirée de l'état : %+v", e)
	}
	if n := r.nbSignatures(); n != 0 {
		t.Fatalf("signatures inactives depuis plus d'une heure oubliées, %d", n)
	}
}

func TestRotationMaxCampagnes(t *testing.T) {
	t0 := time.Now()
	cfg := cfgEssai(t, "auto")
	cfg.MaxCampagnes = 2
	r := NewRotation(cfg, &banFactice{}, &classesFactices{defaut: reseau.ClasseProxyLoue})
	for k := 0; k < 3; k++ {
		tk := t0.Add(time.Duration(k) * time.Minute)
		for i := 0; i < 50; i++ {
			voir(r, adressePublique(i), uaVariante(k), tk)
		}
		r.Tick(tk.Add(time.Second))
	}
	c := r.campagnesActives()
	if len(c) != 2 {
		t.Fatalf("2 campagnes au plus : %+v", c)
	}
	for _, x := range c {
		if x.Signature == Signature(uaVariante(0), "", hoteFictif) {
			t.Fatalf("la plus ancienne inactive est sortie : %+v", c)
		}
	}
}

func TestMemoireBornee(t *testing.T) {
	t0 := time.Now()
	cfg := cfgEssai(t, "auto")
	cfg.MaxSignatures = 20000
	r := NewRotation(cfg, &banFactice{}, &classesFactices{defaut: reseau.ClasseProxyLoue})
	for i := 0; i < 30000; i++ {
		voir(r, adressePublique(i%400), uaVariante(i), t0)
		if i%5000 == 0 && r.nbSignatures() > 20000 {
			t.Fatalf("plus de 20 000 signatures suivies à %d", i)
		}
	}
	if n := r.nbSignatures(); n != 20000 {
		t.Fatalf("20 000 signatures suivies attendues, %d", n)
	}
	// Sources par signature bornées, et total borné.
	cfg2 := cfgEssai(t, "auto")
	r2 := NewRotation(cfg2, &banFactice{}, &classesFactices{defaut: reseau.ClasseProxyLoue})
	r2.maxSourcesSig = 100
	for i := 0; i < 300; i++ {
		voir(r2, adressePublique(i), uaFictif, t0)
	}
	if n := r2.nbSources(); n != 100 {
		t.Fatalf("100 sources au plus par signature, %d", n)
	}
	r3 := NewRotation(cfgEssai(t, "auto"), &banFactice{}, &classesFactices{defaut: reseau.ClasseProxyLoue})
	r3.maxSourcesTotal = 250
	for k := 0; k < 10; k++ {
		for i := 0; i < 100; i++ {
			voir(r3, adressePublique(i), uaVariante(k), t0)
		}
	}
	if n := r3.nbSources(); n > 250 {
		t.Fatalf("total des sources borné à 250, %d", n)
	}
	// Verdicts en attente bornés : au-delà, l'adresse n'est pas jugée (jamais bannie).
	b4 := &banFactice{}
	r4 := NewRotation(cfgEssai(t, "auto"), b4, &classesFactices{defaut: reseau.ClasseProxyLoue})
	r4.maxAttente = 10
	etablir(r4, 0, 50, t0)
	tx := t0.Add(2 * time.Second)
	for i := 100; i < 130; i++ {
		page(r4, adressePublique(i), tx)
	}
	if n := r4.nbAttente(); n > 10 {
		t.Fatalf("10 verdicts au plus, %d", n)
	}
	r4.Tick(tx.Add(11 * time.Second))
	if n := len(b4.liste()); n != 10 {
		t.Fatalf("seuls les 10 verdicts gardés sont rendus, %d", n)
	}
	if b4.banni(adressePublique(129)) {
		t.Fatalf("un verdict refusé n'est jamais un ban")
	}
}

func TestAudit(t *testing.T) {
	t0 := time.Now()
	cfg := cfgEssai(t, "auto")
	if err := os.WriteFile(cfg.Audit, []byte(`{"ts":"avant","module":"waf","action":"autre"}`+"\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	r := NewRotation(cfg, &banFactice{}, &classesFactices{defaut: reseau.ClasseProxyLoue})
	etablir(r, 0, 50, t0)
	r.Tick(t0.Add(25 * time.Hour))
	f, err := os.Open(cfg.Audit)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var actions []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var l map[string]any
		if err := json.Unmarshal(sc.Bytes(), &l); err != nil {
			t.Fatalf("ligne d'audit non JSON : %q", sc.Text())
		}
		actions = append(actions, fmt.Sprint(l["action"]))
		if l["action"] == "rotation_etablie" && (l["module"] != "waf" || l["signature"] != Signature(uaFictif, "", hoteFictif)) {
			t.Fatalf("ligne d'établissement incomplète : %v", l)
		}
	}
	if strings.Join(actions, ",") != "autre,rotation_etablie,rotation_fin" {
		t.Fatalf("audit : ajout seul, une ligne par établissement et par fin : %v", actions)
	}
}

func TestEtatRelu(t *testing.T) {
	t0 := time.Now()
	cfg := cfgEssai(t, "auto")
	r := NewRotation(cfg, &banFactice{}, &classesFactices{defaut: reseau.ClasseProxyLoue})
	etablir(r, 0, 50, t0)

	b := &banFactice{}
	r2 := NewRotation(cfg, b, &classesFactices{defaut: reseau.ClasseProxyLoue})
	c := r2.campagnesActives()
	if len(c) != 1 || c[0].Signature != Signature(uaFictif, "", hoteFictif) || c[0].Sources != 50 {
		t.Fatalf("campagne relue attendue : %+v", c)
	}
	x := adressePublique(100)
	tx := t0.Add(3 * time.Second)
	page(r2, x, tx)
	r2.Tick(tx.Add(11 * time.Second))
	if !b.banni(x) {
		t.Fatalf("la campagne relue rend ses verdicts")
	}

	// État de plus de 24 h : ignoré.
	e := lireEtatRotation(t, cfg.Etat)
	e.GenereLe = time.Now().Add(-25 * time.Hour).Unix()
	vieux, _ := json.Marshal(e)
	if err := os.WriteFile(cfg.Etat, vieux, 0o640); err != nil {
		t.Fatal(err)
	}
	r3 := NewRotation(cfg, &banFactice{}, &classesFactices{defaut: reseau.ClasseProxyLoue})
	if c := r3.campagnesActives(); len(c) != 0 {
		t.Fatalf("état périmé ignoré : %+v", c)
	}
	// État corrompu : ignoré sans panique.
	_ = os.WriteFile(cfg.Etat, []byte("{tronqué"), 0o640)
	if c := NewRotation(cfg, &banFactice{}, nil).campagnesActives(); len(c) != 0 {
		t.Fatalf("état corrompu ignoré : %+v", c)
	}
}

func TestRotationOffInerte(t *testing.T) {
	cfg := cfgEssai(t, "off")
	b := &banFactice{}
	r := NewRotation(cfg, b, &classesFactices{defaut: reseau.ClasseProxyLoue})
	etablir(r, 0, 60, time.Now())
	if r.nbSignatures() != 0 || len(b.liste()) != 0 {
		t.Fatalf("mode off : rien n'est suivi")
	}
	var nul *Rotation
	nul.Observe(nav("203.0.113.1", uaFictif), time.Now()) // pas de panique
	nul.NoterPreuve("203.0.113.1", time.Now())
	nul.Servie(nil, time.Now())
	nul.Suivre(nil)
}

// Observe et Tick concurrents (à passer sous -race).
func TestRotationConcurrence(t *testing.T) {
	t0 := time.Now()
	r := NewRotation(cfgEssai(t, "auto"), &banFactice{}, &classesFactices{defaut: reseau.ClasseProxyLoue})
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 2000; i++ {
				q := nav(adressePublique((g*2000+i)%3000), uaVariante(i%7))
				q.Preuve = i%5 == 0
				tt := t0.Add(time.Duration(i) * time.Millisecond)
				r.Servie(r.Observe(q, tt), tt)
				r.NoterPreuve(adressePublique(i+5000), tt)
			}
		}(g)
	}
	for k := 0; k < 20; k++ {
		r.Tick(t0.Add(time.Duration(k) * time.Second))
	}
	wg.Wait()
	r.Tick(t0.Add(time.Minute))
}

func BenchmarkObserve(b *testing.B) {
	// Régime établi : 1 000 adresses × une signature connue, JA4 présent. « navigation » : page suivie ; « preuve » : ressource (1 requête sur 2 à 10 en
	// vrai) ; « inerte » : client non suivi, sans preuve.
	const ua = "Mozilla/5.0 (X11; Linux aarch64) MoteurFictif/537.36 (essai de performance, chaîne longue) Chrome/120.0.0.0 Safari/537.36"
	ips := make([]string, 1000)
	for i := range ips {
		ips[i] = adressePublique(i)
	}
	essai := func(nom string, q RotationRequete) {
		b.Run(nom, func(b *testing.B) {
			r := NewRotation(RotationConfig{Mode: "auto", Verdict: "differe", Grace: -1}, &banFactice{}, &classesFactices{defaut: reseau.ClasseProxyLoue})
			t0 := time.Now()
			q.JA4, q.Hote = "t13d1516h2_8daaf6152771_02713d6af862", hoteFictif
			for i := 0; i < 10000; i++ {
				q.IP = ips[i%1000]
				r.Observe(q, t0)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				q.IP = ips[i%1000]
				r.Observe(q, t0)
			}
		})
	}
	essai("navigation", RotationRequete{UA: ua, Navigation: true})
	essai("navigation_preuve", RotationRequete{UA: ua, Navigation: true, Preuve: true})
	essai("preuve", RotationRequete{UA: ua, Preuve: true})
	essai("inerte", RotationRequete{UA: "git/2.45.0", Navigation: true})
}

// Lecture des en-têtes d'une requête de navigateur réelle (preuve + navigation), sur le chemin chaud.
func BenchmarkRotationRequete(b *testing.B) {
	h := http.Header{"User-Agent": {"x"}, "Accept": {"text/html"}, "Sec-Fetch-Dest": {"document"}, "Sec-Fetch-Site": {"none"}, "Accept-Language": {"fr"}}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if preuveNavigateur("/utilisateur/depot/commits", h) || !estNavigation("GET", "/utilisateur/depot/commits", h) {
			b.Fatal("navigation attendue")
		}
	}
}
