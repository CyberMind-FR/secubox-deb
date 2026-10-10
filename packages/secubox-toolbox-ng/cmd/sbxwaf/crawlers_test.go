// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// See LICENCE-CMSD-1.0.md for terms.

package main

import (
	"path/filepath"
	"testing"
	"time"
)

// dns simule le DNS : inverse (ip → noms) et direct (nom → ips).
type dns struct {
	inv  map[string][]string
	dir  map[string][]string
	nbRq int
}

func (d *dns) install(c *Crawlers) {
	c.inverse = func(ip string) ([]string, error) { d.nbRq++; return d.inv[ip], nil }
	c.direct = func(nom string) ([]string, error) { d.nbRq++; return d.dir[nom], nil }
}

func TestCrawlers_GooglebotVerifieParDNSInverseConfirme(t *testing.T) {
	d := &dns{inv: map[string][]string{"192.178.6.100": {"crawl-192-178-6-100.googlebot.com."}},
		dir: map[string][]string{"crawl-192-178-6-100.googlebot.com": {"192.178.6.100"}}}
	c := NewCrawlers()
	d.install(c)
	if nom := c.Verifie("192.178.6.100"); nom != "googlebot.com" {
		t.Fatalf("un robot dont l'inverse ET le direct concordent est vérifié : %q", nom)
	}
}

func TestCrawlers_UnNomUsurpeNEstPasUnRobot(t *testing.T) {
	// L'attaquant contrôle son DNS inverse (il peut y écrire « googlebot.com ») mais pas le direct de googlebot.com.
	d := &dns{inv: map[string][]string{"203.0.113.50": {"crawl-1.googlebot.com."}}, dir: map[string][]string{"crawl-1.googlebot.com": {"66.249.66.1"}}}
	c := NewCrawlers()
	d.install(c)
	if nom := c.Verifie("203.0.113.50"); nom != "" {
		t.Fatalf("l'inverse seul ne prouve rien : %q", nom)
	}
}

func TestCrawlers_DomaineHorsListeNEstPasExempte(t *testing.T) {
	d := &dns{inv: map[string][]string{"198.51.100.7": {"scan.evil.example."}}, dir: map[string][]string{"scan.evil.example": {"198.51.100.7"}}}
	c := NewCrawlers()
	d.install(c)
	if nom := c.Verifie("198.51.100.7"); nom != "" {
		t.Fatalf("seuls les domaines des moteurs reconnus comptent : %q", nom)
	}
	if c.Verifie("not-an-ip") != "" {
		t.Fatal("une adresse invalide n'est jamais un robot")
	}
}

func TestCrawlers_UnSuffixeSimilaireNEstPasAccepte(t *testing.T) {
	d := &dns{inv: map[string][]string{"198.51.100.8": {"evilgooglebot.com."}}, dir: map[string][]string{"evilgooglebot.com": {"198.51.100.8"}}}
	c := NewCrawlers()
	d.install(c)
	if c.Verifie("198.51.100.8") != "" {
		t.Fatal("« evilgooglebot.com » n'est pas « googlebot.com »")
	}
}

func TestCrawlers_LeResultatEstMemoriseEtExpire(t *testing.T) {
	d := &dns{inv: map[string][]string{"192.178.6.101": {"crawl.googlebot.com."}}, dir: map[string][]string{"crawl.googlebot.com": {"192.178.6.101"}}}
	c := NewCrawlers()
	d.install(c)
	maintenant := time.Unix(1_800_000_000, 0)
	c.now = func() time.Time { return maintenant }
	c.Verifie("192.178.6.101")
	n := d.nbRq
	c.Verifie("192.178.6.101")
	if d.nbRq != n {
		t.Fatalf("deuxième appel servi par le cache : %d requêtes DNS de plus", d.nbRq-n)
	}
	maintenant = maintenant.Add(25 * time.Hour)
	c.Verifie("192.178.6.101")
	if d.nbRq == n {
		t.Fatal("le cache expire : un robot dont l'adresse a changé de propriétaire est revérifié")
	}
}

func TestBan_UnRobotVerifieNEstJamaisBanni(t *testing.T) {
	d := &dns{inv: map[string][]string{"192.178.6.100": {"crawl.googlebot.com."}}, dir: map[string][]string{"crawl.googlebot.com": {"192.178.6.100"}}}
	c := NewCrawlers()
	d.install(c)
	r, fx, store, _ := bancReeval(t, "auto", nil)
	r.banneur.robots = c
	r.banneur.BanFor("192.178.6.100", "leurre:unrouted", "medium", time.Hour)
	if fx.vu("add element") {
		t.Fatalf("on ne bannit pas Googlebot : %v", fx.cmds)
	}
	if len(store.ActiveBans(time.Now().Unix())) != 0 {
		t.Fatal("et rien n'est journalisé comme ban")
	}
	r.banneur.BanFor("198.51.100.9", "leurre:unrouted", "medium", time.Hour) // une adresse ordinaire reste bannie
	if !fx.vu("add element") {
		t.Fatal("les autres adresses restent bannies")
	}
}

func TestLibererRobots_RetireLesBansDejaPosesEtLeJournalise(t *testing.T) {
	d := &dns{inv: map[string][]string{"192.178.6.100": {"crawl.googlebot.com."}}, dir: map[string][]string{"crawl.googlebot.com": {"192.178.6.100"}}}
	c := NewCrawlers()
	d.install(c)
	now := time.Now().Unix()
	r, fx, store, dir := bancReeval(t, "auto", map[string][2]int64{"192.178.6.100": {5, 3000}, "198.51.100.9": {5, 3000}})
	r.banneur.robots = c
	poseBan(store, "192.178.6.100", "leurre:unrouted", now-60, now+3000)
	poseBan(store, "198.51.100.9", "leurre:unrouted", now-60, now+3000)
	n := r.banneur.LibererRobots()
	if n != 1 || !fx.vu("delete element inet secubox waf_ban { 192.178.6.100 }") || fx.vu("delete element inet secubox waf_ban { 198.51.100.9 }") {
		t.Fatalf("seul le robot vérifié est libéré (%d) : %v", n, fx.cmds)
	}
	for _, b := range store.ActiveBans(now) {
		if b.IP == "192.178.6.100" {
			t.Fatal("le journal porte un unban : le robot ne revient pas au prochain Reload")
		}
	}
	_ = filepath.Join(dir, "x")
}
