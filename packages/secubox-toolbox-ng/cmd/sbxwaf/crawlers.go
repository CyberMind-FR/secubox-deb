// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// See LICENCE-CMSD-1.0.md for terms.

package main

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"
)

// ROBOTS D'INDEXATION VÉRIFIÉS (#2240). Un ban nft ferme TOUS les ports de la box, vhosts publics compris : bannir l'adresse d'un moteur de recherche
// le retire de l'index pour la durée du ban. Les leurres (hôtes non routés, chemins-appâts) sont touchés par les robots qui suivent les journaux de
// transparence des certificats ou d'anciens liens ; ce sont des visites, pas des attaques (constat gk2 : 8 adresses de Googlebot bannies, 4 prolongées).
//
// LA PREUVE est le DNS inverse CONFIRMÉ par le direct (FCrDNS), la méthode que les moteurs documentent eux-mêmes : l'inverse d'une adresse donne un nom
// d'un domaine reconnu, et ce nom résout vers CETTE adresse. L'inverse seul ne prouve rien (l'attaquant écrit ce qu'il veut dans son inverse) ; le
// User-Agent encore moins. Un usurpateur n'est donc pas exempté : il reste banni.
var domainesRobots = []string{
	"googlebot.com", "google.com", // Googlebot, Google-Extended, lecteurs déclenchés par l'utilisateur
	"search.msn.com",     // Bingbot
	"applebot.apple.com", // Applebot
	"crawl.baidu.com",    // Baiduspider
	"yandex.com", "yandex.ru", "yandex.net",
}

const (
	crawlerTTLPositif = 24 * time.Hour
	crawlerTTLNegatif = 1 * time.Hour
	crawlerDelaiDNS   = 2 * time.Second
	crawlerCacheMax   = 4096
)

type crawlerEntree struct {
	nom       string
	exp       time.Time
	incertain bool // le DNS n'a pas répondu : « pas de robot » n'est pas prouvé (VerifieSur refait la recherche)
}

type Crawlers struct {
	inverse func(ip string) ([]string, error)
	direct  func(nom string) ([]string, error)
	now     func() time.Time
	mu      sync.Mutex
	cache   map[string]crawlerEntree
}

func NewCrawlers() *Crawlers {
	r := &net.Resolver{}
	return &Crawlers{
		inverse: func(ip string) ([]string, error) {
			ctx, cancel := context.WithTimeout(context.Background(), crawlerDelaiDNS)
			defer cancel()
			return r.LookupAddr(ctx, ip)
		},
		direct: func(nom string) ([]string, error) {
			ctx, cancel := context.WithTimeout(context.Background(), crawlerDelaiDNS)
			defer cancel()
			return r.LookupHost(ctx, nom)
		},
		now:   time.Now,
		cache: map[string]crawlerEntree{},
	}
}

// domaineRobot rend le domaine reconnu dont `nom` est un sous-domaine (jamais un simple suffixe de texte : « evilgooglebot.com » n'est pas « googlebot.com »).
func domaineRobot(nom string) string {
	nom = strings.ToLower(strings.TrimSuffix(nom, "."))
	for _, d := range domainesRobots {
		if nom == d || strings.HasSuffix(nom, "."+d) {
			return d
		}
	}
	return ""
}

// Verifie rend le domaine du moteur si l'adresse est un robot vérifié, "" sinon (y compris sur erreur DNS : le doute ne vaut pas exemption).
func (c *Crawlers) Verifie(ip string) string {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return ""
	}
	ip = a.String()
	now := c.now()
	c.mu.Lock()
	if e, ok := c.cache[ip]; ok && now.Before(e.exp) {
		c.mu.Unlock()
		return e.nom
	}
	c.mu.Unlock()
	nom, sur := c.verifieSansCache(ip, a)
	c.memoriser(ip, nom, sur, now)
	return nom
}

// VerifieSur est Verifie à TROIS états (#3919) : (domaine, true) robot vérifié ; ("", true) pas un robot ; ("", false) on ne sait pas (DNS en panne,
// délai dépassé, adresse invalide). Un doute n'est jamais mémorisé ici et ne change rien pour les appelants de Verifie.
func (c *Crawlers) VerifieSur(ip string) (string, bool) {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return "", false
	}
	ip = a.String()
	now := c.now()
	c.mu.Lock()
	e, ok := c.cache[ip]
	c.mu.Unlock()
	if ok && now.Before(e.exp) && !e.incertain {
		return e.nom, true
	}
	nom, sur := c.verifieSansCache(ip, a)
	if sur {
		c.memoriser(ip, nom, true, now)
	}
	return nom, sur
}

func (c *Crawlers) memoriser(ip, nom string, sur bool, now time.Time) {
	ttl := crawlerTTLNegatif
	if nom != "" {
		ttl = crawlerTTLPositif
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.cache) >= crawlerCacheMax {
		for k, e := range c.cache {
			if now.After(e.exp) {
				delete(c.cache, k)
			}
		}
		if len(c.cache) >= crawlerCacheMax {
			c.cache = map[string]crawlerEntree{}
		}
	}
	c.cache[ip] = crawlerEntree{nom: nom, exp: now.Add(ttl), incertain: !sur}
}

// Resolu : la vérification de cette adresse est déjà connue (robot ou non), valide dans le cache.
func (c *Crawlers) Resolu(ip string) bool {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return true // pas une adresse : rien à vérifier
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.cache[a.String()]
	return ok && c.now().Before(e.exp)
}

// absent : le DNS a répondu « ce nom n'existe pas » ; toute autre erreur est une panne, qui ne prouve rien.
func absent(err error) bool {
	var d *net.DNSError
	return errors.As(err, &d) && d.IsNotFound
}

// verifieSansCache rend le domaine du robot, et si la réponse est SÛRE (le DNS a répondu à tout).
func (c *Crawlers) verifieSansCache(ip string, a netip.Addr) (nom string, sur bool) {
	noms, err := c.inverse(ip)
	if err != nil {
		return "", absent(err)
	}
	sur = true
	for _, n := range noms {
		dom := domaineRobot(n)
		if dom == "" {
			continue
		}
		ips, err := c.direct(strings.TrimSuffix(n, "."))
		if err != nil {
			sur = sur && absent(err)
			continue
		}
		for _, x := range ips {
			if b, err := netip.ParseAddr(x); err == nil && b == a {
				return dom, true
			}
		}
	}
	return "", sur
}
