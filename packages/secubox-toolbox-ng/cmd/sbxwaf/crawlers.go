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
	crawlerCacheMax   = 65536 // ~8 Mo plein ; des dizaines de milliers de bans ne doivent pas chasser les robots connus (#3930)
)

type crawlerEntree struct {
	nom    string
	exp    time.Time
	conclu bool // réponse ferme ; faux : le DNS n'a pas répondu, le doute demeure
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
	nom, _ := c.VerifieConclu(ip)
	return nom
}

// VerifieConclu est Verifie qui dit aussi si la réponse est ferme (faux : panne DNS, à revérifier un jour).
func (c *Crawlers) VerifieConclu(ip string) (string, bool) {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return "", true
	}
	a = a.Unmap()
	ip = a.String()
	now := c.now()
	c.mu.Lock()
	if e, ok := c.cache[ip]; ok && now.Before(e.exp) {
		c.mu.Unlock()
		return e.nom, e.conclu
	}
	c.mu.Unlock()
	nom, conclu := c.verifieSansCache(ip, a)
	ttl := crawlerTTLNegatif
	if nom != "" {
		ttl = crawlerTTLPositif
	}
	c.mu.Lock()
	if len(c.cache) >= crawlerCacheMax {
		c.faireDeLaPlace(now)
	}
	c.cache[ip] = crawlerEntree{nom: nom, exp: now.Add(ttl), conclu: conclu}
	c.mu.Unlock()
	return nom, conclu
}

// faireDeLaPlace (c.mu tenu) : les entrées échues, sinon les négatives. Un robot connu n'est chassé que par d'autres robots connus : le perdre
// laisserait un lot déjà préparé le rebannir (#3930).
func (c *Crawlers) faireDeLaPlace(now time.Time) {
	for k, e := range c.cache {
		if now.After(e.exp) {
			delete(c.cache, k)
		}
	}
	if len(c.cache) < crawlerCacheMax {
		return
	}
	for k, e := range c.cache {
		if e.nom == "" {
			delete(c.cache, k)
		}
	}
	if len(c.cache) >= crawlerCacheMax {
		c.cache = map[string]crawlerEntree{}
	}
}

// Connu rend le domaine du moteur si l'adresse est un robot DÉJÀ vérifié ; jamais de DNS.
func (c *Crawlers) Connu(ip string) string {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return ""
	}
	a = a.Unmap()
	c.mu.Lock()
	defer c.mu.Unlock()
	if e, ok := c.cache[a.String()]; ok && c.now().Before(e.exp) {
		return e.nom
	}
	return ""
}

// Resolu : la vérification de cette adresse est déjà connue (robot ou non), valide dans le cache.
func (c *Crawlers) Resolu(ip string) bool {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return true // pas une adresse : rien à vérifier
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.cache[a.Unmap().String()]
	return ok && c.now().Before(e.exp)
}

func (c *Crawlers) verifieSansCache(ip string, a netip.Addr) (string, bool) {
	noms, err := c.inverse(ip)
	if err != nil {
		return "", absenceDNS(err)
	}
	conclu := true
	for _, n := range noms {
		dom := domaineRobot(n)
		if dom == "" {
			continue
		}
		ips, err := c.direct(strings.TrimSuffix(n, "."))
		if err != nil {
			conclu = conclu && absenceDNS(err)
			continue
		}
		for _, x := range ips {
			if b, err := netip.ParseAddr(x); err == nil && b.Unmap() == a {
				return dom, true
			}
		}
	}
	return "", conclu
}

// absenceDNS : le DNS a répondu « ce nom n'existe pas » (ferme), par opposition à un délai, un SERVFAIL ou un refus.
func absenceDNS(err error) bool {
	var e *net.DNSError
	return errors.As(err, &e) && e.IsNotFound
}
