// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// Package federation : réglages de /etc/secubox/federation.yaml et niveaux
// d'abonnement (#1389).
//
// LA BOX DÉCIDE. Rien ici n'ouvre de connexion : les intervalles disent QUAND
// la box ira chercher ce que son certificat lui ouvre, jamais quand on viendra
// la chercher. Sans fichier, la box est autonome et hors fédération.
package federation

import (
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Duree : « 5m », « 6h », « 24h », « 0 » (= temps réel : dès que possible).
type Duree time.Duration

func (d *Duree) UnmarshalYAML(n *yaml.Node) error {
	s := strings.TrimSpace(n.Value)
	if s == "0" || s == "temps-reel" || s == "realtime" {
		*d = 0
		return nil
	}
	v, err := time.ParseDuration(s)
	if err != nil || v < 0 {
		return fmt.Errorf("durée invalide %q (ex. 5m, 6h, 0)", s)
	}
	*d = Duree(v)
	return nil
}

func (d Duree) MarshalYAML() (any, error) { return d.String(), nil }

func (d Duree) String() string {
	if d == 0 {
		return "0"
	}
	// « 5m », « 6h », « 1h30m » — pas « 5m0s » : c'est ce qu'on écrit dans le
	// fichier de config, c'est ce qu'on relit.
	s := time.Duration(d).String()
	if strings.HasSuffix(s, "m0s") {
		s = strings.TrimSuffix(s, "0s")
	}
	if strings.HasSuffix(s, "h0m") {
		s = strings.TrimSuffix(s, "0m")
	}
	return s
}

// Tier : ce qu'un niveau d'abonnement ouvre.
type Tier struct {
	Channels []string         `yaml:"channels"`
	Rights   map[string]bool  `yaml:"rights"`
	AppStore string           `yaml:"appstore"` // public | public+sites | complet | complet+dev
	Sync     map[string]Duree `yaml:"sync"`     // waf, appstore, metapack
}

// TiersParDefaut : le tableau du cahier des charges (#1388). Deux écarts,
// assumés et documentés : premium garde aussi « stable » (une box premium
// installe d'abord des paquets stables), et « temps réel » s'écrit 0.
func TiersParDefaut() map[string]Tier {
	h := func(s string) Duree { v, _ := time.ParseDuration(s); return Duree(v) }
	return map[string]Tier{
		"community": {Channels: []string{"stable"}, AppStore: "public",
			Rights: map[string]bool{"appstore": true, "mesh": true},
			Sync:   map[string]Duree{"waf": h("24h"), "appstore": h("24h"), "metapack": h("24h")}},
		"standard": {Channels: []string{"stable"}, AppStore: "public+sites",
			Rights: map[string]bool{"appstore": true, "metapack": true, "mesh": true},
			Sync:   map[string]Duree{"waf": h("6h"), "appstore": h("6h"), "metapack": h("6h")}},
		"pro": {Channels: []string{"stable", "beta"}, AppStore: "complet",
			Rights: map[string]bool{"appstore": true, "metapack": true, "waf_pro": true, "mesh": true, "support": true},
			Sync:   map[string]Duree{"waf": h("5m"), "appstore": h("15m"), "metapack": h("30m")}},
		"premium": {Channels: []string{"stable", "beta", "alpha"}, AppStore: "complet+dev",
			Rights: map[string]bool{"appstore": true, "metapack": true, "waf_pro": true, "mesh": true, "support": true},
			Sync:   map[string]Duree{"waf": 0, "appstore": h("5m"), "metapack": h("5m")}},
	}
}

// Config : /etc/secubox/federation.yaml.
type Config struct {
	// Role : « member » (une box) ou « authority » (la CA GK2).
	Role       string `yaml:"role"`
	Tier       string `yaml:"tier"`
	Owner      string `yaml:"owner"`
	Federation struct {
		URL string `yaml:"url"`
	} `yaml:"federation"`
	// Sync : surcharge LOCALE des intervalles (jamais plus fréquente que le
	// tier ne l'autorise — voir Intervalle).
	Sync map[string]Duree `yaml:"sync"`
	// Tiers : surcharge des niveaux (côté autorité surtout).
	Tiers map[string]Tier `yaml:"tiers"`
	CA    struct {
		DureeJours int  `yaml:"duree_jours"`
		AutoJoin   bool `yaml:"auto_join"`
	} `yaml:"ca"`
	// Catalogue : où ranger les objets publiés. Sur gk2, le SSD (/data) plutôt
	// que la carte SD qui porte /var/lib (#1393).
	Catalogue struct {
		Dir string `yaml:"dir"`
	} `yaml:"catalogue"`
}

// Charge lit le fichier ; absent, rend une config « hors fédération ».
func Charge(chemin string) (*Config, error) {
	c := &Config{Role: "member", Tier: "community"}
	b, err := os.ReadFile(chemin)
	if errors.Is(err, os.ErrNotExist) {
		c.completer()
		return c, nil
	}
	if err != nil {
		return nil, err
	}
	d := yaml.NewDecoder(strings.NewReader(string(b)))
	d.KnownFields(true)
	if err := d.Decode(c); err != nil {
		return nil, fmt.Errorf("%s : %w", chemin, err)
	}
	c.completer()
	return c, c.Valide()
}

func (c *Config) completer() {
	if c.CA.DureeJours == 0 {
		c.CA.DureeJours = 365
	}
	base := TiersParDefaut()
	for nom, t := range c.Tiers {
		b := base[nom]
		if t.Channels != nil {
			b.Channels = t.Channels
		}
		if t.Rights != nil {
			b.Rights = t.Rights
		}
		if t.AppStore != "" {
			b.AppStore = t.AppStore
		}
		if b.Sync == nil {
			b.Sync = map[string]Duree{}
		}
		for k, v := range t.Sync {
			b.Sync[k] = v
		}
		base[nom] = b
	}
	c.Tiers = base
}

func (c *Config) Valide() error {
	if c.Role != "member" && c.Role != "authority" {
		return fmt.Errorf("role : member ou authority, pas %q", c.Role)
	}
	if _, ok := c.Tiers[c.Tier]; !ok {
		return fmt.Errorf("tier inconnu : %q (connus : %s)", c.Tier, strings.Join(c.NomsTiers(), ", "))
	}
	if c.CA.DureeJours < 1 || c.CA.DureeJours > 3650 {
		return errors.New("ca.duree_jours : 1 à 3650")
	}
	return nil
}

func (c *Config) NomsTiers() []string {
	n := make([]string, 0, len(c.Tiers))
	for k := range c.Tiers {
		n = append(n, k)
	}
	sort.Strings(n)
	return n
}

// Intervalle : ce que la box appliquera pour `quoi` (waf, appstore, metapack).
//
// LE TIER EST UN PLANCHER DE FRÉQUENCE, PAS UNE CONSIGNE. Une box peut choisir
// de synchroniser MOINS souvent que son abonnement ne le permet (bande
// passante, sobriété) ; elle ne peut pas le faire PLUS souvent — la surcharge
// locale plus courte que le tier est ramenée au tier.
func (c *Config) Intervalle(tier, quoi string) Duree {
	t := c.Tiers[tier]
	base, ok := t.Sync[quoi]
	if !ok {
		base = Duree(24 * time.Hour)
	}
	if v, ok := c.Sync[quoi]; ok && v > base {
		return v
	}
	return base
}
