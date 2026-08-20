// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// See LICENCE-CMSD-1.0.md for terms.

package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// Ban nft natif (#1070, phase B).
//
// Jusqu'ici le WAF déléguait TOUT le ban à CrowdSec (cscli → bouncer → nft). Un
// WAF sans CrowdSec ne bloquait donc rien. NftBanner rend le WAF AUTONOME : il
// gère son PROPRE set nft `inet secubox waf_ban{,6}` avec un `timeout` par
// élément — le noyau retire l'IP à l'échéance (le retrait différé). Le journal
// (BanStore) assure la persistance au restart et l'audit.
//
// Ça tourne EN PARALLÈLE de CrowdSec : les deux backends sont appelés à chaque
// ban, mais le drop nft est effectif même si CrowdSec est absent.
//
// Le processus a besoin de CAP_NET_ADMIN (ou `sudo nft`) — sinon `nft` échoue et
// on se rabat sur CrowdSec seul, en journalisant.

// nftRunner exécute `nft <args...>`. Injectable pour les tests.
type nftRunner func(ctx context.Context, args ...string) ([]byte, error)

// NftBanner pose des bans dans un set nft à timeout.
type NftBanner struct {
	nftPath  string
	table    string
	set4     string
	set6     string
	duration time.Duration
	store    *BanStore
	runner   nftRunner

	cooldown time.Duration
	mu       sync.Mutex
	recent   map[string]time.Time // ip → dernier ban (anti-tempête)
	ready    bool
}

// NewNftBanner construit le banneur. `store` peut être nil (pas de persistance).
func NewNftBanner(nftPath, table string, duration time.Duration, store *BanStore) *NftBanner {
	if nftPath == "" {
		nftPath = "nft"
	}
	if table == "" {
		table = "secubox"
	}
	b := &NftBanner{
		nftPath:  nftPath,
		table:    table,
		set4:     "waf_ban",
		set6:     "waf_ban6",
		duration: duration,
		store:    store,
		cooldown: 30 * time.Second,
		recent:   make(map[string]time.Time),
	}
	b.runner = b.execNft
	return b
}

func (b *NftBanner) execNft(ctx context.Context, args ...string) ([]byte, error) {
	// argv discrets : une IP influençable ne peut pas injecter d'argument (elle
	// est déjà validée en amont), et il n'y a pas de shell.
	return exec.CommandContext(ctx, b.nftPath, args...).CombinedOutput()
}

// Ensure crée table + sets de façon idempotente. À appeler une fois au
// démarrage. Renvoie une erreur si nft n'est pas utilisable (droits) — l'appelant
// désactive alors le backend nft et garde CrowdSec.
func (b *NftBanner) Ensure() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmds := [][]string{
		{"add", "table", "inet", b.table},
		{"add", "set", "inet", b.table, b.set4, "{", "type", "ipv4_addr;", "flags", "timeout;", "}"},
		{"add", "set", "inet", b.table, b.set6, "{", "type", "ipv6_addr;", "flags", "timeout;", "}"},
	}
	for _, c := range cmds {
		if out, err := b.runner(ctx, c...); err != nil {
			return fmt.Errorf("nft %s: %v: %s", strings.Join(c, " "), err, strings.TrimSpace(string(out)))
		}
	}
	b.mu.Lock()
	b.ready = true
	b.mu.Unlock()
	return nil
}

func (b *NftBanner) setPour(ip string) (string, bool) {
	p := net.ParseIP(ip)
	if p == nil {
		return "", false
	}
	if p.To4() != nil {
		return b.set4, true
	}
	return b.set6, true
}

// Ban ajoute l'IP au set nft avec un timeout, et journalise ban. Anti-tempête
// par IP (cooldown) : la réponse graduée appelle Ban à CHAQUE requête bannie.
func (b *NftBanner) Ban(ip, cat, sev string) {
	b.mu.Lock()
	if !b.ready {
		b.mu.Unlock()
		return
	}
	now := time.Now()
	if last, ok := b.recent[ip]; ok && now.Sub(last) < b.cooldown {
		b.mu.Unlock()
		return
	}
	b.recent[ip] = now
	if len(b.recent) > 4096 {
		for k, t := range b.recent {
			if now.Sub(t) > b.cooldown {
				delete(b.recent, k)
			}
		}
	}
	b.mu.Unlock()

	set, ok := b.setPour(ip)
	if !ok {
		return
	}
	secs := int(b.duration.Seconds())
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	elem := fmt.Sprintf("{ %s timeout %ds }", ip, secs)
	if out, err := b.runner(ctx, "add", "element", "inet", b.table, set, elem); err != nil {
		log.Printf("sbxwaf: nft ban échec %s (%s): %v: %s", ip, cat, err, strings.TrimSpace(string(out)))
		b.mu.Lock()
		delete(b.recent, ip) // laisser le prochain coup réessayer
		b.mu.Unlock()
		return
	}
	if b.store != nil {
		_ = b.store.Append(BanRecord{
			IP: ip, Category: cat, Severity: sev,
			At: now.Unix(), Expires: now.Add(b.duration).Unix(), Action: "ban",
		})
	}
	log.Printf("sbxwaf: nft BAN %s ← %s (sev=%s, dur=%s)", ip, cat, sev, b.duration)
}

// Reload ré-injecte dans nft les bans encore actifs du journal (démarrage).
// C'est ce qui fait SURVIVRE les bans au redémarrage du WAF. Le timeout ré-armé
// est le RESTE à courir, pas la durée pleine.
func (b *NftBanner) Reload() int {
	if b.store == nil {
		return 0
	}
	now := time.Now()
	actifs := b.store.ActiveBans(now.Unix())
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	n := 0
	for _, r := range actifs {
		set, ok := b.setPour(r.IP)
		if !ok {
			continue
		}
		reste := r.Expires - now.Unix()
		if r.Expires == 0 {
			reste = int64(b.duration.Seconds())
		}
		if reste <= 0 {
			continue
		}
		elem := fmt.Sprintf("{ %s timeout %ds }", r.IP, reste)
		if _, err := b.runner(ctx, "add", "element", "inet", b.table, set, elem); err == nil {
			n++
		}
	}
	if n > 0 {
		log.Printf("sbxwaf: nft — %d ban(s) ré-injecté(s) depuis le journal", n)
	}
	return n
}
