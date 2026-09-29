// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// See LICENCE-CMSD-1.0.md for terms.

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// Ban nft natif (#1070, phase B).
//
// Jusqu'ici le WAF déléguait TOUT le ban à un relais externe (→ bouncer → nft). Un
// WAF sans ce relais ne bloquait donc rien. NftBanner rend le WAF AUTONOME : il
// gère son PROPRE set nft `inet secubox waf_ban{,6}` avec un `timeout` par
// élément — le noyau retire l'IP à l'échéance (le retrait différé). Le journal
// (BanStore) assure la persistance au restart et l'audit.
//
// LE WAF BLOQUE LUI-MÊME, sans relais externe (#1218) : l'ancienne voie
// échouait de toute façon en silence (droits/config du relais externe),
// que le compte de service ne peut pas ouvrir.
//
// PIÈGE CORRIGÉ (#1218) : Ensure() ne créait que la table et les deux SETS. Rien
// ne les consultait — aucune chaîne, aucune règle, zéro référence à @waf_ban
// dans tout le jeu de règles. Le banner remplissait donc consciencieusement un
// ensemble que le noyau n'interrogeait jamais : 91 adresses « bannies » qui
// passaient toutes. Un set sans règle ne bloque rien ; la chaîne ci-dessous est
// ce qui rend le blocage réel.
//
// Le processus a besoin de CAP_NET_ADMIN (ou `sudo nft`) — sinon `nft` échoue et
// aucun ban natif n'est posé, en journalisant.

// nftRunner exécute `nft <args...>`. Injectable pour les tests.
type nftRunner func(ctx context.Context, args ...string) ([]byte, error)

// NftBanner pose des bans dans un set nft à timeout.
type NftBanner struct {
	nftPath  string
	table    string
	chain    string
	set4     string
	set6     string
	duration time.Duration
	store    *BanStore
	runner   nftRunner

	cooldown time.Duration
	mu       sync.Mutex
	recent   map[string]time.Time // ip → dernier ban (anti-tempête)
	ready    bool

	// Auto-réparation (#1693). repMu sérialise les réparations : une rafale de
	// bans qui échouent en même temps ne doit recréer la table qu'une fois.
	repMu        sync.Mutex
	reparations  int
	derniereRep  time.Time
	dernierEchec string
	echecA       time.Time
	dernierBan   time.Time
	etatFichier  string // "" = pas d'état écrit (tests)
	etatMu       sync.Mutex
	etatEchoue   bool
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
		chain:    "waf_drop",
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
// désactive alors le backend nft (plus de ban natif).
func (b *NftBanner) Ensure() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmds := [][]string{
		{"add", "table", "inet", b.table},
		{"add", "set", "inet", b.table, b.set4, "{", "type", "ipv4_addr;", "flags", "timeout;", "}"},
		{"add", "set", "inet", b.table, b.set6, "{", "type", "ipv6_addr;", "flags", "timeout;", "}"},
		// La chaîne qui CONSULTE les sets. Sans elle, tout ce qui précède est
		// une comptabilité sans effet. Priorité -100 : avant le filtrage
		// général, pour qu'une source bannie soit écartée au plus tôt.
		// Politique accept : cette chaîne ne fait que retirer les bannis, elle
		// ne décide de rien d'autre — on n'ajoute pas un point de coupure au
		// trafic légitime.
		{"add", "chain", "inet", b.table, b.chain,
			"{", "type", "filter", "hook", "input", "priority", "-100;", "policy", "accept;", "}"},
		// `add rule` n'est PAS idempotent : sans ce flush, chaque démarrage
		// empilerait un doublon de plus.
		{"flush", "chain", "inet", b.table, b.chain},
		{"add", "rule", "inet", b.table, b.chain, "ip", "saddr", "@" + b.set4, "counter", "drop"},
		{"add", "rule", "inet", b.table, b.chain, "ip6", "saddr", "@" + b.set6, "counter", "drop"},
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
//
// GARDE-FOU : une adresse privée n'est JAMAIS ajoutée. Les appelants exemptent
// déjà le LAN, mais ce drop est réel depuis qu'il existe une règle — une seule
// erreur en amont couperait l'accès d'administration à la box, depuis la box.
// Le refus est ici, au dernier moment, où rien ne peut le contourner.
func (b *NftBanner) Ban(ip, cat, sev string) {
	if p := net.ParseIP(ip); p == nil || p.IsLoopback() || p.IsPrivate() || p.IsLinkLocalUnicast() {
		return
	}
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
	out, err := b.runner(ctx, "add", "element", "inet", b.table, set, elem)
	if err != nil && tableEffacee(out) {
		// La table venait d'être effacée par un rechargement du ruleset : elle
		// est recréée (ici, ou par un autre ban de la même rafale qui a pris le
		// verrou d'abord), et le ban est rejoué une fois plutôt que perdu.
		b.Reparer("échec d'un ban")
		out, err = b.runner(ctx, "add", "element", "inet", b.table, set, elem)
	}
	if err != nil {
		msg := strings.TrimSpace(string(out))
		log.Printf("sbxwaf: nft ban échec %s (%s): %v: %s", ip, cat, err, msg)
		b.mu.Lock()
		delete(b.recent, ip) // laisser le prochain coup réessayer
		b.mu.Unlock()
		b.noterEchec(msg)
		return
	}
	b.mu.Lock()
	b.dernierBan = now
	b.mu.Unlock()
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

// ── Auto-réparation (#1693) ──────────────────────────────────────────────────
//
// Ensure ne tourne qu'au démarrage, mais la table ne vit que dans le noyau :
// tout `nft -f /etc/nftables.conf` commence par `flush ruleset` et l'efface
// (`systemctl reload nftables.service` dans un postinst, un outil qui réécrit
// nftables.conf, un redémarrage de nftables.service). Le WAF continuait alors
// à décider des bans que plus rien n'appliquait : chaque `add element`
// échouait, le SOC lisait un ensemble absent comme « aucun ban actif », et
// seul le redémarrage suivant (RuntimeMaxSec=12h) remettait la table. Six
// trous de 6 à 12 h en une semaine sur gk2. Le WAF ne dépend plus de qui
// recharge le pare-feu : il vérifie et répare lui-même.

// tableEffacee reconnaît la réponse de nft quand la table ou l'ensemble visé
// n'existe plus.
func tableEffacee(out []byte) bool {
	return strings.Contains(string(out), "No such file or directory")
}

// Presente dit si le blocage est en place : la chaîne existe ET consulte
// l'ensemble. Tester la seule table ne suffit pas — un `flush table` garde la
// chaîne mais retire les règles, et un ensemble que rien ne consulte ne bloque
// rien (#1218).
func (b *NftBanner) Presente(ctx context.Context) bool {
	out, err := b.runner(ctx, "list", "chain", "inet", b.table, b.chain)
	return err == nil && strings.Contains(string(out), "@"+b.set4)
}

// Reparer recrée la table si elle a disparu et y ré-applique les bans actifs du
// journal. Renvoie true si une réparation a eu lieu. Sans effet sur un banneur
// qui n'a jamais été prêt (nft indisponible au démarrage).
func (b *NftBanner) Reparer(motif string) bool {
	b.mu.Lock()
	pret := b.ready
	b.mu.Unlock()
	if !pret {
		return false
	}
	b.repMu.Lock()
	defer b.repMu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if b.Presente(ctx) {
		return false
	}
	if err := b.Ensure(); err != nil {
		log.Printf("sbxwaf: nft — table inet %s absente (%s) et IMPOSSIBLE à recréer : %v", b.table, motif, err)
		b.noterEchec(err.Error())
		b.EcrireEtat()
		return false
	}
	n := b.Reload()
	b.mu.Lock()
	b.reparations++
	b.derniereRep = time.Now()
	b.mu.Unlock()
	b.EcrireEtat()
	log.Printf("sbxwaf: nft — table inet %s effacée (%s, rechargement du pare-feu ?) : recréée, %d ban(s) ré-appliqué(s)",
		b.table, motif, n)
	return true
}

// Veiller vérifie la table toutes les `pas` et ré-affirme les bans du journal
// toutes les `pasReload` (un `flush set` vide l'ensemble sans toucher la
// chaîne). Ne rend jamais la main.
func (b *NftBanner) Veiller(pas, pasReload time.Duration) {
	t := time.NewTicker(pas)
	defer t.Stop()
	dernier := time.Now()
	b.EcrireEtat()
	for range t.C {
		if b.Reparer("veille") {
			dernier = time.Now()
		} else if time.Since(dernier) >= pasReload {
			b.Reload()
			dernier = time.Now()
		}
		b.EcrireEtat()
	}
}

// EtatNft est l'état du blocage, pour le tableau de bord : un WAF qui décide
// des bans que rien n'applique ne doit plus passer pour un WAF calme.
// Verifie date l'instantané : un fichier qui ne se renouvelle plus veut dire
// un WAF arrêté — ce que personne n'a vu sur gk3, en boucle de redémarrage.
type EtatNft struct {
	Actif        bool   `json:"actif"`
	Table        string `json:"table"`
	Verifie      int64  `json:"verifie"`
	Reparations  int    `json:"reparations"`
	DerniereRep  int64  `json:"derniere_reparation,omitempty"`
	DernierBan   int64  `json:"dernier_ban,omitempty"`
	DernierEchec string `json:"dernier_echec,omitempty"`
	EchecA       int64  `json:"echec_a,omitempty"`
}

func unixOuZero(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.Unix()
}

// Etat renvoie un instantané de l'état du banneur.
func (b *NftBanner) Etat() EtatNft {
	b.mu.Lock()
	defer b.mu.Unlock()
	return EtatNft{
		Actif:        b.ready,
		Table:        "inet " + b.table,
		Verifie:      time.Now().Unix(),
		Reparations:  b.reparations,
		DerniereRep:  unixOuZero(b.derniereRep),
		DernierBan:   unixOuZero(b.dernierBan),
		DernierEchec: b.dernierEchec,
		EchecA:       unixOuZero(b.echecA),
	}
}

func (b *NftBanner) noterEchec(msg string) {
	b.mu.Lock()
	b.dernierEchec, b.echecA = msg, time.Now()
	b.mu.Unlock()
}

// EcrireEtat publie l'état dans etatFichier (écriture atomique). Une erreur
// d'écriture est journalisée une fois, sans jamais gêner le blocage.
func (b *NftBanner) EcrireEtat() {
	if b.etatFichier == "" {
		return
	}
	b.etatMu.Lock()
	defer b.etatMu.Unlock()
	buf, err := json.Marshal(b.Etat())
	if err == nil {
		tmp := b.etatFichier + ".tmp"
		if err = os.WriteFile(tmp, buf, 0o640); err == nil {
			err = os.Rename(tmp, b.etatFichier)
		}
	}
	if err != nil && !b.etatEchoue {
		log.Printf("sbxwaf: état nft non publié dans %s : %v", b.etatFichier, err)
	}
	b.etatEchoue = err != nil
}
