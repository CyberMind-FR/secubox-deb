// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// See LICENCE-CMSD-1.0.md for terms.

package main

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type fauxNft struct {
	mu   sync.Mutex
	cmds [][]string
	fail bool
}

func (f *fauxNft) run(_ context.Context, args ...string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.cmds = append(f.cmds, args)
	if f.fail {
		return []byte("Operation not permitted"), errors.New("nft fail")
	}
	return nil, nil
}

func (f *fauxNft) dernier() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.cmds) == 0 {
		return nil
	}
	return f.cmds[len(f.cmds)-1]
}

func joint(a []string) string { return strings.Join(a, " ") }

func banneurTest(t *testing.T, fx *fauxNft) *NftBanner {
	t.Helper()
	store := NewBanStore(filepath.Join(t.TempDir(), "bans.jsonl"))
	b := NewNftBanner("nft", "secubox", time.Hour, store)
	b.runner = fx.run
	b.cooldown = time.Hour // fige le cooldown pour les tests
	return b
}

func TestNftBanner_EnsurePuisBan(t *testing.T) {
	fx := &fauxNft{}
	b := banneurTest(t, fx)

	if err := b.Ensure(); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	if len(fx.cmds) != 3 {
		t.Fatalf("Ensure attendait 3 commandes (table+set4+set6), obtenu %d", len(fx.cmds))
	}

	b.Ban("203.0.113.7", "host_anomaly:ip_literal", "high")
	got := joint(fx.dernier())
	if !strings.Contains(got, "add element inet secubox waf_ban") ||
		!strings.Contains(got, "203.0.113.7 timeout 3600s") {
		t.Fatalf("commande de ban inattendue: %q", got)
	}
	// journal : un ban actif.
	if act := b.store.ActiveBans(time.Now().Unix()); len(act) != 1 || act[0].IP != "203.0.113.7" {
		t.Fatalf("journal attendu 1 ban actif, obtenu %+v", act)
	}
}

func TestNftBanner_IPv6UtiliseLeBonSet(t *testing.T) {
	fx := &fauxNft{}
	b := banneurTest(t, fx)
	_ = b.Ensure()
	b.Ban("2001:db8::1", "scanners", "medium")
	if got := joint(fx.dernier()); !strings.Contains(got, "waf_ban6") {
		t.Fatalf("IPv6 devait viser waf_ban6, obtenu: %q", got)
	}
}

func TestNftBanner_PasPretNeFaitRien(t *testing.T) {
	fx := &fauxNft{}
	b := banneurTest(t, fx)
	// pas de Ensure → pas prêt
	b.Ban("203.0.113.9", "x", "high")
	if len(fx.cmds) != 0 {
		t.Fatalf("un banneur non prêt ne doit pas toucher nft, obtenu %v", fx.cmds)
	}
}

func TestNftBanner_CooldownDedup(t *testing.T) {
	fx := &fauxNft{}
	b := banneurTest(t, fx)
	_ = b.Ensure()
	n0 := len(fx.cmds)
	b.Ban("203.0.113.5", "x", "high")
	b.Ban("203.0.113.5", "x", "high") // même IP, dans le cooldown
	if got := len(fx.cmds) - n0; got != 1 {
		t.Fatalf("cooldown: attendu 1 commande de ban, obtenu %d", got)
	}
}

func TestNftBanner_ReloadReinjecte(t *testing.T) {
	fx := &fauxNft{}
	b := banneurTest(t, fx)
	_ = b.Ensure()
	// deux bans persistés
	b.Ban("203.0.113.1", "x", "high")
	b.Ban("203.0.113.2", "x", "high")

	// nouveau banneur, même journal → Reload doit ré-injecter 2 éléments.
	fx2 := &fauxNft{}
	b2 := NewNftBanner("nft", "secubox", time.Hour, b.store)
	b2.runner = fx2.run
	if n := b2.Reload(); n != 2 {
		t.Fatalf("Reload attendait 2 ré-injections, obtenu %d", n)
	}
}

func TestBanStore_UnbanEtEcheance(t *testing.T) {
	s := NewBanStore(filepath.Join(t.TempDir(), "b.jsonl"))
	now := time.Now().Unix()
	_ = s.Append(BanRecord{IP: "1.1.1.1", At: now, Expires: now + 3600, Action: "ban"})
	_ = s.Append(BanRecord{IP: "2.2.2.2", At: now, Expires: now + 3600, Action: "ban"})
	_ = s.Append(BanRecord{IP: "2.2.2.2", At: now, Action: "unban"}) // levé
	_ = s.Append(BanRecord{IP: "3.3.3.3", At: now - 7200, Expires: now - 3600, Action: "ban"}) // échu

	act := s.ActiveBans(now)
	if len(act) != 1 || act[0].IP != "1.1.1.1" {
		t.Fatalf("attendu seul 1.1.1.1 actif, obtenu %+v", act)
	}
}
