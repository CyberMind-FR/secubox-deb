// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// See LICENCE-CMSD-1.0.md for terms.

package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// #3988 : un leurre de service bannit 24 h au premier contact, 7 j à la
// récidive ; les mots de passe ratés gardent `--duree-ban`.
func TestLeurreBannit24hPuis7j(t *testing.T) {
	k := &noyauAbsent{}
	b := NewBanneur("nft", "secubox", "waf_ban", "waf_ban6", 4*time.Hour, false)
	b.exec = k.run
	ctx := context.Background()

	if d, err := b.BannitLeurre(ctx, "203.0.113.40"); err != nil || d != 24*time.Hour {
		t.Fatalf("premier contact : 24 h attendues, obtenu %s (%v)", d, err)
	}
	if !strings.Contains(k.cmds[len(k.cmds)-1], "203.0.113.40 timeout 86400s") {
		t.Fatalf("élément nft inattendu : %s", k.cmds[len(k.cmds)-1])
	}
	if d, _ := b.BannitLeurre(ctx, "203.0.113.40"); d != 7*24*time.Hour {
		t.Fatalf("récidive : 7 j attendus, obtenu %s", d)
	}
	_ = b.Bannit(ctx, "203.0.113.41")
	if !strings.Contains(k.cmds[len(k.cmds)-1], "203.0.113.41 timeout 14400s") {
		t.Fatalf("mot de passe raté : --duree-ban (4 h) inchangée, obtenu %s", k.cmds[len(k.cmds)-1])
	}
	if _, err := b.BannitLeurre(ctx, "192.168.1.5"); err == nil {
		t.Fatal("une adresse privée ne doit jamais être bannie")
	}
}

func TestRegleLeurresRecidiveJamaisPlusCourte(t *testing.T) {
	b := NewBanneur("nft", "secubox", "waf_ban", "waf_ban6", time.Hour, true)
	b.RegleLeurres(48*time.Hour, time.Hour)
	if b.dureeLeurre != 48*time.Hour || b.dureeLeurreRecidive != 48*time.Hour {
		t.Fatalf("obtenu %s / %s", b.dureeLeurre, b.dureeLeurreRecidive)
	}
}

// appliquer : un signal de leurre passe par la durée des leurres.
func TestTraiteLeurreDuree24h(t *testing.T) {
	k := &noyauAbsent{}
	b := NewBanneur("nft", "secubox", "waf_ban", "waf_ban6", 4*time.Hour, false)
	b.exec = k.run
	sig := Signal{IP: "203.0.113.42", Service: "telnet", Categorie: "leurre:telnet"}
	appliquer(context.Background(), sig, 1, b, nil, false)
	if !strings.Contains(strings.Join(k.cmds, "\n"), "203.0.113.42 timeout 86400s") {
		t.Fatalf("leurre : 24 h attendues, %v", k.cmds)
	}
}

// Au redémarrage, un ban de leurre de 10 h retrouvé dans le journal court
// encore (24 h), un ban de mot de passe du même âge est échu (4 h).
func TestRechargeJournalDureeLeurre(t *testing.T) {
	chemin := filepath.Join(t.TempDir(), "waf-threats.log")
	now := time.Now()
	l := func(ip, cat string, il time.Duration) string {
		return fmt.Sprintf(`{"timestamp":%q,"client_ip":%q,"category":%q,"action":"banned","tool":"authwatch"}`+"\n",
			now.Add(-il).Format(time.RFC3339), ip, cat)
	}
	_ = os.WriteFile(chemin, []byte(
		l("203.0.113.50", "leurre:rdp", 10*time.Hour)+
			l("203.0.113.51", "ssh_auth_failed", 10*time.Hour)+
			l("203.0.113.52", "leurre:mssql", 40*time.Hour)+ // premier : échu
			l("203.0.113.52", "leurre:mssql", 30*time.Hour)), 0o600) // récidive : 7 j, court encore
	b := NewBanneur("nft", "secubox", "waf_ban", "waf_ban6", 4*time.Hour, false)
	if n := b.RechargeJournal([]string{chemin}, now); n != 2 {
		t.Fatalf("2 bans actifs attendus (…50 et …52), obtenu %d : %v", n, b.actifs)
	}
	if _, ok := b.actifs["203.0.113.51"]; ok {
		t.Fatal("le ban de mot de passe (4 h) devait être échu")
	}
	if fin := b.actifs["203.0.113.52"]; fin.Sub(now) < 100*time.Hour {
		t.Fatalf("récidive : échéance à ~138 h attendue, obtenu %s", fin.Sub(now))
	}
}
