// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// See LICENCE-CMSD-1.0.md for terms.

package main

import (
	"os"
	"strings"
	"testing"
	"time"
)

// Bans de rotation (#3919) dans la repose par lots (#3930) : même journal, mêmes levées, jamais plus de 24 h.

func TestRotation_BanAtNeRelabellePasUnBanPlusLong(t *testing.T) {
	now := time.Now().Unix()
	leurre := BanRecord{IP: "203.0.113.1", Category: "leurre:x", Severity: "high", At: now, Expires: now + 7*86400, Action: "ban"}
	court := BanRecord{IP: "203.0.113.2", Category: "leurre:x", Severity: "high", At: now, Expires: now + 3600, Action: "ban"}
	b, k := banneurLots(t, []BanRecord{leurre, court})
	b.cooldown = 0
	for _, ip := range []string{"203.0.113.1", "203.0.113.2", "203.0.113.3"} {
		b.BanFor(ip, "rotation:0a1b2c3d", "high", 24*time.Hour)
	}
	if r, _ := b.store.Actif("203.0.113.1", now); r != leurre || k.elems["203.0.113.1"] < 7*86400-5 {
		t.Fatalf("ban plus long : ligne et échéance gardées, élément posé : %+v %d", r, k.elems["203.0.113.1"])
	}
	for _, ip := range []string{"203.0.113.2", "203.0.113.3"} {
		r, _ := b.store.Actif(ip, now)
		if r.Category != "rotation:0a1b2c3d" || r.Expires > now+86405 || k.elems[ip] > 86400 || k.elems[ip] < 86300 {
			t.Fatalf("%s : rotation, 24 h au plus : %+v %d", ip, r, k.elems[ip])
		}
		if d := Reevaluer(r.Category, 1000, true, 5, time.Hour, 10); d.Action != "RELEASE" {
			t.Fatalf("jamais prolongé : %+v", d)
		}
	}
	// L'inverse : une sanction d'une autre famille remplace la ligne de rotation, sans raccourcir le ban.
	b.BanFor("203.0.113.3", "leurre:x", "high", time.Hour)
	if r, _ := b.store.Actif("203.0.113.3", now); r.Category != "leurre:x" || r.Expires < now+86300 {
		t.Fatalf("sanction après rotation : %+v", r)
	}
}

func TestRotation_ReposeEtLevees(t *testing.T) {
	b, k := banneurLots(t, nil)
	for i := 0; i < 1500; i++ {
		b.BanFor(ipTest(i), "rotation:0a1b2c3d", "high", 24*time.Hour)
	}
	// La ligne que wafctl unban écrit (cat « levee:… »), puis le retrait de l'élément.
	f, err := os.OpenFile(b.store.path, os.O_APPEND|os.O_WRONLY, 0o640)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.WriteString(`{"ip":"` + ipTest(3) + `","cat":"levee:waf-unban","sev":"info","at":1,"exp":0,"action":"unban"}` + "\n")
	f.Close()
	k.flushRuleset()
	_ = b.Ensure()
	b.mu.Lock()
	b.recent = map[string]time.Time{}
	b.mu.Unlock()
	k.avant = func(n int) {
		if n == 1 { // levée pendant la passe, après la pose du premier lot
			_ = b.store.Append(BanRecord{IP: ipTest(1499), Category: "levee:waf-unban", At: time.Now().Unix(), Action: "unban"})
			_ = b.store.Append(BanRecord{IP: ipTest(4), Category: "levee:waf-unban", At: time.Now().Unix(), Action: "unban"})
		}
	}
	b.Reload()
	for _, i := range []int{3, 4, 1499} {
		if _, p := k.elems[ipTest(i)]; p {
			t.Fatalf("%s levé, remis par la repose", ipTest(i))
		}
	}
	if k.nb() != 1497 {
		t.Fatalf("1497 bans de rotation reposés attendus, %d", k.nb())
	}
	for ip, d := range k.elems {
		if d > 86400 {
			t.Fatalf("%s reposé pour %d s, plus de 24 h", ip, d)
		}
	}
	for _, s := range k.scripts {
		if strings.Contains(s, ipTest(3)+" timeout") {
			t.Fatal("un ban levé ne repart dans aucun lot")
		}
	}
}

// VerifieSur partage la mémoire de la repose (Connu) et de LibererRobots : une réponse ferme du détecteur les dispense de DNS.
func TestRotation_VerifieSurEtRobots(t *testing.T) {
	c := NewCrawlers()
	dnsRobot("198.51.100.9").install(c)
	if nom, sur := c.VerifieSur("::ffff:198.51.100.9"); nom == "" || !sur || c.Connu("198.51.100.9") == "" {
		t.Fatalf("robot en IPv4 projetée : %q %t", nom, sur)
	}
	if _, sur := c.VerifieSur("203.0.113.7"); !sur || !c.Resolu("203.0.113.7") {
		t.Fatal("réponse ferme mémorisée")
	}
	c.inverse = dnsInterdit(t).inverse
	if nom, conclu := c.VerifieConclu("203.0.113.7"); nom != "" || !conclu {
		t.Fatal("réponse ferme reprise par LibererRobots")
	}
}
