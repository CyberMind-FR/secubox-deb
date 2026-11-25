// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// See LICENCE-CMSD-1.0.md for terms.

package main

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// Banc du port fermé pendant un redémarrage (#3932), vrai binaire et vrai nft dans un espace de noms réseau :
//
//	unshare -rn sh -c 'ip link set lo up; SBXWAF_BANC=/chemin/sbxwaf sbxwaf.test -test.run BancPortFerme -test.v'
//
// SBXWAF_BANC_NFT_LENT=0.5 : chaque appel à nft attend autant (gk2, ensembles de 10 000 bans, met ~0,5 s par commande).
func TestBancPortFerme(t *testing.T) {
	bin := os.Getenv("SBXWAF_BANC")
	if bin == "" {
		t.Skip("SBXWAF_BANC non posé")
	}
	_ = exec.Command("nft", "flush", "ruleset").Run()
	d := t.TempDir()
	ecrire := func(nom, texte string, mode os.FileMode) string {
		p := filepath.Join(d, nom)
		if err := os.WriteFile(p, []byte(texte), mode); err != nil {
			t.Fatal(err)
		}
		return p
	}
	nft := "nft"
	if lent := os.Getenv("SBXWAF_BANC_NFT_LENT"); lent != "" {
		nft = ecrire("nft-lent", "#!/bin/sh\nsleep "+lent+"\nexec nft \"$@\"\n", 0o755)
	}
	store := NewBanStore(filepath.Join(d, "bans.jsonl"))
	ecrireJournal(t, store, bansTest(10000, time.Now().Unix()))
	const adresse = "127.0.0.1:18085"
	lancer := func() *exec.Cmd {
		c := exec.Command(bin, "--listen", adresse, "--routes", ecrire("h.json", "{}", 0o600),
			"--rules", "../../../secubox-waf-ng/composants/waf/config/waf-rules.json",
			"--nft-ban", "--nft-path", nft, "--ban-store", store.path, "--nft-etat", filepath.Join(d, "etat.json"), "--actor-socket", "",
			"--threat-log", filepath.Join(d, "menaces.log"), "--cookie-audit-log", "", "--media-cache-dir", "", "--visits-stats", "",
			"--vhost-signals", "", "--host-anomaly=false", "--mesures-preuves", filepath.Join(d, "m.jsonl"),
			"--reevaluation-preuves", filepath.Join(d, "r.jsonl"))
		if err := c.Start(); err != nil {
			t.Fatal(err)
		}
		return c
	}
	ouvert := func(depuis time.Time) time.Duration {
		for time.Since(depuis) < 60*time.Second {
			if c, err := net.DialTimeout("tcp", adresse, 50*time.Millisecond); err == nil {
				c.Close()
				return time.Since(depuis)
			}
			time.Sleep(time.Millisecond)
		}
		t.Fatal("port jamais ouvert")
		return 0
	}
	servi := func(depuis time.Time) time.Duration {
		r, err := (&http.Client{Timeout: 60 * time.Second}).Get("http://" + adresse + "/")
		if err != nil {
			t.Fatal(err)
		}
		r.Body.Close()
		return time.Since(depuis)
	}
	p := lancer()
	froid := time.Now()
	t.Logf("démarrage à froid (table absente) : port ouvert %s, première réponse %s", ouvert(froid), servi(froid))
	time.Sleep(8 * time.Second) // la première repose finit
	for i := 0; i < 3; i++ {
		debut := time.Now()
		_ = p.Process.Signal(syscall.SIGTERM)
		_ = p.Wait()
		p = lancer()
		t.Logf("redémarrage : port fermé %s, première réponse %s", ouvert(debut), servi(debut))
		out, _ := exec.Command("sh", "-c", "nft -j list set inet secubox waf_ban | tr , '\\n' | grep -c '\"val\"'").Output()
		t.Logf("  bans appliqués par le noyau à cet instant : %s", fmt.Sprint(string(out)))
		time.Sleep(6 * time.Second)
	}
	_ = p.Process.Kill()
	_ = p.Wait()
}
