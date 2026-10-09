// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package main

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/CyberMind-FR/secubox-deb/secubox-toolbox-ng/internal/actor/emit"
)

// L'auto-test de health-doctor (#2200) n'est pas une menace : il ne doit entrer ni dans waf-threats.log, ni dans les statistiques, ni dans actord.
const uaAutoTest = "SecuBox-WAF-SelfTest/1 (health-doctor)"

func TestEstAutoTest(t *testing.T) {
	cas := []struct {
		ip, ua string
		want   bool
	}{
		{"198.51.100.77", uaAutoTest, true},
		{"198.51.100.1", "SecuBox-WAF-SelfTest/2", true},
		{"198.51.100.77", "Mozilla/5.0", false},    // la bonne adresse sans le bon User-Agent
		{"198.51.100.77", "", false},               //
		{"203.0.113.9", uaAutoTest, false},         // un vrai attaquant qui copie le User-Agent reste une menace
		{"8.8.8.8", uaAutoTest, false},             //
		{"198.51.101.5", uaAutoTest, false},        // hors du /24 réservé
		{"198.51.100.77", "x" + uaAutoTest, false}, // préfixe exact
		{"local", uaAutoTest, false},               //
		{"", uaAutoTest, false},                    //
		{"not-an-ip", uaAutoTest, false},           //
	}
	for _, c := range cas {
		if got := estAutoTest(c.ip, c.ua); got != c.want {
			t.Errorf("estAutoTest(%q, %q) = %v, attendu %v", c.ip, c.ua, got, c.want)
		}
	}
}

func lire(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		return ""
	}
	return string(b)
}

func TestRecordAutoTestVaDansSonJournalEtNeEmetRien(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "actord.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	recu := make(chan string, 8)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				buf := make([]byte, 65536)
				n, _ := c.Read(buf)
				recu <- string(buf[:n])
			}(c)
		}
	}()
	log := NewThreatLog(filepath.Join(dir, "waf-threats.log"))
	em := emit.New(sock, 16)
	defer em.Close()
	log.SetEmitter(em)

	log.Record(ThreatRecord{ClientIP: "198.51.100.77", Host: "x.gk2.net", Method: "GET", Path: "/etc/passwd", Category: "lfi", Severity: "critical", Action: "banned", UA: uaAutoTest})
	log.Record(ThreatRecord{ClientIP: "203.0.113.9", Host: "x.gk2.net", Method: "GET", Path: "/etc/passwd", Category: "lfi", Severity: "critical", Action: "banned", UA: "curl/8"})

	menaces := lire(t, filepath.Join(dir, "waf-threats.log"))
	autotest := lire(t, filepath.Join(dir, "waf-selftest.log"))
	if strings.Contains(menaces, "198.51.100.77") {
		t.Errorf("l'auto-test ne doit pas être dans waf-threats.log : %s", menaces)
	}
	if !strings.Contains(menaces, "203.0.113.9") {
		t.Errorf("un vrai événement doit rester dans waf-threats.log : %s", menaces)
	}
	if !strings.Contains(autotest, "198.51.100.77") || strings.Contains(autotest, "203.0.113.9") {
		t.Errorf("waf-selftest.log doit contenir l'auto-test, et lui seul : %s", autotest)
	}
	select {
	case msg := <-recu:
		if strings.Contains(msg, "198.51.100.77") {
			t.Errorf("l'auto-test ne doit pas être émis à actord : %s", msg)
		}
		if !strings.Contains(msg, "203.0.113.9") {
			t.Errorf("le vrai événement doit être émis : %s", msg)
		}
	case <-time.After(2 * time.Second):
		t.Error("le vrai événement n'a pas été émis")
	}
}
