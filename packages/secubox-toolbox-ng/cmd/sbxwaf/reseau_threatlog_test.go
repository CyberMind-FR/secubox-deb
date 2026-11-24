// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package main

import (
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/CyberMind-FR/secubox-deb/secubox-toolbox-ng/internal/actor/emit"
	"github.com/CyberMind-FR/secubox-deb/secubox-toolbox-ng/internal/reseau"
)

// classeurFactice répond comme un annuaire, sans base mmdb (#3919).
type classeurFactice struct{ vus []string }

func (c *classeurFactice) Classer(ip string) reseau.Info {
	c.vus = append(c.vus, ip)
	if ip == "8.8.8.8" {
		return reseau.Info{ASN: 15169, Org: "GOOGLE", Classe: "hebergeur"}
	}
	return reseau.Info{Classe: "inconnu"}
}

func TestRecordPoseLeReseau(t *testing.T) {
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
	tl := NewThreatLog(filepath.Join(dir, "waf-threats.log"))
	em := emit.New(sock, 16)
	defer em.Close()
	tl.SetEmitter(em)
	tl.reseau = &classeurFactice{}

	tl.Record(ThreatRecord{ClientIP: "8.8.8.8", Host: "x.gk2.net", Method: "GET", Path: "/etc/passwd", Category: "lfi", Severity: "critical", Action: "banned", UA: "curl/8"})

	ligne := lire(t, filepath.Join(dir, "waf-threats.log"))
	for _, want := range []string{`"asn":15169`, `"asn_org":"GOOGLE"`, `"reseau_classe":"hebergeur"`} {
		if !strings.Contains(ligne, want) {
			t.Errorf("ligne sans %s : %s", want, ligne)
		}
	}
	select {
	case msg := <-recu:
		if !strings.Contains(msg, `"asn":15169`) {
			t.Errorf("enveloppe sans asn : %s", msg)
		}
	case <-time.After(2 * time.Second):
		t.Error("enveloppe non émise")
	}
}

func TestRecordSansAnnuaire(t *testing.T) {
	dir := t.TempDir()
	tl := NewThreatLog(filepath.Join(dir, "waf-threats.log"))
	tl.Record(ThreatRecord{ClientIP: "8.8.8.8", Host: "x.gk2.net", Method: "GET", Path: "/x", Category: "lfi", Severity: "high", Action: "detect", UA: "curl/8"})
	ligne := lire(t, filepath.Join(dir, "waf-threats.log"))
	if ligne == "" {
		t.Fatal("aucune ligne écrite")
	}
	for _, non := range []string{"\"asn\"", "asn_org", "reseau_classe"} {
		if strings.Contains(ligne, non) {
			t.Errorf("clé %s inattendue sans annuaire : %s", non, ligne)
		}
	}
}

func TestRecordAdresseLocale(t *testing.T) {
	dir := t.TempDir()
	tl := NewThreatLog(filepath.Join(dir, "waf-threats.log"))
	tl.reseau = &classeurFactice{}
	tl.Record(ThreatRecord{ClientIP: "10.1.2.3", Host: "x.gk2.net", Method: "GET", Path: "/x", Category: "lfi", Severity: "high", Action: "detect", UA: "curl/8"})
	ligne := lire(t, filepath.Join(dir, "waf-threats.log"))
	if !strings.Contains(ligne, `"client_ip":"local"`) {
		t.Errorf("client_ip local attendu : %s", ligne)
	}
	for _, non := range []string{"\"asn\"", "asn_org", "reseau_classe"} {
		if strings.Contains(ligne, non) {
			t.Errorf("clé %s inattendue pour une adresse locale : %s", non, ligne)
		}
	}
}
