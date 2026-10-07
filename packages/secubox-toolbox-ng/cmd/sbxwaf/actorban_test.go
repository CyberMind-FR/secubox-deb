// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type banneurFaux struct{ bans [][3]string }

func (b *banneurFaux) Ban(ip, cat, sev string) { b.bans = append(b.bans, [3]string{ip, cat, sev}) }

func montage(t *testing.T, mode string, props []actorProp, historique []BanRecord) (*ActorBan, *banneurFaux, string) {
	t.Helper()
	dir := t.TempDir()
	now := time.Unix(1_700_000_000, 0)
	b, _ := json.Marshal(actorFichier{GenereLe: now.Unix(), Propositions: props})
	chemin := filepath.Join(dir, "p.json")
	_ = os.WriteFile(chemin, b, 0o640)
	store := NewBanStore(filepath.Join(dir, "bans.jsonl"))
	for _, r := range historique {
		_ = store.Append(r)
	}
	f := &banneurFaux{}
	ab := NewActorBan(chemin, mode, store, f)
	ab.etat = filepath.Join(dir, "etat.json")
	ab.now = func() time.Time { return now }
	return ab, f, ab.etat
}

func deuxBans(ip string, at int64) []BanRecord {
	return []BanRecord{{IP: ip, Category: "lfi", At: at - 3600, Action: "ban"}, {IP: ip, Category: "scanners", At: at - 600, Action: "ban"}}
}

var now0 = int64(1_700_000_000)

func prop(ip string) actorProp {
	return actorProp{Actor: "ACT-1", Mode: "DENY", IPs: []string{ip}, TTLs: 3600}
}

func TestAutoBanneUneIPDejaBannieDeuxFoisParLeWAF(t *testing.T) {
	ab, f, _ := montage(t, "auto", []actorProp{prop("203.0.113.5")}, deuxBans("203.0.113.5", now0))
	ab.Tick()
	if len(f.bans) != 1 || f.bans[0][0] != "203.0.113.5" || f.bans[0][1] != "actor:ACT-1" {
		t.Fatalf("bans: %+v", f.bans)
	}
}

func TestUneSeuleSanctionNeSuffitPas(t *testing.T) {
	h := []BanRecord{{IP: "203.0.113.5", Category: "lfi", At: now0 - 600, Action: "ban"}}
	ab, f, _ := montage(t, "auto", []actorProp{prop("203.0.113.5")}, h)
	ab.Tick()
	if len(f.bans) != 0 {
		t.Fatalf("ne doit rien bannir: %+v", f.bans)
	}
}

func TestLesBansAuto_NeSontPasComptesCommePreuve(t *testing.T) {
	h := []BanRecord{{IP: "203.0.113.5", Category: "actor:ACT-1", At: now0 - 600, Action: "ban"}, {IP: "203.0.113.5", Category: "actor:ACT-1", At: now0 - 300, Action: "ban"}}
	ab, f, _ := montage(t, "auto", []actorProp{prop("203.0.113.5")}, h)
	ab.Tick()
	if len(f.bans) != 0 {
		t.Fatalf("un ban automatique ne doit pas se nourrir de lui-même: %+v", f.bans)
	}
}

func TestLesSanctionsTropAnciennesNeCompentPas(t *testing.T) {
	h := []BanRecord{{IP: "203.0.113.5", Category: "lfi", At: now0 - 3*86400, Action: "ban"}, {IP: "203.0.113.5", Category: "lfi", At: now0 - 2*86400, Action: "ban"}}
	ab, f, _ := montage(t, "auto", []actorProp{prop("203.0.113.5")}, h)
	ab.Tick()
	if len(f.bans) != 0 {
		t.Fatalf("hors fenêtre: %+v", f.bans)
	}
}

func TestAdressesProtegeesJamaisBannies(t *testing.T) {
	for _, ip := range []string{"192.168.1.200", "10.10.0.1", "127.0.0.1", "fe80::1", "fd00::1", "::1", "224.0.0.1", "0.0.0.0", "pas-une-ip", "82.67.100.75"} {
		ab, f, _ := montage(t, "auto", []actorProp{prop(ip)}, deuxBans(ip, now0))
		ab.protegees = parseCIDRs("82.67.100.75/32")
		ab.Tick()
		if len(f.bans) != 0 {
			t.Fatalf("%s ne doit jamais être banni: %+v", ip, f.bans)
		}
	}
}

func TestModeProposeNAppliqueRienMaisEcritLesCandidats(t *testing.T) {
	ab, f, etat := montage(t, "propose", []actorProp{prop("203.0.113.5")}, deuxBans("203.0.113.5", now0))
	ab.Tick()
	if len(f.bans) != 0 {
		t.Fatal("propose ne bannit pas")
	}
	var e actorEtat
	b, _ := os.ReadFile(etat)
	if json.Unmarshal(b, &e) != nil || e.Mode != "propose" || len(e.Candidats) != 1 || e.Candidats[0].Decision != "a_bannir" || e.Candidats[0].DejaBans != 2 {
		t.Fatalf("état: %s", b)
	}
}

func TestPlafondHoraireCoupeCircuit(t *testing.T) {
	var props []actorProp
	var h []BanRecord
	for i := 1; i <= 5; i++ {
		ip := "203.0.113." + string(rune('0'+i))
		props = append(props, prop(ip))
		h = append(h, deuxBans(ip, now0)...)
	}
	ab, f, etat := montage(t, "auto", props, h)
	ab.maxParHeure = 3
	ab.Tick()
	if len(f.bans) != 3 {
		t.Fatalf("plafond: %d bans", len(f.bans))
	}
	ab.Tick() // le plafond tient sur l'heure glissante, pas par passage
	if len(f.bans) != 3 {
		t.Fatalf("second passage: %d bans", len(f.bans))
	}
	b, _ := os.ReadFile(etat)
	var e actorEtat
	_ = json.Unmarshal(b, &e)
	if !e.PlafondAtteint {
		t.Fatalf("le plafond doit être signalé: %s", b)
	}
}

func TestFichierPerimeOuAbsentNeFaitRien(t *testing.T) {
	ab, f, _ := montage(t, "auto", []actorProp{prop("203.0.113.5")}, deuxBans("203.0.113.5", now0))
	ab.now = func() time.Time { return time.Unix(now0+3600, 0) } // fichier vieux d'une heure
	ab.Tick()
	if len(f.bans) != 0 {
		t.Fatal("fichier périmé ignoré")
	}
	ab.chemin = "/nexiste/pas"
	ab.Tick()
}

func TestModeInconnuOuOffNeFaitRien(t *testing.T) {
	ab, f, _ := montage(t, "off", []actorProp{prop("203.0.113.5")}, deuxBans("203.0.113.5", now0))
	ab.Tick()
	if len(f.bans) != 0 {
		t.Fatal("off")
	}
}
