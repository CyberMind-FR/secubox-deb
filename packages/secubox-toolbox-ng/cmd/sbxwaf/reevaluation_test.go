// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// See LICENCE-CMSD-1.0.md for terms.

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const h = time.Hour

func TestReevaluer_PersistantProlongeEnGradue(t *testing.T) {
	d := Reevaluer("leurre:unrouted", 50, true, 0, 2*h, 10)
	if d.Action != "EXTEND" || d.Duree != 24*h {
		t.Fatalf("un leurre qui insiste pendant son ban : 1 h puis 24 h : %+v", d)
	}
	if d := Reevaluer("campagne:abc", 50, true, 1, 30*h, 10); d.Action != "EXTEND" || d.Duree != 7*24*h {
		t.Fatalf("campagne : 4 h, 24 h, puis 7 j : %+v", d)
	}
}

func TestReevaluer_QuiNInsistePasEstLibere(t *testing.T) {
	d := Reevaluer("leurre:unrouted", 2, true, 0, 2*h, 10)
	if d.Action != "RELEASE" || !strings.Contains(d.Raison, "insist") {
		t.Fatalf("2 paquets pendant le ban : on libère : %+v", d)
	}
}

func TestReevaluer_SansCompteurJamaisDeProlongationALAveugle(t *testing.T) {
	d := Reevaluer("leurre:unrouted", 0, false, 3, 2*h, 10)
	if d.Action != "RELEASE" || !strings.Contains(d.Raison, "compteur") {
		t.Fatalf("sans preuve de persistance : RELEASE : %+v", d)
	}
}

func TestReevaluer_JamaisDeBanPermanentAccidentel(t *testing.T) {
	d := Reevaluer("leurre:unrouted", 9999, true, 5, 30*24*h, 10)
	if d.Action != "RELEASE" || !strings.Contains(d.Raison, "30") {
		t.Fatalf("une chaîne de bans de 30 jours se libère, même si l'adresse insiste : %+v", d)
	}
	d = Reevaluer("leurre:unrouted", 9999, true, 5, 27*24*h, 10)
	if d.Action != "EXTEND" || d.Duree > 3*24*h {
		t.Fatalf("la prolongation ne dépasse jamais le plafond de 30 jours (reste 3 j) : %+v", d)
	}
}

// banc : un banneur au faux nft qui connaît des éléments avec compteurs, un journal et un état de preuves.
type fauxNftElems struct {
	mu    sync.Mutex
	cmds  [][]string
	elems map[string][2]int64 // ip → {paquets, secondes restantes}
}

func (f *fauxNftElems) run(_ context.Context, args ...string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.cmds = append(f.cmds, args)
	if len(args) >= 4 && args[0] == "-j" && args[1] == "list" && args[2] == "set" {
		var el []string
		if args[5] == "waf_ban" {
			for ip, v := range f.elems {
				el = append(el, fmt.Sprintf(`{"elem":{"val":"%s","expires":%d,"counter":{"packets":%d,"bytes":0}}}`, ip, v[1], v[0]))
			}
		}
		return []byte(fmt.Sprintf(`{"nftables":[{"set":{"name":"%s","stmt":[{"counter":null}],"elem":[%s]}}]}`, args[5], strings.Join(el, ","))), nil
	}
	return nil, nil
}

func (f *fauxNftElems) vu(motif string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range f.cmds {
		if strings.Contains(strings.Join(c, " "), motif) {
			return true
		}
	}
	return false
}

func bancReeval(t *testing.T, mode string, elems map[string][2]int64) (*Reeval, *fauxNftElems, *BanStore, string) {
	t.Helper()
	dir := t.TempDir()
	fx := &fauxNftElems{elems: elems}
	store := NewBanStore(filepath.Join(dir, "bans.jsonl"))
	nb := NewNftBanner("nft", "secubox", time.Hour, store)
	nb.runner = fx.run
	nb.cooldown = time.Hour
	nb.ready = true
	r := NewReeval(nb, store, mode, filepath.Join(dir, "reeval.jsonl"))
	r.now = func() time.Time { return time.Unix(1_800_000_000, 0) }
	r.audit = filepath.Join(dir, "audit.log")
	return r, fx, store, dir
}

func poseBan(store *BanStore, ip, cat string, at, exp int64) {
	_ = store.Append(BanRecord{IP: ip, Category: cat, Severity: "high", At: at, Expires: exp, Action: "ban"})
}

func lignesJSON(t *testing.T, chemin string) []map[string]any {
	t.Helper()
	b, _ := os.ReadFile(chemin)
	var out []map[string]any
	for _, l := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		if l == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(l), &m); err != nil {
			t.Fatalf("ligne illisible %q : %v", l, err)
		}
		out = append(out, m)
	}
	return out
}

func TestTick_ProlongeUnBanQuiInsisteEtEnLaisseLaPreuve(t *testing.T) {
	now := int64(1_800_000_000)
	r, fx, store, dir := bancReeval(t, "auto", map[string][2]int64{"198.51.100.5": {40, 45}})
	poseBan(store, "198.51.100.5", "leurre:unrouted", now-3555, now+45)
	r.Tick()
	if !fx.vu("delete element inet secubox waf_ban { 198.51.100.5 }") || !fx.vu("198.51.100.5 timeout 86400s") {
		t.Fatalf("EXTEND : l'élément est retiré puis reposé 24 h : %v", fx.cmds)
	}
	ev := lignesJSON(t, filepath.Join(dir, "reeval.jsonl"))
	if len(ev) != 1 || ev[0]["decision"] != "EXTEND" || ev[0]["applique"] != true || ev[0]["ip"] != "198.51.100.5" || ev[0]["paquets"].(float64) != 40 {
		t.Fatalf("une ligne de preuve par transition : %v", ev)
	}
	if len(lignesJSON(t, r.audit)) != 1 {
		t.Fatal("la transition est aussi une ligne d'audit")
	}
	actifs := store.ActiveBans(now + 1)
	if len(actifs) != 1 || !strings.HasPrefix(actifs[0].Category, "leurre:") || actifs[0].Expires != now+86400 {
		t.Fatalf("le journal de bans porte la prolongation (catégorie de famille conservée) : %+v", actifs)
	}
}

func TestTick_LibereCeluiQuiN_InsistePas_SansToucherNft(t *testing.T) {
	now := int64(1_800_000_000)
	r, fx, store, dir := bancReeval(t, "auto", map[string][2]int64{"198.51.100.6": {1, 30}})
	poseBan(store, "198.51.100.6", "campagne:abc", now-14370, now+30)
	r.Tick()
	if fx.vu("delete element") || fx.vu("add element") {
		t.Fatalf("RELEASE : le timeout nft fait le travail, rien n'est posé ni retiré : %v", fx.cmds)
	}
	ev := lignesJSON(t, filepath.Join(dir, "reeval.jsonl"))
	if len(ev) != 1 || ev[0]["decision"] != "RELEASE" {
		t.Fatalf("la libération laisse sa preuve : %v", ev)
	}
}

func TestTick_ModeProposeNAppliqueRien(t *testing.T) {
	now := int64(1_800_000_000)
	r, fx, store, dir := bancReeval(t, "propose", map[string][2]int64{"198.51.100.7": {99, 20}})
	poseBan(store, "198.51.100.7", "leurre:unrouted", now-3580, now+20)
	r.Tick()
	if fx.vu("delete element") {
		t.Fatalf("propose n'applique rien : %v", fx.cmds)
	}
	ev := lignesJSON(t, filepath.Join(dir, "reeval.jsonl"))
	if len(ev) != 1 || ev[0]["decision"] != "EXTEND" || ev[0]["applique"] != false {
		t.Fatalf("propose écrit ce qu'il ferait : %v", ev)
	}
}

func TestTick_ModeOffNeFaitRien(t *testing.T) {
	now := int64(1_800_000_000)
	r, fx, store, dir := bancReeval(t, "off", map[string][2]int64{"198.51.100.8": {99, 20}})
	poseBan(store, "198.51.100.8", "leurre:unrouted", now-3580, now+20)
	r.Tick()
	if fx.vu("delete element") || len(lignesJSON(t, filepath.Join(dir, "reeval.jsonl"))) != 0 {
		t.Fatalf("off ne fait rien : %v", fx.cmds)
	}
}

func TestTick_UnBanLoinDeLEcheanceNEstPasReevalue(t *testing.T) {
	now := int64(1_800_000_000)
	r, fx, store, dir := bancReeval(t, "auto", map[string][2]int64{"198.51.100.9": {99, 3000}})
	poseBan(store, "198.51.100.9", "leurre:unrouted", now-600, now+3000) // échéance dans 50 min : pas encore l'heure
	r.Tick()
	if fx.vu("delete element") || len(lignesJSON(t, filepath.Join(dir, "reeval.jsonl"))) != 0 {
		t.Fatalf("un ban loin de l'échéance n'est pas réévalué : %v", fx.cmds)
	}
}

func TestTick_UnBanNEstJamaisReevalueDeuxFois(t *testing.T) {
	now := int64(1_800_000_000)
	r, fx, store, dir := bancReeval(t, "auto", map[string][2]int64{"198.51.100.10": {1, 30}})
	poseBan(store, "198.51.100.10", "leurre:unrouted", now-3570, now+30)
	r.Tick()
	r.Tick()
	if n := len(lignesJSON(t, filepath.Join(dir, "reeval.jsonl"))); n != 1 {
		t.Fatalf("une seule réévaluation par ban : %d (%v)", n, fx.cmds)
	}
}

func TestTick_LesBansManuelsHorsJournalNeSontPasTouches(t *testing.T) {
	r, fx, _, dir := bancReeval(t, "auto", map[string][2]int64{"198.51.100.11": {500, 20}}) // dans nft, absent du journal : posé à la main
	r.Tick()
	if fx.vu("delete element") || len(lignesJSON(t, filepath.Join(dir, "reeval.jsonl"))) != 0 {
		t.Fatalf("un ban manuel (hors journal) n'est jamais réévalué : %v", fx.cmds)
	}
}

func TestEnsure_MigreUnEnsembleSansCompteurSansPerdreLaChaine(t *testing.T) {
	fx := &fauxNftMigration{}
	b := NewNftBanner("nft", "secubox", time.Hour, nil)
	b.runner = fx.run
	if err := b.Ensure(); err != nil {
		t.Fatal(err)
	}
	cmds := strings.Join(fx.journal, "\n")
	iFlush, iDel, iAdd := strings.Index(cmds, "flush chain"), strings.Index(cmds, "delete set inet secubox waf_ban"), strings.Index(cmds, "add set inet secubox waf_ban { type ipv4_addr; flags timeout; counter; }")
	if iDel < 0 || iAdd < 0 || iFlush < 0 || !(iFlush < iDel && iDel < iAdd) {
		t.Fatalf("migration : vider la chaîne, supprimer l'ensemble, le recréer avec compteur :\n%s", cmds)
	}
	if strings.Contains(cmds, "delete set inet secubox waf_ban6") {
		t.Fatalf("un ensemble déjà muni de compteur n'est pas touché :\n%s", cmds)
	}
}

type fauxNftMigration struct{ journal []string }

func (f *fauxNftMigration) run(_ context.Context, args ...string) ([]byte, error) {
	f.journal = append(f.journal, strings.Join(args, " "))
	if len(args) >= 6 && args[0] == "-j" && args[1] == "list" && args[2] == "set" {
		stmt := ""
		if args[5] == "waf_ban6" {
			stmt = `,"stmt":[{"counter":null}]`
		}
		return []byte(fmt.Sprintf(`{"nftables":[{"set":{"name":"%s","flags":["timeout"]%s}}]}`, args[5], stmt)), nil
	}
	return nil, nil
}
