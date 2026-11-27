// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// See LICENCE-CMSD-1.0.md for terms.

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Suites de la relecture de WAF 1.45.0 (#3932).

// ── 1. démarrage ─────────────────────────────────────────────────────────────

func TestEnsure_UneSeuleTransaction(t *testing.T) {
	fx := &fauxNft{}
	b := banneurTest(t, fx)
	if err := b.Ensure(); err != nil {
		t.Fatal(err)
	}
	for _, c := range fx.cmds {
		if j := joint(c); !strings.HasPrefix(j, "-f - ") && !strings.HasPrefix(j, "-j ") {
			t.Fatalf("commande d'écriture hors transaction : %q", j)
		}
	}
}

func TestEnsure_EchecVeilleRetenteEtLEtatLeDit(t *testing.T) {
	b, k := banneurLots(t, bansTest(30, time.Now().Unix()))
	b.ready, k.table = false, false
	b.etatFichier = filepath.Join(t.TempDir(), "e.json")
	var ko atomic.Bool
	ko.Store(true)
	b.scripts = func(ctx context.Context, s []byte) ([]byte, error) {
		if ko.Load() {
			return []byte("Error: Operation not permitted"), errors.New("exit status 1")
		}
		return k.script(ctx, s)
	}
	if err := b.Ensure(); err == nil || b.pret() {
		t.Fatal("la pose échoue")
	}
	var lances atomic.Int32
	b.QuandPret(func() { lances.Add(1) })
	fin := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); b.veillerJusqua(fin, 5*time.Millisecond, time.Hour) }()
	lire := func() (e EtatNft) {
		raw, _ := os.ReadFile(b.etatFichier)
		_ = json.Unmarshal(raw, &e)
		return e
	}
	attendre(t, "état non appliqué publié", func() bool {
		e := lire()
		return !e.Actif && strings.Contains(e.DernierEchec, "Operation not permitted")
	})
	b.Ban("203.0.113.9", "x", "high")
	if k.nb() != 0 || lances.Load() != 0 {
		t.Fatal("rien ne se pose ni ne se lance tant que la chaîne manque")
	}
	ko.Store(false)
	attendre(t, "blocage posé et journal appliqué", func() bool { return lire().Actif && k.nb() == 30 })
	if lances.Load() != 1 {
		t.Fatalf("QuandPret : %d lancement(s)", lances.Load())
	}
	b.QuandPret(func() { lances.Add(1) })
	if lances.Load() != 2 {
		t.Fatal("déjà prêt : lancé tout de suite")
	}
	close(fin)
	wg.Wait()
	finRepose(b)
	if e := b.Etat(); e.Reparations != 0 {
		t.Fatalf("une pose tardive n'est pas une réparation : %+v", e)
	}
}

func TestEnsureDemarrage_DitSiLesEnsemblesEtaientLa(t *testing.T) {
	b, k := banneurLots(t, nil)
	if la, err := b.EnsureDemarrage(); err != nil || la {
		t.Fatalf("table neuve : %v %v", la, err)
	}
	b.runner = func(ctx context.Context, args ...string) ([]byte, error) {
		if joint(args) == "-j -t list sets inet" {
			return []byte(`{"nftables":[{"set":{"table":"secubox","name":"waf_ban","stmt":[{"counter":null}]}},{"set":{"table":"secubox","name":"waf_ban6","stmt":[{"counter":null}]}}]}`), nil
		}
		return k.run(ctx, args...)
	}
	if la, err := b.EnsureDemarrage(); err != nil || !la {
		t.Fatalf("ensembles en place : %v %v", la, err)
	}
}

// ── 2. prolongation ──────────────────────────────────────────────────────────

// La prolongation n'est pas avalée par un ban de la même adresse en file, et la durée la plus longue l'emporte dans les deux ordres.
func TestProlonger_PendantQueLAdresseEstEnFile(t *testing.T) {
	for _, prolongeDAbord := range []bool{false, true} {
		now := time.Now()
		b, k := banneurLots(t, []BanRecord{{IP: "203.0.113.1", Category: "leurre:x", At: now.Unix() - 3500, Expires: now.Unix() + 60, Action: "ban"}})
		k.elems["203.0.113.1"] = 60
		b.runner = func(ctx context.Context, args ...string) ([]byte, error) {
			if args[0] == "delete" {
				t.Errorf("retrait seul, adresse libre : %v", args)
			}
			return k.run(ctx, args...)
		}
		court := func() { b.BanFor("203.0.113.1", "leurre:x", "high", time.Hour) }
		long := func() { b.Prolonger("203.0.113.1", "leurre:x|prolonge", "high", 24*time.Hour, now) }
		premier, second := court, long
		if prolongeDAbord {
			premier, second = long, court
		}
		b.poseMu.Lock() // un lot part
		var wg sync.WaitGroup
		for _, f := range []func(){premier, second} {
			wg.Add(1)
			go func() { defer wg.Done(); f() }()
			time.Sleep(20 * time.Millisecond)
		}
		b.poseMu.Unlock()
		wg.Wait()
		r, _ := b.store.Actif("203.0.113.1", now.Unix())
		if k.elems["203.0.113.1"] < 86400-5 || r.Expires < now.Unix()+86400-5 {
			t.Fatalf("prolongeDAbord=%v : élément %d s, journal %d s", prolongeDAbord, k.elems["203.0.113.1"], r.Expires-now.Unix())
		}
		if len(b.enPose) != 0 {
			t.Fatalf("file vidée : %v", b.enPose)
		}
	}
}

// Transaction refusée : l'élément en place reste.
func TestProlonger_RefuseLaisseLElement(t *testing.T) {
	b, k := banneurLots(t, nil)
	k.elems["203.0.113.1"] = 60
	k.toutRefus = true
	b.Prolonger("203.0.113.1", "leurre:x", "high", time.Hour, time.Now())
	if k.elems["203.0.113.1"] != 60 || b.Etat().DernierEchec == "" {
		t.Fatalf("%v %+v", k.elems, b.Etat())
	}
}

// Un élément plus long (ban à la main) n'est pas raccourci par une prolongation.
func TestProlonger_NeRaccourcitPasUnBanPlusLong(t *testing.T) {
	b, k := banneurLots(t, nil)
	k.elems["203.0.113.1"], k.elems["203.0.113.2"] = 7*86400, 0 // 0 : sans échéance
	for _, ip := range []string{"203.0.113.1", "203.0.113.2"} {
		b.Prolonger(ip, "leurre:x", "high", 24*time.Hour, time.Now())
	}
	if k.elems["203.0.113.1"] != 7*86400 || k.elems["203.0.113.2"] != 0 {
		t.Fatalf("%v", k.elems)
	}
	if brut, _ := os.ReadFile(b.store.path); len(brut) != 0 {
		t.Fatalf("prolongation inutile : aucune ligne au journal : %s", brut)
	}
}

// ── 3, 4, 5. levées pendant une repose ───────────────────────────────────────

func levee(t *testing.T, b *NftBanner, ip string) {
	t.Helper()
	if err := b.store.Append(BanRecord{IP: ip, Category: "levee:waf-unban", At: time.Now().Unix(), Action: "unban"}); err != nil {
		t.Fatal(err)
	}
}

func TestRetirerLeves_EchecRetenteALaPasseSuivante(t *testing.T) {
	b, k := banneurLots(t, bansTest(20, time.Now().Unix()))
	var refuse atomic.Bool
	refuse.Store(true)
	fait := false
	b.scripts = func(ctx context.Context, s []byte) ([]byte, error) {
		if bytes.Contains(s, []byte("delete element")) && refuse.Load() {
			return []byte("Error: Device or resource busy"), errors.New("exit status 1")
		}
		out, err := k.script(ctx, s)
		if !fait && bytes.Contains(s, []byte(ipTest(3)+" ")) {
			fait = true
			levee(t, b, ipTest(3)) // croisée par le lot
		}
		return out, err
	}
	b.Reload()
	if _, p := k.elems[ipTest(3)]; !p || len(b.aRetirer) != 1 || !strings.Contains(b.Etat().DernierEchec, "à refaire") {
		t.Fatalf("retrait refusé : gardé pour la passe suivante : %v %+v", b.aRetirer, b.Etat())
	}
	b.Reload()
	if len(b.aRetirer) != 1 {
		t.Fatal("encore refusé, encore gardé")
	}
	refuse.Store(false)
	b.Reload()
	if _, p := k.elems[ipTest(3)]; p || len(b.aRetirer) != 0 || k.nb() != 19 {
		t.Fatalf("retiré à la passe suivante : %v", k.elems)
	}
}

// Le retrait en attente ne défait pas un ban reposé depuis (journal, ou à la main).
func TestRetirerLeves_EnAttenteRebanniDepuis(t *testing.T) {
	b, k := banneurLots(t, nil)
	now := time.Now().Unix()
	for _, ip := range []string{"203.0.113.1", "203.0.113.2"} {
		k.elems[ip] = 3600
		levee(t, b, ip)
		b.aRetirer = map[netip.Addr]poseLot{}
	}
	for _, ip := range []string{"203.0.113.1", "203.0.113.2"} {
		a := netip.MustParseAddr(ip)
		b.aRetirer[a] = poseLot{a, now + 3600, now + 3601}
	}
	_ = b.store.Append(BanRecord{IP: "203.0.113.1", At: now, Expires: now + 3600, Action: "ban"}) // rebanni par sbxwaf
	k.elems["203.0.113.2"] = 600                                                                  // rebanni à la main
	b.Reload()
	if k.elems["203.0.113.1"] != 3600 || k.elems["203.0.113.2"] != 600 || len(b.aRetirer) != 0 {
		t.Fatalf("%v, en attente %v", k.elems, b.aRetirer)
	}
}

// Levée croisée par le lot, puis ban à la main hors journal : il n'est pas défait — un à la fois, et en nombre.
func TestRetirerLeves_BanALaMainApresLaLevee(t *testing.T) {
	for _, n := range []int{1, 10} {
		b, k := banneurLots(t, bansTest(50, time.Now().Unix()))
		b.scripts = func(ctx context.Context, s []byte) ([]byte, error) {
			out, err := k.script(ctx, s)
			if bytes.Contains(s, []byte(ipTest(0)+" timeout")) && !bytes.Contains(s, []byte("delete")) {
				for i := 0; i < 2*n; i++ {
					levee(t, b, ipTest(i))
				}
				k.mu.Lock()
				for i := 0; i < n; i++ {
					k.elems[ipTest(i)] = 4 * 3600 // wafctl unban puis wafctl ban 4 h
				}
				k.mu.Unlock()
			}
			return out, err
		}
		b.Reload()
		for i := 0; i < 2*n; i++ {
			if _, p := k.elems[ipTest(i)]; p != (i < n) {
				t.Fatalf("n=%d, %s : présent=%v", n, ipTest(i), p)
			}
		}
		if k.nb() != 50-n || k.gets > 3 {
			t.Fatalf("n=%d : %d éléments, %d lectures à l'unité sous poseMu", n, k.nb(), k.gets)
		}
	}
}

// Une levée faite avant que le lot parte n'y est pas remise, et ne compte pas comme un manque.
func TestRepose_LeveeAvantLeLotNePartPas(t *testing.T) {
	b, k := banneurLots(t, bansTest(1500, time.Now().Unix()))
	k.avant = func(n int) {
		if n == 0 {
			levee(t, b, ipTest(1400)) // second lot
		}
	}
	b.Reload()
	if strings.Contains(k.scripts[1], ipTest(1400)+" timeout") || k.nb() != 1499 {
		t.Fatalf("%d éléments", k.nb())
	}
	if e := b.Etat(); e.BansAttendus != 1499 || e.BansPoses != 1499 || e.DernierEchec != "" {
		t.Fatalf("%+v", e)
	}
}

// Le journal n'est pas relu : une ligne déjà lue puis récrite sur place (même taille) n'est pas vue, une ligne ajoutée l'est.
func TestLevees_NeLitQueLesOctetsAjoutes(t *testing.T) {
	now := time.Now().Unix()
	s := NewBanStore(filepath.Join(t.TempDir(), "bans.jsonl"))
	ecrireJournal(t, s, bansTest(5000, now))
	s.ActiveBans(now)
	a, b := netip.MustParseAddr(ipTest(0)), netip.MustParseAddr(ipTest(4999))
	f, _ := os.OpenFile(s.path, os.O_WRONLY, 0)
	_, _ = f.WriteAt([]byte(`{"action":"unban","ip":"`+ipTest(0)+`",`), 0)
	f.Close()
	_ = s.Append(BanRecord{IP: ipTest(4999), At: now, Action: "unban"})
	l, err := s.Levees([]netip.Addr{a, b}, now)
	_, la := l[a]
	_, lb := l[b]
	if err != nil || la || !lb {
		t.Fatalf("%v %v", l, err)
	}
}

// Le verrou du chemin de requête (mu : Append, récidives des leurres) ne retient pas la lecture du journal, ni l'inverse.
func TestBanStore_LectureHorsDuVerrouDesRequetes(t *testing.T) {
	now := time.Now().Unix()
	s := NewBanStore(filepath.Join(t.TempDir(), "bans.jsonl"))
	ecrireJournal(t, s, bansTest(10, now))
	s.mu.Lock()
	defer s.mu.Unlock()
	fini := make(chan struct{})
	go func() {
		defer close(fini)
		s.ActiveBans(now)
		s.Actif(ipTest(0), now)
		_, _ = s.Levees([]netip.Addr{netip.MustParseAddr(ipTest(0))}, now)
	}()
	select {
	case <-fini:
	case <-time.After(5 * time.Second):
		t.Fatal("la lecture du journal attend le verrou des requêtes")
	}
}

// Suivi, ajouts et compactage à la fois : l'index rend la vérité à la fin (détecteur de courses compris).
func TestBanStore_SuiviPendantLeCompactage(t *testing.T) {
	now := time.Now()
	s := NewBanStore(filepath.Join(t.TempDir(), "bans.jsonl"))
	recs := bansTest(2000, now.Unix())
	for i := range recs[:1500] {
		recs[i].At, recs[i].Expires = now.Unix()-90*86400, now.Unix()-89*86400
	}
	ecrireJournal(t, s, recs)
	var wg sync.WaitGroup
	fin := make(chan struct{})
	wg.Add(2)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-fin:
				return
			default:
				s.ActiveBans(now.Unix())
			}
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 200; i++ {
			_ = s.Append(BanRecord{IP: ipTest(1500 + i), At: now.Unix(), Action: "unban"})
		}
	}()
	for i := 0; i < 5; i++ {
		if _, err := s.Compacter(now, CompactageBans{Fenetre: 31 * 24 * time.Hour, ArchivesMois: 6}); err != nil {
			t.Fatal(err)
		}
	}
	close(fin)
	wg.Wait()
	if n := len(s.ActiveBans(now.Unix())); n != 300 {
		t.Fatalf("%d bans actifs, 300 attendus", n)
	}
}

// ── 7. réévaluation ──────────────────────────────────────────────────────────

func TestReeval_LAttenteDuVerrouNestPasComptee(t *testing.T) {
	now := int64(1_800_000_000)
	elems := map[string][2]int64{"198.51.100.5": {40, 45}}
	for i := 0; i < 50000; i++ {
		elems[ipTest(i)] = [2]int64{1, 86400}
	}
	r, fx, store, dir := bancReeval(t, "auto", elems)
	poseBan(store, "198.51.100.5", "leurre:unrouted", now-3555, now+45)
	var plusCourt atomic.Int64
	plusCourt.Store(int64(time.Hour))
	r.banneur.runner = func(ctx context.Context, args ...string) ([]byte, error) {
		if joint(args[:2]) == "-j list" {
			d, ok := ctx.Deadline()
			if !ok {
				t.Error("lecture sans délai")
			} else if reste := int64(time.Until(d)); reste < plusCourt.Load() {
				plusCourt.Store(reste)
			}
		}
		return fx.run(ctx, args...)
	}
	r.banneur.listeMu.Lock() // une repose lit 50 000 éléments
	fini := make(chan struct{})
	go func() { defer close(fini); r.Tick() }()
	time.Sleep(700 * time.Millisecond)
	r.banneur.listeMu.Unlock()
	<-fini
	if reste := time.Duration(plusCourt.Load()); reste < delaiListe-300*time.Millisecond {
		t.Fatalf("l'attente du verrou a mangé le délai : %s restants sur %s", reste, delaiListe)
	}
	if ev := lignesJSON(t, filepath.Join(dir, "reeval.jsonl")); len(ev) != 1 || ev[0]["decision"] != "EXTEND" {
		t.Fatalf("%v", ev)
	}
}

// ── 8. plages protégées et CGNAT ─────────────────────────────────────────────

func TestProtegees_JamaisPosees(t *testing.T) {
	now := time.Now().Unix()
	var recs []BanRecord
	proteges := []string{"203.0.113.7", "198.51.100.200", "2001:db8:77::1", "100.64.0.9", "100.127.255.254"}
	for _, ip := range proteges {
		recs = append(recs, BanRecord{IP: ip, Category: "leurre:x", At: now, Expires: now + 3600, Action: "ban"})
	}
	recs = append(recs, BanRecord{IP: "203.0.113.8", At: now, Expires: now + 3600, Action: "ban"})
	b, k := banneurLots(t, recs)
	b.audit = filepath.Join(t.TempDir(), "audit.log")
	b.protegees = parseCIDRs("203.0.113.7/32,198.51.100.0/24,2001:db8:77::/48")
	b.cooldown = 0
	for _, ip := range append(proteges, "::ffff:203.0.113.7") {
		b.BanFor(ip, "leurre:x", "high", time.Hour)
		b.Prolonger(ip, "leurre:x", "high", time.Hour, time.Now())
	}
	if k.nb() != 0 {
		t.Fatalf("protégées posées : %v", k.elems)
	}
	// Déjà dans le noyau avant le démarrage (une du journal, une posée à la main).
	k.elems["203.0.113.7"], k.elems["198.51.100.9"], k.elems["100.64.0.9"], k.elems["198.18.0.1"] = 3000, 3000, 3000, 3000
	b.Reload()
	if k.nb() != 2 || k.elems["203.0.113.8"] == 0 || k.elems["198.18.0.1"] != 3000 {
		t.Fatalf("seuls les bans hors plages restent : %v", k.elems)
	}
	if act := b.store.ActiveBans(now); len(act) != 1 || act[0].IP != "203.0.113.8" {
		t.Fatalf("levés au journal : %+v", act)
	}
	if n := len(lignesJSON(t, b.audit)); n != 6 {
		t.Fatalf("6 levées auditées (5 du journal, 1 à la main), %d", n)
	}
	taille, _ := os.Stat(b.store.path)
	b.Reload()
	if apres, _ := os.Stat(b.store.path); apres.Size() != taille.Size() {
		t.Fatal("le rattrapage ne se refait pas")
	}
}

// Plus de 200 bans visés : la plage est douteuse, aucun n'est levé (le CGNAT, si) ; l'état et l'audit le disent, une fois.
func TestProtegees_PlafondDeLevees(t *testing.T) {
	for _, n := range []int{maxLeveesProtegees, maxLeveesProtegees + 1} {
		now := time.Now().Unix()
		recs := bansTest(n, now)
		recs = append(recs, BanRecord{IP: "100.64.0.9", At: now, Expires: now + 3600, Action: "ban"})
		b, k := banneurLots(t, recs)
		b.audit = filepath.Join(t.TempDir(), "audit.log")
		b.protegees = parseCIDRs("11.0.0.0/16")
		for _, r := range recs {
			k.elems[r.IP] = 3000
		}
		b.Reload()
		b.Reload()
		leve := n <= maxLeveesProtegees
		if (k.nb() == 0) != leve || (len(b.store.ActiveBans(now)) == 0) != leve || (!leve && k.nb() != n) {
			t.Fatalf("%d : %d dans nft, %d au journal", n, k.nb(), len(b.store.ActiveBans(now)))
		}
		if a := lignesJSON(t, b.audit); !leve && (len(a) != 2 || a[0]["action"] != "ban_protegee_plafond" || !strings.Contains(b.Etat().DernierEchec, "AUCUN")) {
			t.Fatalf("audit %v, état %+v", a, b.Etat())
		}
	}
}

func TestProtegees_RetraitRefuseRefait(t *testing.T) {
	b, k := banneurLots(t, nil)
	b.protegees = parseCIDRs("203.0.113.0/24")
	k.elems["203.0.113.7"] = 3000
	k.toutRefus = true
	b.Reload()
	if b.protegeesLevees || k.nb() != 1 {
		t.Fatal("refusé : à refaire")
	}
	k.toutRefus = false
	b.Reload()
	if !b.protegeesLevees || k.nb() != 0 {
		t.Fatalf("%v", k.elems)
	}
}

// Le reste ne change pas : une adresse voisine d'une plage protégée, ou du CGNAT, est bannie.
func TestProtegees_LesAutresRestentBannies(t *testing.T) {
	b, k := banneurLots(t, nil)
	b.protegees = parseCIDRs("203.0.113.7/32")
	for _, ip := range []string{"203.0.113.6", "203.0.113.8", "100.63.255.255", "100.128.0.1", "2001:db8::1"} {
		b.BanFor(ip, "leurre:x", "high", time.Hour)
		if k.elems[ip] != 3600 {
			t.Fatalf("%s doit rester bannissable", ip)
		}
	}
}

// ── vrai nft ─────────────────────────────────────────────────────────────────

// `unshare -rn env SBXWAF_NFT_REEL=1 sbxwaf.test -test.run NftReel -test.v`.
func TestNftReel_3932(t *testing.T) {
	if os.Getenv("SBXWAF_NFT_REEL") == "" {
		t.Skip("SBXWAF_NFT_REEL non posé")
	}
	nft := func(args ...string) (string, error) {
		out, err := exec.Command("nft", args...).CombinedOutput()
		return string(out), err
	}
	_, _ = nft("flush", "ruleset")
	now := time.Now().Unix()
	store := NewBanStore(filepath.Join(t.TempDir(), "bans.jsonl"))
	ecrireJournal(t, store, bansTest(5000, now))
	b := NewNftBanner("nft", "secubox", time.Hour, store)
	if la, err := b.EnsureDemarrage(); err != nil || la {
		t.Fatal(la, err)
	}
	b.Reload()
	ban := netip.MustParseAddr(ipTest(0))

	// La chaîne n'est jamais vue sans ses règles, ni l'élément libre, pendant 30 Ensure et 30 prolongations.
	fin := make(chan struct{})
	var wg sync.WaitGroup
	var lectures, vides atomic.Int32
	for _, args := range [][]string{{"list", "chain", "inet", "secubox", "waf_drop"}, {"get", "element", "inet", "secubox", "waf_ban", "{ " + ban.String() + " }"}} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-fin:
					return
				default:
				}
				out, err := nft(args...)
				lectures.Add(1)
				if err != nil || (args[0] == "list" && strings.Count(out, " drop") != 2) {
					vides.Add(1)
					t.Logf("%v : %v %s", args, err, out)
				}
			}
		}()
	}
	for i := 0; i < 30; i++ {
		if la, err := b.EnsureDemarrage(); err != nil || !la {
			t.Fatal(la, err)
		}
		b.Prolonger(ban.String(), "leurre:x", "high", time.Duration(2+i)*time.Hour, time.Now())
	}
	close(fin)
	wg.Wait()
	if vides.Load() != 0 || lectures.Load() < 10 {
		t.Fatalf("%d lecture(s) vides sur %d", vides.Load(), lectures.Load())
	}
	if r, ok := b.resteElement(context.Background(), "waf_ban", ban.String()); !ok || r < 31*3600-30 {
		t.Fatalf("prolongé à %d s (%v)", r, ok)
	}
	if out, _ := nft("list", "chain", "inet", "secubox", "waf_drop"); strings.Count(out, " drop") != 2 {
		t.Fatalf("règles empilées : %s", out)
	}

	// Migration d'ensembles sans compteur, chaîne en place : une transaction.
	_, _ = nft("flush", "ruleset")
	vieux := "add table inet secubox\nadd set inet secubox waf_ban { type ipv4_addr; flags timeout; }\nadd set inet secubox waf_ban6 { type ipv6_addr; flags timeout; }\n" +
		"add chain inet secubox waf_drop { type filter hook input priority -100; policy accept; }\nadd rule inet secubox waf_drop ip saddr @waf_ban counter drop\nadd element inet secubox waf_ban { 203.0.113.1 timeout 60s }\n"
	if out, err := lancerNft(exec.Command("nft", "-f", "-"), []byte(vieux)); err != nil {
		t.Fatalf("%v %s", err, out)
	}
	if la, err := b.EnsureDemarrage(); err != nil || la {
		t.Fatal(la, err)
	}
	if out, _ := nft("list", "table", "inet", "secubox"); strings.Count(out, "flags timeout") != 2 || !strings.Contains(out, "counter") || strings.Count(out, " drop") != 2 {
		t.Fatalf("migration : %s", out)
	}
	if b.Reload() != 5000 {
		t.Fatal("journal réinjecté")
	}
	// Transaction refusée : rien n'a changé.
	_, _ = nft("delete", "table", "inet", "secubox")
	_, _ = nft("add", "table", "inet", "secubox")
	_, _ = nft("add", "set", "inet", "secubox", "waf_ban", "{ type ipv6_addr; flags timeout; counter; }")
	if err := b.Ensure(); err == nil {
		t.Fatal("définition contraire : refus attendu")
	}
	if out, _ := nft("list", "table", "inet", "secubox"); strings.Contains(out, "waf_drop") || strings.Contains(out, "waf_ban6") {
		t.Fatalf("transaction à moitié passée : %s", out)
	}
	// Levées : ni l'élément d'un autre, ni un de trop.
	_, _ = nft("flush", "ruleset")
	if err := b.Ensure(); err != nil {
		t.Fatal(err)
	}
	b.Reload()
	var poses []poseLot
	for i := 100; i < 110; i++ {
		a := netip.MustParseAddr(ipTest(i))
		poses = append(poses, poseLot{a, now + 3600, time.Now().Unix() + 3600})
		_ = store.Append(BanRecord{IP: ipTest(i), At: now, Action: "unban"})
	}
	if out, err := lancerNft(exec.Command("nft", "-f", "-"), scriptRemplacer("secubox", "waf_ban", ipTest(100), 600)); err != nil {
		t.Fatalf("%v %s", err, out)
	}
	b.retirerLeves(poses)
	for i := 100; i < 110; i++ {
		if _, p := b.resteElement(context.Background(), "waf_ban", ipTest(i)); p != (i == 100) {
			t.Fatalf("%s : présent=%v", ipTest(i), p)
		}
	}
	fmt.Println("vrai nft :", lectures.Load(), "lectures, aucune vide")
}

// #4008 : Epargne annonce ce que la pose écartera, pour que le journal des menaces n'écrive pas « banned » à tort.
func TestEpargne4008(t *testing.T) {
	b, _ := banneurLots(t, nil)
	b.protegees = parseCIDRs("203.0.113.7/32")
	if r := b.Epargne("203.0.113.7"); r != "plage protégée" {
		t.Fatalf("plage protégée non signalée : %q", r)
	}
	if r := b.Epargne("::ffff:203.0.113.7"); r != "plage protégée" {
		t.Fatalf("forme IPv4 mappée non signalée : %q", r)
	}
	if r := b.Epargne("203.0.113.8"); r != "" {
		t.Fatalf("adresse ordinaire épargnée à tort : %q", r)
	}
	var nul *NftBanner
	if nul.Epargne("203.0.113.7") != "" {
		t.Fatal("un banneur absent n'épargne rien")
	}
	s := &Server{nftBan: b}
	if s.actionBan("203.0.113.7") != "epargne" || s.actionBan("203.0.113.8") != "banned" {
		t.Fatal("actionBan ne suit pas Epargne")
	}
}
