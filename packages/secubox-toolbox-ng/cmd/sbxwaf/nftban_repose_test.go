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
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// noyauLots simule nft et son noyau : ensembles, scripts en UNE transaction, `flush ruleset`, éléments refusés.
type noyauLots struct {
	mu        sync.Mutex
	table     bool
	elems     map[string]int64 // adresse → délai posé
	refuses   map[string]bool
	execs     int // scripts + listes
	scripts   []string
	listeKO   bool
	avant     func(n int) // appelé AVANT le n-ième script (0, 1, …), hors verrou
	toutRefus bool
}

func (k *noyauLots) liste(set string) []byte {
	var el []string
	for ip, d := range k.elems {
		if (strings.Contains(ip, ":")) == (set == "waf_ban6") {
			el = append(el, fmt.Sprintf(`{"elem":{"val":%q,"timeout":%d,"expires":%d,"counter":null}}`, ip, d, d))
		}
	}
	return []byte(fmt.Sprintf(`{"nftables":[{"metainfo":{"version":"1"}},{"set":{"family":"inet","name":%q,"table":"secubox","stmt":[{"counter":null}],"elem":[%s]}}]}`,
		set, strings.Join(el, ",")))
}

func (k *noyauLots) run(_ context.Context, args ...string) ([]byte, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	j := joint(args)
	absente := []byte("Error: No such file or directory")
	switch {
	case strings.HasPrefix(j, "add table"):
		k.table = true
	case strings.HasPrefix(j, "list chain"):
		if !k.table {
			return absente, errors.New("exit status 1")
		}
		return []byte("ip saddr @waf_ban counter drop"), nil
	case strings.HasPrefix(j, "-j -s list set"):
		k.execs++
		if k.listeKO || !k.table {
			return absente, errors.New("exit status 1")
		}
		return k.liste(args[len(args)-1]), nil
	case strings.HasPrefix(j, "delete element"):
		delete(k.elems, strings.Fields(args[5])[1])
	case strings.HasPrefix(j, "add element"):
		if !k.table {
			return absente, errors.New("exit status 1")
		}
		k.elems[strings.Fields(args[5])[1]] = 1
	}
	return nil, nil
}

func (k *noyauLots) script(ctx context.Context, script []byte) ([]byte, error) {
	k.mu.Lock()
	n := len(k.scripts)
	k.scripts = append(k.scripts, string(script))
	k.execs++
	avant := k.avant
	k.mu.Unlock()
	if avant != nil {
		avant(n)
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	if !k.table {
		return []byte("Error: No such file or directory"), errors.New("exit status 1")
	}
	if k.toutRefus {
		return []byte("Error: Operation not permitted"), errors.New("exit status 1")
	}
	neufs := map[string]int64{}
	for _, l := range strings.Split(strings.TrimSpace(string(script)), "\n") {
		champs := strings.SplitN(l, "{", 2)
		for _, e := range strings.Split(strings.Trim(champs[1], " }"), ", ") {
			f := strings.Fields(e)
			if len(f) != 3 || f[1] != "timeout" {
				return []byte("Error: syntax error"), errors.New("exit status 1")
			}
			a, err := netip.ParseAddr(f[0])
			d, errD := strconv.ParseInt(strings.TrimSuffix(f[2], "s"), 10, 64)
			if err != nil || errD != nil || d <= 0 || k.refuses[f[0]] || a.Is4() != strings.Contains(champs[0], "waf_ban ") {
				return []byte("Error: invalid element"), errors.New("exit status 1")
			}
			neufs[f[0]] = d
		}
	}
	for ip, d := range neufs {
		if _, deja := k.elems[ip]; !deja {
			k.elems[ip] = d
		}
	}
	return nil, nil
}

func (k *noyauLots) nb() int {
	k.mu.Lock()
	defer k.mu.Unlock()
	return len(k.elems)
}

func (k *noyauLots) flushRuleset() {
	k.mu.Lock()
	k.table, k.elems = false, map[string]int64{}
	k.mu.Unlock()
}

func ipTest(i int) string { return fmt.Sprintf("11.%d.%d.%d", i>>16&255, i>>8&255, i&255) }

// ecrireJournal écrit le journal d'un coup (Append rouvre le fichier à chaque ligne).
func ecrireJournal(t testing.TB, s *BanStore, recs []BanRecord) {
	t.Helper()
	var buf bytes.Buffer
	for _, r := range recs {
		b, _ := json.Marshal(r)
		buf.Write(append(b, '\n'))
	}
	if err := os.WriteFile(s.path, buf.Bytes(), 0o640); err != nil {
		t.Fatal(err)
	}
}

func bansTest(n int, now int64) []BanRecord {
	recs := make([]BanRecord, n)
	for i := range recs {
		recs[i] = BanRecord{IP: ipTest(i), Category: "leurre:unrouted", Severity: "high", At: now - int64(i), Expires: now + 3600, Action: "ban"}
	}
	return recs
}

func banneurLots(t testing.TB, recs []BanRecord) (*NftBanner, *noyauLots) {
	t.Helper()
	store := NewBanStore(filepath.Join(t.TempDir(), "bans.jsonl"))
	ecrireJournal(t, store, recs)
	k := &noyauLots{elems: map[string]int64{}, refuses: map[string]bool{}}
	b := NewNftBanner("/nonexistent/nft", "secubox", time.Hour, store)
	b.runner, b.scripts = k.run, k.script
	b.robotsPas = time.Microsecond
	if err := b.Ensure(); err != nil {
		t.Fatal(err)
	}
	return b, k
}

func dnsInterdit(t testing.TB) *Crawlers {
	c := NewCrawlers()
	c.inverse = func(ip string) ([]string, error) { t.Errorf("DNS inverse de %s", ip); return nil, nil }
	c.direct = func(n string) ([]string, error) { t.Errorf("DNS direct de %s", n); return nil, nil }
	return c
}

func TestRepose_20000BansPeuDExecsAucunDNS(t *testing.T) {
	b, k := banneurLots(t, bansTest(20000, time.Now().Unix()))
	b.robots = dnsInterdit(t)
	debut := time.Now()
	if n := b.Reload(); n != 20000 || k.nb() != 20000 {
		t.Fatalf("20 000 bans attendus, reposés %d, dans nft %d", n, k.nb())
	}
	if k.execs > 25 {
		t.Fatalf("%d exécutions de nft, 25 au plus", k.execs)
	}
	e := b.Etat()
	if e.BansAttendus != 20000 || e.BansPoses != 20000 || e.ReposeEnCours || e.DerniereRepose == 0 || e.DernierEchec != "" {
		t.Fatalf("état : %+v", e)
	}
	t.Logf("20 000 bans : %d exécutions, %s", k.execs, time.Since(debut))
}

func TestRepose_SeulsLesManquants(t *testing.T) {
	b, k := banneurLots(t, bansTest(3000, time.Now().Unix()))
	for i := 0; i < 3000; i++ {
		if i != 7 && i != 2500 {
			k.elems[ipTest(i)] = 42
		}
	}
	k.elems["198.51.100.200"] = 99 // posé à la main, hors journal : jamais touché
	if n := b.Reload(); n != 2 {
		t.Fatalf("2 manquants, %d reposés", n)
	}
	if len(k.scripts) != 1 || strings.Count(k.scripts[0], "timeout") != 2 {
		t.Fatalf("un seul script de 2 éléments : %v", k.scripts)
	}
	if k.elems[ipTest(8)] != 42 || k.elems["198.51.100.200"] != 99 {
		t.Fatal("un élément présent garde son échéance")
	}
	if b.Reload() != 0 || len(k.scripts) != 1 {
		t.Fatal("rien à poser : aucun script")
	}
	if e := b.Etat(); e.BansPoses != 3000 {
		t.Fatalf("présents et ajoutés comptent : %+v", e)
	}
}

func TestRepose_TableIllisibleReposeDeTout(t *testing.T) {
	b, k := banneurLots(t, bansTest(1500, time.Now().Unix()))
	k.listeKO = true
	if n := b.Reload(); n != 1500 || len(k.scripts) != 2 {
		t.Fatalf("liste illisible : tout est reposé par lots (%d bans, %d scripts)", n, len(k.scripts))
	}
}

func TestRepose_UnElementRefuseNePerdPasLesAutres(t *testing.T) {
	b, k := banneurLots(t, bansTest(2500, time.Now().Unix()))
	k.refuses[ipTest(3)], k.refuses[ipTest(1700)] = true, true
	if n := b.Reload(); n != 2498 || k.nb() != 2498 {
		t.Fatalf("2 498 bans attendus, %d reposés, %d dans nft", n, k.nb())
	}
	if len(k.scripts) > 60 {
		t.Fatalf("isolement borné : %d scripts", len(k.scripts))
	}
	if e := b.Etat(); e.BansAttendus != 2500 || e.BansPoses != 2498 || e.DernierEchec == "" {
		t.Fatalf("l'état dit l'écart : %+v", e)
	}
}

func TestRepose_ToutRefuseResteBorne(t *testing.T) {
	b, k := banneurLots(t, bansTest(20000, time.Now().Unix()))
	k.toutRefus = true
	if n := b.Reload(); n != 0 {
		t.Fatalf("rien ne passe : %d", n)
	}
	if len(k.scripts) > 20+budgetIsolement {
		t.Fatalf("%d scripts : les essais ne sont pas bornés", len(k.scripts))
	}
}

func TestRepose_IPv6EchusEtInjections(t *testing.T) {
	now := time.Now().Unix()
	ban := func(ip string, exp int64) BanRecord {
		return BanRecord{IP: ip, At: now, Expires: exp, Action: "ban"}
	}
	b, k := banneurLots(t, []BanRecord{
		ban("2001:DB8:0::1", now+100), ban("203.0.113.1", now+100), ban("::ffff:203.0.113.2", now+100),
		ban("203.0.113.3", now), ban("203.0.113.4", now-5), ban("203.0.113.5", 0), ban("203.0.113.6", 1<<60),
		ban("203.0.113.7 }; flush ruleset; add element inet secubox waf_ban { 1.1.1.1", now+100),
		ban("203.0.113.8\nflush ruleset", now+100), ban("2001:db8::9%}\nflush ruleset\n", now+100), ban("0.0.0.0/0", now+100),
		ban("203.0.113.1-203.0.113.9", now+100), ban("localhost", now+100), ban("192.168.1.1", now+100), ban("127.0.0.1", now+100),
		ban("fe80::1", now+100), ban("::ffff:10.0.0.1", now+100), ban("::1", now+100), ban("0.0.0.0", now+100), ban("", now+100),
	})
	n := b.Reload()
	if n != 5 || k.nb() != 5 {
		t.Fatalf("5 bans valides, %d reposés : %v", n, k.elems)
	}
	for ip, max := range map[string]int64{"2001:db8::1": 100, "203.0.113.1": 100, "203.0.113.2": 100, "203.0.113.5": 3600, "203.0.113.6": resteMax} {
		if d := k.elems[ip]; d <= max-5 || d > max {
			t.Errorf("%s : délai %d, attendu ~%d", ip, d, max)
		}
	}
	for _, s := range k.scripts {
		if strings.Contains(s, "flush") || strings.Count(s, "\n") > 2 {
			t.Fatalf("texte du journal dans le script : %q", s)
		}
	}
}

// Prolongé ou rebanni pendant la repose : le lot porte l'ancienne échéance, il ne doit pas l'imposer (noyau ≥ 6.12).
func TestRepose_BanPlusRecentQueLeRelevePasRejoue(t *testing.T) {
	b, k := banneurLots(t, bansTest(1500, time.Now().Unix()))
	cible := ipTest(1400) // second lot
	k.avant = func(n int) {
		if n == 0 {
			b.BanFor(cible, "leurre:x", "high", 24*time.Hour)
		}
	}
	b.Reload()
	if len(k.scripts) != 2 || strings.Contains(k.scripts[1], cible+" ") {
		t.Fatal("une adresse rebannie depuis le relevé ne part pas dans le lot")
	}
	if e := b.Etat(); e.BansPoses != 1500 {
		t.Fatalf("elle compte comme posée : %+v", e)
	}
}

func TestRepose_TableEffaceePendantLaRepose(t *testing.T) {
	b, k := banneurLots(t, bansTest(5000, time.Now().Unix()))
	k.avant = func(n int) {
		if n == 2 {
			k.flushRuleset()
		}
	}
	b.Reload()
	if !k.table || k.nb() != 5000 {
		t.Fatalf("table recréée et 5 000 bans remis, obtenu %d (table=%v)", k.nb(), k.table)
	}
	if e := b.Etat(); e.Reparations != 1 || e.BansPoses != 5000 {
		t.Fatalf("état : %+v", e)
	}
}

// Une repose bloquée ne retient ni la publication de l'état, ni la réparation de la table.
func TestVeiller_EtatEtReparationPendantUneReposeBloquee(t *testing.T) {
	b, k := banneurLots(t, bansTest(3000, time.Now().Unix()))
	b.etatFichier = filepath.Join(t.TempDir(), "nft-etat.json")
	bloque, liberer := make(chan struct{}), make(chan struct{})
	k.avant = func(n int) {
		if n == 1 {
			close(bloque)
			<-liberer
		}
	}
	fin := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); b.veillerJusqua(fin, 5*time.Millisecond, 10*time.Millisecond) }()
	<-bloque

	lire := func() (e EtatNft) {
		raw, _ := os.ReadFile(b.etatFichier)
		_ = json.Unmarshal(raw, &e)
		return e
	}
	_ = os.Remove(b.etatFichier)
	attendre(t, "état publié pendant la repose", func() bool {
		e := lire()
		return e.Verifie != 0 && e.ReposeEnCours && e.BansAttendus == 3000
	})
	k.flushRuleset()
	attendre(t, "table recréée pendant la repose", func() bool { k.mu.Lock(); defer k.mu.Unlock(); return k.table })
	close(liberer)
	attendre(t, "bans remis", func() bool { e := lire(); return k.nb() == 3000 && e.BansPoses == 3000 && e.Reparations == 1 })
	close(fin)
	wg.Wait()
	finRepose(b)
}

// finRepose attend la fin des reposes demandées en arrière-plan.
func finRepose(b *NftBanner) {
	for b.reposeAttend.Load() {
		time.Sleep(time.Millisecond)
	}
	b.reposeMu.Lock()
	defer b.reposeMu.Unlock()
}

func attendre(t *testing.T, quoi string, f func() bool) {
	t.Helper()
	limite := time.Now().Add(10 * time.Second)
	for !f() {
		if time.Now().After(limite) {
			t.Fatalf("%s : pas en 10 s", quoi)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

func TestRepose_UneSeuleALaFois(t *testing.T) {
	b, k := banneurLots(t, bansTest(2000, time.Now().Unix()))
	var en, pic atomic.Int32
	k.avant = func(int) {
		if v := en.Add(1); v > pic.Load() {
			pic.Store(v)
		}
		time.Sleep(time.Millisecond)
		en.Add(-1)
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); b.Reload(); b.lancerRepose() }()
	}
	wg.Wait()
	finRepose(b)
	if pic.Load() != 1 || len(k.scripts) != 2 {
		t.Fatalf("pic %d, %d scripts", pic.Load(), len(k.scripts))
	}
}

func TestPremiereRepose_NAttendPasUneBoxLente(t *testing.T) {
	b, k := banneurLots(t, bansTest(1000, time.Now().Unix()))
	liberer := make(chan struct{})
	k.avant = func(int) { <-liberer }
	debut := time.Now()
	if _, fini := b.PremiereRepose(30 * time.Millisecond); fini || time.Since(debut) > 2*time.Second {
		t.Fatal("l'écoute n'attend pas la repose")
	}
	close(liberer)
	attendre(t, "repose finie en arrière-plan", func() bool { return k.nb() == 1000 && b.Etat().DerniereRepose != 0 })
}

// ── Robots ───────────────────────────────────────────────────────────────────

func dnsRobot(ip string) *dns {
	return &dns{inv: map[string][]string{ip: {"crawl.googlebot.com."}}, dir: map[string][]string{"crawl.googlebot.com": {ip}}}
}

func TestRepose_RobotConnuParLaMemoireSeule(t *testing.T) {
	b, k := banneurLots(t, bansTest(10, time.Now().Unix()))
	c := NewCrawlers()
	d := dnsRobot(ipTest(4))
	d.install(c)
	if c.Connu(ipTest(4)) != "" || d.nbRq != 0 {
		t.Fatal("Connu ne fait jamais de DNS")
	}
	c.Verifie(ipTest(4))
	n := d.nbRq
	b.robots = c
	b.Reload()
	if _, pose := k.elems[ipTest(4)]; pose || k.nb() != 9 || d.nbRq != n {
		t.Fatalf("robot connu écarté, sans DNS : %v (%d requêtes)", k.elems, d.nbRq-n)
	}
}

// Le robot libéré entre le relevé du journal et l'envoi du lot ne revient pas dans nft.
func TestRepose_RobotLibereEntreTempsNeRevientPas(t *testing.T) {
	b, k := banneurLots(t, bansTest(1500, time.Now().Unix()))
	c := NewCrawlers()
	dnsRobot(ipTest(1400)).install(c)
	b.robots = c
	k.avant = func(n int) {
		if n == 0 {
			c.Verifie(ipTest(1400)) // ce que fait LibererRobots avant d'attendre poseMu
			go b.leverRobot(ipTest(1400), "googlebot.com", []string{ipTest(1400)})
		}
	}
	b.Reload()
	attendre(t, "unban écrit", func() bool { return len(b.store.ActiveBans(time.Now().Unix())) == 1499 })
	if _, pose := k.elems[ipTest(1400)]; pose || k.nb() != 1499 {
		t.Fatal("robot rebanni par un lot préparé avant sa libération")
	}
}

func TestLibererRobots_ReponseFermeUneFoisPanneRetentee3Fois(t *testing.T) {
	b, _ := banneurLots(t, bansTest(40, time.Now().Unix()))
	b.Reload()
	c := NewCrawlers()
	var rq sync.Map
	c.inverse = func(ip string) ([]string, error) {
		v, _ := rq.LoadOrStore(ip, new(atomic.Int32))
		v.(*atomic.Int32).Add(1)
		if ip == ipTest(1) {
			return nil, &net.DNSError{Err: "i/o timeout", IsTimeout: true}
		}
		return nil, &net.DNSError{Err: "no such host", IsNotFound: true}
	}
	var decal atomic.Int64
	c.now = func() time.Time { return time.Now().Add(time.Duration(decal.Load())) }
	b.robots = c
	for i := 0; i < 6; i++ {
		b.LibererRobots()
		decal.Add(int64(2 * time.Hour)) // mémoire négative échue
	}
	for i := 0; i < 40; i++ {
		v, ok := rq.Load(ipTest(i))
		voulu := int32(1)
		if i == 1 {
			voulu = robotsEssaisMax
		}
		if !ok || v.(*atomic.Int32).Load() != voulu {
			t.Fatalf("%s : %v requêtes, attendu %d", ipTest(i), v, voulu)
		}
	}
}

// Banni pendant une panne DNS : libéré dès que le DNS répond, journal compris, et pas reposé ensuite.
func TestLibererRobots_PanneDNSPuisReponse(t *testing.T) {
	b, k := banneurLots(t, nil)
	c := NewCrawlers()
	var panne atomic.Bool
	panne.Store(true)
	c.inverse = func(string) ([]string, error) {
		if panne.Load() {
			return nil, &net.DNSError{Err: "timeout", IsTimeout: true}
		}
		return []string{"crawl.googlebot.com."}, nil
	}
	c.direct = func(string) ([]string, error) { return []string{"66.249.66.1"}, nil }
	var decal atomic.Int64
	c.now = func() time.Time { return time.Now().Add(time.Duration(decal.Load())) }
	b.robots = c
	b.Ban("66.249.66.1", "leurre:x", "high")
	if k.nb() != 1 {
		t.Fatal("le doute ne vaut pas exemption")
	}
	panne.Store(false)
	decal.Store(int64(2 * time.Hour))
	if b.LibererRobots() != 1 || k.nb() != 0 {
		t.Fatalf("robot libéré : %v", k.elems)
	}
	if b.Reload() != 0 || len(b.store.ActiveBans(time.Now().Unix())) != 0 {
		t.Fatal("rien à reposer")
	}
	b.robots = NewCrawlers() // redémarrage : mémoire perdue
	if b.Reload() != 0 || k.nb() != 0 {
		t.Fatal("le journal suffit à ne pas le rebannir")
	}
}

func TestLibererRobots_DebitBorneEtPlausiblesDAbord(t *testing.T) {
	b, _ := banneurLots(t, bansTest(30, time.Now().Unix()))
	b.Reload()
	b.robotsPas = 10 * time.Millisecond
	c := NewCrawlers()
	var mu sync.Mutex
	var ordre []string
	c.inverse = func(ip string) ([]string, error) {
		mu.Lock()
		ordre = append(ordre, ip)
		mu.Unlock()
		return nil, &net.DNSError{IsNotFound: true}
	}
	b.robots = c
	b.robotPlausible = func(ip string) bool { return ip == ipTest(17) }
	debut := time.Now()
	b.LibererRobots()
	if d := time.Since(debut); d < 25*10*time.Millisecond {
		t.Fatalf("30 vérifications en %s : débit non borné", d)
	}
	if len(ordre) != 30 || ordre[0] != ipTest(17) {
		t.Fatalf("le plausible d'abord : %v", ordre)
	}
}

func TestCrawlers_LesNegatifsNeChassentPasUnRobotConnu(t *testing.T) {
	c := NewCrawlers()
	dnsRobot("66.249.66.1").install(c)
	c.Verifie("66.249.66.1")
	for i := 0; i < crawlerCacheMax+10; i++ {
		c.Verifie(ipTest(i))
	}
	if c.Connu("66.249.66.1") == "" {
		t.Fatal("robot oublié")
	}
}

// ── Décodage, index du journal ───────────────────────────────────────────────

func TestDecoderPresents(t *testing.T) {
	ok := `{"nftables":[{"metainfo":{"a":[1,{"b":2}]}},{"set":{"elem":["203.0.113.1",{"elem":{"val":"2001:db8::1","timeout":3,"counter":null}},{"elem":{"val":{"range":["a","b"]}}}],"name":"x"}}]}`
	m, err := decoderPresents(strings.NewReader(ok))
	if err != nil || len(m) != 2 {
		t.Fatalf("%v %v", m, err)
	}
	if m, err := decoderPresents(strings.NewReader(`{"nftables":[{"set":{"name":"x"}}]}`)); err != nil || len(m) != 0 {
		t.Fatalf("ensemble vide : %v %v", m, err)
	}
	for _, ko := range []string{"", "{}", `{"nftables":[]}`, ok[:len(ok)-40], "Error: x", `{"nftables":[{"set":{"elem":"x"}}]}`} {
		if _, err := decoderPresents(strings.NewReader(ko)); err == nil {
			t.Errorf("%q devait être illisible", ko)
		}
	}
}

func TestLancerNft_SortieBornee(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if _, err := lancerNft(exec.CommandContext(ctx, "head", "-c", strconv.Itoa(sortieNftMax+1), "/dev/zero"), nil); err == nil {
		t.Fatal("une sortie démesurée est une erreur")
	}
	if out, err := lancerNft(exec.CommandContext(ctx, "cat"), []byte("abc")); err != nil || string(out) != "abc" {
		t.Fatalf("entrée standard : %q %v", out, err)
	}
}

// L'index rend toujours ce que rend une relecture complète.
func TestActiveBans_IndexEgaleRelecture(t *testing.T) {
	s := NewBanStore(filepath.Join(t.TempDir(), "bans.jsonl"))
	now := int64(1_800_000_000)
	verifier := func(etape string, now int64) {
		t.Helper()
		a, b := map[string]BanRecord{}, map[string]BanRecord{}
		for _, r := range s.ActiveBans(now) {
			a[r.IP] = r
		}
		for _, r := range (&BanStore{path: s.path}).ActiveBans(now) {
			b[r.IP] = r
		}
		if fmt.Sprint(a) != fmt.Sprint(b) {
			t.Fatalf("%s : index %v, relecture %v", etape, a, b)
		}
	}
	for i := 0; i < 500; i++ {
		_ = s.Append(BanRecord{IP: ipTest(i % 90), At: now + int64(i), Expires: now + int64(i*60%9000), Action: []string{"ban", "ban", "unban"}[i%3]})
		if i%7 == 0 {
			verifier("ajouts", now+int64(i*20))
		}
	}
	verifier("horloge en arrière", now)
	f, _ := os.OpenFile(s.path, os.O_APPEND|os.O_WRONLY, 0)
	_, _ = f.WriteString(strings.Repeat("x", ligneMaxLectures+300_000) + "\n{\"ip\":\"203.0.113.9\",\"at\":1,\"exp\":0,\"action\":\"ban\"}")
	verifier("ligne démesurée, fin sans saut de ligne", now)
	_, _ = f.WriteString("\n")
	f.Close()
	verifier("saut de ligne", now)
	if n := len(s.ActiveBans(now)); n == 0 || s.idx.dernier["203.0.113.9"].IP == "" {
		t.Fatal("la ligne qui suit une ligne démesurée est lue")
	}
	st, _ := os.Stat(s.path)
	ecrireJournal(t, s, bansTest(20000, now)) // réécrit sur place, plus long
	st2, _ := os.Stat(s.path)
	if !os.SameFile(st, st2) {
		t.Skip("inode changé")
	}
	verifier("réécriture sur place", now)
	ecrireJournal(t, s, bansTest(3, now))
	verifier("raccourci", now)
	os.Remove(s.path)
	if s.ActiveBans(now) != nil {
		t.Fatal("journal absent")
	}
}

func TestActiveBans_LIndexSurvitAuCompactage(t *testing.T) {
	s := NewBanStore(filepath.Join(t.TempDir(), "bans.jsonl"))
	now := time.Now()
	recs := bansTest(200, now.Unix())
	for i := 0; i < 300; i++ {
		v := now.Add(-60 * 24 * time.Hour).Unix()
		recs = append(recs, BanRecord{IP: ipTest(1000 + i), At: v, Expires: v + 3600, Action: "ban"})
	}
	recs = append(recs, BanRecord{IP: ipTest(0), At: now.Unix(), Action: "unban"})
	ecrireJournal(t, s, recs)
	s.ActiveBans(now.Unix())
	avant := s.idx
	_ = s.Append(BanRecord{IP: "203.0.113.50", At: now.Unix(), Expires: now.Unix() + 3600, Action: "ban"})
	b, err := s.Compacter(now, CompactageBans{Fenetre: 31 * 24 * time.Hour, ArchivesMois: 6})
	if err != nil || !b.Reecrit {
		t.Fatalf("%+v %v", b, err)
	}
	_ = s.Append(BanRecord{IP: "203.0.113.51", At: now.Unix(), Expires: now.Unix() + 3600, Action: "ban"})
	if n := len(s.ActiveBans(now.Unix())); n != 201 || s.idx != avant {
		t.Fatalf("%d bans (201 attendus), index gardé : %v", n, s.idx == avant)
	}
	if n := len((&BanStore{path: s.path}).ActiveBans(now.Unix())); n != 201 {
		t.Fatalf("relecture : %d", n)
	}
}

func BenchmarkActiveBans50000(b *testing.B) {
	for _, hist := range []int{50000, 750000} {
		s := NewBanStore(filepath.Join(b.TempDir(), "bans.jsonl"))
		now := time.Now().Unix()
		recs := make([]BanRecord, 0, hist)
		for i := 0; i < hist-50000; i++ {
			recs = append(recs, BanRecord{IP: ipTest(100000 + i%300000), Category: "leurre:unrouted", Severity: "high", At: now - 1e6, Expires: now - 9e5, Action: "ban"})
		}
		ecrireJournal(b, s, append(recs, bansTest(50000, now)...))
		b.Run(fmt.Sprintf("froid-%d-lignes", hist), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				(&BanStore{path: s.path}).ActiveBans(now)
			}
		})
		b.Run(fmt.Sprintf("suivi-%d-lignes", hist), func(b *testing.B) {
			s.ActiveBans(now)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				s.ActiveBans(now)
			}
		})
	}
}

// Vrai nft dans un espace de noms réseau : `unshare -rn env SBXWAF_NFT_REEL=1 sbxwaf.test -test.run NftReel -test.v`.
func TestRepose_NftReel(t *testing.T) {
	if os.Getenv("SBXWAF_NFT_REEL") == "" {
		t.Skip("SBXWAF_NFT_REEL non posé")
	}
	for _, n := range []int{10000, 50000} {
		_ = exec.Command("nft", "flush", "ruleset").Run()
		now := time.Now().Unix()
		recs := bansTest(n, now)
		for i := 0; i < n/10; i++ {
			recs[i].IP = fmt.Sprintf("2001:db8::%x:%x", i>>16, i&0xffff)
		}
		store := NewBanStore(filepath.Join(t.TempDir(), "bans.jsonl"))
		ecrireJournal(t, store, recs)
		b := NewNftBanner("nft", "secubox", time.Hour, store)
		chrono := func(quoi string, f func()) {
			d := time.Now()
			f()
			t.Logf("%d bans — %s : %s", n, quoi, time.Since(d).Round(time.Millisecond))
		}
		chrono("Ensure", func() {
			if err := b.Ensure(); err != nil {
				t.Fatal(err)
			}
		})
		chrono("repose complète", func() {
			if got := b.Reload(); got != n {
				t.Fatalf("%d reposés", got)
			}
		})
		chrono("ré-affirmation sans manquant", func() {
			if got := b.Reload(); got != 0 || b.Etat().BansPoses != n {
				t.Fatalf("%d reposés, %+v", got, b.Etat())
			}
		})
		el := fmt.Sprintf("{ %s }", ipTest(n-1))
		if out, err := exec.Command("nft", "delete", "element", "inet", "secubox", "waf_ban", el).CombinedOutput(); err != nil {
			t.Fatalf("%v %s", err, out)
		}
		if got := b.Reload(); got != 1 {
			t.Fatalf("1 manquant, %d reposés", got)
		}
		_ = exec.Command("nft", "flush", "set", "inet", "secubox", "waf_ban").Run()
		chrono("après flush set", func() {
			if got := b.Reload(); got != n-n/10 {
				t.Fatalf("%d reposés", got)
			}
		})
		chrono("Ensure au redémarrage", func() {
			if err := b.Ensure(); err != nil {
				t.Fatal(err)
			}
		})
		_ = exec.Command("nft", "flush", "ruleset").Run()
		chrono("réparation après flush ruleset", func() {
			if !b.Reparer("test") || b.Etat().BansPoses != n {
				t.Fatalf("%+v", b.Etat())
			}
		})
		store.Append(BanRecord{IP: "11.9.9.9", At: now, Expires: 1 << 60, Action: "ban"})
		if got := b.Reload(); got != 1 {
			t.Fatalf("échéance démesurée bornée, %d", got)
		}
	}
}
