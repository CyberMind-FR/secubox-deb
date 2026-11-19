// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// See LICENCE-CMSD-1.0.md for terms.

package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

// #3816 : compactage de bans.jsonl. La propriété centrale : relire le journal compacté rend la même chose que relire
// le journal complet (bans actifs, récidive sur 30 j, durée de chaîne), à l'instant du compactage et après tout ajout.

const jourS = int64(86400)

var categoriesTest = []string{"leurre:unrouted", "leurre:unrouted|prolonge", "campagne:c1", "mesure:x", "host_anomaly:ip_literal", "scanners", "actor:a"}

// journalSynthetique écrit `n` lignes sur `jours` jours se terminant à `now`, sur `nIP` adresses (dont une partie très
// récidiviste pour former des chaînes longues), plus des lignes illisibles.
func journalSynthetique(t testing.TB, chemin string, n, nIP int, jours, now int64, graine int64) {
	t.Helper()
	rng := rand.New(rand.NewSource(graine))
	f, err := os.Create(chemin)
	if err != nil {
		t.Fatal(err)
	}
	w := bufio.NewWriter(f)
	debut := now - jours*jourS
	pas := float64(jours*jourS) / float64(n)
	for i := 0; i < n; i++ {
		at := debut + int64(float64(i)*pas) + rng.Int63n(30) - 15 // presque dans l'ordre, comme sbxwaf
		ip := fmt.Sprintf("203.0.%d.%d", rng.Intn(nIP)/250, rng.Intn(nIP)%250)
		if rng.Intn(10) < 3 { // récidivistes : 20 adresses qui reviennent sans cesse
			ip = fmt.Sprintf("198.51.100.%d", rng.Intn(20))
		}
		switch x := rng.Intn(100); {
		case x == 0:
			fmt.Fprintln(w, `{"ip":`) // illisible
			continue
		case x < 8:
			b, _ := json.Marshal(BanRecord{IP: ip, Category: "robot-verifie:g", Severity: "info", At: at, Action: "unban"})
			w.Write(append(b, '\n'))
			continue
		}
		duree := []int64{4 * 3600, jourS, 7 * jourS, 30 * jourS}[rng.Intn(4)]
		exp := at + duree
		if rng.Intn(500) == 0 {
			exp = 0 // jusqu'à un unban explicite
		}
		b, _ := json.Marshal(BanRecord{IP: ip, Category: categoriesTest[rng.Intn(len(categoriesTest))], Severity: "medium", At: at, Expires: exp, Action: "ban"})
		w.Write(append(b, '\n'))
	}
	if err := w.Flush(); err != nil {
		t.Fatal(err)
	}
	f.Close()
}

func copierFichier(t testing.TB, src, dst string) {
	t.Helper()
	b, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, b, 0o640); err != nil {
		t.Fatal(err)
	}
}

func adressesDe(t testing.TB, chemin string) []string {
	t.Helper()
	b, _ := os.ReadFile(chemin)
	vu := map[string]bool{}
	for _, l := range bytes.Split(b, []byte("\n")) {
		var r BanRecord
		if json.Unmarshal(l, &r) == nil && r.IP != "" {
			vu[r.IP] = true
		}
	}
	var out []string
	for ip := range vu {
		out = append(out, ip)
	}
	sort.Strings(out)
	return out
}

func actifsTries(s *BanStore, now int64) []string {
	var out []string
	for _, r := range s.ActiveBans(now) {
		b, _ := json.Marshal(r)
		out = append(out, string(b))
	}
	sort.Strings(out)
	return out
}

// memeRelecture compare tout ce que le WAF relit du journal, à l'instant `now`.
func memeRelecture(t *testing.T, complet, compacte *BanStore, ips []string, now int64, maxBannies int) {
	t.Helper()
	a, b := actifsTries(complet, now), actifsTries(compacte, now)
	if strings.Join(a, "\n") != strings.Join(b, "\n") {
		t.Fatalf("ActiveBans diffère : %d contre %d", len(a), len(b))
	}
	actives := map[string]bool{}
	for _, r := range complet.ActiveBans(now) {
		actives[r.IP] = true
	}
	for _, ip := range ips {
		for _, p := range []string{"leurre:", "campagne:", ""} {
			for _, fen := range []int64{jourS, 30 * jourS} {
				if x, y := complet.CompteCategorie(ip, p, now-fen), compacte.CompteCategorie(ip, p, now-fen); x != y {
					t.Fatalf("CompteCategorie(%s, %q, %d j) : %d contre %d", ip, p, fen/jourS, x, y)
				}
			}
		}
	}
	// DepuisChaine ne sert qu'à réévaluer un ban ACTIF (reevaluation.go) : comparée pour les adresses bannies de
	// l'échantillon et `maxBannies` autres (chaque appel relit tout le journal).
	var bannies []string
	for ip := range actives {
		bannies = append(bannies, ip)
	}
	sort.Strings(bannies)
	if len(bannies) > maxBannies {
		bannies = bannies[:maxBannies]
	}
	for _, ip := range ips {
		if actives[ip] {
			bannies = append(bannies, ip)
		}
	}
	for _, ip := range bannies {
		if x, y := complet.DepuisChaine(ip, now), compacte.DepuisChaine(ip, now); x != y {
			t.Fatalf("DepuisChaine(%s) : %s contre %s", ip, x, y)
		}
	}
	// sanctions de l'actor-ban (24 h)
	ab1, ab2 := &ActorBan{store: complet}, &ActorBan{store: compacte}
	s1, s2 := ab1.sanctions(now-jourS), ab2.sanctions(now-jourS)
	if fmt.Sprint(s1) != fmt.Sprint(s2) {
		t.Fatalf("sanctions 24 h diffèrent")
	}
}

// echantillon : les 20 récidivistes (longues chaînes) et environ 40 autres au hasard (CompteCategorie
// relit le journal à chaque appel).
func echantillon(ips []string, graine int64) []string {
	rng := rand.New(rand.NewSource(graine))
	vu := map[string]bool{}
	var out []string
	for _, ip := range ips {
		if strings.HasPrefix(ip, "198.51.100.") || rng.Intn(len(ips)) < 40 {
			vu[ip] = true
			out = append(out, ip)
		}
	}
	return out
}

// lignesArchivees relit toutes les archives mensuelles (gzip multi-membres).
func lignesArchivees(t testing.TB, dir string) []string {
	t.Helper()
	var out []string
	noms, _ := filepath.Glob(filepath.Join(dir, "bans-*.jsonl.gz"))
	for _, nom := range noms {
		f, err := os.Open(nom)
		if err != nil {
			t.Fatal(err)
		}
		gz, err := gzip.NewReader(f)
		if err != nil {
			t.Fatal(err)
		}
		b, err := io.ReadAll(gz)
		if err != nil {
			t.Fatalf("%s : %v", nom, err)
		}
		f.Close()
		for _, l := range strings.Split(strings.TrimSuffix(string(b), "\n"), "\n") {
			if l != "" {
				out = append(out, l)
			}
		}
	}
	return out
}

func lignesJournal(t testing.TB, chemin string) []string {
	t.Helper()
	b, err := os.ReadFile(chemin)
	if err != nil {
		t.Fatal(err)
	}
	s := strings.TrimSuffix(string(b), "\n")
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
}

func TestCompactageRelectureIdentique(t *testing.T) {
	now := time.Date(2026, 11, 19, 8, 0, 0, 0, time.UTC)
	for graine := int64(1); graine <= 4; graine++ {
		t.Run(fmt.Sprint(graine), func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			chemin := filepath.Join(dir, "bans.jsonl")
			journalSynthetique(t, chemin, 3000, 200+int(graine)*50, 120, now.Unix(), graine)
			copie := filepath.Join(t.TempDir(), "complet.jsonl")
			copierFichier(t, chemin, copie)
			avant := lignesJournal(t, chemin)

			s, ref := NewBanStore(chemin), NewBanStore(copie)
			b, err := s.Compacter(now, CompactageBans{Fenetre: 31 * 24 * time.Hour, ArchivesMois: 6})
			if err != nil {
				t.Fatal(err)
			}
			if !b.Reecrit || b.Archivees == 0 || b.Gardees+b.Archivees != b.Lignes || b.OctetsApres >= b.OctetsAvant {
				t.Fatalf("bilan inattendu : %+v", b)
			}
			ips := echantillon(adressesDe(t, copie), graine)
			memeRelecture(t, ref, s, ips, now.Unix(), 60)

			// Aucune ligne perdue : gardées + archivées = toutes, dans l'ordre pour les gardées.
			apres, arch := lignesJournal(t, chemin), lignesArchivees(t, dir)
			if len(apres)+len(arch) != len(avant) {
				t.Fatalf("%d gardées + %d archivées ≠ %d lignes", len(apres), len(arch), len(avant))
			}
			tout := append(append([]string{}, apres...), arch...)
			sort.Strings(tout)
			ref2 := append([]string{}, avant...)
			sort.Strings(ref2)
			if strings.Join(tout, "\n") != strings.Join(ref2, "\n") {
				t.Fatal("gardées + archivées ≠ journal d'origine")
			}
			j := 0
			for _, l := range avant {
				if j < len(apres) && apres[j] == l {
					j++
				}
			}
			if j != len(apres) {
				t.Fatal("l'ordre des lignes gardées n'est pas celui du journal")
			}

			// Toutes les lignes de moins de 30 j restent.
			for _, l := range arch {
				var r BanRecord
				if json.Unmarshal([]byte(l), &r) == nil && r.IP != "" && r.At >= now.Unix()-30*jourS {
					t.Fatalf("ligne récente archivée : %s", l)
				}
			}

			// Mêmes ajouts sur les deux journaux, relus plus tard : toujours la même chose (même état de chaîne).
			rng := rand.New(rand.NewSource(graine))
			for i := 0; i < 300; i++ {
				at := now.Unix() + int64(i)*600
				rec := BanRecord{IP: ips[rng.Intn(len(ips))], Category: categoriesTest[rng.Intn(len(categoriesTest))], At: at, Expires: at + 4*3600, Action: "ban"}
				if i%7 == 0 {
					rec = BanRecord{IP: rec.IP, At: at, Action: "unban"}
				}
				s.Append(rec)
				ref.Append(rec)
			}
			for _, d := range []int64{jourS, 10 * jourS} {
				memeRelecture(t, ref, s, ips, now.Unix()+d, 60)
			}

			// Seconde passe : rien à archiver sous le seuil, fichier intact (même inode).
			st1, _ := os.Stat(chemin)
			b2, err := s.Compacter(now, CompactageBans{Fenetre: 31 * 24 * time.Hour, ArchivesMois: 6, Seuil: 1 << 20})
			if err != nil || b2.Reecrit {
				t.Fatalf("seconde passe : %+v %v", b2, err)
			}
			st2, _ := os.Stat(chemin)
			if !os.SameFile(st1, st2) {
				t.Fatal("réécrit sous le seuil")
			}
		})
	}
}

// Cas limites écrits à la main : ban actif très ancien sans échéance, chaîne de 40 j (au-delà de la fenêtre), unban
// récent après un vieux ban, adresse entièrement ancienne.
func TestCompactageCasLimites(t *testing.T) {
	now := time.Date(2026, 11, 19, 8, 0, 0, 0, time.UTC).Unix()
	dir := t.TempDir()
	chemin := filepath.Join(dir, "bans.jsonl")
	var lignes []BanRecord
	// A : ban permanent posé il y a 90 j, toujours actif.
	lignes = append(lignes, BanRecord{IP: "192.0.2.1", Category: "leurre:x", At: now - 90*jourS, Expires: 0, Action: "ban"})
	// B : chaîne ininterrompue de bans de 7 j depuis 40 j.
	for d := int64(40); d > 0; d -= 6 {
		lignes = append(lignes, BanRecord{IP: "192.0.2.2", Category: "campagne:c", At: now - d*jourS, Expires: now - d*jourS + 7*jourS, Action: "ban"})
	}
	// C : vieux ban puis unban récent.
	lignes = append(lignes, BanRecord{IP: "192.0.2.3", Category: "scanners", At: now - 60*jourS, Expires: now - 59*jourS, Action: "ban"},
		BanRecord{IP: "192.0.2.3", At: now - jourS, Action: "unban"})
	// D : tout ancien, échu.
	lignes = append(lignes, BanRecord{IP: "192.0.2.4", Category: "scanners", At: now - 70*jourS, Expires: now - 69*jourS, Action: "ban"},
		BanRecord{IP: "192.0.2.4", At: now - 69*jourS, Action: "unban"})
	// E : ban de 30 j posé il y a 45 j puis ban court il y a 20 j (même chaîne grâce à l'échéance longue).
	lignes = append(lignes, BanRecord{IP: "192.0.2.5", Category: "leurre:y", At: now - 45*jourS, Expires: now - 15*jourS, Action: "ban"},
		BanRecord{IP: "192.0.2.5", Category: "leurre:y", At: now - 20*jourS, Expires: now - 19*jourS, Action: "ban"})
	f, _ := os.Create(chemin)
	for _, r := range lignes {
		b, _ := json.Marshal(r)
		f.Write(append(b, '\n'))
	}
	f.WriteString(`{"ip":"192.0.2.9","cat":"coupée`) // écriture interrompue : recopiée telle quelle
	f.Close()
	copie := filepath.Join(t.TempDir(), "complet.jsonl")
	copierFichier(t, chemin, copie)

	s, ref := NewBanStore(chemin), NewBanStore(copie)
	if _, err := s.Compacter(time.Unix(now, 0), CompactageBans{Fenetre: 31 * 24 * time.Hour, ArchivesMois: 6}); err != nil {
		t.Fatal(err)
	}
	memeRelecture(t, ref, s, []string{"192.0.2.1", "192.0.2.2", "192.0.2.3", "192.0.2.4", "192.0.2.5"}, now, 60)
	garde := string(lireTout(t, chemin))
	for _, attendu := range []string{`"192.0.2.1"`, `"at":` + fmt.Sprint(now-40*jourS), `"at":` + fmt.Sprint(now-45*jourS)} {
		if !strings.Contains(garde, attendu) {
			t.Fatalf("%s devait rester :\n%s", attendu, garde)
		}
	}
	if strings.Contains(garde, `"192.0.2.4"`) || strings.Contains(garde, `"at":`+fmt.Sprint(now-60*jourS)) {
		t.Fatalf("lignes anciennes non archivées :\n%s", garde)
	}
	if !strings.HasSuffix(garde, `{"ip":"192.0.2.9","cat":"coupée`) {
		t.Fatal("fin sans « \\n » non recopiée")
	}
	if d := s.DepuisChaine("192.0.2.2", now); d < 39*24*time.Hour {
		t.Fatalf("chaîne de 40 j raccourcie : %s", d)
	}
}

func lireTout(t testing.TB, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// Ajouts pendant le compactage : aucun n'est perdu (fin recopiée sous le verrou, puis nouveau fichier).
func TestCompactageAjoutsConcurrents(t *testing.T) {
	now := time.Now()
	dir := t.TempDir()
	chemin := filepath.Join(dir, "bans.jsonl")
	journalSynthetique(t, chemin, 20000, 3000, 90, now.Unix(), 42)
	s := NewBanStore(chemin)
	var wg sync.WaitGroup
	stop := make(chan struct{})
	ajoutes := 0
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			s.Append(BanRecord{IP: fmt.Sprintf("192.0.2.%d", ajoutes%250), Category: "concurrent", At: now.Unix(), Expires: now.Unix() + 3600, Action: "ban"})
			ajoutes++
		}
	}()
	for i := 0; i < 3; i++ {
		if _, err := s.Compacter(now, CompactageBans{Fenetre: 31 * 24 * time.Hour, ArchivesMois: 6}); err != nil {
			t.Fatal(err)
		}
	}
	close(stop)
	wg.Wait()
	n := strings.Count(string(lireTout(t, chemin)), `"cat":"concurrent"`)
	if n != ajoutes {
		t.Fatalf("%d ajouts, %d relus", ajoutes, n)
	}
	if ajoutes == 0 {
		t.Fatal("aucun ajout concurrent")
	}
}

// Archives : mois de `at`, ajoutées (gzip multi-membres) sans écraser l'existant, purgées au-delà de N mois ; mode 0640
// du journal conservé ; temporaires d'une passe interrompue retirés.
func TestCompactageArchivesEtPurge(t *testing.T) {
	now := time.Date(2026, 11, 19, 8, 0, 0, 0, time.UTC)
	dir := t.TempDir()
	chemin := filepath.Join(dir, "bans.jsonl")
	ecrire := func(recs ...BanRecord) {
		f, err := os.OpenFile(chemin, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o640)
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range recs {
			b, _ := json.Marshal(r)
			f.Write(append(b, '\n'))
		}
		f.Close()
	}
	aout := time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC).Unix()
	sept := time.Date(2026, 9, 10, 0, 0, 0, 0, time.UTC).Unix()
	ecrire(BanRecord{IP: "192.0.2.1", At: aout, Expires: aout + 3600, Action: "ban", Category: "a"},
		BanRecord{IP: "192.0.2.2", At: sept, Expires: sept + 3600, Action: "ban", Category: "b"},
		BanRecord{IP: "192.0.2.3", At: now.Unix() - 3600, Expires: now.Unix() + 3600, Action: "ban", Category: "c"})
	os.Chmod(chemin, 0o640)
	vieux := filepath.Join(dir, "bans-202604.jsonl.gz")
	limite := filepath.Join(dir, "bans-202605.jsonl.gz")
	os.WriteFile(vieux, []byte("x"), 0o640)
	os.WriteFile(limite, []byte{}, 0o640)
	os.WriteFile(filepath.Join(dir, "bans.jsonl.tmp-123"), []byte("reste"), 0o600)
	os.WriteFile(filepath.Join(dir, "bans-202611.jsonl.gz.tmp-9"), []byte("reste"), 0o600)
	os.WriteFile(filepath.Join(dir, "autre.json"), []byte("{}"), 0o600)

	s := NewBanStore(chemin)
	b, err := s.Compacter(now, CompactageBans{Fenetre: 31 * 24 * time.Hour, ArchivesMois: 6})
	if err != nil || b.Archivees != 2 || b.ArchivesSupprimees != 1 {
		t.Fatalf("%+v %v", b, err)
	}
	if _, err := os.Stat(vieux); !os.IsNotExist(err) {
		t.Fatal("archive de plus de 6 mois non supprimée")
	}
	if _, err := os.Stat(limite); err != nil {
		t.Fatal("archive de mai (6 mois) supprimée à tort")
	}
	for _, nom := range []string{"bans.jsonl.tmp-123", "bans-202611.jsonl.gz.tmp-9"} {
		if _, err := os.Stat(filepath.Join(dir, nom)); !os.IsNotExist(err) {
			t.Fatalf("temporaire %s non retiré", nom)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "autre.json")); err != nil {
		t.Fatal("fichier étranger retiré")
	}
	st, _ := os.Stat(chemin)
	if st.Mode().Perm() != 0o640 {
		t.Fatalf("mode %v", st.Mode().Perm())
	}
	for _, m := range []string{"202608", "202609"} {
		st, err := os.Stat(filepath.Join(dir, "bans-"+m+".jsonl.gz"))
		if err != nil || st.Mode().Perm() != 0o640 {
			t.Fatalf("archive %s : %v", m, err)
		}
	}
	// Une seconde vague pour août : ajoutée à la même archive, l'ancien membre reste lisible.
	ecrire(BanRecord{IP: "192.0.2.4", At: aout + 10, Expires: aout + 20, Action: "ban", Category: "d"})
	if _, err := s.Compacter(now, CompactageBans{Fenetre: 31 * 24 * time.Hour, ArchivesMois: 6}); err != nil {
		t.Fatal(err)
	}
	f, _ := os.Open(filepath.Join(dir, "bans-202608.jsonl.gz"))
	gz, _ := gzip.NewReader(f)
	tout, err := io.ReadAll(gz)
	f.Close()
	if err != nil || strings.Count(string(tout), "\n") != 2 || !strings.Contains(string(tout), "192.0.2.1") || !strings.Contains(string(tout), "192.0.2.4") {
		t.Fatalf("archive d'août : %q %v", tout, err)
	}
	if got := lignesJournal(t, chemin); len(got) != 1 || !strings.Contains(got[0], "192.0.2.3") {
		t.Fatalf("journal : %v", got)
	}
}

// Un journal remplacé par un lien pendant / avant la passe n'est pas suivi : abandon, rien d'écrit à sa place.
func TestCompactageRefuseUnLien(t *testing.T) {
	dir := t.TempDir()
	vrai := filepath.Join(dir, "ailleurs.jsonl")
	now := time.Now()
	journalSynthetique(t, vrai, 2000, 300, 90, now.Unix(), 7)
	chemin := filepath.Join(dir, "bans.jsonl")
	os.Symlink(vrai, chemin)
	avant := lireTout(t, vrai)
	if _, err := NewBanStore(chemin).Compacter(now, CompactageBans{Fenetre: 31 * 24 * time.Hour}); err == nil {
		t.Fatal("lien suivi")
	}
	if !bytes.Equal(avant, lireTout(t, vrai)) {
		t.Fatal("cible du lien modifiée")
	}
	if fi, _ := os.Lstat(chemin); fi.Mode()&os.ModeSymlink == 0 {
		t.Fatal("lien remplacé")
	}
}

// La fenêtre ne descend jamais sous 30 j (lecteurs de récidive).
func TestCompactageFenetreMinimale(t *testing.T) {
	now := time.Date(2026, 11, 19, 8, 0, 0, 0, time.UTC)
	dir := t.TempDir()
	chemin := filepath.Join(dir, "bans.jsonl")
	at := now.Unix() - 20*jourS
	b, _ := json.Marshal(BanRecord{IP: "192.0.2.1", At: at, Expires: at + 3600, Action: "ban", Category: "leurre:x"})
	os.WriteFile(chemin, append(b, '\n'), 0o640)
	r, err := NewBanStore(chemin).Compacter(now, CompactageBans{Fenetre: 7 * 24 * time.Hour})
	if err != nil || r.Archivees != 0 {
		t.Fatalf("ban de 20 j archivé avec une fenêtre demandée de 7 j : %+v %v", r, err)
	}
}

// Journal réel de gk2 : ~105 000 lignes, 27 000 adresses, depuis août. Temps et mémoire d'une passe, et relecture
// identique.
func TestCompactageGrosJournal(t *testing.T) {
	if testing.Short() {
		t.Skip("gros journal")
	}
	now := time.Date(2026, 11, 19, 8, 0, 0, 0, time.UTC)
	dir := t.TempDir()
	chemin := filepath.Join(dir, "bans.jsonl")
	journalSynthetique(t, chemin, 105000, 27000, 90, now.Unix(), 3816)
	copie := filepath.Join(t.TempDir(), "complet.jsonl")
	copierFichier(t, chemin, copie)
	s := NewBanStore(chemin)

	runtime.GC()
	var m0, m1 runtime.MemStats
	runtime.ReadMemStats(&m0)
	debut := time.Now()
	b, err := s.Compacter(now, CompactageBans{Fenetre: 31 * 24 * time.Hour, ArchivesMois: 6, Seuil: 256 * 1024})
	duree := time.Since(debut)
	runtime.ReadMemStats(&m1)
	if err != nil {
		t.Fatal(err)
	}
	alloue := m1.TotalAlloc - m0.TotalAlloc
	t.Logf("105 000 lignes : %s, %d alloués (Mo), %+v", duree, alloue>>20, b)
	if duree > 20*time.Second {
		t.Fatalf("passe trop lente : %s", duree)
	}
	if alloue > 128<<20 {
		t.Fatalf("passe trop gourmande : %d Mo alloués", alloue>>20)
	}
	if !b.Reecrit || b.OctetsApres > b.OctetsAvant*3/4 {
		t.Fatalf("compactage insuffisant : %+v", b)
	}
	ref := NewBanStore(copie)
	a1, a2 := actifsTries(ref, now.Unix()), actifsTries(s, now.Unix())
	if strings.Join(a1, "\n") != strings.Join(a2, "\n") {
		t.Fatalf("ActiveBans diffère : %d contre %d", len(a1), len(a2))
	}
	// échantillon d'adresses pour la récidive et les chaînes (toutes : trop long pour CompteCategorie × 27 000)
	ips := adressesDe(t, copie)
	rng := rand.New(rand.NewSource(1))
	ech := []string{}
	for i := 0; i < 5; i++ {
		ech = append(ech, fmt.Sprintf("198.51.100.%d", i))
	}
	for i := 0; i < 3; i++ {
		ech = append(ech, ips[rng.Intn(len(ips))])
	}
	memeRelecture(t, ref, s, ech, now.Unix(), 10)
}

// La passe périodique démarre tout de suite (démarrage du WAF) et rend la main avec un intervalle nul.
func TestVeillerCompactageUnePasse(t *testing.T) {
	now := time.Now()
	dir := t.TempDir()
	chemin := filepath.Join(dir, "bans.jsonl")
	journalSynthetique(t, chemin, 5000, 500, 120, now.Unix(), 9)
	avant, _ := os.Stat(chemin)
	NewBanStore(chemin).VeillerCompactage(CompactageBans{Fenetre: 31 * 24 * time.Hour, ArchivesMois: 6}, 0)
	apres, _ := os.Stat(chemin)
	if apres.Size() >= avant.Size() {
		t.Fatal("aucune passe au démarrage")
	}
	var nilStore *BanStore
	nilStore.VeillerCompactage(CompactageBans{}, 0) // --ban-store "" : rien
}
