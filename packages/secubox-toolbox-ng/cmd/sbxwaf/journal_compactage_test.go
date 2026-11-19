// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// See LICENCE-CMSD-1.0.md for terms.

package main

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

// #3820 : compactage de mesures.jsonl et reevaluations.jsonl. Propriété centrale : le journal compacté est un SUFFIXE
// octet pour octet de l'ancien (plus les ajouts), qui contient toute ligne de moins de la fenêtre, plus de 8 Mio
// (mesures) ou au moins 5 000 lignes (réévaluations) ; le préfixe retiré se retrouve, dans l'ordre, dans les archives.
// Les lecteurs RÉELS de l'API (Python) rendent donc exactement la même chose (TestCompactageJournauxLecteursPython).

const nowPreuves = int64(1795075200) // 2026-11-19T00:00:00Z

func lignePreuve(r *rand.Rand, genre string, ts int64) string {
	ip := fmt.Sprintf("%d.%d.%d.%d", 1+r.Intn(223), r.Intn(256), r.Intn(256), 1+r.Intn(254))
	var v map[string]any
	if genre == "mesures" {
		v = map[string]any{"actor": fmt.Sprintf("ACT-%04d", r.Intn(2000)), "applique": r.Intn(4) != 0, "confiance": 40 + r.Intn(60),
			"decision": []string{"appliquee", "banni", "ecarte:plafond_horaire", "ecarte:robot_verifie"}[r.Intn(4)], "expire": ts + 300,
			"ip": ip, "mode": "auto", "niveau": []string{"DELAY", "CHALLENGE", "TARPIT", "DENY"}[r.Intn(4)],
			"raison": "bruit automatisé : délai", "risque": r.Intn(100), "ts": ts, "version": "v1"}
	} else {
		d := []string{"RELEASE", "EXTEND"}[r.Intn(2)]
		v = map[string]any{"applique": r.Intn(2) == 0, "categorie": categoriesTest[r.Intn(len(categoriesTest))], "compteur": true, "decision": d,
			"duree_s": r.Intn(3) * 3600, "ip": ip, "mode": "auto", "paquets": r.Intn(50), "raison": "n'a pas insisté pendant son ban",
			"recidives": 1 + r.Intn(4), "ts": ts, "version": "v1"}
	}
	b, _ := json.Marshal(v)
	return string(b) + "\n"
}

// journalPreuvesSynth écrit `parJour` lignes par jour sur `jours` jours se terminant à `fin` (ts croissants), avec
// quelques lignes illisibles (dont une de NUL, comme sur gk2) ; rend le nombre de lignes.
func journalPreuvesSynth(t testing.TB, chemin, genre string, jours, parJour int, fin int64, graine int64) int {
	t.Helper()
	r := rand.New(rand.NewSource(graine))
	var b bytes.Buffer
	debut := fin - int64(jours)*jourS
	n := jours * parJour
	pas := float64(fin-debut) / float64(n)
	for i := 0; i < n; i++ {
		ts := debut + int64(float64(i)*pas)
		switch {
		case i == n/3:
			b.WriteString(strings.Repeat("\x00", 255) + lignePreuve(r, genre, ts))
		case i%9973 == 17:
			b.WriteString("pas du json\n")
		default:
			b.WriteString(lignePreuve(r, genre, ts))
		}
	}
	if err := os.WriteFile(chemin, b.Bytes(), 0o640); err != nil {
		t.Fatal(err)
	}
	return n
}

// archivesBrutes : contenu décompressé des archives <prefixe>-AAAAMM.jsonl.gz, mois dans l'ordre.
func archivesBrutes(t testing.TB, dir, prefixe string) []byte {
	t.Helper()
	noms, _ := filepath.Glob(filepath.Join(dir, prefixe+"-[0-9][0-9][0-9][0-9][0-9][0-9].jsonl.gz"))
	var out []byte
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
		f.Close()
		if err != nil {
			t.Fatalf("%s : %v", nom, err)
		}
		out = append(out, b...)
	}
	return out
}

// verifierSuffixe : compacté = avant[k:] (k début de ligne), archives = avant[:k], et les bornes sont tenues.
func verifierSuffixe(t *testing.T, avant, apres, archives []byte, coupure int64, minOctets int64, minLignes int) {
	t.Helper()
	k := len(avant) - len(apres)
	if k < 0 || !bytes.Equal(avant[k:], apres) {
		t.Fatalf("le journal compacté n'est pas un suffixe de l'ancien (%d → %d octets)", len(avant), len(apres))
	}
	if k > 0 && avant[k-1] != '\n' {
		t.Fatalf("coupure au milieu d'une ligne (octet %d)", k)
	}
	if !bytes.Equal(archives, avant[:k]) {
		t.Fatalf("archives (%d octets) ≠ préfixe retiré (%d octets)", len(archives), k)
	}
	if k == 0 {
		return
	}
	if int64(len(apres)) <= minOctets {
		t.Fatalf("fin gardée %d octets ≤ %d", len(apres), minOctets)
	}
	if n := bytes.Count(apres, []byte("\n")); n < minLignes {
		t.Fatalf("%d lignes gardées < %d", n, minLignes)
	}
	for _, l := range bytes.SplitAfter(avant[:k], []byte("\n")) {
		if ts, ok := horodatageLigne(l); ok && ts >= coupure {
			t.Fatalf("ligne de la fenêtre archivée (ts %d ≥ %d)", ts, coupure)
		}
	}
}

func TestCompactageJournalSuffixeEtBornes(t *testing.T) {
	cas := []struct {
		nom, genre        string
		jours, parJour    int
		fenetre           time.Duration
		minOctets         int64
		minLignes         int
		attenduReecrit    bool
		fenetreDetermine  bool // la fenêtre (et non une borne) fixe la coupure
		attenduArchivesMo int
	}{
		{"fenêtre", "reevaluations", 40, 1000, 8 * 24 * time.Hour, 0, lignesLuesReevaluations, true, true, 0},
		{"plancher de lignes", "reevaluations", 40, 300, 8 * 24 * time.Hour, 0, lignesLuesReevaluations, true, false, 0},
		{"plancher d'octets", "mesures", 20, 2000, 2 * 24 * time.Hour, 4 * 1024 * 1024, 0, true, false, 0},
		{"fenêtre minimale 24 h", "reevaluations", 10, 1000, time.Hour, 0, 100, true, true, 0},
		{"tout dans la fenêtre", "mesures", 5, 1000, 8 * 24 * time.Hour, 0, 0, false, true, 0},
	}
	for i, c := range cas {
		t.Run(c.nom, func(t *testing.T) {
			dir := t.TempDir()
			chemin := filepath.Join(dir, c.genre+".jsonl")
			journalPreuvesSynth(t, chemin, c.genre, c.jours, c.parJour, nowPreuves, int64(i+1))
			avant := lireTout(t, chemin)
			now := time.Unix(nowPreuves, 0)
			b, err := CompacterJournal(chemin, c.genre, now, CompactageJournal{Fenetre: c.fenetre, MinOctets: c.minOctets,
				MinLignes: c.minLignes, ArchivesMois: 6})
			if err != nil {
				t.Fatal(err)
			}
			if b.Reecrit != c.attenduReecrit {
				t.Fatalf("réécrit = %v, attendu %v (%+v)", b.Reecrit, c.attenduReecrit, b)
			}
			fen := max(c.fenetre, fenetreMinimalePreuves)
			coupure := nowPreuves - int64(fen.Seconds())
			apres := lireTout(t, chemin)
			verifierSuffixe(t, avant, apres, archivesBrutes(t, dir, c.genre), coupure, c.minOctets, c.minLignes)
			if c.fenetreDetermine && b.Reecrit {
				// la première ligne gardée est la première de la fenêtre
				premiere := apres[:bytes.IndexByte(apres, '\n')+1]
				ts, ok := horodatageLigne(premiere)
				if !ok || ts < coupure {
					t.Fatalf("première ligne gardée ts=%d (%v), coupure %d", ts, ok, coupure)
				}
			}
			st, _ := os.Stat(chemin)
			if st.Mode().Perm() != 0o640 {
				t.Fatalf("mode %v", st.Mode().Perm())
			}
		})
	}
}

// Les lecteurs réels de l'API (veille_lecture.lire_fin_jsonl pour /mesures, readlines()[-5000:] puis
// enforcement.reevaluations pour /reevaluations) rendent la même chose avant et après compactage.
func TestCompactageJournauxLecteursPython(t *testing.T) {
	api, _ := filepath.Abs("../../../secubox-waf-ng/composants/waf/api")
	py, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 absent")
	}
	if _, err := os.Stat(filepath.Join(api, "veille_lecture.py")); err != nil {
		t.Skip("sources de l'API du WAF absentes")
	}
	script := filepath.Join(t.TempDir(), "lecteurs.py")
	if err := os.WriteFile(script, []byte(scriptLecteurs), 0o600); err != nil {
		t.Fatal(err)
	}
	lire := func(genre, chemin string, now int64) map[string]any {
		t.Helper()
		out, err := exec.Command(py, "-I", script, api, genre, chemin, fmt.Sprint(now)).Output()
		if err != nil {
			t.Fatalf("lecteurs.py : %v", err)
		}
		var v map[string]any
		if err := json.Unmarshal(out, &v); err != nil {
			t.Fatal(err)
		}
		return v
	}
	for _, c := range []struct {
		genre          string
		jours, parJour int
		j              JournalPreuves
	}{
		{"mesures", 30, 1500, JournalPreuves{Prefixe: "mesures", MinOctets: octetsLusMesures}}, // plancher de 8 Mio
		{"mesures", 30, 5000, JournalPreuves{Prefixe: "mesures", MinOctets: octetsLusMesures}}, // fenêtre de 8 j > 8 Mio
		{"reevaluations", 30, 1000, JournalPreuves{Prefixe: "reevaluations", MinLignes: lignesLuesReevaluations}},
		{"reevaluations", 30, 300, JournalPreuves{Prefixe: "reevaluations", MinLignes: lignesLuesReevaluations}}, // plancher de lignes
	} {
		t.Run(fmt.Sprintf("%s-%d", c.genre, c.parJour), func(t *testing.T) {
			dir := t.TempDir()
			chemin := filepath.Join(dir, c.genre+".jsonl")
			avantCopie := filepath.Join(t.TempDir(), "avant.jsonl")
			journalPreuvesSynth(t, chemin, c.genre, c.jours, c.parJour, nowPreuves, 7)
			copierFichier(t, chemin, avantCopie)
			b, err := CompacterJournal(chemin, c.j.Prefixe, time.Unix(nowPreuves, 0), CompactageJournal{Fenetre: 8 * 24 * time.Hour,
				MinOctets: c.j.MinOctets, MinLignes: c.j.MinLignes, ArchivesMois: 6})
			if err != nil || !b.Reecrit {
				t.Fatalf("compactage : %+v %v", b, err)
			}
			avant, apres := lire(c.genre, avantCopie, nowPreuves), lire(c.genre, chemin, nowPreuves)
			// Les bornes du Go sont celles de l'API.
			if int64(avant["octets"].(float64)) != octetsLusMesures || int(avant["lignes_max"].(float64)) != lignesLuesReevaluations {
				t.Fatalf("bornes de l'API changées : %v / %v", avant["octets"], avant["lignes_max"])
			}
			ja, _ := json.Marshal(avant["resultats"])
			jb, _ := json.Marshal(apres["resultats"])
			if !bytes.Equal(ja, jb) {
				t.Fatalf("lecture différente après compactage (%d → %d octets)", b.OctetsAvant, b.OctetsApres)
			}
			if len(ja) < 1000 {
				t.Fatalf("résultats suspects (trop courts) : %s", ja)
			}
			t.Logf("%s : %d → %d octets, %d lignes archivées ; lectures identiques", c.genre, b.OctetsAvant, b.OctetsApres, b.Archivees)
		})
	}
}

const scriptLecteurs = `
import importlib.util, json, re, sys
from pathlib import Path
api, genre, chemin, now = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4])
def charger(nom):
    spec = importlib.util.spec_from_file_location(nom, f"{api}/{nom}.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m
src = open(f"{api}/main.py", encoding="utf-8").read()
def produit(nom):
    expr = re.search(r"^" + nom + r" = ([0-9 *]+)", src, re.M).group(1)
    v = 1
    for x in expr.split("*"):
        v *= int(x)
    return v
octets, lignes_max, marge = produit("_MESURES_OCTETS"), produit("_REEVAL_LIGNES_MAX"), produit("_BANS_DEPUIS_MARGE_S")
res = {}
if genre == "mesures":
    vl = charger("veille_lecture")
    def ts(r):
        v = r.get("ts")
        return float(v) if isinstance(v, (int, float)) and not isinstance(v, bool) else None
    for depuis in (0, now - 40 * 86400, now - 8 * 86400 + marge, now - 3 * 86400, now - 86400, now - 3600, now + 10):
        for limite in (1, 500, 2000):
            recs, complet = vl.lire_fin_jsonl(Path(chemin), lambda r: (ts(r) or 0) >= depuis,
                                              lambda r: ts(r) is not None and ts(r) < depuis - marge, octets, limite)
            res[f"{depuis}/{limite}"] = {"complet": complet, "mesures": recs}
else:
    en = charger("enforcement")
    with open(chemin, encoding="utf-8") as f:
        fin = f.readlines()[-lignes_max:]
    out = []
    for ligne in fin:
        try:
            r = json.loads(ligne)
        except ValueError:
            continue
        if isinstance(r, dict):
            out.append(r)
    for limite in (1, 100, 1000):
        res[str(limite)] = en.reevaluations(out, now, limite)
print(json.dumps({"octets": octets, "lignes_max": lignes_max, "resultats": res}, sort_keys=True))
`

// Ajouts pendant le compactage (par les écrivains réels, sous verrouAjout) : aucun n'est perdu ni réordonné.
func TestCompactageJournalAjoutsConcurrents(t *testing.T) {
	dir := t.TempDir()
	chemin := filepath.Join(dir, "reevaluations.jsonl")
	journalPreuvesSynth(t, chemin, "reevaluations", 30, 1000, nowPreuves, 3)
	avant := lireTout(t, chemin)
	rv := &Reeval{}
	var wg sync.WaitGroup
	stop := make(chan struct{})
	var ajoutes []string
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			v := map[string]any{"ts": nowPreuves + int64(i), "ip": "198.51.100.7", "decision": "RELEASE", "n": i}
			b, _ := json.Marshal(v)
			ajoutes = append(ajoutes, string(b)+"\n")
			rv.ecrire(chemin, v)
		}
	}()
	for p := 0; p < 3; p++ {
		if _, err := CompacterJournal(chemin, "reevaluations", time.Unix(nowPreuves+int64(p)*3*jourS, 0),
			CompactageJournal{Fenetre: 8 * 24 * time.Hour, MinLignes: 100, ArchivesMois: 6}); err != nil {
			t.Fatal(err)
		}
	}
	close(stop)
	wg.Wait()
	tout := append(archivesBrutes(t, dir, "reevaluations"), lireTout(t, chemin)...)
	attendu := append(append([]byte{}, avant...), []byte(strings.Join(ajoutes, ""))...)
	if !bytes.Equal(tout, attendu) {
		t.Fatalf("archives + journal ≠ ancien journal + ajouts (%d / %d octets, %d ajouts)", len(tout), len(attendu), len(ajoutes))
	}
	if len(ajoutes) == 0 {
		t.Fatal("aucun ajout concurrent")
	}
}

func TestCompactageJournalSeuilFinPartielleEtLien(t *testing.T) {
	dir := t.TempDir()
	chemin := filepath.Join(dir, "mesures.jsonl")
	journalPreuvesSynth(t, chemin, "mesures", 12, 200, nowPreuves, 5)
	// fin sans « \n » (écriture en cours) : recopiée telle quelle
	f, _ := os.OpenFile(chemin, os.O_WRONLY|os.O_APPEND, 0)
	f.WriteString(`{"ts":17950`)
	f.Close()
	avant := lireTout(t, chemin)
	st0, _ := os.Stat(chemin)
	cfg := CompactageJournal{Fenetre: 8 * 24 * time.Hour, ArchivesMois: 6, Seuil: int64(len(avant))}
	b, err := CompacterJournal(chemin, "mesures", time.Unix(nowPreuves, 0), cfg)
	if err != nil || b.Reecrit {
		t.Fatalf("sous le seuil : %+v %v", b, err)
	}
	if st1, _ := os.Stat(chemin); !os.SameFile(st0, st1) {
		t.Fatal("réécrit sous le seuil")
	}
	cfg.Seuil = 0
	if b, err = CompacterJournal(chemin, "mesures", time.Unix(nowPreuves, 0), cfg); err != nil || !b.Reecrit {
		t.Fatalf("%+v %v", b, err)
	}
	apres := lireTout(t, chemin)
	verifierSuffixe(t, avant, apres, archivesBrutes(t, dir, "mesures"), nowPreuves-8*jourS, 0, 0)
	if !bytes.HasSuffix(apres, []byte(`{"ts":17950`)) {
		t.Fatal("fin partielle perdue")
	}
	// un lien n'est jamais suivi
	lien := filepath.Join(dir, "lien.jsonl")
	os.Symlink(chemin, lien)
	if _, err := CompacterJournal(lien, "lien", time.Unix(nowPreuves+30*jourS, 0), cfg); err == nil {
		t.Fatal("lien suivi")
	}
	if !bytes.Equal(lireTout(t, chemin), apres) {
		t.Fatal("cible du lien modifiée")
	}
	// absent : rien
	if b, err := CompacterJournal(filepath.Join(dir, "absent.jsonl"), "absent", time.Unix(nowPreuves, 0), cfg); err != nil || b.Reecrit {
		t.Fatalf("absent : %+v %v", b, err)
	}
}

// Archives : un mois par ts (une ligne illisible suit la précédente), membres ajoutés, purge au-delà de ArchivesMois,
// temporaires d'une passe interrompue retirés, autres fichiers du dossier intouchés.
func TestCompactageJournalArchivesEtPurge(t *testing.T) {
	dir := t.TempDir()
	chemin := filepath.Join(dir, "mesures.jsonl")
	r := rand.New(rand.NewSource(9))
	var b strings.Builder
	for _, j := range []string{"2026-03-15", "2026-09-30", "2026-10-02"} {
		d, _ := time.Parse("2006-01-02", j)
		b.WriteString(lignePreuve(r, "mesures", d.Unix()))
	}
	b.WriteString("illisible\n")
	b.WriteString(lignePreuve(r, "mesures", nowPreuves-3600))
	os.WriteFile(chemin, []byte(b.String()), 0o640)
	for _, nom := range []string{"mesures.jsonl.tmp-123", "mesures-202610.jsonl.gz.tmp-9", "mesures-etat.json", "bans-202603.jsonl.gz"} {
		os.WriteFile(filepath.Join(dir, nom), []byte("x"), 0o640)
	}
	cfg := CompactageJournal{Fenetre: 24 * time.Hour, ArchivesMois: 6}
	if _, err := CompacterJournal(chemin, "mesures", time.Unix(nowPreuves, 0), cfg); err != nil {
		t.Fatal(err)
	}
	noms := func() string {
		e, _ := os.ReadDir(dir)
		var s []string
		for _, x := range e {
			s = append(s, x.Name())
		}
		return strings.Join(s, " ")
	}
	// 2026-03 < 2026-11 − 6 mois = 2026-05 : purgée tout de suite (même passe) ; illisible → mois d'octobre.
	if got := noms(); got != "bans-202603.jsonl.gz mesures-202609.jsonl.gz mesures-202610.jsonl.gz mesures-etat.json mesures.jsonl" {
		t.Fatalf("dossier : %s", got)
	}
	if a := string(archivesBrutes(t, dir, "mesures")); strings.Count(a, "\n") != 3 || !strings.HasSuffix(a, "illisible\n") {
		t.Fatalf("archives : %q", a)
	}
	// seconde passe : un membre gzip de plus dans l'archive d'octobre, toujours lisible
	f, _ := os.OpenFile(chemin, os.O_WRONLY|os.O_APPEND, 0)
	d, _ := time.Parse("2006-01-02", "2026-10-20")
	f.WriteString(lignePreuve(r, "mesures", d.Unix()+1)) // ts hors ordre : archivée avec la récente (tout est avant la coupure)
	f.Close()
	if _, err := CompacterJournal(chemin, "mesures", time.Unix(nowPreuves+2*jourS, 0), cfg); err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(string(archivesBrutes(t, dir, "mesures")), "\n"); n != 5 {
		t.Fatalf("%d lignes archivées, 5 attendues", n)
	}
	st, _ := os.Stat(filepath.Join(dir, "mesures-202610.jsonl.gz"))
	if st.Mode().Perm() != 0o640 {
		t.Fatalf("mode de l'archive %v", st.Mode().Perm())
	}
}

// Un fichier qui n'est pas à nous n'est pas réécrit (pas de chown possible sous seccomp).
func TestCompactageJournalAutreProprietaire(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("nécessite root pour poser un autre propriétaire")
	}
	dir := t.TempDir()
	chemin := filepath.Join(dir, "mesures.jsonl")
	journalPreuvesSynth(t, chemin, "mesures", 20, 100, nowPreuves, 1)
	os.Chown(chemin, 65534, 65534)
	if _, err := CompacterJournal(chemin, "mesures", time.Unix(nowPreuves, 0), CompactageJournal{Fenetre: 24 * time.Hour}); err == nil {
		t.Fatal("fichier d'un autre propriétaire compacté")
	}
}

// Volume de gk2 : 303 000 lignes / 84 Mo de mesures sur 41 jours.
func TestCompactageJournalGros(t *testing.T) {
	if testing.Short() {
		t.Skip("gros journal")
	}
	dir := t.TempDir()
	chemin := filepath.Join(dir, "mesures.jsonl")
	n := journalPreuvesSynth(t, chemin, "mesures", 41, 7400, nowPreuves, 11)
	avant := lireTout(t, chemin)
	var m0, m1 runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&m0)
	debut := time.Now()
	b, err := CompacterJournal(chemin, "mesures", time.Unix(nowPreuves, 0), CompactageJournal{Fenetre: 8 * 24 * time.Hour,
		MinOctets: octetsLusMesures, ArchivesMois: 6, Seuil: 1 << 20})
	duree := time.Since(debut)
	runtime.ReadMemStats(&m1)
	if err != nil || !b.Reecrit {
		t.Fatalf("%+v %v", b, err)
	}
	verifierSuffixe(t, avant, lireTout(t, chemin), archivesBrutes(t, dir, "mesures"), nowPreuves-8*jourS, octetsLusMesures, 0)
	var arch int64
	noms, _ := filepath.Glob(filepath.Join(dir, "mesures-*.jsonl.gz"))
	for _, nom := range noms {
		st, _ := os.Stat(nom)
		arch += st.Size()
	}
	t.Logf("%d lignes, %.1f Mo → %.1f Mo (%d archivées, archives gzip %.1f Mo) en %s, %.0f Mo alloués",
		n, float64(b.OctetsAvant)/1e6, float64(b.OctetsApres)/1e6, b.Archivees, float64(arch)/1e6, duree.Round(time.Millisecond),
		float64(m1.TotalAlloc-m0.TotalAlloc)/1e6)
	if b.OctetsApres > b.OctetsAvant/4 {
		t.Fatalf("pas assez réduit : %d → %d", b.OctetsAvant, b.OctetsApres)
	}
}

func TestVeillerCompactageJournauxUnePasse(t *testing.T) {
	dir := t.TempDir()
	m, r := filepath.Join(dir, "mesures.jsonl"), filepath.Join(dir, "reevaluations.jsonl")
	journalPreuvesSynth(t, m, "mesures", 20, 100, time.Now().Unix(), 1)
	journalPreuvesSynth(t, r, "reevaluations", 20, 100, time.Now().Unix(), 2)
	VeillerCompactageJournaux([]JournalPreuves{{Chemin: m, Prefixe: "mesures"}, {Chemin: r, Prefixe: "reevaluations", MinLignes: 1500},
		{Chemin: filepath.Join(dir, "absent.jsonl"), Prefixe: "absent"}}, CompactageJournal{Fenetre: 8 * 24 * time.Hour, ArchivesMois: 6}, 0)
	if n := len(lignesJournal(t, m)); n < 790 || n > 810 {
		t.Fatalf("mesures : %d lignes gardées, ≈ 800 attendues", n)
	}
	if n := len(lignesJournal(t, r)); n != 1500 {
		t.Fatalf("réévaluations : %d lignes gardées, 1500 attendues (plancher)", n)
	}
}
