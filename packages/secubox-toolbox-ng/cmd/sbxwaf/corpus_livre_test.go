// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// Corpus livré par le paquet secubox-waf-ng : il doit se charger sans rejet et
// la catégorie php2shell doit détecter l'exploit de référence (#3257).
package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"
)

const corpusLivre = "../../../secubox-waf-ng/composants/waf/config/waf-rules.json"

func TestCorpusLivreSansRejet(t *testing.T) {
	r := LoadRules(corpusLivre)
	_, _, rej, _ := r.Integrite()
	if len(rej) != 0 {
		t.Fatalf("rejetes=%v, attendu aucun", rej)
	}
	for _, id := range idsAttendusLivres() {
		if !chargeesLivre(t)[id] {
			t.Errorf("signature %s absente du catalogue chargé", id)
		}
	}
	res := analyserMultipart(corpsImbrique(), ctTest, false, LimitesMultipart{})
	ids := map[string]bool{}
	for _, d := range r.EvaluerStructurel(res) {
		ids[d.RuleID] = true
	}
	for _, id := range []string{"php2shell-001", "php2shell-002"} {
		if !ids[id] {
			t.Errorf("%s absent des détections : %v", id, ids)
		}
	}
}

func TestCorpusLivrePhp2shellEnDernier(t *testing.T) {
	brut, err := os.ReadFile(corpusLivre)
	if err != nil {
		t.Fatal(err)
	}
	// L'ordre des clés n'est conservé que par un décodage par jetons.
	var racine struct {
		Categories json.RawMessage `json:"categories"`
	}
	if err := json.Unmarshal(brut, &racine); err != nil {
		t.Fatal(err)
	}
	dec := json.NewDecoder(bytes.NewReader(racine.Categories))
	if _, err := dec.Token(); err != nil {
		t.Fatal(err)
	}
	var noms []string
	for dec.More() {
		k, err := dec.Token()
		if err != nil {
			t.Fatal(err)
		}
		noms = append(noms, k.(string))
		var ignore json.RawMessage
		if err := dec.Decode(&ignore); err != nil {
			t.Fatal(err)
		}
	}
	if len(noms) == 0 || noms[len(noms)-1] != "php2shell" {
		t.Fatalf("dernière catégorie = %v", noms)
	}
	var cats map[string]struct {
		Mode string `json:"mode"`
	}
	if err := json.Unmarshal(racine.Categories, &cats); err != nil {
		t.Fatal(err)
	}
	if cats["php2shell"].Mode != "detect" {
		t.Errorf("mode = %q", cats["php2shell"].Mode)
	}
}

// idsAttendusLivres : toutes les signatures structurelles que le catalogue livré
// doit porter (#3273).
func idsAttendusLivres() []string {
	var ids []string
	for i := 1; i <= 6; i++ {
		ids = append(ids, "rc-00"+string(rune('0'+i)))
	}
	for i := 1; i <= 5; i++ {
		ids = append(ids, "nc-00"+string(rune('0'+i)))
	}
	for i := 1; i <= 7; i++ {
		ids = append(ids, "php-00"+string(rune('0'+i)))
	}
	for i := 1; i <= 8; i++ {
		ids = append(ids, "php2shell-00"+string(rune('0'+i)))
	}
	return ids
}

// chargeesLivre : ids des signatures structurelles chargées par LoadRules.
func chargeesLivre(t *testing.T) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	r := LoadRules(corpusLivre)
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, c := range r.current.cats {
		for _, s := range c.data.structurelles {
			out[s.id] = true
		}
	}
	return out
}

// entreeCatalogue : une signature du catalogue livré, lue en JSON brut.
type entreeCatalogue struct {
	ID       string                     `json:"id"`
	Check    string                     `json:"check"`
	Params   map[string]json.RawMessage `json:"params"`
	Severity string                     `json:"severity"`
	Services []string                   `json:"services"`
	CVE      string                     `json:"cve"`
	Seuil    string                     `json:"seuil"`
	Conf     string                     `json:"confidence"`
	Desc     string                     `json:"desc"`
	Source   []string                   `json:"source"`
}

type categorieCatalogue struct {
	Severity   string            `json:"severity"`
	Mode       string            `json:"mode"`
	Enabled    *bool             `json:"enabled"`
	Services   []string          `json:"services"`
	Structural []entreeCatalogue `json:"structural"`
}

func lireCatalogueLivre(t *testing.T) (map[string]categorieCatalogue, map[string]entreeCatalogue, map[string]string) {
	t.Helper()
	brut, err := os.ReadFile(corpusLivre)
	if err != nil {
		t.Fatal(err)
	}
	var racine struct {
		Categories map[string]categorieCatalogue `json:"categories"`
	}
	if err := json.Unmarshal(brut, &racine); err != nil {
		t.Fatal(err)
	}
	sigs := map[string]entreeCatalogue{}
	cat := map[string]string{}
	for nom, c := range racine.Categories {
		for _, s := range c.Structural {
			sigs[s.ID] = s
			cat[s.ID] = nom
		}
	}
	return racine.Categories, sigs, cat
}

func TestCorpusLivreDetecteLesReferences(t *testing.T) {
	r := LoadRules(corpusLivre)
	if _, _, rej, _ := r.Integrite(); len(rej) != 0 {
		t.Fatalf("rejetes=%v", rej)
	}
	ids := func(e *EntreePHP) map[string]bool {
		m := map[string]bool{}
		for _, d := range r.EvaluerPHP(e) {
			m[d.RuleID] = true
		}
		return m
	}
	multi := func(n int, frontiere string) *EntreePHP {
		ps := make([]partieTest, n)
		for i := range ps {
			ps[i] = partieTest{nom: "c" + strings.Repeat("x", i%3), contenu: "v"}
		}
		res := analyserMultipart(fabriquerMultipart(frontiere, ps, false), "multipart/form-data; boundary="+frontiere, false, LimitesMultipart{})
		return &EntreePHP{Multipart: &res}
	}
	// PoC de CVE-2025-49113 : _from piégé en requête, filename de session en multipart.
	poc := entreeRC("roundcube", "POST",
		"_task=settings&_action=upload&_from=edit-!%22;i:0;O:16:%22Crypt_GPG_Engine%22:",
		ctTest, fabriquerMultipart("BND", []partieTest{{nom: "_file[]", filename: `x|b:0;preferences_time|b:0;preferences|s:179:"a:3:{i:0;s:57:".png`, fichier: true, contenu: "x"}}, false))
	var chunked http.Request
	chunked.Method = "POST"
	chunked.Header = http.Header{"Content-Type": {"multipart/form-data; boundary=x"}}
	chunked.TransferEncoding = []string{"chunked"}
	cas := []struct {
		nom  string
		e    *EntreePHP
		want []string
	}{
		{"PoC 49113", poc, []string{"rc-001", "rc-002"}},
		{"POST /ocm/shares anonyme", &EntreePHP{Service: "nextcloud", PartageFedereAnonyme: true}, []string{"nc-001"}},
		{"PROPFIND GHSA-3qrf", &EntreePHP{DTDXML: prologueAvecDTD([]byte(pocDTD))}, []string{"php-002"}},
		{"cookie _[Host-x", &EntreePHP{CookieFauxPrefixe: cookieFauxPrefixe([]string{"_[Host-x=1"})}, []string{"php-003"}},
		{"1021 parties", multi(1021, "BND"), []string{"php-001"}},
		{"frontière 71", multi(2, strings.Repeat("B", 71)), []string{"php-004"}},
		{"chunked multipart", &EntreePHP{SansLongueur: corpsSansLongueur(&chunked)}, []string{"php2shell-005"}},
		{"Progress seul", &EntreePHP{Multipart: &ResultatMultipart{Progress: true}}, []string{"php-006"}},
		{"-d allow_url_include", &EntreePHP{SondePHPCGI: sondePHPCGI("-d+allow_url_include%3d1")}, []string{"php-007"}},
	}
	for _, c := range cas {
		got := ids(c.e)
		for _, w := range c.want {
			if !got[w] {
				t.Errorf("%s : %s absent (%v)", c.nom, w, got)
			}
		}
	}
	// Un service ne reçoit que ses familles.
	if got := ids(&EntreePHP{Service: "roundcube", PartageFedereAnonyme: true}); got["nc-001"] {
		t.Errorf("nc-001 vu sur un vhost roundcube")
	}
}

func TestCorpusLivreStructurellesEnDetect(t *testing.T) {
	cats, _, _ := lireCatalogueLivre(t)
	for nom, c := range cats {
		if len(c.Structural) > 0 && c.Mode != "detect" {
			t.Errorf("catégorie %s : mode %q, attendu detect", nom, c.Mode)
		}
	}
	for _, nom := range []string{"roundcube", "nextcloud", "php_requete"} {
		c, ok := cats[nom]
		if !ok {
			t.Errorf("catégorie %s absente", nom)
			continue
		}
		if c.Enabled == nil || !*c.Enabled {
			t.Errorf("catégorie %s non active", nom)
		}
	}
}

func TestCorpusLivreServicesDesFamilles(t *testing.T) {
	_, sigs, cat := lireCatalogueLivre(t)
	for id, s := range sigs {
		var want []string
		switch cat[id] {
		case "roundcube":
			want = []string{"roundcube"}
		case "nextcloud":
			want = []string{"nextcloud"}
		}
		if !reflect.DeepEqual(s.Services, want) {
			t.Errorf("%s : services %v, attendu %v", id, s.Services, want)
		}
	}
}

func TestCorpusLivreSeuilsProvisoiresEtiquetes(t *testing.T) {
	_, sigs, _ := lireCatalogueLivre(t)
	for _, id := range []string{"php2shell-002", "php2shell-003", "php2shell-006", "php2shell-007"} {
		if got := sigs[id].Seuil; got != "provisoire, non sourcé (2026-10-29)" {
			t.Errorf("%s : seuil %q", id, got)
		}
	}
}

func TestCorpusLivreFichesCompletes(t *testing.T) {
	_, sigs, _ := lireCatalogueLivre(t)
	for _, id := range idsAttendusLivres() {
		s := sigs[id]
		if s.CVE == "" {
			t.Errorf("%s : cve vide", id)
		}
		if s.Conf == "" || s.Desc == "" || len(s.Source) == 0 {
			t.Errorf("%s : confidence/desc/source incomplets", id)
		}
	}
}

// Le catalogue livré et les corpus des tests ne divergent pas : chaque
// signature d'un corpus de test existe dans le catalogue avec le même id, le
// même contrôle, la même gravité (si le corpus la fixe), les mêmes paramètres
// et les mêmes services.
func TestCorpusLivreEgalAuxCorpusDeTest(t *testing.T) {
	_, sigs, _ := lireCatalogueLivre(t)
	corpus := map[string]string{
		"roundcube": corpusRoundcubeTest, "nextcloud": corpusNextcloudTest,
		"php_requete": corpusPHPGeneriqueTest, "complements": corpusComplementsTest,
		"etiquettes": corpusEtiquettesTest,
	}
	noms := make([]string, 0, len(corpus))
	for n := range corpus {
		noms = append(noms, n)
	}
	sort.Strings(noms)
	vus := 0
	for _, n := range noms {
		var racine struct {
			Categories map[string]categorieCatalogue `json:"categories"`
		}
		if err := json.Unmarshal([]byte(corpus[n]), &racine); err != nil {
			t.Fatalf("%s : %v", n, err)
		}
		for _, c := range racine.Categories {
			for _, e := range c.Structural {
				vus++
				l, ok := sigs[e.ID]
				if !ok {
					t.Errorf("%s : %s absente du catalogue livré", n, e.ID)
					continue
				}
				if l.Check != e.Check {
					t.Errorf("%s : contrôle %q, livré %q", e.ID, e.Check, l.Check)
				}
				if e.Severity != "" && l.Severity != e.Severity {
					t.Errorf("%s : gravité %q, livrée %q", e.ID, e.Severity, l.Severity)
				}
				// Le cve n'est pas comparé : le corpus de test de php2shell-001
				// porte une valeur d'illustration ; TestCorpusLivreFichesCompletes
				// exige un cve non vide dans le catalogue.
				if e.Seuil != "" && l.Seuil != e.Seuil {
					t.Errorf("%s : seuil %q, livré %q", e.ID, e.Seuil, l.Seuil)
				}
				for p, v := range e.Params {
					if string(l.Params[p]) != string(v) {
						t.Errorf("%s : paramètre %s = %s, livré %s", e.ID, p, v, l.Params[p])
					}
				}
				if len(e.Services) > 0 && !reflect.DeepEqual(e.Services, l.Services) {
					t.Errorf("%s : services %v, livrés %v", e.ID, e.Services, l.Services)
				}
			}
		}
	}
	if vus < 20 {
		t.Errorf("seulement %d signatures comparées", vus)
	}
}
