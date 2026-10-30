// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
//
// Tests des signatures STRUCTURELLES du moteur de regles (#3257, tache 2).
//
// Une signature structurelle ne lit pas le texte de la requete : elle lit le
// ResultatMultipart de l'analyseur. Chacune est chargee ou rejetee NOMMEMENT,
// jamais ignoree en silence, et une erreur locale ne vide jamais le moteur.

package main

import (
	"os"
	"strings"
	"testing"
	"time"
)

const corpusStructurel = `{
  "_meta": {"version": "t"},
  "categories": {
    "php2shell": {"name": "P", "severity": "high", "mode": "detect",
      "patterns": [{"id": "p-1", "pattern": "zzzjamais"}],
      "structural": [
        {"id": "php2shell-001", "check": "upload_progress_fichiers", "params": {"fichiers_apres_min": 2},
         "cve": "CVE-2026-109618", "source": ["https://exemple.invalid/a", "https://exemple.invalid/b"], "confidence": "high", "desc": "d"},
        {"id": "php2shell-002", "check": "parties_nombre", "params": {"parties_min": 50},
         "severity": "medium", "cve": "CVE-2026-109619", "source": "https://exemple.invalid/chaine", "confidence": "medium",
         "seuil": "provisoire, non sourcé (2026-10-29)"},
        {"id": "php2shell-003", "check": "noms_profondeur", "params": {"profondeur_min": 12}, "source": 42, "champ_inconnu": true},
        {"id": "php2shell-004", "check": "filename_charge", "params": {}},
        {"id": "x-1", "check": "inconnu", "params": {"a": 1}},
        {"id": "x-2", "check": "parties_nombre"}
      ]},
    "sqli": {"name": "S", "severity": "critical", "patterns": [{"id": "sq-1", "pattern": "union select"}]}
  }
}`

func evalIDs(ds []DetectionStructurelle) []string {
	var out []string
	for _, d := range ds {
		out = append(out, d.RuleID)
	}
	return out
}

func TestStructurelChargeEtCompte(t *testing.T) {
	r := LoadRules(ecrisRegles(t, corpusStructurel))
	d, c, rej, _ := r.Integrite()
	// 2 motifs regex + 4 structurelles valides ; 6 structurelles declarees.
	if d != 2+6 || c != 2+4 {
		t.Errorf("declares=%d charges=%d, attendu 8/6", d, c)
	}
	j := strings.Join(rej, "|")
	if !strings.Contains(j, "x-1") || !strings.Contains(j, "x-2") || len(rej) != 2 {
		t.Errorf("rejetes=%v, attendu x-1 et x-2 seulement", rej)
	}
	// source de type inattendu : le fichier reste charge (moteur non vide).
	if _, _, _, _, hit := r.MatchDetail("GET", "/", "q=union select 1", "", "ua", true, nil); !hit {
		t.Error("le moteur est vide : un champ source inattendu a fait echouer le chargement")
	}
}

func TestStructurelHorsDetectRejete(t *testing.T) {
	for _, mode := range []string{"block", "escalate", ""} {
		corpus := `{"categories": {"php2shell": {"severity": "high", "mode": "` + mode + `",
		  "patterns": [{"id": "p-1", "pattern": "abc"}],
		  "structural": [
		    {"id": "h-1", "check": "parties_nombre", "params": {"parties_min": 1}},
		    {"id": "h-2", "check": "filename_charge"}]}}}`
		r := LoadRules(ecrisRegles(t, corpus))
		d, c, rej, _ := r.Integrite()
		if d != 3 || c != 1 {
			t.Errorf("mode %q : declares=%d charges=%d, attendu 3/1", mode, d, c)
		}
		j := strings.Join(rej, "|")
		if !strings.Contains(j, "h-1") || !strings.Contains(j, "h-2") {
			t.Errorf("mode %q : rejetes=%v", mode, rej)
		}
		if got := r.EvaluerStructurel(ResultatMultipart{Parties: 99, FilenamePHP: true}); len(got) != 0 {
			t.Errorf("mode %q : evaluation non vide : %v", mode, got)
		}
	}
}

func TestStructurelParamsInvalidesEtIdVide(t *testing.T) {
	corpus := `{"categories": {"php2shell": {"mode": "detect", "structural": [
	  {"id": "a", "check": "parties_nombre", "params": {"parties_min": 0}},
	  {"id": "b", "check": "parties_nombre", "params": {"parties_min": 2.5}},
	  {"id": "c", "check": "parties_nombre", "params": {"parties_min": "50"}},
	  {"id": "", "check": "filename_charge"},
	  "pas un objet",
	  {"id": "ok", "check": "parties_nombre", "params": {"parties_min": 3}}]}}}`
	r := LoadRules(ecrisRegles(t, corpus))
	d, c, rej, _ := r.Integrite()
	if d != 6 || c != 1 || len(rej) != 5 {
		t.Errorf("declares=%d charges=%d rejetes=%v, attendu 6/1/5", d, c, rej)
	}
	if !strings.Contains(strings.Join(rej, "|"), "php2shell#3") {
		t.Errorf("id vide : le rejet doit etre nomme <categorie>#<index> : %v", rej)
	}
}

func TestStructurelStructuralMalForme(t *testing.T) {
	// "structural" n'est pas une liste : rejet nomme, motifs regex intacts.
	corpus := `{"categories": {"php2shell": {"mode": "detect",
	  "patterns": [{"id": "p-1", "pattern": "abc"}], "structural": {"id": "x"}}}}`
	r := LoadRules(ecrisRegles(t, corpus))
	_, c, rej, _ := r.Integrite()
	if c != 1 || len(rej) != 1 {
		t.Errorf("charges=%d rejetes=%v, attendu 1 et 1 rejet", c, rej)
	}
}

func TestEvaluerStructurelSeuils(t *testing.T) {
	r := LoadRules(ecrisRegles(t, corpusStructurel))
	cas := []struct {
		nom string
		res ResultatMultipart
		ids []string
	}{
		{"parties 49", ResultatMultipart{Parties: 49}, nil},
		{"parties 50", ResultatMultipart{Parties: 50}, []string{"php2shell-002"}},
		{"profondeur 11", ResultatMultipart{ProfondeurMax: 11}, nil},
		{"profondeur 12", ResultatMultipart{ProfondeurMax: 12}, []string{"php2shell-003"}},
		{"progress +1", ResultatMultipart{Progress: true, FichiersApresProgress: 1}, nil},
		{"progress +2", ResultatMultipart{Progress: true, FichiersApresProgress: 2}, []string{"php2shell-001"}},
		{"sans progress +5", ResultatMultipart{FichiersApresProgress: 5}, nil},
		{"filename objet", ResultatMultipart{FilenameObjet: true}, []string{"php2shell-004"}},
		{"filename php", ResultatMultipart{FilenamePHP: true}, []string{"php2shell-004"}},
		{"tout, ordre du fichier", ResultatMultipart{Parties: 60, ProfondeurMax: 20, Progress: true, FichiersApresProgress: 3, FilenamePHP: true},
			[]string{"php2shell-001", "php2shell-002", "php2shell-003", "php2shell-004"}},
	}
	for _, c := range cas {
		got := evalIDs(r.EvaluerStructurel(c.res))
		if strings.Join(got, ",") != strings.Join(c.ids, ",") {
			t.Errorf("%s : %v, attendu %v", c.nom, got, c.ids)
		}
	}
	// Severite : celle de la signature si renseignee, sinon celle de la categorie.
	ds := r.EvaluerStructurel(ResultatMultipart{Parties: 60, Progress: true, FichiersApresProgress: 2})
	if len(ds) != 2 {
		t.Fatalf("detections=%v", ds)
	}
	if ds[0].Severity != "high" || ds[0].Categorie != "php2shell" || ds[0].CVE != "CVE-2026-109618" {
		t.Errorf("sig 001 : %+v", ds[0])
	}
	if ds[1].Severity != "medium" || ds[1].CVE != "CVE-2026-109619" {
		t.Errorf("sig 002 : %+v", ds[1])
	}
}

func TestEvaluerStructurelCategorieDesactivee(t *testing.T) {
	corpus := `{"categories": {"php2shell": {"enabled": false, "mode": "detect", "structural": [
	  {"id": "d-1", "check": "parties_nombre", "params": {"parties_min": 1}}]}}}`
	r := LoadRules(ecrisRegles(t, corpus))
	if got := r.EvaluerStructurel(ResultatMultipart{Parties: 9}); got != nil {
		t.Errorf("attendu nil, recu %v", got)
	}
	if d, c, rej, _ := r.Integrite(); d != 0 || c != 0 || len(rej) != 0 {
		t.Errorf("categorie desactivee comptee : %d/%d %v", d, c, rej)
	}
}

func TestStructurelNeMasquePasMatchDetail(t *testing.T) {
	// php2shell placee AVANT sqli : ses signatures structurelles ne doivent
	// jamais entrer dans MatchDetail ni masquer une categorie suivante.
	r := LoadRules(ecrisRegles(t, corpusStructurel))
	cat, _, _, id, hit := r.MatchDetail("GET", "/", "q=union select 1", "", "ua", true, nil)
	if !hit || cat != "sqli" || id != "sq-1" {
		t.Errorf("cat=%q id=%q hit=%v", cat, id, hit)
	}
	if _, _, _, _, hit := r.MatchDetail("GET", "/", "q=php2shell-001", "", "ua", true, nil); hit {
		t.Error("une signature structurelle a fuite dans MatchDetail")
	}
}

func TestStructurelRechargementAChaud(t *testing.T) {
	f := ecrisRegles(t, corpusStructurel)
	r := LoadRules(f)
	if got := r.EvaluerStructurel(ResultatMultipart{Parties: 10}); len(got) != 0 {
		t.Fatalf("avant rechargement : %v", got)
	}
	nouveau := strings.Replace(corpusStructurel, `"parties_min": 50`, `"parties_min": 10`, 1)
	if err := os.WriteFile(f, []byte(nouveau), 0o644); err != nil {
		t.Fatal(err)
	}
	plus := time.Now().Add(2 * time.Second)
	if err := os.Chtimes(f, plus, plus); err != nil {
		t.Fatal(err)
	}
	r.Maybe()
	got := evalIDs(r.EvaluerStructurel(ResultatMultipart{Parties: 10}))
	if len(got) != 1 || got[0] != "php2shell-002" {
		t.Errorf("apres rechargement : %v", got)
	}
}
