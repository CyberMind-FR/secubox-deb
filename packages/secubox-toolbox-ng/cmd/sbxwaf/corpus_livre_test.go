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
	"os"
	"testing"
)

const corpusLivre = "../../../secubox-waf-ng/composants/waf/config/waf-rules.json"

func TestCorpusLivreSansRejet(t *testing.T) {
	r := LoadRules(corpusLivre)
	_, _, rej := r.Integrite()
	if len(rej) != 0 {
		t.Fatalf("rejetes=%v, attendu aucun", rej)
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
	dec := json.NewDecoder(bytes.NewReader(brut))
	var noms []string
	var racine struct {
		Categories json.RawMessage `json:"categories"`
	}
	if err := json.Unmarshal(brut, &racine); err != nil {
		t.Fatal(err)
	}
	dec = json.NewDecoder(bytes.NewReader(racine.Categories))
	dec.Token()
	for dec.More() {
		k, _ := dec.Token()
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
	json.Unmarshal(racine.Categories, &cats)
	if cats["php2shell"].Mode != "detect" {
		t.Errorf("mode = %q", cats["php2shell"].Mode)
	}
}
