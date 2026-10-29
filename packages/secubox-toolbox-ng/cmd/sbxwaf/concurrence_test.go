// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// Tests de la passe de correction finale de #3273 (M1, reclassé Important) :
// la ligne capture-concurrence. En saturation, donc sous attaque, elle n'est
// plus écrite avant le relais : elle l'est après la réponse, sous le recover
// de l'analyse, au plus une par seconde et par genre, les suppressions
// comptées dans la ligne suivante.
package main

import (
	"bytes"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// M1 : pendant le relais, aucune ligne capture-concurrence n'est encore
// écrite ; elle l'est après la réponse.
func TestCaptureConcurrenceApresLeRelais(t *testing.T) {
	var b *bancMultipart
	var mu sync.Mutex
	pendant := -1
	b = nouveauBancMultipart(t, func(w http.ResponseWriter, r *http.Request) {
		brut, _ := os.ReadFile(b.journal)
		mu.Lock()
		pendant = strings.Count(string(brut), `"capture-concurrence"`)
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	})
	b.s.capturesMultipart = make(chan struct{}, 1)
	b.s.capturesMultipart <- struct{}{}
	b.envoyer("nc.example", "/upload", ipPublique, ctTest, bytes.NewReader(corpsExploit()))
	mu.Lock()
	defer mu.Unlock()
	if pendant != 0 {
		t.Errorf("lignes capture-concurrence écrites avant le relais : %d, attendu 0", pendant)
	}
	if ls := lignesDe(b.lignes(t), "capture-concurrence"); len(ls) != 1 {
		t.Errorf("une ligne capture-concurrence attendue après la réponse, eu %v", ls)
	}
}

// M1 : au plus une ligne par seconde et par genre ; la suivante porte le
// nombre de lignes supprimées entre-temps (signal supprimees).
func TestCaptureConcurrenceDebitLimite(t *testing.T) {
	maintenant := time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)
	orig := horlogeConcurrence
	horlogeConcurrence = func() time.Time { return maintenant }
	t.Cleanup(func() { horlogeConcurrence = orig })

	b := nouveauBancMultipart(t, nil)
	b.s.rules = LoadRules(ecrisRegles(t, corpusUrlencodedTest))
	b.s.capturesMultipart = make(chan struct{}, 1)
	b.s.capturesMultipart <- struct{}{}
	b.s.capturesUrlencoded = make(chan struct{}, 1)
	b.s.capturesUrlencoded <- struct{}{}
	for i := 0; i < 3; i++ {
		b.envoyer("nc.example", "/upload", ipPublique, ctTest, bytes.NewReader(corpsExploit()))
	}
	b.envoyer("nc.example", "/index.php", ipPublique, "application/x-www-form-urlencoded", strings.NewReader("_task=mail"))
	conc := lignesDe(b.lignes(t), "capture-concurrence")
	if len(conc) != 2 {
		t.Fatalf("une ligne par genre attendue dans la seconde, eu %v", conc)
	}
	if g0, g1 := signalLigne(t, conc[0], "genre"), signalLigne(t, conc[1], "genre"); g0 != int(corpsMultipart) || g1 != int(corpsUrlencoded) {
		t.Errorf("genres %d puis %d, attendu multipart puis urlencoded", g0, g1)
	}
	maintenant = maintenant.Add(1100 * time.Millisecond)
	b.envoyer("nc.example", "/upload", ipPublique, ctTest, bytes.NewReader(corpsExploit()))
	conc = lignesDe(b.lignes(t), "capture-concurrence")
	if len(conc) != 3 {
		t.Fatalf("une nouvelle ligne multipart attendue après une seconde, eu %v", conc)
	}
	if n := signalLigne(t, conc[2], "supprimees"); n != 2 {
		t.Errorf("signals.supprimees = %d, attendu 2", n)
	}
	b.verifierSansSanction(t, ipPublique)
}
