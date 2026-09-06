// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package evidence

import (
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"go.etcd.io/bbolt"
)

// sample fabrique trois preuves déterministes à figer dans le ledger.
func sample() []Record {
	return []Record{
		{ID: "ev-1", Timestamp: 1788000001, Sensor: "sbxwaf", Observation: "sqli-probe", Weight: 40, Explanation: "motif union select", AlgorithmVersion: "v1"},
		{ID: "ev-2", Timestamp: 1788000002, Sensor: "sentinel", Observation: "scan-ports", Weight: 20, Explanation: "balayage rapide", AlgorithmVersion: "v1"},
		{ID: "ev-3", Timestamp: 1788000003, Sensor: "dpi", Observation: "tor-exit", Weight: -10, Explanation: "contexte routage", AlgorithmVersion: "v1"},
	}
}

func ouvre(t *testing.T, path string) *Ledger {
	t.Helper()
	l, err := Open(path)
	if err != nil {
		t.Fatalf("Open : %v", err)
	}
	return l
}

func TestAppendGetChain(t *testing.T) {
	path := filepath.Join(t.TempDir(), "evidence.db")
	l := ouvre(t, path)
	defer l.Close()

	var appended []Record
	for _, r := range sample() {
		got, err := l.Append(r)
		if err != nil {
			t.Fatalf("Append %s : %v", r.ID, err)
		}
		appended = append(appended, got)
	}

	// Seq croît 1,2,3.
	for i, r := range appended {
		if r.Seq != uint64(i+1) {
			t.Fatalf("Seq attendu %d, obtenu %d", i+1, r.Seq)
		}
	}

	// Premier maillon : PrevHash = genesis.
	if appended[0].PrevHash != GenesisHash {
		t.Fatalf("PrevHash du 1er maillon = %q, attendu genesis %q", appended[0].PrevHash, GenesisHash)
	}
	// Chaque PrevHash = Hash du précédent.
	for i := 1; i < len(appended); i++ {
		if appended[i].PrevHash != appended[i-1].Hash {
			t.Fatalf("maillon %d : PrevHash=%q, attendu Hash précédent=%q", i, appended[i].PrevHash, appended[i-1].Hash)
		}
	}
	// Chaque Hash est non vide.
	for _, r := range appended {
		if r.Hash == "" {
			t.Fatalf("Hash vide pour %s", r.ID)
		}
	}

	// Get retrouve chaque enregistrement à l'identique.
	for _, want := range appended {
		got, ok, err := l.Get(want.ID)
		if err != nil {
			t.Fatalf("Get %s : %v", want.ID, err)
		}
		if !ok {
			t.Fatalf("Get %s : introuvable", want.ID)
		}
		if got != want {
			t.Fatalf("Get %s : %+v != %+v", want.ID, got, want)
		}
	}

	// Get d'un ID inconnu.
	if _, ok, err := l.Get("inexistant"); err != nil || ok {
		t.Fatalf("Get inexistant : ok=%v err=%v", ok, err)
	}

	// Count correct.
	if n, err := l.Count(); err != nil || n != 3 {
		t.Fatalf("Count = %d (err %v), attendu 3", n, err)
	}

	// Verify sur chaîne saine.
	ok, idx, err := l.Verify()
	if err != nil {
		t.Fatalf("Verify : %v", err)
	}
	if !ok || idx != -1 {
		t.Fatalf("Verify chaîne saine = (%v, %d), attendu (true, -1)", ok, idx)
	}
}

func TestVerifyDetectsTampering(t *testing.T) {
	path := filepath.Join(t.TempDir(), "evidence.db")
	l := ouvre(t, path)
	for _, r := range sample() {
		if _, err := l.Append(r); err != nil {
			t.Fatalf("Append : %v", err)
		}
	}
	if err := l.Close(); err != nil {
		t.Fatalf("Close : %v", err)
	}

	// Falsification directe des octets : on rouvre la bbolt et on réécrit le
	// record du MILIEU (seq=2) avec une Observation modifiée, mais en CONSERVANT
	// son ancien Hash. La chaîne (PrevHash) reste cohérente autour de lui, donc
	// la seule anomalie détectable est que le hash recalculé de ce record ne
	// correspond plus à son Hash stocké : Verify doit le repérer à l'index 1.
	const tamperedSeq = uint64(2)
	const tamperedIdx = 1

	db, err := bbolt.Open(path, 0o600, &bbolt.Options{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("réouverture bbolt : %v", err)
	}
	err = db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketRecords)
		key := seqKey(tamperedSeq)
		var rec Record
		if e := json.Unmarshal(b.Get(key), &rec); e != nil {
			return e
		}
		oldHash := rec.Hash
		rec.Observation = "observation-falsifiee" // contenu altéré
		rec.Hash = oldHash                        // on garde l'ancien Hash
		blob, e := json.Marshal(rec)
		if e != nil {
			return e
		}
		return b.Put(key, blob)
	})
	if err != nil {
		t.Fatalf("falsification : %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("Close bbolt : %v", err)
	}

	// Réouverture via l'API : Verify détecte la corruption.
	l = ouvre(t, path)
	defer l.Close()

	ok, idx, err := l.Verify()
	if err != nil {
		t.Fatalf("Verify : %v", err)
	}
	if ok {
		t.Fatal("Verify n'a pas détecté la falsification")
	}
	if idx != tamperedIdx {
		t.Fatalf("index corrompu = %d, attendu %d", idx, tamperedIdx)
	}

	// Count reste correct après falsification (append-only : rien n'a été ajouté).
	if n, err := l.Count(); err != nil || n != 3 {
		t.Fatalf("Count = %d (err %v), attendu 3", n, err)
	}
}
