// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// Package evidence implémente l'Evidence Ledger append-only INVIOLABLE d'Actor
// Intelligence (RFC-0013 §7/§14, RFC-0007). C'est un journal de preuves à
// chaînage de hash (tamper-evident) : chaque enregistrement embarque le hash de
// son prédécesseur, si bien qu'altérer un enregistrement passé casse la chaîne
// et devient détectable par Verify. Le journal est append-only STRICT — aucune
// API ne modifie ni ne supprime un enregistrement déjà figé.
//
// Deux invariants de conception guident ce module :
//
//   - « ASN/pays sont des contextes de routage, pas des identités » (RFC-0007).
//     On ne stocke ici que des observations MINIMISÉES (jamais un secret, jamais
//     un identifiant réputé stable) : la preuve décrit un comportement observé,
//     pas une personne.
//   - « une mise à jour des poids ne falsifie pas les anciens verdicts » : chaque
//     enregistrement fige sa propre AlgorithmVersion. Réviser le barème plus tard
//     n'altère aucun hash déjà chaîné — les anciens verdicts restent lisibles et
//     vérifiables tels qu'ils ont été émis.
package evidence

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"go.etcd.io/bbolt"
)

// GenesisHash est le PrevHash conventionnel du tout premier enregistrement :
// la chaîne démarre sur une valeur vide, documentée et stable.
const GenesisHash = ""

var (
	// bucketRecords contient chaque preuve figée, clé = numéro de séquence
	// (8 octets big-endian). L'ordre lexicographique bbolt = ordre de la chaîne,
	// ce qui rend Verify un simple range-scan sans index annexe.
	bucketRecords = []byte("records")
	// bucketByID indexe ID -> clé de séquence, pour un Get(id) en O(log n).
	bucketByID = []byte("by_id")
)

// Record est une preuve figée du ledger. Les champs Seq, PrevHash et Hash sont
// renseignés par Append ; toute valeur fournie par l'appelant y est écrasée.
type Record struct {
	ID               string `json:"id"`                // fourni par l'appelant (ex. evidence_id)
	Timestamp        int64  `json:"timestamp"`         // horodatage RFC 3339 en secondes unix
	Sensor           string `json:"sensor"`            // capteur émetteur
	Observation      string `json:"observation"`       // observation brute MINIMISÉE (pas de secret)
	Weight           int    `json:"weight"`            // pondération de la preuve (peut être négative)
	Explanation      string `json:"explanation"`       // justification explicable du verdict
	AlgorithmVersion string `json:"algorithm_version"` // version du barème figée avec la preuve
	Seq              uint64 `json:"seq"`               // rang dans la chaîne (rempli par Append)
	PrevHash         string `json:"prev_hash"`         // hash de l'enregistrement précédent (rempli par Append)
	Hash             string `json:"hash"`              // SHA256(canonical(record sans Hash) + PrevHash)
}

// canonicalRecord est la vue canonique et stable d'un Record hors champ Hash.
// L'ordre des champs y est figé : json.Marshal d'une struct sérialise dans
// l'ordre de déclaration, ce qui rend le hash DÉTERMINISTE et reproductible.
type canonicalRecord struct {
	ID               string `json:"id"`
	Timestamp        int64  `json:"timestamp"`
	Sensor           string `json:"sensor"`
	Observation      string `json:"observation"`
	Weight           int    `json:"weight"`
	Explanation      string `json:"explanation"`
	AlgorithmVersion string `json:"algorithm_version"`
	Seq              uint64 `json:"seq"`
	PrevHash         string `json:"prev_hash"`
}

// Ledger est le journal de preuves append-only adossé à bbolt.
type Ledger struct {
	db *bbolt.DB
}

// Open ouvre (ou crée) le ledger bbolt à `path` et garantit l'existence des
// buckets. Même motif que internal/sentinel/store.go.
func Open(path string) (*Ledger, error) {
	db, err := bbolt.Open(path, 0o600, &bbolt.Options{Timeout: 5 * time.Second})
	if err != nil {
		return nil, fmt.Errorf("evidence : ouverture ledger %q : %w", path, err)
	}
	err = db.Update(func(tx *bbolt.Tx) error {
		if _, e := tx.CreateBucketIfNotExists(bucketRecords); e != nil {
			return e
		}
		_, e := tx.CreateBucketIfNotExists(bucketByID)
		return e
	})
	if err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("evidence : init buckets : %w", err)
	}
	return &Ledger{db: db}, nil
}

// Close ferme la base sous-jacente.
func (l *Ledger) Close() error {
	return l.db.Close()
}

// seqKey encode un numéro de séquence en clé 8 octets big-endian (ordre
// lexicographique = ordre chronologique de la chaîne).
func seqKey(seq uint64) []byte {
	k := make([]byte, 8)
	binary.BigEndian.PutUint64(k, seq)
	return k
}

// hashRecord calcule le hash DÉTERMINISTE d'un enregistrement : SHA256 de la
// sérialisation canonique (hors Hash) concaténée au PrevHash, en hexadécimal.
func hashRecord(rec Record) (string, error) {
	c := canonicalRecord{
		ID:               rec.ID,
		Timestamp:        rec.Timestamp,
		Sensor:           rec.Sensor,
		Observation:      rec.Observation,
		Weight:           rec.Weight,
		Explanation:      rec.Explanation,
		AlgorithmVersion: rec.AlgorithmVersion,
		Seq:              rec.Seq,
		PrevHash:         rec.PrevHash,
	}
	blob, err := json.Marshal(c)
	if err != nil {
		return "", fmt.Errorf("evidence : sérialisation canonique : %w", err)
	}
	h := sha256.New()
	h.Write(blob)
	h.Write([]byte(rec.PrevHash))
	return hex.EncodeToString(h.Sum(nil)), nil
}

// Append fige un enregistrement : il renseigne Seq (rang monotone dans la
// chaîne), PrevHash (Hash du dernier enregistrement, ou GenesisHash si le ledger
// est vide), puis Hash, et l'écrit. Il ne modifie JAMAIS un enregistrement
// existant. Il retourne l'enregistrement complété.
func (l *Ledger) Append(rec Record) (Record, error) {
	var out Record
	err := l.db.Update(func(tx *bbolt.Tx) error {
		recs := tx.Bucket(bucketRecords)
		byID := tx.Bucket(bucketByID)

		// PrevHash = hash du dernier maillon (clé la plus haute), sinon genesis.
		prev := GenesisHash
		if _, last := recs.Cursor().Last(); last != nil {
			var lastRec Record
			if e := json.Unmarshal(last, &lastRec); e != nil {
				return fmt.Errorf("evidence : lecture dernier maillon : %w", e)
			}
			prev = lastRec.Hash
		}

		seq, e := recs.NextSequence()
		if e != nil {
			return fmt.Errorf("evidence : séquence : %w", e)
		}

		rec.Seq = seq
		rec.PrevHash = prev
		hash, e := hashRecord(rec)
		if e != nil {
			return e
		}
		rec.Hash = hash

		blob, e := json.Marshal(rec)
		if e != nil {
			return fmt.Errorf("evidence : sérialisation record : %w", e)
		}
		key := seqKey(seq)
		if e := recs.Put(key, blob); e != nil {
			return fmt.Errorf("evidence : écriture record : %w", e)
		}
		if e := byID.Put([]byte(rec.ID), key); e != nil {
			return fmt.Errorf("evidence : écriture index id : %w", e)
		}
		out = rec
		return nil
	})
	if err != nil {
		return Record{}, err
	}
	return out, nil
}

// Get retourne l'enregistrement d'identifiant `id`. Le booléen vaut false si
// aucun enregistrement ne porte cet ID.
func (l *Ledger) Get(id string) (Record, bool, error) {
	var rec Record
	found := false
	err := l.db.View(func(tx *bbolt.Tx) error {
		key := tx.Bucket(bucketByID).Get([]byte(id))
		if key == nil {
			return nil
		}
		blob := tx.Bucket(bucketRecords).Get(key)
		if blob == nil {
			return nil
		}
		if e := json.Unmarshal(blob, &rec); e != nil {
			return fmt.Errorf("evidence : désérialisation record : %w", e)
		}
		found = true
		return nil
	})
	if err != nil {
		return Record{}, false, err
	}
	return rec, found, nil
}

// Count retourne le nombre d'enregistrements figés dans la chaîne.
func (l *Ledger) Count() (int, error) {
	n := 0
	err := l.db.View(func(tx *bbolt.Tx) error {
		n = tx.Bucket(bucketRecords).Stats().KeyN
		return nil
	})
	if err != nil {
		return 0, err
	}
	return n, nil
}

// Verify recompute toute la chaîne et retourne (ok, index). ok vaut true et
// index -1 si la chaîne est intègre. Sinon ok vaut false et index (>=0) est le
// rang, dans l'ordre de la chaîne, du PREMIER enregistrement altéré — soit parce
// que son hash recalculé ne correspond plus au hash stocké (contenu modifié),
// soit parce que son PrevHash ne pointe plus sur le maillon précédent (chaîne
// rompue).
func (l *Ledger) Verify() (bool, int, error) {
	ok := true
	corrupt := -1
	err := l.db.View(func(tx *bbolt.Tx) error {
		c := tx.Bucket(bucketRecords).Cursor()
		prev := GenesisHash
		idx := 0
		for k, v := c.First(); k != nil; k, v = c.Next() {
			var rec Record
			if e := json.Unmarshal(v, &rec); e != nil {
				return fmt.Errorf("evidence : désérialisation record : %w", e)
			}
			computed, e := hashRecord(rec)
			if e != nil {
				return e
			}
			if rec.PrevHash != prev || computed != rec.Hash {
				ok = false
				corrupt = idx
				return nil
			}
			prev = rec.Hash
			idx++
		}
		return nil
	})
	if err != nil {
		return false, -1, err
	}
	return ok, corrupt, nil
}
