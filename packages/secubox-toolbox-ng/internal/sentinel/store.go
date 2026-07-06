// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package sentinel

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"time"

	"go.etcd.io/bbolt"
)

// verdictsBucket is the single bbolt bucket holding all persisted verdicts.
// Keys are 12 bytes: an 8-byte big-endian unix timestamp (seconds) followed
// by a 4-byte big-endian per-bucket sequence number. This keeps keys sorted
// chronologically for cheap ts-DESC iteration while guaranteeing uniqueness
// for verdicts recorded within the same second.
var verdictsBucket = []byte("verdicts")

// Store persists Sentinel verdicts in a bbolt (pure-Go, cgo-free) database.
// Identity is carried only as MacHash; the store is meant to be TTL-bounded
// via Prune, never a long-term archive.
type Store struct {
	db *bbolt.DB
}

// OpenStore opens (creating if necessary) a bbolt-backed verdict store at
// path, ensuring the verdicts bucket exists.
func OpenStore(path string) (*Store, error) {
	db, err := bbolt.Open(path, 0o600, &bbolt.Options{Timeout: 5 * time.Second})
	if err != nil {
		return nil, fmt.Errorf("sentinel: open store %q: %w", path, err)
	}
	err = db.Update(func(tx *bbolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists(verdictsBucket)
		return err
	})
	if err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("sentinel: init bucket: %w", err)
	}
	return &Store{db: db}, nil
}

// Close closes the underlying database.
func (s *Store) Close() error {
	return s.db.Close()
}

// verdictKey builds the 12-byte chronological+sequence key for ts.
func verdictKey(ts int64, seq uint64) []byte {
	key := make([]byte, 12)
	// ts is stored as unsigned for correct big-endian lexicographic sort;
	// verdict timestamps are always non-negative unix seconds.
	binary.BigEndian.PutUint64(key[0:8], uint64(ts))
	binary.BigEndian.PutUint32(key[8:12], uint32(seq))
	return key
}

func keyTS(key []byte) int64 {
	return int64(binary.BigEndian.Uint64(key[0:8]))
}

// Record persists v as-is. It does NOT stamp or otherwise mutate v.TS — the
// gate stamps the timestamp at match time.
func (s *Store) Record(v *Verdict) error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket(verdictsBucket)
		seq, err := b.NextSequence()
		if err != nil {
			return fmt.Errorf("sentinel: next sequence: %w", err)
		}
		data, err := json.Marshal(v)
		if err != nil {
			return fmt.Errorf("sentinel: marshal verdict: %w", err)
		}
		return b.Put(verdictKey(v.TS, seq), data)
	})
}

// Recent returns up to limit verdicts, most-recent (highest TS) first.
func (s *Store) Recent(limit int) ([]Verdict, error) {
	var out []Verdict
	if limit <= 0 {
		return out, nil
	}
	err := s.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket(verdictsBucket)
		c := b.Cursor()
		for k, v := c.Last(); k != nil && len(out) < limit; k, v = c.Prev() {
			var vd Verdict
			if err := json.Unmarshal(v, &vd); err != nil {
				return fmt.Errorf("sentinel: unmarshal verdict: %w", err)
			}
			out = append(out, vd)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ByMac returns up to limit verdicts for macHash, most-recent first. This is
// a linear reverse scan — the store is TTL-bounded/small by design, so this
// avoids the need for a secondary index.
func (s *Store) ByMac(macHash string, limit int) ([]Verdict, error) {
	var out []Verdict
	if limit <= 0 {
		return out, nil
	}
	err := s.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket(verdictsBucket)
		c := b.Cursor()
		for k, v := c.Last(); k != nil && len(out) < limit; k, v = c.Prev() {
			var vd Verdict
			if err := json.Unmarshal(v, &vd); err != nil {
				return fmt.Errorf("sentinel: unmarshal verdict: %w", err)
			}
			if vd.MacHash == macHash {
				out = append(out, vd)
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Prune deletes all verdicts older than olderThan (relative to now) and
// returns the number of deleted rows.
func (s *Store) Prune(olderThan time.Duration) (int, error) {
	cutoff := time.Now().Add(-olderThan).Unix()
	deleted := 0
	err := s.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket(verdictsBucket)
		c := b.Cursor()
		var toDelete [][]byte
		for k, _ := c.First(); k != nil; k, _ = c.Next() {
			if keyTS(k) <= cutoff {
				// Copy the key: it's only valid for the lifetime of the
				// transaction / until the cursor moves on.
				kc := make([]byte, len(k))
				copy(kc, k)
				toDelete = append(toDelete, kc)
			}
		}
		for _, k := range toDelete {
			if err := b.Delete(k); err != nil {
				return fmt.Errorf("sentinel: delete pruned key: %w", err)
			}
			deleted++
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	return deleted, nil
}
