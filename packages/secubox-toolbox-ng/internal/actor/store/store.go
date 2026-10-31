// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// Package store persiste les Event Envelopes ingérés par sbx-actord (RFC-0013
// §9). Phase 0/1 : append-only sur bbolt (déjà vendoré et utilisé par
// internal/sentinel), avec compteurs agrégés pour alimenter /api/v1/actor/stats.
// Aucune décision ici : on stocke et on compte, la corrélation viendra dans
// internal/actor/{similarity,graph}.
//
// Clé d'événement : 8 octets timestamp (secondes, big-endian) + 8 octets numéro
// de séquence monotone. L'ordre lexicographique bbolt = ordre chronologique, ce
// qui rend les fenêtres 24 h (RFC-0013 §11) et le prune (rétention) triviaux par
// range-scan, sans index séparé.
package store

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"time"

	"go.etcd.io/bbolt"

	"github.com/CyberMind-FR/secubox-deb/secubox-toolbox-ng/internal/actor/envelope"
)

var (
	bucketEvents = []byte("events")
	bucketMeta   = []byte("meta")
	keySeq       = []byte("seq")   // compteur de séquence (uint64)
	keyTotal     = []byte("total") // total d'événements ingérés (uint64)
)

// Store est le magasin d'événements append-only.
type Store struct {
	db *bbolt.DB
}

// Stats est l'agrégat servi à la WebUI (contrat /api/v1/actor/stats).
type Stats struct {
	Total       uint64         `json:"total"`
	Events24h   int            `json:"events_24h"`
	Blocked24h  int            `json:"blocked_24h"`
	Attempts24h int            `json:"attempts_24h"`
	BySensor    map[string]int `json:"by_sensor"`
	FirstTS     int64          `json:"first_ts"`
	LastTS      int64          `json:"last_ts"`
}

// Open ouvre (ou crée) le magasin bbolt à `path`.
func Open(path string) (*Store, error) {
	db, err := bbolt.Open(path, 0o600, OptionsBolt())
	if err != nil {
		return nil, fmt.Errorf("ouverture store actord : %w", err)
	}
	err = db.Update(func(tx *bbolt.Tx) error {
		if _, e := tx.CreateBucketIfNotExists(bucketEvents); e != nil {
			return e
		}
		_, e := tx.CreateBucketIfNotExists(bucketMeta)
		return e
	})
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	return &Store{db: db}, nil
}

// Close ferme le magasin.
func (s *Store) Close() error { return s.db.Close() }

func eventKey(ts int64, seq uint64) []byte {
	k := make([]byte, 16)
	binary.BigEndian.PutUint64(k[0:8], uint64(ts))
	binary.BigEndian.PutUint64(k[8:16], seq)
	return k
}

// OptionsBolt : options d'ouverture communes (#3320). NoFreelistSync : la liste
// des pages libres n'est plus reecrite a chaque commit (enorme apres les purges
// d'une base de plusieurs centaines de Mo) ; elle est reconstruite a
// l'ouverture. FreelistMapType : allocation en O(1) au lieu d'un tableau trie.
func OptionsBolt() *bbolt.Options {
	return &bbolt.Options{Timeout: 5 * time.Second, NoFreelistSync: true, FreelistType: bbolt.FreelistMapType}
}

// Ingest persiste une enveloppe (supposée déjà validée par l'appelant) et met à
// jour les compteurs, dans une seule transaction.
func (s *Store) Ingest(e *envelope.Envelope) error {
	return s.IngestLot([]*envelope.Envelope{e})
}

// IngestLot persiste un lot d'enveloppes en UNE transaction (#3320 : une
// transaction synchronisee par evenement coutait deux fsync par requete vue par
// le WAF).
func (s *Store) IngestLot(lot []*envelope.Envelope) error {
	blobs := make([][]byte, len(lot))
	for i, e := range lot {
		b, err := json.Marshal(e)
		if err != nil {
			return err
		}
		blobs[i] = b
	}
	return s.db.Update(func(tx *bbolt.Tx) error {
		meta := tx.Bucket(bucketMeta)
		seq := readU64(meta, keySeq)
		evs := tx.Bucket(bucketEvents)
		for i, e := range lot {
			seq++
			if err := evs.Put(eventKey(e.Timestamp, seq), blobs[i]); err != nil {
				return err
			}
		}
		if err := putU64(meta, keySeq, seq); err != nil {
			return err
		}
		return putU64(meta, keyTotal, readU64(meta, keyTotal)+uint64(len(lot)))
	})
}

// Stats calcule l'agrégat. `now` est l'horloge (injectable pour les tests) ;
// la fenêtre 24 h est un range-scan à partir de now-86400.
func (s *Store) Stats(now int64) (Stats, error) {
	st := Stats{BySensor: map[string]int{}}
	cutoff := eventKey(now-86400, 0)
	err := s.db.View(func(tx *bbolt.Tx) error {
		meta := tx.Bucket(bucketMeta)
		st.Total = readU64(meta, keyTotal)
		c := tx.Bucket(bucketEvents).Cursor()
		if k, _ := c.First(); k != nil {
			st.FirstTS = int64(binary.BigEndian.Uint64(k[0:8]))
		}
		if k, _ := c.Last(); k != nil {
			st.LastTS = int64(binary.BigEndian.Uint64(k[0:8]))
		}
		for k, v := c.Seek(cutoff); k != nil; k, v = c.Next() {
			var e envelope.Envelope
			if json.Unmarshal(v, &e) != nil {
				continue
			}
			st.Events24h++
			st.BySensor[e.Sensor]++
			switch e.Action {
			case envelope.ActionBlock, envelope.ActionQuarantps:
				st.Blocked24h++
			default:
				st.Attempts24h++
			}
		}
		return nil
	})
	return st, err
}

// Recent retourne les n derniers événements, du plus récent au plus ancien.
func (s *Store) Recent(n int) ([]envelope.Envelope, error) {
	out := make([]envelope.Envelope, 0, n)
	err := s.db.View(func(tx *bbolt.Tx) error {
		c := tx.Bucket(bucketEvents).Cursor()
		for k, v := c.Last(); k != nil && len(out) < n; k, v = c.Prev() {
			var e envelope.Envelope
			if json.Unmarshal(v, &e) == nil {
				out = append(out, e)
			}
		}
		return nil
	})
	return out, err
}

// Prune supprime les événements antérieurs à `before` (rétention configurable,
// RFC-0013 §15). Retourne le nombre d'événements supprimés.
//
// #3320 : par lots de pruneLot cles, une transaction chacun — une heure
// d'evenements en un seul commit gonflait la liste des pages libres et les pages
// modifiees, et tenait le verrou d'ecriture tout du long.
func (s *Store) Prune(before int64) (int, error) {
	n := 0
	cutoff := eventKey(before, 0)
	for {
		lot := 0
		err := s.db.Update(func(tx *bbolt.Tx) error {
			c := tx.Bucket(bucketEvents).Cursor()
			for k, _ := c.First(); k != nil && lot < pruneLot; k, _ = c.First() {
				if string(k) >= string(cutoff) {
					break
				}
				if err := c.Delete(); err != nil {
					return err
				}
				lot++
			}
			return nil
		})
		n += lot
		if err != nil || lot < pruneLot {
			return n, err
		}
	}
}

// pruneLot : cles supprimees par transaction de purge.
const pruneLot = 5000

func readU64(b *bbolt.Bucket, key []byte) uint64 {
	v := b.Get(key)
	if len(v) != 8 {
		return 0
	}
	return binary.BigEndian.Uint64(v)
}

func putU64(b *bbolt.Bucket, key []byte, val uint64) error {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], val)
	return b.Put(key, buf[:])
}
