// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// Package store persiste les METADONNEES de messages.
//
// CE QU'IL NE STOCKE PAS. Le corps des messages, sauf si l'exploitant a
// explicitement mis `retention.store_body = true`. Une box qui archive des
// conversations chiffrees de bout en bout devient une cible d'un interet tout
// autre, et deplace la responsabilite juridique sur celui qui l'exploite
// (RFC §7). Le defaut protege donc l'exploitant, pas le code.
//
// L'expediteur est HACHE (SHA-256 tronque) meme quand le corps n'est pas
// conserve : un journal de qui parle a qui reste un journal, et la doctrine du
// parc hache deja les MAC pour la meme raison.
package store

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

type Store struct {
	db        *sql.DB
	storeBody bool
}

type Message struct {
	ID        string
	TS        time.Time
	Direction string // "in" | "out"
	Peer      string
	GroupID   string
	Size      int
	Body      string // vide si storeBody est faux
}

const schema = `
CREATE TABLE IF NOT EXISTS messages (
  id         TEXT PRIMARY KEY,
  ts         INTEGER NOT NULL,
  direction  TEXT    NOT NULL CHECK (direction IN ('in','out')),
  peer_hash  TEXT    NOT NULL,
  peer       TEXT,
  group_id   TEXT,
  size       INTEGER NOT NULL,
  body       TEXT,
  -- Colonne prevue pour le multi-comptes (RFC §11) : la v1 n'ecrit qu'une
  -- valeur, mais l'ajouter apres coup couterait une migration.
  account    TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_messages_ts   ON messages(ts DESC);
CREATE INDEX IF NOT EXISTS idx_messages_peer ON messages(peer_hash, ts DESC);
`

func Open(chemin string, storeBody bool) (*Store, error) {
	// _time_format=sqlite et le WAL : le demon ecrit pendant que l'API lit.
	db, err := sql.Open("sqlite", chemin+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, err
	}
	if _, err := db.Exec(schema); err != nil {
		return nil, fmt.Errorf("schema : %w", err)
	}
	return &Store{db: db, storeBody: storeBody}, nil
}

func hacher(s string) string {
	somme := sha256.Sum256([]byte(s))
	return hex.EncodeToString(somme[:16])
}

func (s *Store) Add(m Message) error {
	corps := ""
	if s.storeBody {
		corps = m.Body
	}
	_, err := s.db.Exec(
		`INSERT OR REPLACE INTO messages (id, ts, direction, peer_hash, peer, group_id, size, body)
		 VALUES (?,?,?,?,?,?,?,?)`,
		m.ID, m.TS.Unix(), m.Direction, hacher(m.Peer), m.Peer, m.GroupID, m.Size, corps)
	return err
}

// List rend une page d'historique, du plus recent au plus ancien.
func (s *Store) List(peer string, limite int, avant int64) ([]Message, error) {
	if limite <= 0 || limite > 200 {
		limite = 50
	}
	if avant <= 0 {
		avant = 1 << 62
	}
	req := `SELECT id, ts, direction, COALESCE(peer,''), COALESCE(group_id,''), size, COALESCE(body,'')
	        FROM messages WHERE ts < ?`
	args := []any{avant}
	if peer != "" {
		req += " AND peer_hash = ?"
		args = append(args, hacher(peer))
	}
	req += " ORDER BY ts DESC LIMIT ?"
	args = append(args, limite)

	lignes, err := s.db.Query(req, args...)
	if err != nil {
		return nil, err
	}
	defer lignes.Close()

	var out []Message
	for lignes.Next() {
		var m Message
		var ts int64
		if err := lignes.Scan(&m.ID, &ts, &m.Direction, &m.Peer, &m.GroupID, &m.Size, &m.Body); err != nil {
			return nil, err
		}
		m.TS = time.Unix(ts, 0).UTC()
		out = append(out, m)
	}
	return out, lignes.Err()
}

// Purge efface ce qui depasse la retention. Appelee periodiquement : une
// retention qui ne s'applique qu'au demarrage n'est pas une retention.
func (s *Store) Purge(heures int) (int64, error) {
	limite := time.Now().Add(-time.Duration(heures) * time.Hour).Unix()
	res, err := s.db.Exec(`DELETE FROM messages WHERE ts < ?`, limite)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func (s *Store) Close() error { return s.db.Close() }
