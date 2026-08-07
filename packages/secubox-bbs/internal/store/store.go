// Package store porte l'index SQLite du BBS.
//
// RAPPEL DE LA REGLE D'OR : le disque fait foi. Cette base est un INDEX,
// reconstructible en entier depuis content/ et files/. Rien de ce qu'elle
// contient n'existe uniquement ici — sinon la promesse « tout le BBS tient
// dans un repertoire copiable par rsync » serait fausse.
package store

import (
	"database/sql"
	"embed"
	"fmt"
	"sort"
	"strconv"
	"strings"

	_ "modernc.org/sqlite"
)

//go:embed migrations/*.sql
var migrationFS embed.FS

type Store struct{ db *sql.DB }

// Open ouvre la base et applique les migrations en attente.
func Open(path string) (*Store, error) {
	// _pragma dans la DSN : modernc applique ces PRAGMA a CHAQUE connexion du
	// pool. Les poser une seule fois via Exec ne vaudrait que pour la
	// connexion qui les a recus — et foreign_keys, desactive par defaut dans
	// SQLite, laisserait alors passer des cles etrangeres invalides EN
	// SILENCE sur les autres.
	dsn := path + "?_pragma=foreign_keys(1)&_pragma=journal_mode(wal)&_pragma=busy_timeout(5000)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("ouverture %s : %w", path, err)
	}
	s := &Store{db: db}
	if err := s.Migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

// Version rend le numero de la derniere migration appliquee.
func (s *Store) Version() (int, error) {
	var v sql.NullInt64
	err := s.db.QueryRow(`SELECT max(version) FROM schema_migrations`).Scan(&v)
	if err != nil {
		return 0, err
	}
	return int(v.Int64), nil
}

// Migrate applique les migrations manquantes, dans l'ordre.
//
// Idempotent par construction : une unite systemd redemarre, un paquet se
// reinstalle — cette fonction s'executera bien plus souvent qu'une fois.
func (s *Store) Migrate() error {
	if _, err := s.db.Exec(
		`CREATE TABLE IF NOT EXISTS schema_migrations (
			version INTEGER PRIMARY KEY, applied_at INTEGER NOT NULL)`); err != nil {
		return fmt.Errorf("table des migrations : %w", err)
	}

	applied := map[int]bool{}
	rows, err := s.db.Query(`SELECT version FROM schema_migrations`)
	if err != nil {
		return err
	}
	for rows.Next() {
		var v int
		if err := rows.Scan(&v); err != nil {
			rows.Close()
			return err
		}
		applied[v] = true
	}
	rows.Close()

	entries, err := migrationFS.ReadDir("migrations")
	if err != nil {
		return fmt.Errorf("lecture des migrations : %w", err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".sql") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names) // 0001_, 0002_ … l'ordre lexical EST l'ordre d'application

	for _, name := range names {
		v, err := versionOf(name)
		if err != nil {
			return err
		}
		if applied[v] {
			continue
		}
		body, err := migrationFS.ReadFile("migrations/" + name)
		if err != nil {
			return err
		}
		if err := s.applyOne(v, string(body)); err != nil {
			return fmt.Errorf("migration %s : %w", name, err)
		}
	}
	return nil
}

// applyOne applique UNE migration dans une transaction.
//
// L'atomicite n'est pas un detail : une migration a moitie appliquee laisse un
// schema qui ne correspond plus au code, et rien ne le signale. Mieux vaut
// refuser de demarrer que demarrer sur un schema partiel.
func (s *Store) applyOne(version int, body string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if _, err := tx.Exec(body); err != nil {
		return err
	}
	if _, err := tx.Exec(
		`INSERT INTO schema_migrations(version, applied_at) VALUES(?, unixepoch())`,
		version); err != nil {
		return err
	}
	return tx.Commit()
}

func versionOf(name string) (int, error) {
	i := strings.IndexByte(name, '_')
	if i < 0 {
		return 0, fmt.Errorf("nom de migration sans numero : %s", name)
	}
	v, err := strconv.Atoi(name[:i])
	if err != nil {
		return 0, fmt.Errorf("numero de migration illisible dans %s : %w", name, err)
	}
	return v, nil
}
