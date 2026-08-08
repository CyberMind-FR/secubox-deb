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
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"

	_ "modernc.org/sqlite"
)

//go:embed migrations/*.sql
var migrationFS embed.FS

type Store struct {
	db *sql.DB
	// root est le repertoire qui CONTIENT la base. content/ et files/ vivent a
	// cote d'elle, et c'est ce repertoire entier qui constitue le BBS : le
	// copier, c'est tout emporter. La base n'est qu'un fichier de plus dedans,
	// et le seul qu'on puisse jeter sans rien perdre.
	root string
}

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
	s := &Store{db: db, root: filepath.Dir(path)}
	if err := s.Migrate(); err != nil {
		db.Close()
		return nil, err
	}
	// L'OUTIL D'ADMINISTRATION TOURNE EN ROOT, LE SERVICE SOUS SON PROPRE
	// COMPTE. Sans ce realignement, `bbsctl user-add` cree un index.db
	// appartenant a root, et le service — qui peut le LIRE mais pas l'ECRIRE —
	// authentifie correctement puis echoue a ouvrir une session. Le symptome
	// est trompeur : un mot de passe faux repond 401, un mot de passe JUSTE
	// renvoie la page de connexion.
	//
	// Les fichiers -wal et -shm comptent autant : SQLite ecrit d'abord dedans.
	for _, suffixe := range []string{"", "-wal", "-shm"} {
		adopteProprietaireDuDossier(path + suffixe)
	}
	return s, nil
}

// adopteProprietaireDuDossier donne au fichier le proprietaire de son
// repertoire, quand on tourne en root.
//
// POURQUOI : l'outil d'administration s'execute en root, le service sous son
// propre compte. Un fichier de hashes cree par root en 0600 est ILLISIBLE par
// le service — il refuse alors de demarrer, et le message parle de permissions
// sur un fichier que root voit tres bien.
//
// C'est exactement ce qui s'est produit au premier deploiement : comptes crees,
// service incapable de demarrer. Le repertoire, lui, appartient deja au bon
// compte ; on s'aligne sur lui plutot que de coder un nom d'utilisateur en dur.
func adopteProprietaireDuDossier(fichier string) error {
	if os.Geteuid() != 0 {
		return nil // rien a faire : le fichier appartient deja a qui l'a ecrit
	}
	fi, err := os.Stat(filepath.Dir(fichier))
	if err != nil {
		return nil
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return nil
	}
	return os.Chown(fichier, int(st.Uid), int(st.Gid))
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
