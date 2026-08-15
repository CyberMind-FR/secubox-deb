// Package store retient les pistes, les coeurs et l'historique des lectures.
package store

import (
	"database/sql"
	"embed"
	"errors"
	"net/url"
	"sort"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

//go:embed migrations/*.sql
var migrations embed.FS

type Store struct{ db *sql.DB }

var ErrPisteInconnue = errors.New("piste inconnue")

func Open(chemin string) (*Store, error) {
	// WAL : un lecteur ne bloque pas l'ecrivain. La page publique lit a chaque
	// rafraichissement pendant que le tirage ecrit une lecture.
	db, err := sql.Open("sqlite", chemin+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)")
	if err != nil {
		return nil, err
	}
	s := &Store{db: db}
	if err := s.migre(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) migre() error {
	if _, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS schema_migrations (
		nom TEXT PRIMARY KEY, applique_le INTEGER NOT NULL)`); err != nil {
		return err
	}
	noms, err := migrations.ReadDir("migrations")
	if err != nil {
		return err
	}
	var liste []string
	for _, n := range noms {
		liste = append(liste, n.Name())
	}
	sort.Strings(liste)
	for _, nom := range liste {
		var un int
		err := s.db.QueryRow(`SELECT 1 FROM schema_migrations WHERE nom = ?`, nom).Scan(&un)
		if err == nil {
			continue
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		sqlTexte, err := migrations.ReadFile("migrations/" + nom)
		if err != nil {
			return err
		}
		// UNE MIGRATION EST ATOMIQUE : a moitie appliquee, elle laisserait un
		// schema qu'aucune version du code ne connait.
		tx, err := s.db.Begin()
		if err != nil {
			return err
		}
		if _, err := tx.Exec(string(sqlTexte)); err != nil {
			tx.Rollback()
			return errors.New(nom + " : " + err.Error())
		}
		if _, err := tx.Exec(`INSERT INTO schema_migrations(nom, applique_le) VALUES(?,?)`,
			nom, time.Now().Unix()); err != nil {
			tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

// CleSource normalise une adresse pour que la MEME chanson ne rentre pas trois
// fois.
//
// `youtu.be/X`, `youtube.com/watch?v=X&t=42` et `youtube.com/watch?v=X`
// designent la meme piste. Comparer les adresses brutes remplirait la playlist
// de doublons que personne ne comprend — et le desaccord ne se verrait qu'a
// l'ecoute.
//
// ON NE REND JAMAIS UNE CHAINE VIDE POUR UNE ENTREE NON VIDE : deux adresses
// inconnues se retrouveraient alors « egales » et la seconde ecraserait la
// premiere. Faute de mieux, on rend l'adresse nettoyee.
func CleSource(brut string) string {
	s := strings.TrimSpace(brut)
	if s == "" {
		return ""
	}
	u, err := url.Parse(s)
	if err != nil || u.Host == "" {
		return s
	}
	hote := strings.ToLower(strings.TrimPrefix(u.Hostname(), "www."))
	switch hote {
	case "youtu.be":
		if id := strings.Trim(u.Path, "/"); id != "" {
			return "yt:" + id
		}
	case "youtube.com", "m.youtube.com", "music.youtube.com":
		if id := u.Query().Get("v"); id != "" {
			return "yt:" + id
		}
		if strings.HasPrefix(u.Path, "/shorts/") {
			if id := strings.Trim(strings.TrimPrefix(u.Path, "/shorts/"), "/"); id != "" {
				return "yt:" + id
			}
		}
	}
	// Hote inconnu : on garde schema + hote + chemin, sans les parametres de
	// suivi ni le fragment.
	u.RawQuery, u.Fragment = "", ""
	return strings.ToLower(u.Scheme) + "://" + hote + strings.TrimRight(u.Path, "/")
}
