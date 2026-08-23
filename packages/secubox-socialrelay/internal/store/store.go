// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// Package store : magasin SQLite de SocialRelay (sources, posts, médias cachés).
package store

import (
	"database/sql"
	"embed"
	"fmt"
	"sort"
	"strings"

	_ "modernc.org/sqlite"
)

//go:embed migrations/*.sql
var migrations embed.FS

// Store enveloppe la base SQLite.
type Store struct{ db *sql.DB }

// Source : un compte / flux social à relayer.
type Source struct {
	ID         int64  `json:"id"`
	Slug       string `json:"slug"`
	Name       string `json:"name"`
	Kind       string `json:"kind"`   // mastodon | facebook | …
	Handle     string `json:"handle"` // @user@instance, #tag@instance, id de page…
	URL        string `json:"url"`
	Enabled    bool   `json:"enabled"`
	Mode       string `json:"mode"`  // open | bridge | consent
	Salon      string `json:"salon"` // salon BBS cible
	RefreshSec int64  `json:"refresh_sec"`
	LastSync   int64  `json:"last_sync"`
	LastError  string `json:"last_error"`
}

// Post : un post relayé.
type Post struct {
	ID          int64  `json:"id"`
	SourceID    int64  `json:"source_id"`
	Ref         string `json:"ref"`
	Author      string `json:"author"`
	URL         string `json:"url"`
	Text        string `json:"text"`
	PublishedAt int64  `json:"published_at"`
	FetchedAt   int64  `json:"fetched_at"`
	BBSThreadID int64  `json:"bbs_thread_id"`
	Media       string `json:"media"` // JSON [{hash,kind,orig}]
}

// Open ouvre (ou crée) la base et applique les migrations.
func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(on)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

// Close ferme la base.
func (s *Store) Close() error { return s.db.Close() }

func (s *Store) migrate() error {
	if _, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS _migrations(nom TEXT PRIMARY KEY)`); err != nil {
		return err
	}
	noms, err := migrations.ReadDir("migrations")
	if err != nil {
		return err
	}
	var fics []string
	for _, n := range noms {
		if strings.HasSuffix(n.Name(), ".sql") {
			fics = append(fics, n.Name())
		}
	}
	sort.Strings(fics)
	for _, f := range fics {
		var vu string
		if s.db.QueryRow(`SELECT nom FROM _migrations WHERE nom=?`, f).Scan(&vu); vu == f {
			continue
		}
		sqlb, err := migrations.ReadFile("migrations/" + f)
		if err != nil {
			return err
		}
		if _, err := s.db.Exec(string(sqlb)); err != nil {
			return fmt.Errorf("migration %s : %w", f, err)
		}
		if _, err := s.db.Exec(`INSERT INTO _migrations(nom) VALUES(?)`, f); err != nil {
			return err
		}
	}
	return nil
}

func b2i(b bool) int64 {
	if b {
		return 1
	}
	return 0
}

// ── Sources ─────────────────────────────────────────────────────────────────

// AddSource insère une source.
func (s *Store) AddSource(x Source) (int64, error) {
	if x.Kind == "" {
		x.Kind = "mastodon"
	}
	if x.Mode == "" {
		x.Mode = "open"
	}
	if x.Salon == "" {
		x.Salon = "reseaux"
	}
	if x.RefreshSec <= 0 {
		x.RefreshSec = 600
	}
	res, err := s.db.Exec(`INSERT INTO source(slug,name,kind,handle,url,enabled,mode,salon,refresh_sec) VALUES(?,?,?,?,?,?,?,?,?)`,
		x.Slug, x.Name, x.Kind, x.Handle, x.URL, b2i(x.Enabled), x.Mode, x.Salon, x.RefreshSec)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// Sources retourne toutes les sources.
func (s *Store) Sources() ([]Source, error) { return s.scanSources("") }

// SourcesDues retourne les sources activées dont le rafraîchissement est dû.
func (s *Store) SourcesDues(now int64) ([]Source, error) {
	return s.scanSources(fmt.Sprintf(`WHERE enabled=1 AND (%d - last_sync) >= refresh_sec`, now))
}

func (s *Store) scanSources(where string) ([]Source, error) {
	rows, err := s.db.Query(`SELECT id,slug,name,kind,handle,url,enabled,mode,salon,refresh_sec,last_sync,last_error FROM source ` + where + ` ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Source
	for rows.Next() {
		var x Source
		var en int64
		if err := rows.Scan(&x.ID, &x.Slug, &x.Name, &x.Kind, &x.Handle, &x.URL, &en, &x.Mode, &x.Salon, &x.RefreshSec, &x.LastSync, &x.LastError); err != nil {
			return nil, err
		}
		x.Enabled = en != 0
		out = append(out, x)
	}
	return out, rows.Err()
}

// UpdateSource met à jour les champs éditables.
func (s *Store) UpdateSource(x Source) error {
	_, err := s.db.Exec(`UPDATE source SET name=?,kind=?,handle=?,url=?,enabled=?,mode=?,salon=?,refresh_sec=? WHERE id=?`,
		x.Name, x.Kind, x.Handle, x.URL, b2i(x.Enabled), x.Mode, x.Salon, x.RefreshSec, x.ID)
	return err
}

// MarquerSync enregistre l'heure de synchro et l'erreur éventuelle.
func (s *Store) MarquerSync(id, now int64, errMsg string) error {
	_, err := s.db.Exec(`UPDATE source SET last_sync=?, last_error=? WHERE id=?`, now, errMsg, id)
	return err
}

// DeleteSource supprime une source (et ses posts, par cascade).
func (s *Store) DeleteSource(id int64) error {
	_, err := s.db.Exec(`DELETE FROM source WHERE id=?`, id)
	return err
}

// ── Posts ───────────────────────────────────────────────────────────────────

// UpsertPost insère le post s'il est neuf. Retourne (id, neuf, err).
func (s *Store) UpsertPost(p Post) (int64, bool, error) {
	res, err := s.db.Exec(`INSERT OR IGNORE INTO post(source_id,ref,author,url,text,published_at,fetched_at,media) VALUES(?,?,?,?,?,?,?,?)`,
		p.SourceID, p.Ref, p.Author, p.URL, p.Text, p.PublishedAt, p.FetchedAt, p.Media)
	if err != nil {
		return 0, false, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		var id int64
		err = s.db.QueryRow(`SELECT id FROM post WHERE source_id=? AND ref=?`, p.SourceID, p.Ref).Scan(&id)
		return id, false, err
	}
	id, err := res.LastInsertId()
	return id, true, err
}

// PostsRecents retourne les posts récents (toutes sources).
func (s *Store) PostsRecents(limit int) ([]Post, error) {
	return s.scanPosts(`ORDER BY published_at DESC LIMIT ?`, limit)
}

// PostsSansFil retourne les posts neufs sans fil BBS (pour la passerelle).
func (s *Store) PostsSansFil(limit int) ([]Post, error) {
	return s.scanPosts(`WHERE bbs_thread_id=0 ORDER BY published_at DESC LIMIT ?`, limit)
}

func (s *Store) scanPosts(where string, args ...any) ([]Post, error) {
	rows, err := s.db.Query(`SELECT id,source_id,ref,author,url,text,published_at,fetched_at,bbs_thread_id,media FROM post `+where, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Post
	for rows.Next() {
		var p Post
		if err := rows.Scan(&p.ID, &p.SourceID, &p.Ref, &p.Author, &p.URL, &p.Text, &p.PublishedAt, &p.FetchedAt, &p.BBSThreadID, &p.Media); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// FixerFilBBS enregistre le fil BBS d'un post.
func (s *Store) FixerFilBBS(postID, threadID int64) error {
	_, err := s.db.Exec(`UPDATE post SET bbs_thread_id=? WHERE id=?`, threadID, postID)
	return err
}

// ── Médias cachés ───────────────────────────────────────────────────────────

// MediaConnu rend l'extension d'un média déjà caché, ou "" s'il est inconnu.
func (s *Store) MediaConnu(hash string) (string, bool) {
	var ext string
	err := s.db.QueryRow(`SELECT ext FROM media WHERE hash=?`, hash).Scan(&ext)
	return ext, err == nil
}

// AddMedia enregistre un média caché.
func (s *Store) AddMedia(hash, kind, ext string, bytes, now int64, orig string) error {
	_, err := s.db.Exec(`INSERT OR IGNORE INTO media(hash,kind,bytes,ext,fetched_at,orig_url) VALUES(?,?,?,?,?,?)`,
		hash, kind, bytes, ext, now, orig)
	return err
}
