// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// Package store : magasin SQLite de MetaNews (sources, articles, sujets).
package store

import (
	"database/sql"
	"embed"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	_ "modernc.org/sqlite"
)

//go:embed migrations/*.sql
var migrations embed.FS

// Store enveloppe la base SQLite.
type Store struct{ db *sql.DB }

// Source : un flux déclaré.
type Source struct {
	ID         int64  `json:"id"`
	Slug       string `json:"slug"`
	Name       string `json:"name"`
	Type       string `json:"type"`
	URL        string `json:"url"`
	Enabled    bool   `json:"enabled"`
	Category   string `json:"category"`
	RefreshSec int64  `json:"refresh_sec"`
	LastSync   int64  `json:"last_sync"`
	LastError  string `json:"last_error"`
}

// Article : une entrée normalisée d'un flux.
type Article struct {
	ID          int64    `json:"id"`
	SourceID    int64    `json:"source_id"`
	Ref         string   `json:"ref"`
	Title       string   `json:"title"`
	URL         string   `json:"url"`
	Summary     string   `json:"summary"`
	Author      string   `json:"author"`
	Lang        string   `json:"lang"`
	PublishedAt int64    `json:"published_at"`
	FetchedAt   int64    `json:"fetched_at"`
	Fingerprint string   `json:"fingerprint"`
	Image       string   `json:"image"`
	Entities    []string `json:"entities"`
	Tags        []string `json:"tags"`
	TopicID     string   `json:"topic_id"`
}

// Topic : un événement MetaNews (grappe d'articles).
type Topic struct {
	ID           string   `json:"id"`
	Title        string   `json:"title"`
	Summary      string   `json:"summary"`
	Lang         string   `json:"lang"`
	CreatedAt    int64    `json:"created_at"`
	UpdatedAt    int64    `json:"updated_at"`
	Tags         []string `json:"tags"`
	Entities     []string `json:"entities"`
	SourcesCount int64    `json:"sources_count"`
	Confidence   float64  `json:"confidence"`
	Importance   float64  `json:"importance"`
	Vignette     string   `json:"vignette"`
	BBSThreadID  int64    `json:"bbs_thread_id"`
	BBSSlug      string   `json:"bbs_slug"`
}

// Open ouvre (ou crée) la base et applique les migrations.
func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(on)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1) // WAL + un seul writer : simple et sûr pour ce volume
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
	// Journal des migrations appliquées : une migration `ALTER TABLE` n'est pas
	// idempotente (rejouée, elle échoue sur « duplicate column »). On ne rejoue
	// donc jamais une migration déjà passée.
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
			continue // déjà appliquée
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

func jarr(v []string) string {
	if v == nil {
		v = []string{}
	}
	b, _ := json.Marshal(v)
	return string(b)
}

func parr(s string) []string {
	var v []string
	if s == "" {
		return nil
	}
	_ = json.Unmarshal([]byte(s), &v)
	return v
}

// ── Sources ────────────────────────────────────────────────────────────────

// AddSource insère une source et retourne son id.
func (s *Store) AddSource(src Source) (int64, error) {
	if src.Type == "" {
		src.Type = "rss"
	}
	if src.Category == "" {
		src.Category = "general"
	}
	if src.RefreshSec <= 0 {
		src.RefreshSec = 900
	}
	res, err := s.db.Exec(
		`INSERT INTO source(slug,name,type,url,enabled,category,refresh_sec) VALUES(?,?,?,?,?,?,?)`,
		src.Slug, src.Name, src.Type, src.URL, b2i(src.Enabled), src.Category, src.RefreshSec)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// Sources retourne toutes les sources.
func (s *Store) Sources() ([]Source, error) { return s.scanSources(``) }

// SourcesDues retourne les sources activées dont le rafraîchissement est dû.
func (s *Store) SourcesDues(now int64) ([]Source, error) {
	return s.scanSources(fmt.Sprintf(`WHERE enabled=1 AND (%d - last_sync) >= refresh_sec`, now))
}

func (s *Store) scanSources(where string) ([]Source, error) {
	rows, err := s.db.Query(`SELECT id,slug,name,type,url,enabled,category,refresh_sec,last_sync,last_error FROM source ` + where + ` ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Source
	for rows.Next() {
		var x Source
		var en int64
		if err := rows.Scan(&x.ID, &x.Slug, &x.Name, &x.Type, &x.URL, &en, &x.Category, &x.RefreshSec, &x.LastSync, &x.LastError); err != nil {
			return nil, err
		}
		x.Enabled = en != 0
		out = append(out, x)
	}
	return out, rows.Err()
}

// UpdateSource met à jour les champs éditables.
func (s *Store) UpdateSource(src Source) error {
	_, err := s.db.Exec(`UPDATE source SET name=?,type=?,url=?,enabled=?,category=?,refresh_sec=? WHERE id=?`,
		src.Name, src.Type, src.URL, b2i(src.Enabled), src.Category, src.RefreshSec, src.ID)
	return err
}

// MarquerSync enregistre l'heure de dernière synchro et l'erreur éventuelle.
func (s *Store) MarquerSync(id, now int64, errMsg string) error {
	_, err := s.db.Exec(`UPDATE source SET last_sync=?, last_error=? WHERE id=?`, now, errMsg, id)
	return err
}

// DeleteSource supprime une source (et ses articles, par cascade).
func (s *Store) DeleteSource(id int64) error {
	_, err := s.db.Exec(`DELETE FROM source WHERE id=?`, id)
	return err
}

// ── Articles ───────────────────────────────────────────────────────────────

// UpsertArticle insère l'article s'il est neuf. Retourne (id, neuf, err).
// Idempotent sur (source_id, ref) : un article déjà vu n'est pas ré-inséré.
func (s *Store) UpsertArticle(a Article) (int64, bool, error) {
	res, err := s.db.Exec(
		`INSERT OR IGNORE INTO article(source_id,ref,title,url,summary,author,lang,published_at,fetched_at,fingerprint,image,entities,tags)
		 VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		a.SourceID, a.Ref, a.Title, a.URL, a.Summary, a.Author, a.Lang, a.PublishedAt, a.FetchedAt,
		a.Fingerprint, a.Image, jarr(a.Entities), jarr(a.Tags))
	if err != nil {
		return 0, false, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		// Article déjà vu : on ne le recompte pas, mais on COMPLÈTE l'image si
		// elle manquait (le flux l'a peut-être ajoutée depuis) — sans toucher au
		// reste, pour ne pas fausser la détection « neuf ».
		if a.Image != "" {
			_, _ = s.db.Exec(`UPDATE article SET image=? WHERE source_id=? AND ref=? AND image=''`,
				a.Image, a.SourceID, a.Ref)
		}
		var id int64
		err = s.db.QueryRow(`SELECT id FROM article WHERE source_id=? AND ref=?`, a.SourceID, a.Ref).Scan(&id)
		return id, false, err
	}
	id, err := res.LastInsertId()
	return id, true, err
}

// ArticlesSansSujet retourne les articles non encore regroupés, du plus récent
// au plus ancien.
func (s *Store) ArticlesSansSujet(limit int) ([]Article, error) {
	return s.scanArticles(`WHERE topic_id='' ORDER BY published_at DESC LIMIT ?`, limit)
}

// ArticlesDuSujet retourne les articles d'un sujet.
func (s *Store) ArticlesDuSujet(topicID string) ([]Article, error) {
	return s.scanArticles(`WHERE topic_id=? ORDER BY published_at DESC`, topicID)
}

// ArticlesRecents retourne les articles les plus récents (toutes sources), pour
// la vue « par source ».
func (s *Store) ArticlesRecents(limit int) ([]Article, error) {
	return s.scanArticles(`ORDER BY published_at DESC LIMIT ?`, limit)
}

// ImageConnue : l'URL est-elle l'image d'un article ou d'un sujet connu ? Garde
// le relais d'images FERMÉ (jamais un proxy ouvert) : on ne relaie que ce que
// nos propres flux ont rapporté.
func (s *Store) ImageConnue(u string) bool {
	if u == "" {
		return false
	}
	var n int
	_ = s.db.QueryRow(`SELECT 1 FROM article WHERE image=? LIMIT 1`, u).Scan(&n)
	if n > 0 {
		return true
	}
	_ = s.db.QueryRow(`SELECT 1 FROM topic WHERE vignette=? LIMIT 1`, u).Scan(&n)
	return n > 0
}

func (s *Store) scanArticles(where string, args ...any) ([]Article, error) {
	rows, err := s.db.Query(`SELECT id,source_id,ref,title,url,summary,author,lang,published_at,fetched_at,fingerprint,image,entities,tags,topic_id FROM article `+where, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Article
	for rows.Next() {
		var a Article
		var ent, tags string
		if err := rows.Scan(&a.ID, &a.SourceID, &a.Ref, &a.Title, &a.URL, &a.Summary, &a.Author, &a.Lang,
			&a.PublishedAt, &a.FetchedAt, &a.Fingerprint, &a.Image, &ent, &tags, &a.TopicID); err != nil {
			return nil, err
		}
		a.Entities, a.Tags = parr(ent), parr(tags)
		out = append(out, a)
	}
	return out, rows.Err()
}

// SetArticleSujet rattache un article à un sujet.
func (s *Store) SetArticleSujet(articleID int64, topicID string) error {
	_, err := s.db.Exec(`UPDATE article SET topic_id=? WHERE id=?`, topicID, articleID)
	return err
}

// ── Sujets ─────────────────────────────────────────────────────────────────

// SujetsRecents retourne les sujets touchés depuis `since` (candidats au
// regroupement d'un nouvel article).
func (s *Store) SujetsRecents(since int64) ([]Topic, error) {
	return s.scanTopics(`WHERE updated_at >= ? ORDER BY updated_at DESC`, since)
}

// SujetsListe retourne les sujets pour l'affichage (catégorie vide = tous).
// SujetsListe classe les sujets par IMPORTANCE DÉCRUE PAR L'ÂGE : un radar
// d'actualité doit remonter le RÉCENT, pas les gros sujets figés. Le score
// importance/(1 + âge/3h) divise l'importance par le nombre de tranches de 3 h
// écoulées depuis la dernière activité (updated_at) : un sujet frais garde tout
// son poids, un sujet de 11 jours voit le sien s'effondrer. Corrige « je ne
// vois que d'anciennes nouvelles » (un sujet du 26/08 trustait la une).
func (s *Store) SujetsListe(category string, limit int) ([]Topic, error) {
	if category == "" || category == "une" {
		return s.scanTopics(`ORDER BY importance * 1.0 / (1.0 + (strftime('%s','now') - updated_at) / 10800.0) DESC, updated_at DESC LIMIT ?`, limit)
	}
	return s.scanTopics(`WHERE id IN (SELECT DISTINCT topic_id FROM article a JOIN source s ON s.id=a.source_id WHERE s.category=? AND a.topic_id<>'') ORDER BY importance * 1.0 / (1.0 + (strftime('%s','now') - updated_at) / 10800.0) DESC, updated_at DESC LIMIT ?`, category, limit)
}

// SujetParID retourne un sujet, ou une erreur sql.ErrNoRows.
func (s *Store) SujetParID(id string) (Topic, error) {
	ts, err := s.scanTopics(`WHERE id=?`, id)
	if err != nil {
		return Topic{}, err
	}
	if len(ts) == 0 {
		return Topic{}, sql.ErrNoRows
	}
	return ts[0], nil
}

func (s *Store) scanTopics(where string, args ...any) ([]Topic, error) {
	rows, err := s.db.Query(`SELECT id,title,summary,lang,created_at,updated_at,tags,entities,sources_count,confidence,importance,vignette,bbs_thread_id,bbs_slug FROM topic `+where, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Topic
	for rows.Next() {
		var t Topic
		var tags, ent string
		if err := rows.Scan(&t.ID, &t.Title, &t.Summary, &t.Lang, &t.CreatedAt, &t.UpdatedAt, &tags, &ent,
			&t.SourcesCount, &t.Confidence, &t.Importance, &t.Vignette, &t.BBSThreadID, &t.BBSSlug); err != nil {
			return nil, err
		}
		t.Tags, t.Entities = parr(tags), parr(ent)
		out = append(out, t)
	}
	return out, rows.Err()
}

// CreerSujet insère un sujet.
func (s *Store) CreerSujet(t Topic) error {
	_, err := s.db.Exec(
		`INSERT INTO topic(id,title,summary,lang,created_at,updated_at,tags,entities,sources_count,confidence,importance,vignette,bbs_thread_id,bbs_slug)
		 VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		t.ID, t.Title, t.Summary, t.Lang, t.CreatedAt, t.UpdatedAt, jarr(t.Tags), jarr(t.Entities),
		t.SourcesCount, t.Confidence, t.Importance, t.Vignette, t.BBSThreadID, t.BBSSlug)
	return err
}

// MajSujet met à jour un sujet (résumé, compteurs, tags…).
func (s *Store) MajSujet(t Topic) error {
	_, err := s.db.Exec(
		`UPDATE topic SET title=?,summary=?,lang=?,updated_at=?,tags=?,entities=?,sources_count=?,confidence=?,importance=?,vignette=? WHERE id=?`,
		t.Title, t.Summary, t.Lang, t.UpdatedAt, jarr(t.Tags), jarr(t.Entities), t.SourcesCount, t.Confidence, t.Importance, t.Vignette, t.ID)
	return err
}

// FixerFilBBS enregistre le fil BBS associé au sujet.
func (s *Store) FixerFilBBS(topicID string, threadID int64, slug string) error {
	_, err := s.db.Exec(`UPDATE topic SET bbs_thread_id=?, bbs_slug=? WHERE id=?`, threadID, slug, topicID)
	return err
}

// BackfillVignettes : donne une vignette aux sujets qui n'en ont pas encore
// mais dont un article porte une image (après complétion des images au re-sondage).
func (s *Store) BackfillVignettes() error {
	_, err := s.db.Exec(`UPDATE topic SET vignette=(
		SELECT a.image FROM article a WHERE a.topic_id=topic.id AND a.image<>''
		ORDER BY a.published_at DESC LIMIT 1)
		WHERE vignette='' AND EXISTS(
		SELECT 1 FROM article a WHERE a.topic_id=topic.id AND a.image<>'')`)
	return err
}

// AjouterEvenement journalise une étape de construction du sujet (timeline).
func (s *Store) AjouterEvenement(topicID string, at int64, kind, detail string) error {
	_, err := s.db.Exec(`INSERT INTO topic_event(topic_id,at,kind,detail) VALUES(?,?,?,?)`, topicID, at, kind, detail)
	return err
}

// Timeline retourne les événements d'un sujet (chronologique).
func (s *Store) Timeline(topicID string) ([]map[string]any, error) {
	rows, err := s.db.Query(`SELECT at,kind,detail FROM topic_event WHERE topic_id=? ORDER BY at`, topicID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []map[string]any
	for rows.Next() {
		var at int64
		var kind, detail string
		if err := rows.Scan(&at, &kind, &detail); err != nil {
			return nil, err
		}
		out = append(out, map[string]any{"at": at, "kind": kind, "detail": detail})
	}
	return out, rows.Err()
}

func b2i(b bool) int64 {
	if b {
		return 1
	}
	return 0
}
