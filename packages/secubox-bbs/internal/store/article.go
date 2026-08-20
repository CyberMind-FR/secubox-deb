// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
//
// Article collaboratif (#1056 stage 3) : le magasin d'un document à plusieurs
// mains. Les CONTRIBUTIONS sont attribuées et ordonnées ; les co-auteurs se
// déduisent de qui a contribué. La publication vers billets vit dans la couche
// web (elle relaie la session de l'opérateur), pas ici.
package store

import (
	"database/sql"
	"errors"
	"strings"
	"time"
)

// ErrArticleInconnu : l'article demandé n'existe pas (ou plus).
var ErrArticleInconnu = errors.New("article inconnu")

// Article : l'entête d'un document collaboratif.
type Article struct {
	ID           int64
	Title        string
	ThreadID     int64
	Status       string // "draft" | "published"
	CreatedBy    int64
	Auteur       string // handle du créateur
	CreatedAt    int64
	UpdatedAt    int64
	PublishedURL string
	CoAuteurs    []string // handles distincts ayant contribué
	NbParts      int
}

// ArticlePart : une contribution attribuée.
type ArticlePart struct {
	ID        int64
	AuthorID  int64
	Auteur    string
	Initiales string
	Body      string
	Position  int
	CreatedAt int64
}

// CreerArticle ouvre un brouillon. threadID vaut 0 s'il naît vierge.
func (s *Store) CreerArticle(title string, threadID, authorID int64) (int64, error) {
	if strings.TrimSpace(title) == "" {
		return 0, errors.New("titre vide")
	}
	now := time.Now().Unix()
	var tid any
	if threadID > 0 {
		tid = threadID
	}
	res, err := s.db.Exec(`INSERT INTO articles(title, thread_id, status, created_by,
		created_at, updated_at) VALUES(?,?,'draft',?,?,?)`,
		strings.TrimSpace(title), tid, authorID, now, now)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// AjouterPart ajoute une contribution en fin d'article et touche updated_at.
func (s *Store) AjouterPart(articleID, authorID int64, body string) error {
	if strings.TrimSpace(body) == "" {
		return errors.New("contribution vide")
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var pos int
	if err := tx.QueryRow(`SELECT COALESCE(MAX(position),0)+1 FROM article_parts WHERE article_id=?`,
		articleID).Scan(&pos); err != nil {
		return err
	}
	now := time.Now().Unix()
	if _, err := tx.Exec(`INSERT INTO article_parts(article_id, author_id, body, position, created_at)
		VALUES(?,?,?,?,?)`, articleID, authorID, body, pos, now); err != nil {
		return err
	}
	if _, err := tx.Exec(`UPDATE articles SET updated_at=? WHERE id=?`, now, articleID); err != nil {
		return err
	}
	return tx.Commit()
}

// Article relit l'entête (avec co-auteurs) et ses contributions ordonnées.
func (s *Store) Article(id int64) (Article, []ArticlePart, error) {
	var a Article
	err := s.db.QueryRow(`SELECT a.id, a.title, COALESCE(a.thread_id,0), a.status,
		a.created_by, COALESCE(u.handle,''), a.created_at, a.updated_at, a.published_url
		FROM articles a LEFT JOIN users u ON u.id=a.created_by WHERE a.id=?`, id).
		Scan(&a.ID, &a.Title, &a.ThreadID, &a.Status, &a.CreatedBy, &a.Auteur,
			&a.CreatedAt, &a.UpdatedAt, &a.PublishedURL)
	if err == sql.ErrNoRows {
		return Article{}, nil, ErrArticleInconnu
	}
	if err != nil {
		return Article{}, nil, err
	}
	rows, err := s.db.Query(`SELECT p.id, p.author_id, COALESCE(u.handle,''), p.body, p.position, p.created_at
		FROM article_parts p LEFT JOIN users u ON u.id=p.author_id
		WHERE p.article_id=? ORDER BY p.position`, id)
	if err != nil {
		return Article{}, nil, err
	}
	defer rows.Close()
	var parts []ArticlePart
	vus := map[int64]bool{} // par AUTEUR (id), pas par handle : robuste même si un
	for rows.Next() { //       handle n'est pas encore résolu.
		var pt ArticlePart
		if err := rows.Scan(&pt.ID, &pt.AuthorID, &pt.Auteur, &pt.Body, &pt.Position, &pt.CreatedAt); err != nil {
			return Article{}, nil, err
		}
		pt.Initiales = initialesDe(pt.Auteur)
		parts = append(parts, pt)
		if !vus[pt.AuthorID] {
			vus[pt.AuthorID] = true
			a.CoAuteurs = append(a.CoAuteurs, pt.Auteur)
		}
	}
	a.NbParts = len(parts)
	return a, parts, rows.Err()
}

// Articles liste les articles d'un statut (vide = tous), du plus récemment
// modifié au plus ancien, avec le compte de co-auteurs — pour la rédaction.
func (s *Store) Articles(status string, limit int) ([]Article, error) {
	if limit <= 0 {
		limit = 20
	}
	q := `SELECT a.id, a.title, a.status, a.updated_at, a.published_url,
		(SELECT COUNT(DISTINCT author_id) FROM article_parts WHERE article_id=a.id),
		(SELECT COUNT(*) FROM article_parts WHERE article_id=a.id)
		FROM articles a`
	var args []any
	if status != "" {
		q += ` WHERE a.status=?`
		args = append(args, status)
	}
	q += ` ORDER BY a.updated_at DESC LIMIT ?`
	args = append(args, limit)
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Article
	for rows.Next() {
		var a Article
		var nbAuteurs int
		if err := rows.Scan(&a.ID, &a.Title, &a.Status, &a.UpdatedAt, &a.PublishedURL,
			&nbAuteurs, &a.NbParts); err != nil {
			return nil, err
		}
		a.CoAuteurs = make([]string, nbAuteurs) // seul le NOMBRE est utile ici
		out = append(out, a)
	}
	return out, rows.Err()
}

// MarquerArticlePublie fige l'article et retient son adresse publique.
func (s *Store) MarquerArticlePublie(id int64, url string) error {
	_, err := s.db.Exec(`UPDATE articles SET status='published', published_url=?, updated_at=? WHERE id=?`,
		url, time.Now().Unix(), id)
	return err
}

// initialesDe : deux lettres pour une pastille, depuis un handle.
func initialesDe(handle string) string {
	handle = strings.TrimSpace(strings.TrimPrefix(handle, "@"))
	if handle == "" {
		return "?"
	}
	r := []rune(handle)
	if len(r) == 1 {
		return strings.ToUpper(string(r))
	}
	return strings.ToUpper(string(r[0:2]))
}
