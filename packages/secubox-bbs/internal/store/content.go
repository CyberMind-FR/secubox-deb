// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// Content object commun : un ContentObject fédère toutes les représentations
// (radio, billets, mediatheque…) d'un même contenu source, relié par sa
// provenance. Cf. RÈGLE D'OR dans constraints.md : content_provenance a
// toujours ≥1 ligne is_original=1, jamais supprimée.
package store

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

// ContentObject est l'entité pivot du content lifecycle.
type ContentObject struct {
	ID         string
	Type       string
	Title      string
	Metadata   string
	BBSTopicID int64
	Status     string
	Visibility string
	CreatedAt  int64
	UpdatedAt  int64
}

// Provenance décrit une source d'un ContentObject. Original marque la source
// canonique — il en faut toujours au moins une.
type Provenance struct {
	SourceURL  string
	SourceType string
	Original   bool
}

// genererIDContenu produit un identifiant stable et non devinable :
// co_<yyyymmdd>_<rand6 hex>.
func genererIDContenu(now int64) (string, error) {
	var buf [3]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", fmt.Errorf("génération id contenu : %w", err)
	}
	jour := time.Unix(now, 0).UTC().Format("20060102")
	return fmt.Sprintf("co_%s_%s", jour, hex.EncodeToString(buf[:])), nil
}

// CreerContenu insère un ContentObject et ses provenances.
//
// Idempotent sur la provenance originale : si une ligne is_original=1 existe
// déjà pour l'une des sources fournies, l'id existant est renvoyé SANS créer
// de doublon — deux collecteurs qui notent la même source ne doivent jamais
// fabriquer deux objets pour un seul contenu.
//
// Exige au moins une provenance is_original=1 : un contenu sans origine
// connue ne doit jamais entrer en base (RÈGLE D'OR).
func (s *Store) CreerContenu(o ContentObject, prov []Provenance, now int64) (string, error) {
	aUneOriginale := false
	for _, p := range prov {
		if p.Original {
			aUneOriginale = true
			break
		}
	}
	if !aUneOriginale {
		return "", errors.New("content: au moins une provenance is_original=1 est requise")
	}

	tx, err := s.db.Begin()
	if err != nil {
		return "", err
	}
	defer tx.Rollback()

	// Résolution idempotente : une provenance originale déjà connue renvoie
	// l'objet existant, sans rien insérer de nouveau.
	for _, p := range prov {
		if !p.Original {
			continue
		}
		var existant string
		err := tx.QueryRow(
			`SELECT content_id FROM content_provenance WHERE source_url=? AND is_original=1`,
			p.SourceURL).Scan(&existant)
		if err == nil {
			return existant, tx.Commit()
		}
		if err != sql.ErrNoRows {
			return "", err
		}
	}

	id := o.ID
	if id == "" {
		id, err = genererIDContenu(now)
		if err != nil {
			return "", err
		}
	}
	if o.Metadata == "" {
		o.Metadata = "{}"
	}
	if o.Status == "" {
		o.Status = "proposed"
	}
	if o.Visibility == "" {
		o.Visibility = "community"
	}

	if _, err := tx.Exec(
		`INSERT INTO content_object(id,type,title,metadata,bbs_topic_id,status,visibility,created_at,updated_at)
		 VALUES(?,?,?,?,?,?,?,?,?)`,
		id, o.Type, o.Title, o.Metadata, o.BBSTopicID, o.Status, o.Visibility, now, now); err != nil {
		return "", err
	}

	for _, p := range prov {
		original := 0
		if p.Original {
			original = 1
		}
		if _, err := tx.Exec(
			`INSERT OR IGNORE INTO content_provenance(content_id,source_url,source_type,is_original,noted_at)
			 VALUES(?,?,?,?,?)`,
			id, p.SourceURL, p.SourceType, original, now); err != nil {
			return "", err
		}
	}

	if err := tx.Commit(); err != nil {
		return "", err
	}
	return id, nil
}

// ContenuParID rend le ContentObject identifié par id.
func (s *Store) ContenuParID(id string) (ContentObject, error) {
	var o ContentObject
	err := s.db.QueryRow(
		`SELECT id,type,title,metadata,bbs_topic_id,status,visibility,created_at,updated_at
		   FROM content_object WHERE id=?`, id).Scan(
		&o.ID, &o.Type, &o.Title, &o.Metadata, &o.BBSTopicID, &o.Status, &o.Visibility,
		&o.CreatedAt, &o.UpdatedAt)
	if err != nil {
		return ContentObject{}, err
	}
	return o, nil
}

// ContenuParRef résout un content_id depuis une représentation (module, ref).
func (s *Store) ContenuParRef(module, ref string) (string, bool) {
	var id string
	err := s.db.QueryRow(
		`SELECT content_id FROM content_representation WHERE module=? AND ref=? LIMIT 1`,
		module, ref).Scan(&id)
	if err != nil {
		return "", false
	}
	return id, true
}
