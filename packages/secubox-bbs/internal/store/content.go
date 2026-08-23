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

// premiereSourceOriginale rend l'URL de la première provenance is_original.
// Le point d'entrée public a déjà validé qu'il en existe au moins une.
func premiereSourceOriginale(prov []Provenance) string {
	for _, p := range prov {
		if p.Original {
			return p.SourceURL
		}
	}
	return ""
}

// contenuOriginalPar résout le content_id de la provenance is_original=1
// portant sourceURL, si elle existe.
func (s *Store) contenuOriginalPar(sourceURL string) (string, bool) {
	var id string
	err := s.db.QueryRow(
		`SELECT content_id FROM content_provenance WHERE source_url=? AND is_original=1`,
		sourceURL).Scan(&id)
	if err != nil {
		return "", false
	}
	return id, true
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
//
// RACE-SAFE : la SELECT de pré-vérification ci-dessous est un "check-then-act"
// — deux appels VRAIMENT concurrents pour la même source originale peuvent
// tous les deux la trouver absente et tenter d'écrire. Le backstop vit en
// base (index unique partiel idx_prov_original sur content_provenance,
// migration 0024) : il garantit qu'une seule des deux écritures aboutit. Quand
// l'autre échoue — conflit sur cet index une fois le gagnant commité, ou
// verrou SQLITE_BUSY pendant qu'il est en vol — on ne renvoie JAMAIS l'erreur
// brute à l'appelant : on se re-résout sur la source originale, et si elle
// est désormais connue, on renvoie l'id du gagnant. Voir provenance.go
// (noter) et board.go (upsertSourced) pour l'idiome maison équivalent.
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
	sourceOriginale := premiereSourceOriginale(prov)

	// Chemin rapide : évite d'ouvrir une transaction d'écriture dans le cas
	// courant où le contenu existe déjà.
	if existant, ok := s.contenuOriginalPar(sourceOriginale); ok {
		return existant, nil
	}

	id, err := s.ecrireContenu(o, prov, now)
	if err == nil {
		return id, nil
	}

	// Backstop : quelqu'un d'autre a peut-être gagné la course pendant notre
	// écriture. On re-résout AVANT de rendre l'erreur — un id trouvé ici
	// prouve que l'échec est bien un conflit sur la provenance originale, pas
	// une panne indépendante.
	if existant, ok := s.contenuOriginalPar(sourceOriginale); ok {
		return existant, nil
	}
	return "", err
}

// ecrireContenu porte l'écriture transactionnelle proprement dite : un
// content_object et ses provenances. Toute erreur — y compris un conflit sur
// idx_prov_original ou un verrou — remonte telle quelle ; c'est à
// CreerContenu de décider si elle doit se transformer en résolution.
func (s *Store) ecrireContenu(o ContentObject, prov []Provenance, now int64) (string, error) {
	id := o.ID
	var err error
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

	tx, err := s.db.Begin()
	if err != nil {
		return "", err
	}
	defer tx.Rollback()

	if _, err := tx.Exec(
		`INSERT INTO content_object(id,type,title,metadata,bbs_topic_id,status,visibility,created_at,updated_at)
		 VALUES(?,?,?,?,?,?,?,?,?)`,
		id, o.Type, o.Title, o.Metadata, o.BBSTopicID, o.Status, o.Visibility, now, now); err != nil {
		return "", err
	}

	for _, p := range prov {
		if !p.Original {
			// Provenance secondaire : pas couverte par idx_prov_original,
			// `OR IGNORE` n'y absorbe qu'un doublon exact (content_id,
			// source_url) — inoffensif.
			if _, err := tx.Exec(
				`INSERT OR IGNORE INTO content_provenance(content_id,source_url,source_type,is_original,noted_at)
				 VALUES(?,?,?,0,?)`,
				id, p.SourceURL, p.SourceType, now); err != nil {
				return "", err
			}
			continue
		}
		// Provenance originale : INSERT nu, SANS `OR IGNORE`. `OR IGNORE`
		// avalerait un conflit sur idx_prov_original en silence et commiterait
		// un content_object SANS AUCUNE provenance originale — violation
		// directe de la RÈGLE D'OR. L'erreur doit remonter pour que
		// CreerContenu la traite explicitement.
		if _, err := tx.Exec(
			`INSERT INTO content_provenance(content_id,source_url,source_type,is_original,noted_at)
			 VALUES(?,?,?,1,?)`,
			id, p.SourceURL, p.SourceType, now); err != nil {
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

// AjouterRepresentation enregistre une représentation d'un ContentObject dans
// un module consommateur (radio, billets, mediatheque…). Idempotent : la
// contrainte UNIQUE(content_id,kind,module,ref) absorbe les ré-appels sans
// dupliquer — un collecteur qui repasse ne doit jamais créer de doublon.
func (s *Store) AjouterRepresentation(contentID, kind, module, ref string,
	isCache bool, url string, now int64) error {
	cache := 0
	if isCache {
		cache = 1
	}
	_, err := s.db.Exec(
		`INSERT OR IGNORE INTO content_representation(content_id,kind,module,ref,is_cache,url,created_at)
		 VALUES(?,?,?,?,?,?,?)`,
		contentID, kind, module, ref, cache, url, now)
	return err
}

// AjouterEvent journalise un événement du cycle de vie d'un ContentObject.
// Append-only : jamais de mise à jour ni de suppression d'un événement.
func (s *Store) AjouterEvent(contentID, kind, actor, payloadJSON string, at int64) error {
	_, err := s.db.Exec(
		`INSERT INTO content_event(content_id,kind,actor,payload,at) VALUES(?,?,?,?,?)`,
		contentID, kind, actor, payloadJSON, at)
	return err
}

// LierTopic rattache un ContentObject à un fil BBS.
func (s *Store) LierTopic(contentID string, topicID int64) error {
	_, err := s.db.Exec(
		`UPDATE content_object SET bbs_topic_id=? WHERE id=?`, topicID, contentID)
	return err
}

// ErrAnonymeNonPersiste : GATE D'IDENTITÉ (constraints.md). content_timeline
// exige un author_id > 0 — un commentaire anonyme ne doit JAMAIS atteindre la
// base, quel que soit l'appelant.
var ErrAnonymeNonPersiste = errors.New("content: un commentaire anonyme (author_id<=0) ne peut pas être persisté")

// TimelineComment est un commentaire horodaté sur la timeline d'un contenu
// (ex. réactions synchronisées à la diffusion radio).
type TimelineComment struct {
	ID          int64
	Author      string
	AuthorID    int64
	OffsetMS    int64
	Body        string
	BroadcastAt int64
	CreatedAt   int64
}

// AjouterTimeline insère un commentaire de timeline. Rejette AuthorID<=0 :
// c'est la gate d'identité, appliquée ici en plus de la contrainte NOT NULL
// du schéma, pour que l'erreur soit explicite et testable côté Go.
func (s *Store) AjouterTimeline(contentID string, c TimelineComment) (int64, error) {
	if c.AuthorID <= 0 {
		return 0, ErrAnonymeNonPersiste
	}
	res, err := s.db.Exec(
		`INSERT INTO content_timeline(content_id,author,author_id,offset_ms,body,broadcast_at,created_at)
		 VALUES(?,?,?,?,?,?,?)`,
		contentID, c.Author, c.AuthorID, c.OffsetMS, c.Body, c.BroadcastAt, c.CreatedAt)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// TimelineDe rend les commentaires d'un contenu entre fromMS et toMS (bornes
// incluses), ordonnés par offset_ms. toMS<=0 signifie : pas de borne haute.
func (s *Store) TimelineDe(contentID string, fromMS, toMS int64) ([]TimelineComment, error) {
	const cols = `id,author,author_id,offset_ms,body,broadcast_at,created_at`
	var rows *sql.Rows
	var err error
	if toMS <= 0 {
		rows, err = s.db.Query(
			`SELECT `+cols+` FROM content_timeline
			  WHERE content_id=? AND offset_ms>=?
			  ORDER BY offset_ms`, contentID, fromMS)
	} else {
		rows, err = s.db.Query(
			`SELECT `+cols+` FROM content_timeline
			  WHERE content_id=? AND offset_ms>=? AND offset_ms<=?
			  ORDER BY offset_ms`, contentID, fromMS, toMS)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []TimelineComment
	for rows.Next() {
		var c TimelineComment
		if err := rows.Scan(&c.ID, &c.Author, &c.AuthorID, &c.OffsetMS, &c.Body,
			&c.BroadcastAt, &c.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}
