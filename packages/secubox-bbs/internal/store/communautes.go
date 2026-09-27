// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package store

import (
	"database/sql"
	"os"
	"sync"
	"time"
)

// SbxDB : la base d'identite SBX OS (secubox-sbxid). Le BBS la LIT, jamais ne
// l'ecrit : les communautes et leurs membres se gerent dans l'Identity Manager.
// Variable pour les tests.
var SbxDB = "/var/lib/secubox/sbxid/sbx.db"

// Communaute : ce que le BBS sait d'une communaute SBX OS.
type Communaute struct {
	UUID string
	Nom  string
}

var (
	sbxMu  sync.Mutex
	sbxCon *sql.DB
	sbxDe  string
)

// sbx ouvre (une fois) sbx.db en LECTURE SEULE. nil si elle n'existe pas : le
// BBS fonctionne alors sans communautes — seuls les membres nommes entrent.
func sbx() *sql.DB {
	sbxMu.Lock()
	defer sbxMu.Unlock()
	if sbxCon != nil && sbxDe == SbxDB {
		return sbxCon
	}
	if _, err := os.Stat(SbxDB); err != nil {
		return nil
	}
	db, err := sql.Open("sqlite", "file:"+SbxDB+"?mode=ro&_pragma=busy_timeout(2000)")
	if err != nil {
		return nil
	}
	if sbxCon != nil {
		sbxCon.Close()
	}
	sbxCon, sbxDe = db, SbxDB
	return db
}

// CommunautesDe rend les communautes ACTIVES de la personne SBX OS liee a ce
// compte BBS (sbx_app_links app='bbs', par pseudonyme, sans egard a la casse).
// Personne suspendue, communaute archivee, compte non lie : rien.
func (s *Store) CommunautesDe(userID int64) (map[string]bool, error) {
	out := map[string]bool{}
	if userID <= 0 {
		return out, nil
	}
	var handle string
	if err := s.db.QueryRow(`SELECT handle FROM users WHERE id = ? AND disabled_at IS NULL`,
		userID).Scan(&handle); err != nil {
		if err == sql.ErrNoRows {
			return out, nil
		}
		return nil, err
	}
	db := sbx()
	if db == nil {
		return out, nil
	}
	rows, err := db.Query(
		`SELECT m.community_uuid FROM sbx_app_links l
		   JOIN sbx_users u ON u.user_uuid = l.user_uuid
		   JOIN sbx_community_members m ON m.user_uuid = l.user_uuid
		   JOIN sbx_communities c ON c.community_uuid = m.community_uuid
		  WHERE l.app = 'bbs' AND lower(l.app_id) = lower(?)
		    AND u.status = 'active' AND c.archived_at IS NULL`, handle)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out[id] = true
	}
	return out, rows.Err()
}

// CommunautesActives : le choix offert au sysop pour ouvrir un salon.
func (s *Store) CommunautesActives() ([]Communaute, error) {
	db := sbx()
	if db == nil {
		return nil, nil
	}
	rows, err := db.Query(`SELECT community_uuid, name FROM sbx_communities
	                        WHERE archived_at IS NULL ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Communaute
	for rows.Next() {
		var c Communaute
		if err := rows.Scan(&c.UUID, &c.Nom); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// OuvreACommunaute : les membres de la communaute entrent dans le salon.
// Idempotent, comme AjouteMembre.
func (s *Store) OuvreACommunaute(catID int64, c Communaute, par int64) error {
	var parN sql.NullInt64
	if par > 0 {
		parN = sql.NullInt64{Int64: par, Valid: true}
	}
	_, err := s.db.Exec(
		`INSERT INTO salon_communautes (category_id, community_uuid, nom, ajoute_par, ajoute_le)
		 VALUES (?, ?, ?, ?, ?)
		 ON CONFLICT (category_id, community_uuid) DO UPDATE SET nom = excluded.nom`,
		catID, c.UUID, c.Nom, parN, time.Now().Unix())
	return err
}

// FermeACommunaute reprend l'acces donne a une communaute. Les membres conviees
// nommement gardent le leur.
func (s *Store) FermeACommunaute(catID int64, communityUUID string) error {
	_, err := s.db.Exec(`DELETE FROM salon_communautes WHERE category_id = ? AND community_uuid = ?`,
		catID, communityUUID)
	return err
}

// CommunautesDuSalon : a qui le salon est ouvert, pour la console du sysop.
func (s *Store) CommunautesDuSalon(catID int64) ([]Communaute, error) {
	rows, err := s.db.Query(`SELECT community_uuid, nom FROM salon_communautes
	                          WHERE category_id = ? ORDER BY nom`, catID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Communaute
	for rows.Next() {
		var c Communaute
		if err := rows.Scan(&c.UUID, &c.Nom); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// salonsOuvertsParCommunaute : parmi ces salons, ceux qu'une des communautes
// de la personne ouvre.
func (s *Store) salonsOuvertsParCommunaute(userID int64) (map[int64]bool, error) {
	ouverts := map[int64]bool{}
	comms, err := s.CommunautesDe(userID)
	if err != nil || len(comms) == 0 {
		return ouverts, err
	}
	rows, err := s.db.Query(`SELECT category_id, community_uuid FROM salon_communautes`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id int64
		var c string
		if err := rows.Scan(&id, &c); err != nil {
			return nil, err
		}
		if comms[c] {
			ouverts[id] = true
		}
	}
	return ouverts, rows.Err()
}
