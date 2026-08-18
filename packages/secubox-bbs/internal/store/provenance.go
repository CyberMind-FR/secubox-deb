// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/CyberMind-FR/secubox-deb/secubox-bbs/internal/gateway"
)

// GatewayNoter ajoute un maillon à la chaîne de provenance.
func (s *Store) GatewayNoter(empreinte, evenement, acteur string,
	details map[string]string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := noter(tx, empreinte, evenement, acteur, details); err != nil {
		return err
	}
	return tx.Commit()
}

// noter écrit dans une transaction déjà ouverte, afin qu'un contenu et son
// premier événement entrent en base d'un seul tenant : un objet sans origine
// serait pire qu'un objet absent.
func noter(tx *sql.Tx, empreinte, evenement, acteur string,
	details map[string]string) error {
	if !gateway.EvenementConnu(evenement) {
		return fmt.Errorf("événement hors vocabulaire : %q", evenement)
	}

	// Le dernier maillon est lu DANS la transaction : deux collecteurs qui
	// notent en même temps ne peuvent pas s'accrocher au même prédécesseur et
	// forker la chaîne.
	var precedent string
	err := tx.QueryRow(
		`SELECT somme FROM gateway_provenance ORDER BY id DESC LIMIT 1`).Scan(&precedent)
	if err != nil && err != sql.ErrNoRows {
		return err
	}

	e := gateway.Evenement{
		Empreinte: empreinte,
		Horodate:  time.Now().Unix(),
		Evenement: evenement,
		Acteur:    acteur,
		Details:   details,
		Precedent: precedent,
	}
	e.Somme = gateway.SommeEvenement(precedent, e)

	brut, err := json.Marshal(nonNil(details))
	if err != nil {
		return err
	}
	_, err = tx.Exec(
		`INSERT INTO gateway_provenance(empreinte,horodate,evenement,acteur,details,precedent,somme)
		 VALUES(?,?,?,?,?,?,?)`,
		e.Empreinte, e.Horodate, e.Evenement, e.Acteur, string(brut), e.Precedent, e.Somme)
	return err
}

// GatewayProvenance rend l'histoire d'un contenu, du plus ancien au plus récent.
func (s *Store) GatewayProvenance(empreinte string) ([]gateway.Evenement, error) {
	rows, err := s.db.Query(
		`SELECT id,empreinte,horodate,evenement,acteur,details,precedent,somme
		   FROM gateway_provenance WHERE empreinte=? ORDER BY id`, empreinte)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []gateway.Evenement
	for rows.Next() {
		var e gateway.Evenement
		var brut string
		if err := rows.Scan(&e.ID, &e.Empreinte, &e.Horodate, &e.Evenement,
			&e.Acteur, &brut, &e.Precedent, &e.Somme); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(brut), &e.Details)
		out = append(out, e)
	}
	return out, rows.Err()
}

// GatewayVerifierProvenance recalcule toute la chaîne.
//
// C'est la preuve d'intégrité de l'historique : une ligne réécrite ou un
// maillon disparu font diverger le calcul à partir du point touché.
func (s *Store) GatewayVerifierProvenance() error {
	rows, err := s.db.Query(
		`SELECT id,empreinte,horodate,evenement,acteur,details,precedent,somme
		   FROM gateway_provenance ORDER BY id`)
	if err != nil {
		return err
	}
	defer rows.Close()

	attendu := ""
	for rows.Next() {
		var e gateway.Evenement
		var brut string
		if err := rows.Scan(&e.ID, &e.Empreinte, &e.Horodate, &e.Evenement,
			&e.Acteur, &brut, &e.Precedent, &e.Somme); err != nil {
			return err
		}
		_ = json.Unmarshal([]byte(brut), &e.Details)

		if e.Precedent != attendu {
			return fmt.Errorf("provenance rompue au maillon %d : "+
				"prédécesseur déclaré %q, attendu %q", e.ID, e.Precedent, attendu)
		}
		if calc := gateway.SommeEvenement(e.Precedent, e); calc != e.Somme {
			return fmt.Errorf("provenance falsifiée au maillon %d (%s) : "+
				"somme %q, recalculée %q", e.ID, e.Evenement, e.Somme, calc)
		}
		attendu = e.Somme
	}
	return rows.Err()
}
