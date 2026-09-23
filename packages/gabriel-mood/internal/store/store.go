// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// Package store — l'historique, et ce qu'on refuse d'y mettre.
//
// ┌──────────────────────────────────────────────────────────────────────────┐
// │ AUCUN ÉCHANTILLON AUDIO N'EST ÉCRIT SUR LE DISQUE. JAMAIS.                │
// └──────────────────────────────────────────────────────────────────────────┘
//
// Ce n'est pas une politique de configuration, c'est une propriété du code :
// il n'existe dans ce paquet aucune colonne, aucun chemin, aucune fonction qui
// accepte des échantillons. Le son traverse la mémoire et disparaît. Ce qu'on
// garde tient en quelques nombres par minute — une hauteur médiane, une
// énergie, un débit — dont on ne peut reconstituer ni parole ni voix.
//
// POURQUOI GARDER QUOI QUE CE SOIT. Parce qu'un indice n'a de sens que comparé
// à soi-même dans le temps : « plus tendu que d'habitude » demande de savoir
// ce qu'est l'habitude. Une seule mesure ne dit rien.
//
// CE QU'ON NE FAIT PAS NON PLUS : aucune identification de locuteur, aucun
// horodatage plus fin que la minute, aucune association à un compte. Les
// sessions sont anonymes et leur identifiant est jeté à la fermeture.
package store

import (
	"database/sql"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

// Store : la base d'historique.
type Store struct{ db *sql.DB }

// Resume : une minute d'observation agrégée. C'est la SEULE chose qui
// descende sur le disque.
type Resume struct {
	Minute     int64   `json:"minute"` // epoch arrondi à la minute
	Session    string  `json:"session"`
	F0Median   float64 `json:"f0"`
	F0Etendue  float64 `json:"f0_etendue"`
	Energie    float64 `json:"energie"`
	Debit      float64 `json:"debit"`
	Jitter     float64 `json:"jitter"`
	Shimmer    float64 `json:"shimmer"`
	Activation float64 `json:"activation"`
	Etat       string  `json:"etat"`
	Confiance  float64 `json:"confiance"`
	PartVoisee float64 `json:"part_voisee"`
}

const schema = `
CREATE TABLE IF NOT EXISTS resume (
  minute      INTEGER NOT NULL,
  session     TEXT    NOT NULL,
  f0          REAL    NOT NULL DEFAULT 0,
  f0_etendue  REAL    NOT NULL DEFAULT 0,
  energie     REAL    NOT NULL DEFAULT 0,
  debit       REAL    NOT NULL DEFAULT 0,
  jitter      REAL    NOT NULL DEFAULT 0,
  shimmer     REAL    NOT NULL DEFAULT 0,
  activation  REAL    NOT NULL DEFAULT 0,
  etat        TEXT    NOT NULL DEFAULT '',
  confiance   REAL    NOT NULL DEFAULT 0,
  part_voisee REAL    NOT NULL DEFAULT 0,
  PRIMARY KEY (minute, session)
);
CREATE INDEX IF NOT EXISTS idx_resume_minute ON resume(minute DESC);
`

// Ouvre la base et pose le schéma.
func Ouvre(chemin string) (*Store, error) {
	db, err := sql.Open("sqlite", chemin+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, err
	}
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("schéma : %w", err)
	}
	return &Store{db: db}, nil
}

func (s *Store) Ferme() error { return s.db.Close() }

// Enregistre une minute. `INSERT OR REPLACE` : la minute en cours est réécrite
// à chaque mise à jour, on ne garde qu'une ligne par minute et par session.
func (s *Store) Enregistre(r Resume) error {
	_, err := s.db.Exec(
		`INSERT OR REPLACE INTO resume
		 (minute,session,f0,f0_etendue,energie,debit,jitter,shimmer,activation,etat,confiance,part_voisee)
		 VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`,
		r.Minute, r.Session, r.F0Median, r.F0Etendue, r.Energie, r.Debit,
		r.Jitter, r.Shimmer, r.Activation, r.Etat, r.Confiance, r.PartVoisee)
	return err
}

// Depuis rend les résumés postérieurs à un instant, du plus récent au plus
// ancien, bornés en nombre — une requête d'historique ne doit pas pouvoir
// ramener un mois de lignes par inadvertance.
func (s *Store) Depuis(debut time.Time, limite int) ([]Resume, error) {
	if limite <= 0 || limite > 10000 {
		limite = 1000
	}
	lignes, err := s.db.Query(
		`SELECT minute,session,f0,f0_etendue,energie,debit,jitter,shimmer,
		        activation,etat,confiance,part_voisee
		 FROM resume WHERE minute >= ? ORDER BY minute DESC LIMIT ?`,
		debut.Unix(), limite)
	if err != nil {
		return nil, err
	}
	defer lignes.Close()
	var out []Resume
	for lignes.Next() {
		var r Resume
		if err := lignes.Scan(&r.Minute, &r.Session, &r.F0Median, &r.F0Etendue,
			&r.Energie, &r.Debit, &r.Jitter, &r.Shimmer, &r.Activation,
			&r.Etat, &r.Confiance, &r.PartVoisee); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, lignes.Err()
}

// Purge efface ce qui est plus vieux que `avant`.
//
// ELLE EXISTE PARCE QU'UN HISTORIQUE QUI NE S'EFFACE PAS EST UN DOSSIER. Le
// service l'appelle chaque jour ; la rétention par défaut se règle dans
// l'unité systemd, et la mettre à zéro désactive complètement l'historique.
func (s *Store) Purge(avant time.Time) (int64, error) {
	res, err := s.db.Exec(`DELETE FROM resume WHERE minute < ?`, avant.Unix())
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// OublieSession efface tout ce qui concerne une session. C'est le geste
// « oubliez-moi », et il doit exister.
func (s *Store) OublieSession(id string) (int64, error) {
	res, err := s.db.Exec(`DELETE FROM resume WHERE session = ?`, id)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// Tout efface l'historique entier.
func (s *Store) Tout() (int64, error) {
	res, err := s.db.Exec(`DELETE FROM resume`)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return n, nil
}
