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
	"encoding/json"
	"fmt"
	"time"

	"github.com/CyberMind-FR/secubox-deb/gabriel-mood/internal/ser"

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
	// Motif : POURQUOI c'est indéterminé, quand ça l'est. Vide sinon.
	//
	// AJOUTÉ PARCE QUE SON ABSENCE A COÛTÉ UNE ENQUÊTE (#1333). La base savait
	// dire qu'une minute était indéterminée, jamais laquelle des trois gardes
	// avait tranché — bruit, pas assez de voix, ou ambiance. Les trois appellent
	// des gestes différents, et rien ne permettait de les distinguer après coup :
	// il a fallu rejouer des scénarios synthétiques pour retrouver la cause.
	Motif      string  `json:"motif,omitempty"`
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
  motif       TEXT    NOT NULL DEFAULT '',
  confiance   REAL    NOT NULL DEFAULT 0,
  part_voisee REAL    NOT NULL DEFAULT 0,
  PRIMARY KEY (minute, session)
);
CREATE INDEX IF NOT EXISTS idx_resume_minute ON resume(minute DESC);

-- LA RÉFÉRENCE D'UNE VOIX, POUR QU'ELLE SURVIVE À UN RECHARGEMENT.
--
-- CE QUI EST STOCKÉ TIENT EN QUINZE NOMBRES : cinq traits, chacun avec son
-- centre, sa dispersion et son compte. On ne peut en reconstituer ni parole,
-- ni voix, ni même une phrase — c'est le résumé de ce qui est ORDINAIRE chez
-- quelqu'un, pas un enregistrement de ce qu'il a dit.
--
-- LA CLÉ EST FABRIQUÉE PAR LE NAVIGATEUR et rangée dans son stockage local.
-- Le serveur ne l'attribue pas : il ne peut donc pas la relier à une adresse,
-- un compte ou une session précédente autrement que par ce que le navigateur
-- lui présente. Effacer le stockage du navigateur suffit à redevenir inconnu,
-- et POST /api/mood/oubli efface aussi la ligne cote board.
--
-- CE QU'IL FAUT SAVOIR QUAND MÊME : deux visites qui présentent la même clé
-- sont, par construction, reconnues comme la même. C'est le prix de la
-- persistance, il est assumé, et il est révocable des deux côtés.
CREATE TABLE IF NOT EXISTS reference (
  cle  TEXT    PRIMARY KEY,
  maj  INTEGER NOT NULL,
  doc  TEXT    NOT NULL
);
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
	// `CREATE TABLE IF NOT EXISTS` NE MIGRE RIEN : une base déjà en place garde
	// ses colonnes d'origine, et le schéma ci-dessus n'est appliqué qu'à une
	// base neuve. Sans ce rattrapage, la colonne `motif` n'existerait que sur
	// les installations futures — c'est-à-dire nulle part où l'on en a besoin.
	if err := ajouteColonne(db, "resume", "motif", "TEXT NOT NULL DEFAULT ''"); err != nil {
		db.Close()
		return nil, fmt.Errorf("migration motif : %w", err)
	}
	return &Store{db: db}, nil
}

// ajouteColonne ajoute une colonne si elle manque. On INTERROGE le schéma
// plutôt que d'exécuter l'ALTER en avalant son erreur : « la colonne existe
// déjà » et « la table n'existe pas » se ressemblent trop dans un message, et
// avaler la seconde masquerait une base cassée.
func ajouteColonne(db *sql.DB, table, colonne, definition string) error {
	lignes, err := db.Query("SELECT name FROM pragma_table_info(?)", table)
	if err != nil {
		return err
	}
	defer lignes.Close()
	vues := 0
	for lignes.Next() {
		var n string
		if err := lignes.Scan(&n); err != nil {
			return err
		}
		vues++
		if n == colonne {
			return nil
		}
	}
	if err := lignes.Err(); err != nil {
		return err
	}
	if vues == 0 {
		return fmt.Errorf("table %q absente", table)
	}
	_, err = db.Exec("ALTER TABLE " + table + " ADD COLUMN " + colonne + " " + definition)
	return err
}

func (s *Store) Ferme() error { return s.db.Close() }

// Enregistre une minute. `INSERT OR REPLACE` : la minute en cours est réécrite
// à chaque mise à jour, on ne garde qu'une ligne par minute et par session.
func (s *Store) Enregistre(r Resume) error {
	_, err := s.db.Exec(
		`INSERT OR REPLACE INTO resume
		 (minute,session,f0,f0_etendue,energie,debit,jitter,shimmer,activation,etat,motif,confiance,part_voisee)
		 VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		r.Minute, r.Session, r.F0Median, r.F0Etendue, r.Energie, r.Debit,
		r.Jitter, r.Shimmer, r.Activation, r.Etat, r.Motif, r.Confiance, r.PartVoisee)
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
		        activation,etat,motif,confiance,part_voisee
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
			&r.Etat, &r.Motif, &r.Confiance, &r.PartVoisee); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, lignes.Err()
}

// CleReference : une clé recevable.
//
// ELLE VIENT DU NAVIGATEUR, donc d'un inconnu : on ne la range pas telle
// quelle. Seize à soixante-quatre caractères hexadécimaux, rien d'autre —
// c'est assez pour être unique et ça interdit d'un coup les clés absurdement
// longues, les caractères de contrôle et tout ce qui ressemblerait à une
// tentative de se servir de la base comme d'un dépotoir.
func CleReference(c string) bool {
	if len(c) < 16 || len(c) > 64 {
		return false
	}
	for _, r := range c {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f') {
			return false
		}
	}
	return true
}

// ChargeReference relit la référence d'une clé. Absente ou illisible, on rend
// `false` — on repart d'une référence neuve plutôt que d'installer quelque
// chose qu'on n'a pas su lire.
func (s *Store) ChargeReference(cle string) (ser.Reference, bool) {
	var doc string
	if err := s.db.QueryRow(`SELECT doc FROM reference WHERE cle=?`, cle).Scan(&doc); err != nil {
		return ser.Reference{}, false
	}
	var r ser.Reference
	if err := json.Unmarshal([]byte(doc), &r); err != nil {
		return ser.Reference{}, false
	}
	if r.Observations() <= 0 {
		return ser.Reference{}, false
	}
	return r, true
}

// EnregistreReference retient la référence d'une clé.
func (s *Store) EnregistreReference(cle string, r *ser.Reference) error {
	if r == nil || r.Observations() <= 0 {
		return nil
	}
	doc, err := json.Marshal(r)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(
		`INSERT OR REPLACE INTO reference(cle,maj,doc) VALUES(?,?,?)`,
		cle, time.Now().Unix(), string(doc))
	return err
}

// OublieReference efface la référence d'une clé — le geste « redevenez-moi
// inconnu », côté board.
func (s *Store) OublieReference(cle string) (int64, error) {
	res, err := s.db.Exec(`DELETE FROM reference WHERE cle=?`, cle)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return n, nil
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
	// LES RÉFÉRENCES AUSSI. Une référence qui survit des mois à sa dernière
	// visite n'est plus un service rendu, c'est une trace qu'on garde sans
	// raison — et la seule chose ici qui relie deux visites entre elles.
	if r2, err := s.db.Exec(`DELETE FROM reference WHERE maj < ?`, avant.Unix()); err == nil {
		m, _ := r2.RowsAffected()
		n += m
	}
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

// Tout efface l'historique entier, RÉFÉRENCES COMPRISES. « Oublier » qui
// laisserait en place ce qui permet de vous reconnaître n'oublierait rien.
func (s *Store) Tout() (int64, error) {
	res, err := s.db.Exec(`DELETE FROM resume`)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	if r2, err := s.db.Exec(`DELETE FROM reference`); err == nil {
		m, _ := r2.RowsAffected()
		n += m
	}
	return n, nil
}
