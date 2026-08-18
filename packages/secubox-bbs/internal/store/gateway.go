// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/CyberMind-FR/secubox-deb/secubox-bbs/internal/gateway"
)

// ErrContenuInconnu : demandé par empreinte, jamais vu.
var ErrContenuInconnu = errors.New("contenu inconnu")

// GatewayEnregistrer pose un contenu, ou enrichit celui qui existe déjà.
//
// Le ré-import est un no-op ENRICHISSANT, jamais un écrasement : un collecteur
// qui repasse sur un flux voit souvent moins de choses que le premier passage
// (un champ absent de la réponse du jour, une description tronquée). Écraser
// avec ces valeurs vides ferait perdre ce qu'on savait déjà.
//
// Rend true si le contenu était nouveau.
func (s *Store) GatewayEnregistrer(c gateway.Contenu) (bool, error) {
	if err := c.Valider(); err != nil {
		return false, err
	}
	maintenant := time.Now().Unix()

	ancien, err := s.GatewayContenu(c.Empreinte)
	nouveau := errors.Is(err, ErrContenuInconnu)
	if err != nil && !nouveau {
		return false, err
	}

	tx, err := s.db.Begin()
	if err != nil {
		return false, err
	}
	defer tx.Rollback()

	if nouveau {
		if c.ID == "" {
			// L'empreinte fait un identifiant stable et déjà unique ; on n'en
			// garde qu'un préfixe, suffisant pour des URL lisibles.
			c.ID = c.Empreinte[:16]
		}
		if c.CreeLe == 0 {
			c.CreeLe = maintenant
		}
		meta, _ := json.Marshal(nonNil(c.Metadonnees))
		_, err = tx.Exec(`INSERT INTO gateway_contenu
			(empreinte,id,genre,titre,corps,auteur,publie_le,source_url,connecteur,
			 ref_native,metadonnees,expire_le,retention,propriete,noeud_origine,cree_le,maj_le)
			VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
			c.Empreinte, c.ID, c.Genre, c.Titre, c.Corps, c.Auteur, c.PublieLe,
			c.SourceURL, c.Connecteur, c.RefNative, string(meta), c.ExpireLe,
			c.Retention, c.Propriete, c.NoeudOrigine, c.CreeLe, maintenant)
		if err != nil {
			return false, fmt.Errorf("insertion du contenu : %w", err)
		}
	} else {
		fusion := fusionner(ancien.Metadonnees, c.Metadonnees)
		meta, _ := json.Marshal(fusion)
		// La rétention acquise ne redescend jamais : un contenu épinglé par
		// l'utilisateur ne doit pas retomber en cache parce qu'un collecteur
		// l'a revu. Idem pour les champs vides, qui n'apportent rien.
		_, err = tx.Exec(`UPDATE gateway_contenu SET
			   titre       = CASE WHEN ?='' THEN titre  ELSE ? END,
			   corps       = CASE WHEN ?='' THEN corps  ELSE ? END,
			   auteur      = CASE WHEN ?='' THEN auteur ELSE ? END,
			   publie_le   = CASE WHEN ?=0  THEN publie_le ELSE ? END,
			   metadonnees = ?,
			   maj_le      = ?
			 WHERE empreinte = ?`,
			c.Titre, c.Titre, c.Corps, c.Corps, c.Auteur, c.Auteur,
			c.PublieLe, c.PublieLe, string(meta), maintenant, c.Empreinte)
		if err != nil {
			return false, fmt.Errorf("mise à jour du contenu : %w", err)
		}
		c.Titre, c.Corps = choisir(c.Titre, ancien.Titre), choisir(c.Corps, ancien.Corps)
	}

	// Les médias sont réécrits : ils décrivent l'état du cache, pas l'histoire.
	if _, err := tx.Exec(`DELETE FROM gateway_media WHERE empreinte=?`, c.Empreinte); err != nil {
		return false, err
	}
	for _, m := range c.Medias {
		if _, err := tx.Exec(`INSERT INTO gateway_media(empreinte,chemin,mime,taille,somme)
			VALUES(?,?,?,?,?)`, c.Empreinte, m.Chemin, m.Mime, m.Taille, m.Somme); err != nil {
			return false, fmt.Errorf("insertion d'un média : %w", err)
		}
	}

	if err := indexer(tx, c); err != nil {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return nouveau, nil
}

// indexer tient l'index de recherche à jour. La table `search` est partagée
// avec le reste du BBS : on n'y touche que les lignes de la passerelle.
func indexer(tx *sql.Tx, c gateway.Contenu) error {
	if _, err := tx.Exec(
		`DELETE FROM search WHERE kind='gateway' AND ref_id=?`, c.Empreinte); err != nil {
		return err
	}
	_, err := tx.Exec(
		`INSERT INTO search(title, body, kind, ref_id, visibility) VALUES(?,?,'gateway',?,?)`,
		c.Titre, c.Corps, c.Empreinte, string(VisLocal))
	return err
}

// GatewayContenu relit un contenu et ses médias.
func (s *Store) GatewayContenu(empreinte string) (gateway.Contenu, error) {
	var c gateway.Contenu
	var meta string
	err := s.db.QueryRow(`SELECT empreinte,id,genre,titre,corps,auteur,publie_le,
		source_url,connecteur,ref_native,metadonnees,expire_le,retention,propriete,
		noeud_origine,cree_le,maj_le FROM gateway_contenu WHERE empreinte=?`, empreinte).
		Scan(&c.Empreinte, &c.ID, &c.Genre, &c.Titre, &c.Corps, &c.Auteur, &c.PublieLe,
			&c.SourceURL, &c.Connecteur, &c.RefNative, &meta, &c.ExpireLe, &c.Retention,
			&c.Propriete, &c.NoeudOrigine, &c.CreeLe, &c.MajLe)
	if errors.Is(err, sql.ErrNoRows) {
		return c, ErrContenuInconnu
	}
	if err != nil {
		return c, err
	}
	_ = json.Unmarshal([]byte(meta), &c.Metadonnees)

	rows, err := s.db.Query(
		`SELECT chemin,mime,taille,somme FROM gateway_media WHERE empreinte=? ORDER BY chemin`,
		empreinte)
	if err != nil {
		return c, err
	}
	defer rows.Close()
	for rows.Next() {
		var m gateway.Media
		if err := rows.Scan(&m.Chemin, &m.Mime, &m.Taille, &m.Somme); err != nil {
			return c, err
		}
		c.Medias = append(c.Medias, m)
	}
	return c, rows.Err()
}

// GatewayRetention change le titre auquel on garde un contenu.
func (s *Store) GatewayRetention(empreinte, retention string) error {
	res, err := s.db.Exec(
		`UPDATE gateway_contenu SET retention=?, maj_le=? WHERE empreinte=?`,
		retention, time.Now().Unix(), empreinte)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrContenuInconnu
	}
	return nil
}

// GatewayPurgerMedias libère la place SANS perdre le contenu.
//
// C'est la règle centrale du cycle de vie : le ramasse-miettes retire des
// fichiers, jamais des objets. L'adresse source reste la seule façon de
// retrouver l'œuvre — l'effacer reviendrait à la perdre.
func (s *Store) GatewayPurgerMedias(empreinte string) error {
	_, err := s.db.Exec(`DELETE FROM gateway_media WHERE empreinte=?`, empreinte)
	return err
}

// GatewayRechercher interroge l'index plein texte, limité à la passerelle.
func (s *Store) GatewayRechercher(q string, limite int) ([]gateway.Contenu, error) {
	q = strings.TrimSpace(q)
	if q == "" {
		return nil, nil
	}
	if limite <= 0 {
		limite = 30
	}
	rows, err := s.db.Query(
		`SELECT ref_id FROM search WHERE kind='gateway' AND search MATCH ?
		 ORDER BY rank LIMIT ?`, q, limite)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var empreintes []string
	for rows.Next() {
		var e string
		if err := rows.Scan(&e); err != nil {
			return nil, err
		}
		empreintes = append(empreintes, e)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	out := make([]gateway.Contenu, 0, len(empreintes))
	for _, e := range empreintes {
		c, err := s.GatewayContenu(e)
		if errors.Is(err, ErrContenuInconnu) {
			continue // index en avance sur la table : on ignore, sans échouer
		}
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, nil
}

func nonNil(m map[string]string) map[string]string {
	if m == nil {
		return map[string]string{}
	}
	return m
}

// fusionner complète l'ancien par le nouveau, sans rien perdre.
func fusionner(ancien, nouveau map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range ancien {
		out[k] = v
	}
	for k, v := range nouveau {
		if v != "" {
			out[k] = v
		}
	}
	return out
}

func choisir(nouveau, ancien string) string {
	if nouveau == "" {
		return ancien
	}
	return nouveau
}
