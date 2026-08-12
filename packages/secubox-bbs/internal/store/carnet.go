// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// Annuaire et carnet d'adresses de la messagerie (#1008).
//
// Le selecteur de destinataire affichait TOUS les comptes ouverts, en
// pastilles. Cela tient a cinq membres et devient illisible a cinquante : on
// cherche un nom dans un mur, et la page grossit avec l'annuaire.
//
// Deux objets distincts remplacent ce mur :
//
//   - l'ANNUAIRE est une recherche bornee. On tape ce dont on se souvient, on
//     obtient au plus quelques lignes.
//   - le CARNET nomme ce qu'on utilise vraiment : les quelques personnes a qui
//     l'on ecrit. Il est unidirectionnel, comme un carnet papier — l'y mettre
//     n'oblige a rien et ne se remarque pas de l'autre cote.
package store

import "strings"

// Contact : une entree d'annuaire ou de carnet.
type Contact struct {
	ID      int64
	Handle  string
	Display string
	Note    string
	// Avatar : joint aux requetes existantes. Un annuaire sans visage se lit
	// mal — c'est justement ce qu'on vient chercher en cherchant quelqu'un.
	Avatar int64
	// AuCarnet permet a la liste de resultats de savoir quel bouton montrer.
	// Sans lui, l'annuaire proposerait d'ajouter ce qui y est deja.
	AuCarnet bool
}

// Annuaire cherche parmi les comptes JOIGNABLES.
//
// La recherche porte sur le pseudonyme ET le nom affiche : on se souvient de
// l'un ou de l'autre, rarement des deux. Elle est insensible a la casse et
// travaille par fragment — personne ne tape un pseudonyme exact, et l'exiger
// rendrait la recherche inutilisable au pouce.
//
// LA BORNE N'EST PAS DECORATIVE : une recherche vide sur un millier de comptes
// rendrait un millier de lignes, c'est-a-dire le mur de pastilles qu'on vient
// de retirer.
func (s *Store) Annuaire(moi int64, q string, borne int) ([]Contact, error) {
	if borne <= 0 || borne > 200 {
		borne = 50
	}
	motif := "%" + strings.ToLower(strings.TrimSpace(q)) + "%"
	rows, err := s.db.Query(`
		SELECT u.id, u.handle, u.display_name, COALESCE(c.note,''),
		       c.contact IS NOT NULL, COALESCE(av.id, 0)
		  FROM users u
		  LEFT JOIN carnet c ON c.contact = u.id AND c.proprietaire = ?1
		  LEFT JOIN files av ON av.id = u.avatar_file AND av.deleted_at IS NULL
		 WHERE u.disabled_at IS NULL
		   AND u.id <> ?1
		   AND (?2 = '%%' OR lower(u.handle) LIKE ?2 OR lower(u.display_name) LIKE ?2)
		 ORDER BY c.contact IS NULL, u.handle
		 LIMIT ?3`, moi, motif, borne)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Contact
	for rows.Next() {
		var c Contact
		if err := rows.Scan(&c.ID, &c.Handle, &c.Display, &c.Note, &c.AuCarnet,
			&c.Avatar); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// Carnet rend les contacts enregistres, les plus recemment ajoutes d'abord.
func (s *Store) Carnet(moi int64) ([]Contact, error) {
	rows, err := s.db.Query(`
		SELECT u.id, u.handle, u.display_name, COALESCE(c.note,''), COALESCE(av.id, 0)
		  FROM carnet c
		  JOIN users u ON u.id = c.contact
		  LEFT JOIN files av ON av.id = u.avatar_file AND av.deleted_at IS NULL
		 WHERE c.proprietaire = ? AND u.disabled_at IS NULL
		 ORDER BY c.ajoute_at DESC`, moi)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Contact
	for rows.Next() {
		c := Contact{AuCarnet: true}
		if err := rows.Scan(&c.ID, &c.Handle, &c.Display, &c.Note, &c.Avatar); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// AjouteAuCarnet enregistre un contact. Repeter l'ajout ne cree pas de doublon
// et NE PERD PAS LA NOTE : on reclique sans y penser, et reecrire la note avec
// une chaine vide effacerait ce qu'on avait pris la peine d'ecrire.
func (s *Store) AjouteAuCarnet(moi, contact int64, note string) error {
	if moi == contact {
		return ErrRefuse
	}
	note = strings.TrimSpace(note)
	_, err := s.db.Exec(`
		INSERT INTO carnet(proprietaire, contact, ajoute_at, note)
		VALUES(?,?,unixepoch(),?)
		ON CONFLICT(proprietaire, contact) DO UPDATE
		  SET note = COALESCE(NULLIF(excluded.note,''), carnet.note)`,
		moi, contact, nilSiVide(note))
	return err
}

// RetireDuCarnet efface le raccourci, RIEN D'AUTRE. Un carnet n'est pas une
// relation : le vider ne touche ni au compte ni aux messages echanges.
func (s *Store) RetireDuCarnet(moi, contact int64) error {
	_, err := s.db.Exec(
		`DELETE FROM carnet WHERE proprietaire = ? AND contact = ?`, moi, contact)
	return err
}
