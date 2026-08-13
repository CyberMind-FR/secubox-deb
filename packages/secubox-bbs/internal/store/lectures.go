// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// Suivi lu / non-lu des fils.
//
// La question que se pose un lecteur en arrivant est « qu'est-ce qui a bouge
// depuis la derniere fois ? ». Sans reponse, il relit les memes fils ou en rate
// d'autres — et sur un BBS de 250 fils, il finit par ne plus rien ouvrir.
//
// Le repere est une DATE, pas un identifiant de message : un message efface ou
// modere ferait disparaitre un repere par identifiant, et le fil redeviendrait
// non-lu en entier sans raison visible.
package store

// MarqueLu enregistre que ce membre vient d'ouvrir ce fil.
//
// Appele a CHAQUE ouverture, donc idempotent par construction : `ON CONFLICT`
// met la date a jour au lieu d'echouer. Un visiteur non connecte (user = 0)
// n'ecrit rien — il n'a pas d'historique a tenir.
func (s *Store) MarqueLu(user, thread int64) error {
	if user <= 0 || thread <= 0 {
		return nil
	}
	_, err := s.db.Exec(`
		INSERT INTO lectures(user_id, thread_id, lu_at)
		VALUES(?,?,unixepoch())
		ON CONFLICT(user_id, thread_id) DO UPDATE SET lu_at = unixepoch()`,
		user, thread)
	return err
}

// FilsNonLus rend l'ensemble des fils qui ont du nouveau pour ce membre.
//
// Rendre un ENSEMBLE plutot qu'un drapeau par fil evite une requete par ligne
// affichee : une liste de cent fils ferait cent aller-retours, et c'est ainsi
// qu'une fonction de confort devient une cause de lenteur.
//
// Un fil jamais ouvert est non-lu — c'est ce qu'attend le lecteur d'un fil
// qu'il n'a jamais vu.
func (s *Store) FilsNonLus(user int64) (map[int64]bool, error) {
	out := map[int64]bool{}
	if user <= 0 {
		// Un visiteur non connecte n'a pas d'historique : ne RIEN marquer est
		// plus honnete que de tout marquer comme neuf, ce qui ferait clignoter
		// la page entiere sans que le geste « marquer lu » existe pour lui.
		return out, nil
	}
	rows, err := s.db.Query(`
		SELECT t.id
		  FROM threads t
		  LEFT JOIN lectures l ON l.thread_id = t.id AND l.user_id = ?
		 WHERE l.lu_at IS NULL OR t.last_post_at > l.lu_at`, user)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out[id] = true
	}
	return out, rows.Err()
}

// NonLusParSalon rend le nombre de fils ayant du nouveau, par salon.
//
// C'est ce qui permet a la liste des salons de dire « 3 » sans ouvrir chacun :
// sur un BBS actif, c'est la seule information qui evite d'entrer partout pour
// verifier.
func (s *Store) NonLusParSalon(user int64) (map[int64]int, error) {
	out := map[int64]int{}
	if user <= 0 {
		return out, nil
	}
	rows, err := s.db.Query(`
		SELECT t.category_id, count(*)
		  FROM threads t
		  LEFT JOIN lectures l ON l.thread_id = t.id AND l.user_id = ?
		 WHERE l.lu_at IS NULL OR t.last_post_at > l.lu_at
		 GROUP BY t.category_id`, user)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var cat int64
		var n int
		if err := rows.Scan(&cat, &n); err != nil {
			return nil, err
		}
		out[cat] = n
	}
	return out, rows.Err()
}

// MarqueToutLu pose la date du jour sur tous les fils visibles.
//
// LE GESTE QUI MANQUE LE PLUS a qui revient apres deux semaines : sans lui, la
// seule facon de faire retomber le compteur est d'ouvrir deux cents fils un par
// un — donc de ne jamais le faire, et de cesser de regarder l'indicateur.
//
// Le `WHERE true` n'est pas decoratif : sans lui, SQLite ne sait pas ou finit le
// SELECT et ou commence le ON CONFLICT, et rejette la requete. C'est la parade
// documentee pour un upsert alimente par un SELECT.
func (s *Store) MarqueToutLu(user int64) error {
	if user <= 0 {
		return nil
	}
	_, err := s.db.Exec(`
		INSERT INTO lectures(user_id, thread_id, lu_at)
		SELECT ?, id, unixepoch() FROM threads WHERE true
		ON CONFLICT(user_id, thread_id) DO UPDATE SET lu_at = unixepoch()`, user)
	return err
}
