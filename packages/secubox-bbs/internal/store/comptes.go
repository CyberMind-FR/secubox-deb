// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// Cycle de vie des comptes : suppression reelle, et oubli de l'empreinte.
//
// La desactivation vit dans auth.go et reste le geste par defaut — un compte
// desactive garde son histoire et peut etre rouvert. Ce fichier ajoute la
// SUPPRESSION, demandee par l'exploitant, qui est irreversible.
package store

import (
	"errors"
	"strings"
)

// TombeauHandle : le compte auquel le contenu d'un membre supprime est
// reattribue. Desactive, il ne peut pas se connecter.
const TombeauHandle = "compte-supprime"

// DeleteUser SUPPRIME un compte, contrairement a DisableUser qui le desactive.
//
// LE CONTENU N'EST PAS EFFACE. `threads.author_id` et `posts.author_id` sont
// NOT NULL : une suppression brute violerait la clef etrangere, et la contourner
// en effacant les fils detruirait la conversation de TOUS les autres — un
// membre qui s'en va n'emporte pas les reponses qu'on lui a faites. Le contenu
// est donc reattribue a un compte tombeau, visible comme « compte supprime ».
//
// Le disque fait foi de toute facon : les .md restent, et `Reindex` les
// retrouverait. Effacer en base ce que le disque conserve creerait un ecart que
// la console signalerait comme une corruption.
//
// CE QUI DISPARAIT VRAIMENT : les sessions, les messages prives recus (la clef
// etrangere est en ON DELETE CASCADE — sa boite lui appartenait), et l'entree
// du fichier de mots de passe, que l'appelant doit retirer separement puisque
// ce fichier ne vit pas en base.
func (s *Store) DeleteUser(id int64) error {
	// Le dernier sysop ne se supprime pas : il faudrait rouvrir la porte depuis
	// la ligne de commande sur la board, ce que personne ne devine.
	var sysops int
	if err := s.db.QueryRow(
		`SELECT COUNT(*) FROM users WHERE role = 'sysop' AND disabled_at IS NULL`,
	).Scan(&sysops); err != nil {
		return err
	}
	var role string
	if err := s.db.QueryRow(`SELECT role FROM users WHERE id = ?`, id).Scan(&role); err != nil {
		return err
	}
	if role == string(RoleSysop) && sysops <= 1 {
		return errors.New("dernier sysop : suppression refusee")
	}

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	var tombeau int64
	err = tx.QueryRow(`SELECT id FROM users WHERE handle = ?`, TombeauHandle).Scan(&tombeau)
	if err != nil {
		r, err := tx.Exec(
			`INSERT INTO users(handle, display_name, role, created_at, disabled_at)
			 VALUES(?,?,?,unixepoch(),unixepoch())`,
			TombeauHandle, "Compte supprimé", string(RoleMember))
		if err != nil {
			return err
		}
		if tombeau, err = r.LastInsertId(); err != nil {
			return err
		}
	}
	if tombeau == id {
		return errors.New("le compte tombeau ne se supprime pas")
	}

	for _, q := range []string{
		`UPDATE threads SET author_id = ? WHERE author_id = ?`,
		`UPDATE posts   SET author_id = ? WHERE author_id = ?`,
		`UPDATE files   SET owner_id  = ? WHERE owner_id  = ?`,
	} {
		if _, err := tx.Exec(q, tombeau, id); err != nil {
			return err
		}
	}
	// Traces nullable : on efface le lien, pas la ligne. Une invitation dont
	// l'emetteur a disparu reste listable — sinon une porte ouverte deviendrait
	// invisible dans la console.
	for _, q := range []string{
		`UPDATE audit   SET actor_id  = NULL WHERE actor_id  = ?`,
		`UPDATE invites SET issued_by = NULL WHERE issued_by = ?`,
		`UPDATE invites SET used_by   = NULL WHERE used_by   = ?`,
		`DELETE FROM sessions WHERE user_id = ?`,
		`DELETE FROM messages WHERE sender_id = ? OR recipient_id = ?`,
	} {
		if strings.Count(q, "?") == 2 {
			if _, err := tx.Exec(q, id, id); err != nil {
				return err
			}
			continue
		}
		if _, err := tx.Exec(q, id); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(`DELETE FROM users WHERE id = ?`, id); err != nil {
		return err
	}
	return tx.Commit()
}

// Oublie retire l'empreinte d'un compte du fichier de mots de passe.
//
// Separe de DeleteUser parce que le fichier ne vit PAS en base : il est hors de
// l'arborescence de contenu pour qu'un rsync ne l'emporte jamais. Laisser
// l'empreinte derriere ferait survivre un secret sans compte — et le
// reattribuerait au prochain compte qui recevrait le meme identifiant.
func (a *Auth) Oublie(userID int64) error {
	a.rechargeSiModifie()
	a.mu.Lock()
	delete(a.m, userID)
	a.mu.Unlock()
	return a.flush()
}
