// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// Messagerie interne entre membres enregistres (#1008).
//
// Les messages vivent en base et NON sur disque, contrairement au forum. Le
// forum est publiable et reindexable : ses .md font autorite. Un message prive
// n'est ni l'un ni l'autre, et le mettre dans content/ le ferait emporter par
// la sauvegarde et par le rsync vers un support externe — exactement ce que la
// page /mp annonce ne pas faire.
package store

import (
	"errors"
	"strings"
)

// ErrDestinataire couvre tous les refus d'envoi tenant a l'interlocuteur ou au
// contenu. Un seul type d'erreur suffit : la vue les affiche telles quelles, et
// l'appelant n'a aucune raison de les distinguer pour agir differemment.
var ErrDestinataire = errors.New("destinataire ou message invalide")

// Message est une ligne de conversation. Auteur porte le pseudo de
// l'expediteur, ou reste vide si son compte a ete supprime : la conversation
// survit a la disparition d'un compte, amputee du nom mais pas du propos.
type Message struct {
	ID     int64
	De     int64
	Auteur string
	Body   string
	SentAt int64
	Lu     bool
}

// Conversation resume un interlocuteur dans la boite de reception.
type ConversationResume struct {
	ID      int64
	Handle  string
	Nom     string
	Dernier string
	SentAt  int64
	NonLus  int
}

// Envoyer depose un message. Les trois refus — soi-meme, compte ferme, corps
// vide — sont verifies ICI et non dans la vue : une future API ou une commande
// `bbsctl` doit heriter des memes garde-fous sans les reecrire.
func (s *Store) Envoyer(de, vers int64, corps string) (int64, error) {
	corps = strings.TrimSpace(corps)
	if corps == "" {
		return 0, ErrDestinataire
	}
	if de == vers {
		return 0, ErrDestinataire
	}
	// Les deux comptes doivent etre ouverts. Ecrire a un compte ferme donnerait
	// l'illusion d'avoir prevenu quelqu'un qui ne se connectera plus ; ecrire
	// DEPUIS un compte ferme laisserait une session survivante parler encore.
	for _, id := range []int64{de, vers} {
		var ouvert bool
		err := s.db.QueryRow(
			`SELECT disabled_at IS NULL FROM users WHERE id = ?`, id).Scan(&ouvert)
		if err != nil || !ouvert {
			return 0, ErrDestinataire
		}
	}
	res, err := s.db.Exec(
		`INSERT INTO messages(sender_id, recipient_id, body, sent_at)
		 VALUES(?,?,?,unixepoch())`, de, vers, corps)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// Conversation rend l'echange entre `moi` et `autre`, dans les DEUX sens et en
// ordre chronologique.
//
// La restriction aux deux interlocuteurs est dans la requete, pas dans la vue :
// un filtre pose seulement au rendu laisserait une future API renvoyer le fil
// entier a qui le demande.
func (s *Store) Conversation(moi, autre int64) ([]Message, error) {
	rows, err := s.db.Query(`
		SELECT m.id, COALESCE(m.sender_id,0), COALESCE(u.handle,''), m.body,
		       m.sent_at, m.read_at IS NOT NULL
		  FROM messages m
		  LEFT JOIN users u ON u.id = m.sender_id
		 WHERE (m.sender_id = ? AND m.recipient_id = ?)
		    OR (m.sender_id = ? AND m.recipient_id = ?)
		 ORDER BY m.sent_at, m.id`, moi, autre, autre, moi)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Message
	for rows.Next() {
		var m Message
		if err := rows.Scan(&m.ID, &m.De, &m.Auteur, &m.Body, &m.SentAt, &m.Lu); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// Conversations rend la boite de reception : un resume par interlocuteur, le
// plus recent d'abord.
//
// Trier par date du DERNIER message et non du premier : une boite classee par
// ordre d'ouverture enterre les echanges vivants sous les anciens.
func (s *Store) Conversations(moi int64) ([]ConversationResume, error) {
	rows, err := s.db.Query(`
		WITH fil AS (
		    SELECT CASE WHEN sender_id = ?1 THEN recipient_id ELSE sender_id END AS autre,
		           body, sent_at, id,
		           CASE WHEN recipient_id = ?1 AND read_at IS NULL THEN 1 ELSE 0 END AS non_lu
		      FROM messages
		     WHERE sender_id = ?1 OR recipient_id = ?1
		)
		SELECT f.autre, u.handle, u.display_name,
		       (SELECT body FROM fil g WHERE g.autre = f.autre
		         ORDER BY g.sent_at DESC, g.id DESC LIMIT 1),
		       MAX(f.sent_at), SUM(f.non_lu)
		  FROM fil f
		  JOIN users u ON u.id = f.autre
		 WHERE f.autre IS NOT NULL
		 GROUP BY f.autre
		 ORDER BY MAX(f.sent_at) DESC, f.autre DESC`, moi)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ConversationResume
	for rows.Next() {
		var c ConversationResume
		if err := rows.Scan(&c.ID, &c.Handle, &c.Nom, &c.Dernier, &c.SentAt, &c.NonLus); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// MarquerLu ne touche que les messages RECUS par `moi`.
//
// Marquer la conversation entiere ferait disparaitre le signal chez
// l'interlocuteur : il ne saurait jamais qu'un message l'attend.
func (s *Store) MarquerLu(moi, autre int64) error {
	_, err := s.db.Exec(
		`UPDATE messages SET read_at = unixepoch()
		  WHERE recipient_id = ? AND sender_id = ? AND read_at IS NULL`, moi, autre)
	return err
}

// NonLus compte les messages recus et non lus. Evalue a chaque page pour le
// compteur de navigation : l'index partiel sur read_at IS NULL est la pour ca.
func (s *Store) NonLus(moi int64) (int, error) {
	var n int
	err := s.db.QueryRow(
		`SELECT COUNT(*) FROM messages WHERE recipient_id = ? AND read_at IS NULL`,
		moi).Scan(&n)
	return n, err
}

// Correspondants liste les comptes ouverts a qui `moi` peut ecrire, pour le
// selecteur de destinataire. Soi-meme exclu : l'envoi le refuserait ensuite, et
// proposer un choix qui echoue est une invitation a l'erreur.
func (s *Store) Correspondants(moi int64) ([]Compte, error) {
	rows, err := s.db.Query(
		`SELECT id, handle, display_name FROM users
		  WHERE disabled_at IS NULL AND id <> ? ORDER BY handle`, moi)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Compte
	for rows.Next() {
		var c Compte
		if err := rows.Scan(&c.ID, &c.Handle, &c.Display); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}
