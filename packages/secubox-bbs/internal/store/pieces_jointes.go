package store

import (
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// ErrCibleInvalide : une piece jointe vise exactement un message.
var ErrCibleInvalide = errors.New("piece jointe : une seule cible attendue")

// AttachePost relie un fichier deja depose a un message de forum.
//
// LE FICHIER EST DEJA LA. On ne re-televerse rien : le depot, la validation par
// le contenu et le calcul d'empreinte ont eu lieu au moment du depot. Attacher
// n'est qu'un lien — c'est ce qui rend un message vocal si peu couteux a
// ajouter.
func (s *Store) AttachePost(postID, fileID int64, rang int) error {
	return s.attache("post_id", postID, fileID, rang)
}

// AttacheMessage relie un fichier a un message prive.
func (s *Store) AttacheMessage(messageID, fileID int64, rang int) error {
	return s.attache("message_id", messageID, fileID, rang)
}

func (s *Store) attache(colonne string, cibleID, fileID int64, rang int) error {
	if cibleID <= 0 || fileID <= 0 {
		return ErrCibleInvalide
	}
	// La colonne ne vient JAMAIS de l'exterieur : les deux seules valeurs
	// possibles sont ecrites ici, en clair. Un identifiant de colonne ne peut
	// pas etre passe en parametre lie, donc la seule protection sure est qu'il
	// ne soit pas une donnee.
	if colonne != "post_id" && colonne != "message_id" {
		return ErrCibleInvalide
	}
	_, err := s.db.Exec(
		`INSERT INTO pieces_jointes (file_id, `+colonne+`, rang, cree_le)
		 VALUES (?, ?, ?, ?)`,
		fileID, cibleID, rang, time.Now().Unix())
	return err
}

// PiecesDuPost rend les pieces jointes d'un message de forum, dans l'ordre voulu.
//
// LES FICHIERS SUPPRIMES EN DOUCEUR SONT ECARTES ICI, pas dans l'affichage : un
// media retire par la moderation ne doit reapparaitre dans aucune vue, et
// laisser chaque gabarit y penser serait compter sur la vigilance plutot que sur
// la requete.
func (s *Store) PiecesDuPost(postID int64) ([]Fichier, error) {
	return s.pieces("post_id", postID)
}

// PiecesDuMessage rend les pieces jointes d'un message prive.
func (s *Store) PiecesDuMessage(messageID int64) ([]Fichier, error) {
	return s.pieces("message_id", messageID)
}

func (s *Store) pieces(colonne string, cibleID int64) ([]Fichier, error) {
	if colonne != "post_id" && colonne != "message_id" {
		return nil, ErrCibleInvalide
	}
	rows, err := s.db.Query(
		`SELECT f.id, f.owner_id, f.path, f.name, f.size, f.mime, f.created_at
		   FROM pieces_jointes pj
		   JOIN files f ON f.id = pj.file_id
		  WHERE pj.`+colonne+` = ? AND f.deleted_at IS NULL
		  ORDER BY pj.rang, pj.id`, cibleID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Fichier
	for rows.Next() {
		var f Fichier
		if err := rows.Scan(&f.ID, &f.Owner, &f.Path, &f.Name,
			&f.Size, &f.Mime, &f.Created); err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// DefinitDuree enregistre la duree d'un media, en millisecondes.
//
// DONNEE D'AGREMENT, JAMAIS DE SECURITE. Elle vient du navigateur et sert a
// ecrire « 0:23 » avant lecture. Rien ne doit en dependre pour decider quoi que
// ce soit — une duree annoncee peut etre fausse sans consequence.
func (s *Store) DefinitDuree(fileID int64, ms int64) error {
	if ms < 0 {
		return fmt.Errorf("duree negative")
	}
	_, err := s.db.Exec(`UPDATE files SET duree_ms = ? WHERE id = ?`, ms, fileID)
	return err
}

// DureeDe rend la duree connue d'un media, ou 0 si elle est inconnue.
func (s *Store) DureeDe(fileID int64) (int64, error) {
	var ms sql.NullInt64
	err := s.db.QueryRow(`SELECT duree_ms FROM files WHERE id = ?`, fileID).Scan(&ms)
	if err != nil {
		return 0, err
	}
	return ms.Int64, nil
}
