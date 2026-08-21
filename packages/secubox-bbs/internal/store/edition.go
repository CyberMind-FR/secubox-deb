package store

import (
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
)

// ErrDroitEdition : l'editeur n'est ni l'auteur du message ni un sysop.
var ErrDroitEdition = errors.New("edition non autorisee")

// EditerPost remplace le corps d'un message (#1091).
//
// LA REGLE DE DROIT : l'auteur edite LE SIEN ; un sysop corrige CELUI DES
// AUTRES. Toute autre combinaison est refusee AVANT la moindre ecriture — la
// verification est ici, dans le magasin, pas seulement dans la vue : une regle
// de droit qui ne vit que dans le gabarit tombe des qu'un autre appelant arrive.
//
// L'edition est TRANSPARENTE : `edited_at`/`edited_by` sont poses et le geste
// part au journal d'audit (dans la meme transaction que l'ecriture, comme la
// moderation : un corps reecrit sans trace serait une reecriture de l'histoire).
// L'entete du fichier conserve l'AUTEUR D'ORIGINE — corriger n'est pas
// s'approprier.
func (s *Store) EditerPost(editeur int64, roleEditeur Role, post int64, corps string) error {
	if strings.TrimSpace(corps) == "" {
		return errors.New("un message vide n'a pas de sens")
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// Entete d'origine : auteur, fil, categorie, titre, provenance. On rejoue
	// exactement ce que `insertPost` grave, pour ne rien perdre a la reecriture
	// (« le disque fait foi » n'est vrai que si le disque porte tout).
	var auteur, fil, cree int64
	var handle, catSlug, titre, source, ref, media, kind, rel, vis string
	err = tx.QueryRow(`SELECT p.author_id, p.thread_id, p.body_path, p.created_at,
		p.visibility, u.handle, c.slug, t.title,
		COALESCE(t.source,''), COALESCE(t.source_ref,''),
		COALESCE(t.media_url,''), COALESCE(t.media_kind,'')
		FROM posts p JOIN threads t ON t.id = p.thread_id
		JOIN categories c ON c.id = t.category_id
		JOIN users u ON u.id = p.author_id
		WHERE p.id = ? AND p.deleted_at IS NULL`, post).
		Scan(&auteur, &fil, &rel, &cree, &vis, &handle, &catSlug, &titre,
			&source, &ref, &media, &kind)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrIntrouvable
	}
	if err != nil {
		return err
	}

	if editeur != auteur && roleEditeur != RoleSysop {
		return ErrDroitEdition
	}

	if err := writeBody(filepath.Join(s.root, rel), entete{
		Thread: fil, Category: catSlug, Author: handle,
		Visibility: Visibility(vis), Created: cree, Title: titre,
		Source: source, Ref: ref, Media: media, Kind: kind,
	}, corps); err != nil {
		return err
	}
	sum := sha256.Sum256([]byte(normaliseCorps(corps)))
	if _, err := tx.Exec(`UPDATE posts
		SET body_sha256 = ?, edited_at = unixepoch(), edited_by = ?
		WHERE id = ?`, sum[:], editeur, post); err != nil {
		return err
	}

	// L'action distingue une retouche d'auteur d'une correction de moderation :
	// le journal doit pouvoir repondre « qui a touche au texte d'un autre ? ».
	action := "post.edite"
	if editeur != auteur {
		action = "post.corrige"
	}
	if err := journalise(tx, editeur, action, fmt.Sprintf("post:%d", post), ""); err != nil {
		return err
	}
	return tx.Commit()
}

// PostByID rend un message seul, pour la page d'edition (#1091). Un message
// masque par la moderation (deleted_at) est introuvable ici comme ailleurs.
func (s *Store) PostByID(id int64) (Post, error) {
	var p Post
	var vis string
	err := s.db.QueryRow(`SELECT id,thread_id,author_id,body_path,visibility,created_at,
		COALESCE(edited_at,0),COALESCE(edited_by,0)
		FROM posts WHERE id = ? AND deleted_at IS NULL`, id).
		Scan(&p.ID, &p.ThreadID, &p.AuthorID, &p.BodyPath, &vis,
			&p.CreatedAt, &p.EditedAt, &p.EditedBy)
	if errors.Is(err, sql.ErrNoRows) {
		return Post{}, ErrIntrouvable
	}
	if err != nil {
		return Post{}, err
	}
	p.Visibility = Visibility(vis)
	return p, nil
}

// PeutEditer dit si un visiteur (par son id et son role) peut editer un message
// dont l'auteur est `auteur`. Meme regle que EditerPost — exposee a la vue pour
// n'afficher le bouton d'edition que quand il agira.
func PeutEditer(visiteur int64, role Role, auteur int64) bool {
	return visiteur != 0 && (visiteur == auteur || role == RoleSysop)
}
