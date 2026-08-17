// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// Moderation des fils et des messages.
//
// DEUX REGLES COMMANDENT CE FICHIER.
//
//  1. ON N'EFFACE PAS, ON MASQUE. Un message retire passe en visibilite locale,
//     il ne disparait pas de la base. Une moderation contestee doit pouvoir etre
//     examinee, et un effacement definitif rend le desaccord indecidable — c'est
//     la parole d'un moderateur contre celle d'un membre, sans piece.
//
//  2. TOUT GESTE EST JOURNALISE. Qui, quoi, quand. Un pouvoir de moderation sans
//     trace n'est pas un pouvoir encadre : c'est le journal qui distingue les
//     deux, pas la bonne volonte de celui qui l'exerce.
package store

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
)

// ErrIntrouvable : la cible de la moderation n'existe pas (ou plus).
var ErrIntrouvable = errors.New("cible introuvable")

// journalise ecrit une ligne d'audit dans la MEME transaction que le geste.
//
// Hors transaction, un plantage entre les deux laisserait un fil modifie sans
// trace — exactement le cas ou la trace compte le plus.
func journalise(tx *sql.Tx, acteur int64, action, cible, detail string) error {
	_, err := tx.Exec(`
		INSERT INTO audit(at, actor_id, action, target, detail)
		VALUES(unixepoch(), ?, ?, ?, ?)`, acteur, action, cible, detail)
	return err
}

// RenommeFil change le titre d'un fil.
//
// Le titre est ce que tout le monde voit dans les listes : un titre trompeur ou
// injurieux nuit sans qu'on ait a ouvrir le fil. L'ancien titre part au journal,
// sans quoi la correction serait indistinguable d'une reecriture de l'histoire.
func (s *Store) RenommeFil(acteur, fil int64, titre string) error {
	titre = strings.TrimSpace(titre)
	if titre == "" {
		return errors.New("un titre vide n'aide personne")
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	var ancien string
	if err := tx.QueryRow(`SELECT title FROM threads WHERE id = ?`, fil).Scan(&ancien); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrIntrouvable
		}
		return err
	}
	if _, err := tx.Exec(`UPDATE threads SET title = ? WHERE id = ?`, titre, fil); err != nil {
		return err
	}
	if err := journalise(tx, acteur, "fil.renomme", fmt.Sprintf("thread:%d", fil),
		fmt.Sprintf("%q -> %q", ancien, titre)); err != nil {
		return err
	}
	return tx.Commit()
}

// DeplaceFil change le salon d'un fil.
//
// Un fil au mauvais endroit n'est pas lu par ceux qu'il concerne. Le deplacer
// vaut mieux que le supprimer et demander de le reposter — ce qui perdrait les
// reponses deja ecrites.
func (s *Store) DeplaceFil(acteur, fil, salon int64) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	var ancien int64
	if err := tx.QueryRow(`SELECT category_id FROM threads WHERE id = ?`, fil).Scan(&ancien); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrIntrouvable
		}
		return err
	}
	var existe int
	if err := tx.QueryRow(`SELECT count(*) FROM categories WHERE id = ?`, salon).Scan(&existe); err != nil {
		return err
	}
	if existe == 0 {
		return errors.New("salon de destination inconnu")
	}
	// LE SLUG EST UNIQUE PAR SALON : deplacer peut heurter un fil homonyme deja
	// present. On rend l'erreur telle quelle plutot que de renommer en douce —
	// une adresse qui change sans prevenir casse les liens deja partages.
	if _, err := tx.Exec(`UPDATE threads SET category_id = ? WHERE id = ?`, salon, fil); err != nil {
		return err
	}
	if err := journalise(tx, acteur, "fil.deplace", fmt.Sprintf("thread:%d", fil),
		fmt.Sprintf("salon %d -> %d", ancien, salon)); err != nil {
		return err
	}
	return tx.Commit()
}

// VerrouilleFil empeche (ou reautorise) les reponses.
//
// Verrouiller n'efface rien : le fil reste lisible. C'est la difference entre
// « cette conversation est close » et « cette conversation n'a jamais eu lieu ».
func (s *Store) VerrouilleFil(acteur, fil int64, verrou bool) error {
	return s.bascule(acteur, fil, "locked", verrou, "fil.verrouille", "fil.deverrouille")
}

// EpingleFil place (ou retire) un fil en tete de son salon.
func (s *Store) EpingleFil(acteur, fil int64, epingle bool) error {
	return s.bascule(acteur, fil, "pinned", epingle, "fil.epingle", "fil.desepingle")
}

func (s *Store) bascule(acteur, fil int64, colonne string, valeur bool, actOn, actOff string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	var n int
	if err := tx.QueryRow(`SELECT count(*) FROM threads WHERE id = ?`, fil).Scan(&n); err != nil {
		return err
	}
	if n == 0 {
		return ErrIntrouvable
	}
	v := 0
	if valeur {
		v = 1
	}
	// La colonne vient d'une constante du code, jamais d'une requete : les deux
	// seuls appelants passent "locked" ou "pinned" en litteral.
	if _, err := tx.Exec(
		fmt.Sprintf(`UPDATE threads SET %s = ? WHERE id = ?`, colonne), v, fil); err != nil {
		return err
	}
	act := actOff
	if valeur {
		act = actOn
	}
	if err := journalise(tx, acteur, act, fmt.Sprintf("thread:%d", fil), ""); err != nil {
		return err
	}
	return tx.Commit()
}

// RetireMessage masque un message : il passe en visibilite locale.
//
// ON N'EFFACE PAS. Le message reste en base, lisible des membres connectes et
// des sysops. Une moderation contestee doit pouvoir etre examinee ; un
// effacement definitif rend le desaccord indecidable.
//
// Consequence voulue : retirer un message le fait sortir des publications
// futures, sans reecrire ce qui a deja ete publie.
func (s *Store) RetireMessage(acteur, message int64, motif string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	var vis string
	if err := tx.QueryRow(`SELECT visibility FROM posts WHERE id = ?`, message).Scan(&vis); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrIntrouvable
		}
		return err
	}
	if _, err := tx.Exec(
		`UPDATE posts SET visibility = 'local' WHERE id = ?`, message); err != nil {
		return err
	}
	if err := journalise(tx, acteur, "message.retire", fmt.Sprintf("post:%d", message),
		strings.TrimSpace(motif)); err != nil {
		return err
	}
	return tx.Commit()
}

// RetablitMessage annule un retrait.
//
// La symetrie n'est pas un ornement : une moderation sans retour en arriere
// pousse a ne jamais moderer, de peur de se tromper.
func (s *Store) RetablitMessage(acteur, message int64) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	var n int
	if err := tx.QueryRow(`SELECT count(*) FROM posts WHERE id = ?`, message).Scan(&n); err != nil {
		return err
	}
	if n == 0 {
		return ErrIntrouvable
	}
	if _, err := tx.Exec(
		`UPDATE posts SET visibility = 'public' WHERE id = ?`, message); err != nil {
		return err
	}
	if err := journalise(tx, acteur, "message.retabli", fmt.Sprintf("post:%d", message), ""); err != nil {
		return err
	}
	return tx.Commit()
}

// Moderations rend le journal des gestes de moderation, le plus recent d'abord.
//
// Le journal n'a de valeur que s'il est LISIBLE : un journal qu'il faut aller
// chercher en base n'encadre rien.
type Moderation struct {
	At     int64
	Acteur string
	Action string
	Cible  string
	Detail string
}

func (s *Store) Moderations(borne int) ([]Moderation, error) {
	if borne <= 0 || borne > 500 {
		borne = 100
	}
	rows, err := s.db.Query(`
		SELECT a.at, COALESCE(u.display_name, u.handle, '?'), a.action, a.target,
		       COALESCE(a.detail,'')
		  FROM audit a
		  LEFT JOIN users u ON u.id = a.actor_id
		 -- TOUTES les familles de gestes, pas seulement les fils et les messages.
		 -- Le premier jet oubliait billet. et salon. : les entrees etaient bien
		 -- ecrites mais n'apparaissaient nulle part, ce qui est pire qu'une
		 -- absence de journal — on croit surveille ce qui ne l'est pas.
		 WHERE a.action LIKE 'fil.%' OR a.action LIKE 'message.%'
		    OR a.action LIKE 'billet.%' OR a.action LIKE 'salon.%'
		 ORDER BY a.at DESC, a.id DESC
		 LIMIT ?`, borne)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Moderation
	for rows.Next() {
		var m Moderation
		if err := rows.Scan(&m.At, &m.Acteur, &m.Action, &m.Cible, &m.Detail); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// ── Salons et sous-salons ────────────────────────────────────────────────

// CreeSousSalon cree un salon, eventuellement sous un parent.
//
// `parent` a 0 cree un salon de premier niveau. Un parent inexistant est refuse
// plutot qu'ignore : creer sous un parent qui n'existe pas produirait un salon
// orphelin, visible nulle part, que personne ne penserait a chercher.
//
// UN SALON NE PEUT PAS ETRE SON PROPRE PARENT, ni descendre de lui-meme. Sans
// cette garde, l'affichage de l'arbre boucle — et c'est la page d'accueil qui
// se fige, pas une vue secondaire.
func (s *Store) CreeSousSalon(acteur int64, slug, titre, desc string, parent int64) (int64, error) {
	slug, titre = strings.TrimSpace(slug), strings.TrimSpace(titre)
	if slug == "" || titre == "" {
		return 0, errors.New("un salon a besoin d'un identifiant et d'un titre")
	}
	if parent > 0 {
		var n int
		if err := s.db.QueryRow(
			`SELECT count(*) FROM categories WHERE id = ?`, parent).Scan(&n); err != nil {
			return 0, err
		}
		if n == 0 {
			return 0, errors.New("salon parent inconnu")
		}
	}
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	var p any
	if parent > 0 {
		p = parent
	}
	res, err := tx.Exec(`
		INSERT INTO categories(slug, title, description, parent_id)
		VALUES(?,?,?,?)`, slug, titre, desc, p)
	if err != nil {
		return 0, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, err
	}
	if err := journalise(tx, acteur, "salon.cree", fmt.Sprintf("category:%d", id),
		fmt.Sprintf("%s (parent %d)", slug, parent)); err != nil {
		return 0, err
	}
	return id, tx.Commit()
}

// SalonAvecParent : un salon et son rattachement, pour afficher l'arbre.
type SalonAvecParent struct {
	Category
	Parent int64
}

// Arbre rend les salons avec leur parent, ordonnes pour l'affichage.
func (s *Store) Arbre(publicOnly bool) ([]SalonAvecParent, error) {
	q := `SELECT id, slug, title, COALESCE(description,''), COALESCE(parent_id,0)
	        FROM categories ORDER BY COALESCE(parent_id,0), position, title`
	rows, err := s.db.Query(q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SalonAvecParent
	for rows.Next() {
		var c SalonAvecParent
		if err := rows.Scan(&c.ID, &c.Slug, &c.Title, &c.Desc, &c.Parent); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// ── Billets : depublier et republier ─────────────────────────────────────

// Depublie retire un fil de la vitrine.
//
// LA LIGNE EST SUPPRIMEE, pas marquee : `billets` dit ce qui EST publie, et un
// billet depublie n'est plus publie. Y garder une ligne « inactive » obligerait
// chaque lecture a filtrer, et la premiere lecture qui oublierait le filtre
// afficherait un billet retire comme s'il etait en ligne.
//
// Le geste est journalise : depublier est une decision editoriale, et savoir
// qui l'a prise compte autant que le fait qu'elle ait ete prise.
func (s *Store) Depublie(acteur, fil int64) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	var billetID, url string
	err = tx.QueryRow(`SELECT billet_id, url FROM billets WHERE thread_id = ?`, fil).
		Scan(&billetID, &url)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrIntrouvable
	}
	if err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM billets WHERE thread_id = ?`, fil); err != nil {
		return err
	}
	// L'IDENTIFIANT DISTANT PART AU JOURNAL. Sans lui, republier plus tard
	// creerait un second billet au lieu de remplacer le premier — et l'ancien
	// resterait en ligne sans que rien ne le rattache au fil.
	if err := journalise(tx, acteur, "billet.depublie", fmt.Sprintf("thread:%d", fil),
		fmt.Sprintf("billet %s %s", billetID, url)); err != nil {
		return err
	}
	return tx.Commit()
}

// EstPublie dit si un fil a un billet en ligne, et lequel.
func (s *Store) EstPublie(fil int64) (BilletPublie, bool) {
	var b BilletPublie
	err := s.db.QueryRow(`
		SELECT thread_id, billet_id, url, published_at, taken, held
		  FROM billets WHERE thread_id = ?`, fil).
		Scan(&b.ThreadID, &b.BilletID, &b.URL, &b.Publie, &b.Repris, &b.Retenus)
	return b, err == nil
}
