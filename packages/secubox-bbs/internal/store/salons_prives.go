package store

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"errors"
	"time"
)

var (
	// ErrPasMembre : le salon est prive et la personne n'y a pas ete conviee.
	ErrPasMembre = errors.New("salon prive : acces reserve aux membres du salon")
	// ErrInvitationSalon : code inconnu, deja servi, ou perime.
	ErrInvitationSalon = errors.New("invitation de salon invalide ou expiree")
)

// DureeInvitationSalon : une invitation a un salon ne vit pas eternellement.
// Sept jours suffisent a la transmettre, et une invitation oubliee dans un
// courriel ancien ne doit pas rester une porte ouverte.
const DureeInvitationSalon = 7 * 24 * time.Hour

// RendPrive ferme un salon : desormais, seuls ses membres nommes y accedent.
//
// LE RANG N'EST PAS TOUCHE. `min_role_read` continue de dire « a partir de quel
// niveau » ; la confidentialite dit « qui nommement ». Les deux se cumulent :
// un salon peut etre reserve aux membres ET limite a trois d'entre eux.
func (s *Store) RendPrive(catID int64, prive bool) error {
	v := 0
	if prive {
		v = 1
	}
	_, err := s.db.Exec(`UPDATE categories SET prive = ? WHERE id = ?`, v, catID)
	return err
}

// EstPrive dit si un salon est ferme.
func (s *Store) EstPrive(catID int64) (bool, error) {
	var v int
	err := s.db.QueryRow(`SELECT prive FROM categories WHERE id = ?`, catID).Scan(&v)
	return v == 1, err
}

// AjouteMembre convie une personne dans un salon. Idempotent : convier deux fois
// n'est pas une erreur — c'est le geste d'un sysop qui ne se souvient plus.
func (s *Store) AjouteMembre(catID, userID, par int64) error {
	var parN sql.NullInt64
	if par > 0 {
		parN = sql.NullInt64{Int64: par, Valid: true}
	}
	_, err := s.db.Exec(
		`INSERT INTO salon_membres (category_id, user_id, ajoute_par, ajoute_le)
		 VALUES (?, ?, ?, ?)
		 ON CONFLICT (category_id, user_id) DO NOTHING`,
		catID, userID, parN, time.Now().Unix())
	return err
}

// RetireMembre reprend l'acces.
func (s *Store) RetireMembre(catID, userID int64) error {
	_, err := s.db.Exec(
		`DELETE FROM salon_membres WHERE category_id = ? AND user_id = ?`, catID, userID)
	return err
}

// PeutVoirSalon : la question que pose CHAQUE page.
//
// UN SALON PUBLIC RESTE VISIBLE DE TOUS — la confidentialite ne s'applique
// qu'aux salons fermes. UN SYSOP VOIT TOUT : sans cela, un sysop pourrait
// creer un salon prive puis en perdre l'acces, et plus personne ne pourrait
// le moderer.
func (s *Store) PeutVoirSalon(catID, userID int64, sysop bool) (bool, error) {
	prive, err := s.EstPrive(catID)
	if err != nil {
		return false, err
	}
	if !prive || sysop {
		return true, nil
	}
	if userID <= 0 {
		return false, nil
	}
	var un int
	err = s.db.QueryRow(
		`SELECT 1 FROM salon_membres WHERE category_id = ? AND user_id = ?`,
		catID, userID).Scan(&un)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return err == nil, err
}

// SalonsCachesPour rend les salons que cette personne ne doit PAS voir.
//
// ON REND CE QUI EST CACHE, PAS CE QUI EST VISIBLE. L'appelant construit deja sa
// liste de salons ; lui demander de la remplacer par une autre requete
// l'obligerait a refaire tris et comptages. Une liste d'exclusion se soustrait
// de ce qu'il a deja, et surtout : SI CETTE FONCTION ECHOUE, l'appelant qui
// oublie de traiter l'erreur cache trop, jamais trop peu. L'inverse aurait fait
// fuir l'existence des salons prives a la premiere erreur ignoree.
func (s *Store) SalonsCachesPour(userID int64, sysop bool) (map[int64]bool, error) {
	caches := map[int64]bool{}
	if sysop {
		return caches, nil
	}
	rows, err := s.db.Query(
		`SELECT c.id FROM categories c
		  WHERE c.prive = 1
		    AND NOT EXISTS (SELECT 1 FROM salon_membres m
		                     WHERE m.category_id = c.id AND m.user_id = ?)`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		caches[id] = true
	}
	return caches, rows.Err()
}

// MembresDuSalon liste qui a acces, pour la console du sysop.
func (s *Store) MembresDuSalon(catID int64) ([]UserInfo, error) {
	rows, err := s.db.Query(
		`SELECT u.id FROM salon_membres m JOIN users u ON u.id = m.user_id
		  WHERE m.category_id = ? ORDER BY m.ajoute_le`, catID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	out := make([]UserInfo, 0, len(ids))
	for _, id := range ids {
		info, err := s.UserInfo(id)
		if err != nil {
			return nil, err
		}
		out = append(out, info)
	}
	return out, nil
}

// NouvelleInvitationSalon emet un code d'acces a un salon.
//
// ELLE N'OUVRE PAS DE COMPTE, et c'est tout l'objet de la table separee. Le
// code rend membre d'un salon quelqu'un qui EST DEJA inscrit et connecte.
// Partage par megarde dans un lieu public, il ne donne acces a rien tant que
// celui qui le ramasse n'a pas deja un compte sur la board.
func (s *Store) NouvelleInvitationSalon(catID, par int64) (string, error) {
	brut := make([]byte, 24)
	if _, err := rand.Read(brut); err != nil {
		return "", err
	}
	code := base64.RawURLEncoding.EncodeToString(brut)
	sum := sha256.Sum256([]byte(code))
	maintenant := time.Now()
	_, err := s.db.Exec(
		`INSERT INTO invites_salon
		   (code_sha256, category_id, issued_by, issued_at, expires_at)
		 VALUES (?, ?, ?, ?, ?)`,
		sum[:], catID, par, maintenant.Unix(),
		maintenant.Add(DureeInvitationSalon).Unix())
	if err != nil {
		return "", err
	}
	return code, nil
}

// RejoinsSalon consomme une invitation au profit d'un compte EXISTANT.
//
// L'IDENTIFIANT DU MEMBRE VIENT DE LA SESSION, jamais du lien. Un lien qui
// porterait « qui » en plus de « quoi » permettrait de se faire passer pour un
// autre en le modifiant.
func (s *Store) RejoinsSalon(code string, userID int64) (int64, error) {
	if userID <= 0 {
		return 0, ErrInvitationSalon
	}
	sum := sha256.Sum256([]byte(code))
	var catID, expire int64
	var utilise sql.NullInt64
	err := s.db.QueryRow(
		`SELECT category_id, expires_at, used_at FROM invites_salon
		  WHERE code_sha256 = ?`, sum[:]).Scan(&catID, &expire, &utilise)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, ErrInvitationSalon
	}
	if err != nil {
		return 0, err
	}
	// UNE SEULE FOIS, ET PAS APRES L'ECHEANCE. Un code deja servi reste dans la
	// table — il faut pouvoir dire QUI est entre, et quand.
	if utilise.Valid || time.Now().Unix() > expire {
		return 0, ErrInvitationSalon
	}
	if err := s.AjouteMembre(catID, userID, 0); err != nil {
		return 0, err
	}
	_, err = s.db.Exec(
		`UPDATE invites_salon SET used_at = ?, used_by = ? WHERE code_sha256 = ?`,
		time.Now().Unix(), userID, sum[:])
	return catID, err
}

// SlugDuSalon rend l'identifiant d'adresse d'un salon, pour y renvoyer.
func (s *Store) SlugDuSalon(catID int64) (string, error) {
	var slug string
	err := s.db.QueryRow(`SELECT slug FROM categories WHERE id = ?`, catID).Scan(&slug)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return slug, err
}
