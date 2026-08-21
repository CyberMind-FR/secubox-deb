// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// Depot de fichiers : images, sons, videos, joints aux fils et aux messages.
//
// TROIS REGLES, ET ELLES SONT TOUTES DE SECURITE.
//
//  1. LE TYPE ANNONCE PAR LE CLIENT N'EST JAMAIS CRU. On renifle le contenu.
//     Un client qui annonce « image/png » en envoyant un executable ferait
//     servir cet executable en image, et un navigateur indulgent finirait par
//     l'ouvrir.
//
//  2. LA LISTE EST BLANCHE. Ce qui n'est pas reconnu comme image, son ou video
//     est refuse. Une liste noire vieillit mal : il faudrait y penser avant
//     chaque nouveau format dangereux.
//
//  3. LE CHEMIN SUR DISQUE NE VIENT JAMAIS DU NOM FOURNI. Il est derive de
//     l'identifiant. Un nom peut contenir des separateurs, des `..`, ou
//     n'etre qu'un point ; le nom d'origine ne sert qu'a l'affichage.
//
// LE SVG EST REFUSE, meme si c'est une image. C'est un DOCUMENT EXECUTABLE :
// il embarque du script, et servi en ligne il s'execute dans l'origine du BBS,
// donc avec la session du lecteur. Aucune miniature ne vaut ca.
package store

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// TailleMaxFichier borne un depot. L'eMMC de la board a deja provoque des 502
// en se remplissant : la borne protege le service, pas l'esthetique.
const TailleMaxFichier int64 = 64 << 20 // 64 Mio

// typesAcceptes : la liste BLANCHE des types servis en ligne.
//
// Volontairement courte. Chaque entree est un format que les navigateurs
// affichent nativement et qui ne porte pas de script.
var typesAcceptes = map[string]string{
	"image/png":  ".png",
	"image/jpeg": ".jpg",
	"image/gif":  ".gif",
	"image/webp": ".webp",
	"audio/mpeg": ".mp3",
	"audio/ogg":  ".ogg",
	"audio/wav":  ".wav",
	"audio/flac": ".flac",
	// WebM PORTE DE L'AUDIO SEUL AUTANT QUE DE LA VIDEO — c'est ce que produit
	// Chrome pour une note vocale. Extension distincte : `.webm` fait rendre un
	// lecteur video, et une note vocale s'afficherait en rectangle noir.
	"audio/webm": ".weba",
	"video/mp4":  ".mp4",
	"video/ogg":  ".ogv",
	"video/webm": ".webm",
	// PDF : rendu nativement par le navigateur, servi `inline` avec nosniff — il
	// ne peut donc pas etre requalifie en HTML. Un PDF peut porter du script,
	// mais celui-ci s'execute dans le lecteur PDF cloisonne, pas dans le DOM de
	// l'origine (#1102).
	"application/pdf": ".pdf",
}

// Fichier : une piece jointe.
type Fichier struct {
	ID      int64
	Owner   int64
	Path    string // relatif a files/ — DERIVE DE L'ID, jamais du nom fourni
	Name    string // nom d'origine, pour l'affichage et le telechargement
	Size       int64
	Mime       string
	Created    int64
	Visibility string // 'local' (membres) | 'public' (servi à tout venant, #1114)
}

// EstImage, EstAudio, EstVideo : de quoi choisir la balise a l'affichage.
func (f Fichier) EstImage() bool { return strings.HasPrefix(f.Mime, "image/") }
func (f Fichier) EstAudio() bool { return strings.HasPrefix(f.Mime, "audio/") }
func (f Fichier) EstVideo() bool { return strings.HasPrefix(f.Mime, "video/") }

var ErrTypeRefuse = errors.New("type de fichier refuse")

// DeposeFichier ecrit le contenu et l'enregistre.
//
// `mimeAnnonce` n'est PAS utilise pour decider : il n'est la que pour departager
// deux formats que le renifleur confond, jamais pour elargir la liste blanche.
func (s *Store) DeposeFichier(owner int64, nom, mimeAnnonce string, contenu io.Reader) (Fichier, error) {
	var f Fichier

	// LA BORNE S'APPLIQUE PENDANT LA LECTURE, pas apres : refuser un fichier
	// apres avoir ecrit trois gigaoctets ne protege de rien. `LimitReader` lit
	// un octet de plus que la borne — s'il arrive, c'est que le fichier la
	// depasse.
	brut, err := io.ReadAll(io.LimitReader(contenu, TailleMaxFichier+1))
	if err != nil {
		return f, err
	}
	if len(brut) == 0 {
		return f, errors.New("fichier vide")
	}
	if int64(len(brut)) > TailleMaxFichier {
		return f, fmt.Errorf("fichier trop volumineux (maximum %d Mio)", TailleMaxFichier>>20)
	}

	// LE CONTENU DECIDE. `DetectContentType` lit les 512 premiers octets et ne
	// consulte ni le nom, ni ce que le client annonce.
	mime := http.DetectContentType(brut)
	if i := strings.IndexByte(mime, ';'); i > 0 {
		mime = strings.TrimSpace(mime[:i])
	}
	// LES CONTENEURS SONT AMBIGUS PAR NATURE. Ogg porte de l'audio comme de la
	// video, et le renifleur ne peut pas trancher sans lire tout le flux : il
	// rend `application/ogg`. C'est LE cas ou le type annonce sert — pour
	// DEPARTAGER deux entrees deja acceptees, jamais pour en ouvrir une
	// nouvelle. Le contenu a deja decide qu'il s'agissait d'un Ogg ; le client
	// ne fait que dire lequel.
	if mime == "application/ogg" {
		if strings.HasPrefix(mimeAnnonce, "video/") {
			mime = "video/ogg"
		} else {
			mime = "audio/ogg"
		}
	}
	// MEME DEPARTAGE POUR WEBM, ET POUR LA MEME RAISON. Le renifleur voit un
	// conteneur Matroska et rend `video/webm` sans pouvoir savoir s'il contient
	// une piste video. Ici encore le contenu a deja decide — le client ne fait
	// que preciser laquelle des DEUX entrees deja acceptees s'applique.
	if mime == "video/webm" && strings.HasPrefix(mimeAnnonce, "audio/") {
		mime = "audio/webm"
	}
	ext, ok := typesAcceptes[mime]
	if !ok {
		return f, fmt.Errorf("%w : %s", ErrTypeRefuse, mime)
	}

	somme := sha256.Sum256(brut)
	res, err := s.db.Exec(`
		INSERT INTO files(owner_id, path, name, size, sha256, mime, visibility, created_at)
		VALUES(?,?,?,?,?,?, 'local', unixepoch())`,
		owner, "", nom, len(brut), somme[:], mime)
	if err != nil {
		return f, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return f, err
	}

	// Le chemin est derive de l'IDENTIFIANT. Range par mois : un repertoire
	// unique de plusieurs milliers d'entrees ralentit tout, y compris la
	// sauvegarde.
	rel := filepath.Join("media", time.Now().Format("2006/01"), fmt.Sprintf("%d%s", id, ext))
	abs := filepath.Join(s.root, "files", rel)
	if err := os.MkdirAll(filepath.Dir(abs), 0o750); err != nil {
		s.db.Exec(`DELETE FROM files WHERE id = ?`, id)
		return f, err
	}
	// Ecriture sous nom temporaire puis renommage : un depot interrompu ne
	// laisse pas un fichier a moitie ecrit sous un nom qui parait valide.
	tmp := abs + ".partiel"
	if err := os.WriteFile(tmp, brut, 0o640); err != nil {
		s.db.Exec(`DELETE FROM files WHERE id = ?`, id)
		return f, err
	}
	if err := os.Rename(tmp, abs); err != nil {
		os.Remove(tmp)
		s.db.Exec(`DELETE FROM files WHERE id = ?`, id)
		return f, err
	}
	if _, err := s.db.Exec(`UPDATE files SET path = ? WHERE id = ?`, rel, id); err != nil {
		os.Remove(abs)
		s.db.Exec(`DELETE FROM files WHERE id = ?`, id)
		return f, err
	}
	adopteProprietaireDuDossier(abs)

	return Fichier{ID: id, Owner: owner, Path: rel, Name: nom,
		Size: int64(len(brut)), Mime: mime, Created: time.Now().Unix()}, nil
}

// Fichier rend la fiche d'une piece jointe vivante.
func (s *Store) Fichier(id int64) (Fichier, error) {
	var f Fichier
	err := s.db.QueryRow(`
		SELECT id, owner_id, path, name, size, mime, created_at, visibility
		  FROM files WHERE id = ? AND deleted_at IS NULL AND path <> ''`, id).
		Scan(&f.ID, &f.Owner, &f.Path, &f.Name, &f.Size, &f.Mime, &f.Created, &f.Visibility)
	return f, err
}

// MarqueFichiersPublics passe des fichiers en visibilité PUBLIQUE — appelé
// quand leurs refs `/f/NN` apparaissent dans un post PUBLIC d'un fil public
// (#1114) : le média devient alors aussi accessible que le message qui le
// porte. Idempotent, et ne dé-publie jamais (on n'élargit que l'accès, on ne le
// restreint pas ici — un fichier reste public tant que le contenu l'est).
func (s *Store) MarqueFichiersPublics(ids []int64) error {
	if len(ids) == 0 {
		return nil
	}
	ph := make([]string, len(ids))
	args := make([]any, len(ids))
	for i, id := range ids {
		ph[i] = "?"
		args[i] = id
	}
	_, err := s.db.Exec(
		"UPDATE files SET visibility='public' WHERE id IN ("+strings.Join(ph, ",")+") AND visibility <> 'public'",
		args...)
	return err
}

// CheminFichier rend le chemin ABSOLU d'une piece jointe.
//
// Passe par la base : le chemin ne se reconstruit jamais depuis une donnee
// venue de la requete. C'est ce qui rend la traversee de repertoire impossible
// par construction, et non par filtrage.
func (s *Store) CheminFichier(f Fichier) string {
	return filepath.Join(s.root, "files", f.Path)
}

// CheminVignette : ou la vignette d'un fichier est mise en cache (#1020).
//
// A COTE DES FICHIERS, PAS DEDANS : `files/` est sauvegarde et repliqué, une
// vignette se refabrique. Les melanger ferait grossir chaque sauvegarde d'un
// contenu qu'on sait reproduire a partir de ce qu'elle contient deja.
func (s *Store) CheminVignette(id int64) string {
	return filepath.Join(s.root, "vignettes", strconv.FormatInt(id, 10)+".jpg")
}

// Fichiers rend les depots d'un membre, les plus recents d'abord.
func (s *Store) Fichiers(owner int64, borne int) ([]Fichier, error) {
	if borne <= 0 || borne > 200 {
		borne = 50
	}
	rows, err := s.db.Query(`
		SELECT id, owner_id, path, name, size, mime, created_at
		  FROM files WHERE owner_id = ? AND deleted_at IS NULL AND path <> ''
		 ORDER BY created_at DESC LIMIT ?`, owner, borne)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Fichier
	for rows.Next() {
		var f Fichier
		if err := rows.Scan(&f.ID, &f.Owner, &f.Path, &f.Name, &f.Size, &f.Mime, &f.Created); err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// SupprimeFichier retire un depot — SEULEMENT le sien.
//
// Sans cette garde, connaitre un identifiant suffirait a effacer la piece
// jointe de quelqu'un d'autre.
func (s *Store) SupprimeFichier(owner, id int64) error {
	f, err := s.Fichier(id)
	if err != nil {
		return err
	}
	if f.Owner != owner {
		return ErrRefuse
	}
	if _, err := s.db.Exec(
		`UPDATE files SET deleted_at = unixepoch() WHERE id = ?`, id); err != nil {
		return err
	}
	// Le fichier part du disque : le garder ferait grossir la sauvegarde avec
	// ce que l'on a justement demande d'effacer.
	return os.Remove(s.CheminFichier(f))
}

// PoseAvatar attache une image au compte, ou la retire (id = 0).
//
// L'avatar est une REFERENCE vers `files`, pas une copie ni un chemin : une
// seconde verite se desynchronise, et un fichier supprime laisserait un chemin
// mort dans `users`.
func (s *Store) PoseAvatar(user, fichier int64) error {
	if fichier == 0 {
		_, err := s.db.Exec(`UPDATE users SET avatar_file = NULL WHERE id = ?`, user)
		return err
	}
	// ON NE POSE QUE SON PROPRE FICHIER. Sans cette garde, connaitre un
	// identifiant suffirait a s'attribuer l'image de quelqu'un d'autre.
	f, err := s.Fichier(fichier)
	if err != nil {
		return err
	}
	if f.Owner != user {
		return ErrRefuse
	}
	_, err = s.db.Exec(`UPDATE users SET avatar_file = ? WHERE id = ?`, fichier, user)
	return err
}

// Avatar rend l'identifiant de l'image d'un compte, ou 0 s'il n'en a pas.
func (s *Store) Avatar(user int64) int64 {
	var id int64
	s.db.QueryRow(`
		SELECT COALESCE(u.avatar_file, 0) FROM users u
		  LEFT JOIN files f ON f.id = u.avatar_file AND f.deleted_at IS NULL
		 WHERE u.id = ? AND f.id IS NOT NULL`, user).Scan(&id)
	return id
}

// TousFichiers rend les depots de TOUS les membres, les plus recents d'abord.
//
// LA BIBLIOTHEQUE EST COMMUNE, pas personnelle (#1020). « Les fichiers vivent a
// cote des messages » : un message est lu par tout le salon, sa piece jointe
// aussi. Une bibliotheque filtree par proprietaire aurait montre une page vide a
// tous ceux qui n'ont rien depose — c'est-a-dire a la plupart.
//
// Le nom du deposant accompagne chaque entree : savoir QUI a depose est ce qui
// permet de demander le contexte, et sans quoi une bibliotheque commune devient
// un tas anonyme.
func (s *Store) TousFichiers(borne int) ([]FichierPublie, error) {
	if borne <= 0 || borne > 500 {
		borne = 100
	}
	rows, err := s.db.Query(`
		SELECT f.id, f.owner_id, f.path, f.name, f.size, f.mime, f.created_at,
		       COALESCE(u.display_name, u.handle, '?')
		  FROM files f
		  LEFT JOIN users u ON u.id = f.owner_id
		 WHERE f.deleted_at IS NULL AND f.path <> ''
		 ORDER BY f.created_at DESC, f.id DESC
		 LIMIT ?`, borne)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []FichierPublie
	for rows.Next() {
		var f FichierPublie
		if err := rows.Scan(&f.ID, &f.Owner, &f.Path, &f.Name, &f.Size,
			&f.Mime, &f.Created, &f.Deposant); err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// FichierPublie : une piece jointe telle que la bibliotheque l'affiche.
type FichierPublie struct {
	Fichier
	Deposant string
}
