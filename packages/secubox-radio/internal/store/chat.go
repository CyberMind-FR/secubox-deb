package store

import (
	"errors"
	"strings"
	"time"
	"unicode/utf8"
)

// LongueurMaxChat borne une phrase.
//
// Le chat accompagne l'ecoute ; il n'est pas un forum. Une borne basse est ici
// une decision d'usage autant qu'une protection : au-dela, on ouvre un fil
// dans le BBS.
const LongueurMaxChat = 500

// FenetreAntiFlot et MaxParFenetre : un chat sans limite se fait noyer par le
// premier script venu, et il suffit d'un doigt reste appuye.
const (
	FenetreAntiFlot = 30 * time.Second
	MaxParFenetre   = 8
)

var (
	ErrPhraseVide = errors.New("phrase vide")
	ErrTropVite   = errors.New("trop de messages — laissez souffler l'antenne")
)

// Phrase : une ligne du chat.
type Phrase struct {
	ID      int64
	UserID  int64
	Pseudo  string
	Corps   string
	DitLe   int64
	PisteID int64
}

// Dis ajoute une phrase.
//
// LE CORPS EST RANGE, PAS FILTRE. On coupe les blancs et on borne la longueur ;
// on ne tente pas de nettoyer un balisage qui n'a pas lieu d'etre — l'affichage
// echappe, c'est la sa responsabilite. Un « nettoyage » ici donnerait
// l'illusion que l'affichage peut se relacher.
func (s *Store) Dis(userID int64, pseudo, corps string, pisteID int64, maintenant time.Time) (Phrase, error) {
	corps = strings.TrimSpace(corps)
	if corps == "" {
		return Phrase{}, ErrPhraseVide
	}
	// On coupe en RUNES et non en octets : couper au milieu d'un caractere
	// accentue produirait une sequence invalide.
	if utf8.RuneCountInString(corps) > LongueurMaxChat {
		r := []rune(corps)
		corps = string(r[:LongueurMaxChat])
	}
	var n int
	if err := s.db.QueryRow(
		`SELECT COUNT(*) FROM chat WHERE user_id = ? AND dit_le > ?`,
		userID, maintenant.Add(-FenetreAntiFlot).Unix()).Scan(&n); err != nil {
		return Phrase{}, err
	}
	if n >= MaxParFenetre {
		return Phrase{}, ErrTropVite
	}
	var pisteN any
	if pisteID > 0 {
		pisteN = pisteID
	}
	res, err := s.db.Exec(
		`INSERT INTO chat (user_id, pseudo, corps, dit_le, piste_id) VALUES (?,?,?,?,?)`,
		userID, pseudo, corps, maintenant.Unix(), pisteN)
	if err != nil {
		return Phrase{}, err
	}
	id, _ := res.LastInsertId()
	return Phrase{ID: id, UserID: userID, Pseudo: pseudo, Corps: corps,
		DitLe: maintenant.Unix(), PisteID: pisteID}, nil
}

// Depuis rend les phrases posterieures a `apres`, dans l'ordre.
//
// `apres` PLUTOT QU'UN HORODATAGE : deux phrases dites la meme seconde ont un
// horodatage identique, et l'une des deux serait perdue ou repetee. Un
// identifiant croissant n'a pas ce defaut.
//
// La borne existe pour le premier appel, ou `apres` vaut zero : sans elle, un
// nouvel arrivant recevrait toute l'histoire du chat.
func (s *Store) Depuis(apres int64, borne int) ([]Phrase, error) {
	if borne <= 0 || borne > 200 {
		borne = 50
	}
	// On prend les plus RECENTES puis on remet dans l'ordre : demander les
	// `borne` premieres apres `apres` donnerait le debut de l'histoire a qui
	// arrive, pas la conversation en cours.
	rows, err := s.db.Query(
		`SELECT id, user_id, pseudo, corps, dit_le, COALESCE(piste_id,0)
		   FROM chat WHERE id > ? ORDER BY id DESC LIMIT ?`, apres, borne)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Phrase
	for rows.Next() {
		var p Phrase
		if err := rows.Scan(&p.ID, &p.UserID, &p.Pseudo, &p.Corps, &p.DitLe, &p.PisteID); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out, nil
}

// PurgeChat efface les phrases anciennes.
//
// Le chat accompagne une ecoute, il n'archive rien : garder un an de « salut »
// ferait grossir la base sans que personne n'y revienne. Le BBS est la pour ce
// qui merite d'etre conserve.
func (s *Store) PurgeChat(avant time.Time) (int64, error) {
	res, err := s.db.Exec(`DELETE FROM chat WHERE dit_le < ?`, avant.Unix())
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return n, nil
}
