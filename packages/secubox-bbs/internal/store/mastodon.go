package store

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"errors"
	"strings"
	"time"
)

var (
	// ErrPasDeCompteMastodon : ce membre n'a lie aucun compte. Ce n'est pas une
	// anomalie — c'est l'etat par defaut, et le seul acceptable tant que
	// l'aller-retour OAuth n'a pas eu lieu.
	ErrPasDeCompteMastodon = errors.New("aucun compte Mastodon lie a ce membre")
	// ErrEtatMastodon : retour d'autorisation inconnu, deja servi, ou perime.
	ErrEtatMastodon = errors.New("retour d'autorisation invalide ou expire")
	// ErrIdentitePrise : ce compte fediverse est deja lie a un AUTRE membre.
	ErrIdentitePrise = errors.New("ce compte Mastodon est deja lie a un autre membre")
)

// DureeEtatMastodon borne l'aller-retour. Dix minutes suffisent largement a
// s'authentifier chez soi ; au-dela, l'etat abandonne cesse d'etre une porte.
const DureeEtatMastodon = 10 * time.Minute

// CompteMastodon : le lien personnel d'un membre.
//
// LE JETON N'EST PAS DANS CETTE STRUCTURE. Elle est faite pour etre affichee ;
// tout ce qui la remplit finit tot ou tard dans un gabarit. Le jeton se
// demande separement, par `JetonMastodon`, et seul l'appel a l'instance le lit.
type CompteMastodon struct {
	Instance string
	Acct     string
	CompteID string
	Portee   string
	LieLe    int64
}

// NormaliseInstance ramene ce que tape un membre a un hote comparable.
//
// SANS CELA, `https://Exemple.fr/` et `exemple.fr` seraient deux instances
// distinctes : deux applications OAuth enregistrees, et un index d'unicite qui
// ne protege plus rien.
func NormaliseInstance(brut string) string {
	s := strings.TrimSpace(brut)
	s = strings.TrimPrefix(s, "https://")
	s = strings.TrimPrefix(s, "http://")
	s = strings.TrimSuffix(s, "/")
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	// L'@ d'un identifiant complet (@moi@exemple.fr) : on ne garde que l'hote.
	if i := strings.LastIndex(s, "@"); i >= 0 {
		s = s[i+1:]
	}
	return strings.ToLower(s)
}

// AppMastodon rend l'application enregistree aupres d'une instance.
func (s *Store) AppMastodon(instance string) (idClient, secret string, err error) {
	err = s.db.QueryRow(
		`SELECT client_id, client_secret FROM mastodon_apps WHERE instance = ?`,
		NormaliseInstance(instance)).Scan(&idClient, &secret)
	if errors.Is(err, sql.ErrNoRows) {
		return "", "", nil // pas encore enregistree : a l'appelant de le faire
	}
	return idClient, secret, err
}

// PoseAppMastodon retient l'application enregistree aupres d'une instance.
func (s *Store) PoseAppMastodon(instance, idClient, secret string) error {
	_, err := s.db.Exec(
		`INSERT INTO mastodon_apps (instance, client_id, client_secret, cree_le)
		 VALUES (?, ?, ?, ?)
		 ON CONFLICT (instance) DO UPDATE
		   SET client_id = excluded.client_id, client_secret = excluded.client_secret`,
		NormaliseInstance(instance), idClient, secret, time.Now().Unix())
	return err
}

// NouvelEtatMastodon ouvre un aller-retour d'autorisation pour CE membre.
func (s *Store) NouvelEtatMastodon(userID int64, instance string) (string, error) {
	if userID <= 0 {
		return "", ErrEtatMastodon
	}
	brut := make([]byte, 24)
	if _, err := rand.Read(brut); err != nil {
		return "", err
	}
	etat := base64.RawURLEncoding.EncodeToString(brut)
	sum := sha256.Sum256([]byte(etat))
	_, err := s.db.Exec(
		`INSERT INTO mastodon_etats (etat_sha256, user_id, instance, cree_le)
		 VALUES (?, ?, ?, ?)`,
		sum[:], userID, NormaliseInstance(instance), time.Now().Unix())
	if err != nil {
		return "", err
	}
	return etat, nil
}

// ConsommeEtatMastodon verifie un retour d'autorisation et rend a QUI il
// appartient.
//
// L'APPELANT DOIT COMPARER LE MEMBRE RENDU A CELUI DE LA SESSION. Cette
// fonction dit « cet etat a ete ouvert par le membre N » ; elle ne peut pas
// savoir qui presente le retour. C'est la comparaison des deux qui empeche
// d'attacher un compte dans la session d'un autre.
func (s *Store) ConsommeEtatMastodon(etat string) (userID int64, instance string, err error) {
	if etat == "" {
		return 0, "", ErrEtatMastodon
	}
	sum := sha256.Sum256([]byte(etat))
	var cree int64
	var servi sql.NullInt64
	err = s.db.QueryRow(
		`SELECT user_id, instance, cree_le, servi_le FROM mastodon_etats
		  WHERE etat_sha256 = ?`, sum[:]).Scan(&userID, &instance, &cree, &servi)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, "", ErrEtatMastodon
	}
	if err != nil {
		return 0, "", err
	}
	// UNE SEULE FOIS, ET PAS APRES L'ECHEANCE. Un retour rejoue permettrait de
	// re-attacher un compte apres que le membre l'a delie.
	if servi.Valid || time.Now().After(time.Unix(cree, 0).Add(DureeEtatMastodon)) {
		return 0, "", ErrEtatMastodon
	}
	if _, err := s.db.Exec(
		`UPDATE mastodon_etats SET servi_le = ? WHERE etat_sha256 = ?`,
		time.Now().Unix(), sum[:]); err != nil {
		return 0, "", err
	}
	return userID, instance, nil
}

// LieCompteMastodon attache un compte fediverse a un membre.
//
// N'EST APPELEE QU'APRES UN ALLER-RETOUR OAUTH REUSSI. C'est le seul chemin qui
// mene ici : aucun rapprochement ne se fait sur l'egalite des pseudonymes.
func (s *Store) LieCompteMastodon(userID int64, c CompteMastodon, jeton string) error {
	if userID <= 0 || jeton == "" || c.CompteID == "" {
		return errors.New("lien Mastodon incomplet")
	}
	inst := NormaliseInstance(c.Instance)

	// L'IDENTITE EST-ELLE DEJA PRISE PAR UN AUTRE ? L'index d'unicite le dirait
	// aussi, mais par une erreur de contrainte illisible pour le membre.
	var proprio int64
	err := s.db.QueryRow(
		`SELECT user_id FROM mastodon_comptes WHERE instance = ? AND compte_id = ?`,
		inst, c.CompteID).Scan(&proprio)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if err == nil && proprio != userID {
		return ErrIdentitePrise
	}

	_, err = s.db.Exec(
		`INSERT INTO mastodon_comptes
		   (user_id, instance, acct, compte_id, jeton, portee, lie_le)
		 VALUES (?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT (user_id) DO UPDATE SET
		   instance = excluded.instance, acct = excluded.acct,
		   compte_id = excluded.compte_id, jeton = excluded.jeton,
		   portee = excluded.portee, lie_le = excluded.lie_le`,
		userID, inst, c.Acct, c.CompteID, jeton, c.Portee, time.Now().Unix())
	return err
}

// CompteMastodonDe rend le lien d'un membre, SANS le jeton.
func (s *Store) CompteMastodonDe(userID int64) (CompteMastodon, error) {
	var c CompteMastodon
	if userID <= 0 {
		return c, ErrPasDeCompteMastodon
	}
	err := s.db.QueryRow(
		`SELECT instance, acct, compte_id, portee, lie_le FROM mastodon_comptes
		  WHERE user_id = ?`, userID).
		Scan(&c.Instance, &c.Acct, &c.CompteID, &c.Portee, &c.LieLe)
	if errors.Is(err, sql.ErrNoRows) {
		return c, ErrPasDeCompteMastodon
	}
	return c, err
}

// JetonMastodon rend le jeton d'un membre — le SEUL point qui l'expose.
//
// Separe de `CompteMastodonDe` a dessein : ce qui s'affiche et ce qui autorise
// ne doivent pas voyager dans la meme structure, sinon le jeton finit un jour
// dans un gabarit par simple commodite.
func (s *Store) JetonMastodon(userID int64) (jeton, instance string, err error) {
	if userID <= 0 {
		return "", "", ErrPasDeCompteMastodon
	}
	err = s.db.QueryRow(
		`SELECT jeton, instance FROM mastodon_comptes WHERE user_id = ?`, userID).
		Scan(&jeton, &instance)
	if errors.Is(err, sql.ErrNoRows) {
		return "", "", ErrPasDeCompteMastodon
	}
	return jeton, instance, err
}

// DelieCompteMastodon retire le lien cote BBS.
//
// CE N'EST QUE LA MOITIE DU GESTE, et l'interface doit le dire : le jeton cesse
// d'etre utilisable ici, mais l'autorisation reste inscrite chez Mastodon tant
// que le membre ne l'y revoque pas. Laisser croire l'inverse serait pire que de
// ne rien proposer.
func (s *Store) DelieCompteMastodon(userID int64) error {
	_, err := s.db.Exec(`DELETE FROM mastodon_comptes WHERE user_id = ?`, userID)
	return err
}

// PurgeEtatsMastodon efface les allers-retours abandonnes.
func (s *Store) PurgeEtatsMastodon() error {
	_, err := s.db.Exec(
		`DELETE FROM mastodon_etats WHERE cree_le < ?`,
		time.Now().Add(-DureeEtatMastodon).Unix())
	return err
}
