package store

import (
	"bufio"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"
)

type Role string

const (
	RoleSysop  Role = "sysop"
	RoleMember Role = "member"
	RoleGuest  Role = "guest"
)

const sessionTTL = 30 * 24 * time.Hour
const inviteTTL = 14 * 24 * time.Hour

var ErrRefuse = errors.New("refuse")

// ── Comptes ─────────────────────────────────────────────────────────────

func (s *Store) CreateUser(handle, display string, role Role) (int64, error) {
	res, err := s.db.Exec(
		`INSERT INTO users(handle, display_name, role, created_at)
		 VALUES(?,?,?,unixepoch())`, handle, display, string(role))
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// DisableUser coupe l'acces SANS supprimer le compte.
//
// Supprimer emporterait l'attribution des ecrits et trouerait les fils ; la
// desactivation laisse la conversation lisible. Les sessions en cours sont
// revoquees : sinon « desactive » ne voudrait rien dire jusqu'a expiration.
func (s *Store) DisableUser(id int64) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`UPDATE users SET disabled_at = unixepoch() WHERE id = ?`, id); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM sessions WHERE user_id = ?`, id); err != nil {
		return err
	}
	return tx.Commit()
}

// ── Sessions ────────────────────────────────────────────────────────────

// NewSession rend le jeton EN CLAIR — la seule fois ou il existe chez nous.
// Seule son empreinte est conservee : une base lue par un tiers ne doit pas
// lui permettre de se faire passer pour un membre.
func (s *Store) NewSession(userID int64, ip, ua string) (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	sum := sha256.Sum256([]byte(token))
	_, err := s.db.Exec(
		`INSERT INTO sessions(token_sha256, user_id, created_at, expires_at, ip, user_agent)
		 VALUES(?,?,unixepoch(),unixepoch()+?,?,?)`,
		sum[:], userID, int64(sessionTTL/time.Second), ip, ua)
	if err != nil {
		return "", err
	}
	return token, nil
}

// UserBySession valide un jeton. Expiration ET desactivation sont verifiees
// dans la MEME requete : un compte coupe ne doit pas survivre par sa session.
func (s *Store) UserBySession(token string) (int64, error) {
	sum := sha256.Sum256([]byte(token))
	var id int64
	err := s.db.QueryRow(`
		SELECT u.id FROM sessions s
		JOIN users u ON u.id = s.user_id
		WHERE s.token_sha256 = ?
		  AND s.expires_at > unixepoch()
		  AND u.disabled_at IS NULL`, sum[:]).Scan(&id)
	if err != nil {
		return 0, ErrRefuse
	}
	return id, nil
}

// ── Invitations ─────────────────────────────────────────────────────────

// NewInvite emet une invitation attribuee a son emetteur.
func (s *Store) NewInvite(issuedBy int64) (string, error) {
	return s.NewInviteFor(issuedBy, "")
}

// NewInviteFor emet une invitation, avec un libelle indicatif et un emetteur
// FACULTATIF.
//
// L'emetteur est facultatif parce que `bbsctl` tourne sans session : il n'a
// personne a qui attribuer l'invitation. Le premier jet passait 0 — qui n'est
// l'identifiant de personne — et se heurtait a la clef etrangere sans que le
// message n'explique rien.
//
// Le libelle ne LIE PAS l'invitation a quelqu'un : quiconque detient le code
// peut s'en servir. Il sert a savoir laquelle revoquer, sans quoi une console
// qui annonce « 3 invitations ouvertes » ne permet de decider rien du tout.
func (s *Store) NewInviteFor(issuedBy int64, label string) (string, error) {
	var emetteur any
	if issuedBy > 0 {
		// UN COMPTE FERME N'INVITE PAS. Depuis #1008 tout membre peut emettre
		// une invitation ; fermer un compte doit donc aussi lui retirer ce
		// pouvoir, sans quoi la fermeture ne fermerait qu'une porte sur deux.
		//
		// La vue s'appuie deja sur l'impossibilite d'etre connecte avec un
		// compte ferme ; ce refus est la seconde barriere, celle qui tient si
		// la premiere cede.
		var ouvert bool
		if err := s.db.QueryRow(
			`SELECT disabled_at IS NULL FROM users WHERE id = ?`, issuedBy).Scan(&ouvert); err != nil {
			return "", err
		}
		if !ouvert {
			return "", ErrRefuse
		}
		emetteur = issuedBy
	}
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	code := base64.RawURLEncoding.EncodeToString(raw)
	sum := sha256.Sum256([]byte(code))
	_, err := s.db.Exec(
		`INSERT INTO invites(code_sha256, issued_by, issued_at, expires_at, label)
		 VALUES(?,?,unixepoch(),unixepoch()+?,?)`,
		sum[:], emetteur, int64(inviteTTL/time.Second), nilSiVide(label))
	if err != nil {
		return "", err
	}
	return code, nil
}

// RedeemInvite consomme une invitation et cree le compte.
//
// Consommation et creation dans UNE transaction : deux inscriptions
// simultanees avec le meme code doivent en voir une seule aboutir. La clause
// `used_at IS NULL` dans l'UPDATE fait office de verrou — c'est elle qui rend
// l'invitation reellement a usage unique, pas la lecture prealable.
func (s *Store) RedeemInvite(code, handle, display string) (int64, error) {
	sum := sha256.Sum256([]byte(code))
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	res, err := tx.Exec(`
		UPDATE invites SET used_at = unixepoch()
		WHERE code_sha256 = ? AND used_at IS NULL AND expires_at > unixepoch()`, sum[:])
	if err != nil {
		return 0, err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return 0, fmt.Errorf("%w: invitation inconnue, expiree ou deja utilisee", ErrRefuse)
	}

	r, err := tx.Exec(
		`INSERT INTO users(handle, display_name, role, created_at)
		 VALUES(?,?,?,unixepoch())`, handle, display, string(RoleMember))
	if err != nil {
		return 0, err
	}
	id, err := r.LastInsertId()
	if err != nil {
		return 0, err
	}
	if _, err := tx.Exec(`UPDATE invites SET used_by = ? WHERE code_sha256 = ?`, id, sum[:]); err != nil {
		return 0, err
	}
	return id, tx.Commit()
}

// ── Mots de passe, HORS de la base ──────────────────────────────────────
//
// Fichier a part, 0600 : l'index est cense etre jetable et copiable. Melanger
// les deux ferait qu'un rsync du contenu emporte les identifiants.

type Auth struct {
	path string
	mu   sync.Mutex
	m    map[int64]string
	// Empreinte du fichier tel qu'on l'a lu. LE DAEMON N'EST PAS SEUL A
	// ECRIRE : `bbsctl` tourne dans un autre processus et reecrit le meme
	// fichier — c'est le chemin de secours quand plus personne ne peut entrer.
	//
	// Sans cette empreinte, deux pannes silencieuses, toutes deux observees :
	// la reinitialisation restait sans effet jusqu'au redemarrage, et la
	// premiere ecriture du service reecrivait le fichier depuis sa carte
	// perimee, EFFACANT le mot de passe que la console venait de poser.
	mtime  time.Time
	taille int64
}

// rechargeSiModifie relit le fichier quand un autre processus l'a change.
//
// La comparaison porte sur la date ET la taille : deux ecritures dans la meme
// seconde peuvent partager la date, mais rarement la taille — et un rechargement
// de trop ne coute qu'une lecture de quelques centaines d'octets.
func (a *Auth) rechargeSiModifie() {
	fi, err := os.Stat(a.path)
	if err != nil {
		return // fichier absent : rien a recharger, la carte en memoire fait foi
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if fi.ModTime().Equal(a.mtime) && fi.Size() == a.taille {
		return
	}
	m, err := litPasswd(a.path)
	if err != nil {
		return // fichier illisible : mieux vaut la carte precedente que rien
	}
	a.m, a.mtime, a.taille = m, fi.ModTime(), fi.Size()
}

// litPasswd lit le fichier de hashes. Extrait de OpenAuth pour etre partage
// avec le rechargement : deux analyseurs du meme format finiraient par diverger.
func litPasswd(path string) (map[int64]string, error) {
	m := map[int64]string{}
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return m, nil
		}
		return nil, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		id, rec, ok := strings.Cut(sc.Text(), ":")
		if !ok {
			continue
		}
		var n int64
		fmt.Sscanf(id, "%d", &n)
		m[n] = rec
	}
	return m, sc.Err()
}

func OpenAuth(path string) (*Auth, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	m, err := litPasswd(path)
	if err != nil {
		return nil, err
	}
	a := &Auth{path: path, m: m}
	if fi, err := os.Stat(path); err == nil {
		a.mtime, a.taille = fi.ModTime(), fi.Size()
	}
	return a, nil
}

func (a *Auth) SetPassword(userID int64, password string) error {
	// AVANT D'ECRIRE : sans cela, `flush` reecrirait le fichier entier depuis
	// une carte perimee et effacerait ce qu'un autre processus vient d'y poser.
	a.rechargeSiModifie()
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return err
	}
	// Sel PAR COMPTE : sans lui, deux membres au meme mot de passe ont le meme
	// hash, et la fuite du fichier revele qui partage quoi.
	key := argon2.IDKey([]byte(password), salt, 2, 64*1024, 2, 32)
	a.mu.Lock()
	a.m[userID] = "argon2id$" + hex.EncodeToString(salt) + "$" + hex.EncodeToString(key)
	a.mu.Unlock()
	return a.flush()
}

// ResetPassword pose un mot de passe SANS demander l'ancien — c'est le geste du
// sysop pour quelqu'un qui ne peut plus entrer.
//
// Il passe par la MEME politique de longueur que le libre-service. Appeler
// `SetPassword` directement depuis la console aurait ouvert une porte derobee
// dans la politique, sur le chemin qu'on emprunte justement dans l'urgence.
//
// Fermer les sessions n'est PAS fait ici : la console le fait, parce qu'elle
// seule sait s'il s'agit d'un depannage (le titulaire est present) ou d'une
// reprise en main (il faut tout couper). Le magasin ne peut pas trancher.
func (a *Auth) ResetPassword(userID int64, nouveau string) error {
	// AUCUNE LONGUEUR MINIMALE — retiree sur demande de l'exploitant.
	//
	// Seul le mot de passe VIDE reste refuse, et ce n'est pas une limite de
	// longueur : c'est la difference entre avoir un mot de passe et ne pas en
	// avoir. L'accepter creerait un compte ou la chaine vide authentifie.
	if nouveau == "" {
		return errors.New("mot de passe vide")
	}
	return a.SetPassword(userID, nouveau)
}

func (a *Auth) Verify(userID int64, password string) bool {
	a.rechargeSiModifie()
	a.mu.Lock()
	rec, ok := a.m[userID]
	a.mu.Unlock()
	if !ok {
		return false
	}
	parts := strings.Split(rec, "$")
	if len(parts) != 3 || parts[0] != "argon2id" {
		return false
	}
	salt, err1 := hex.DecodeString(parts[1])
	want, err2 := hex.DecodeString(parts[2])
	if err1 != nil || err2 != nil {
		return false
	}
	got := argon2.IDKey([]byte(password), salt, 2, 64*1024, 2, 32)
	// Comparaison a temps constant : une comparaison naive fuit la longueur du
	// prefixe correct, donc le hash, octet par octet.
	return subtle.ConstantTimeCompare(got, want) == 1
}

func (a *Auth) raw(userID int64) string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.m[userID]
}

func (a *Auth) flush() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	var b strings.Builder
	for id, rec := range a.m {
		fmt.Fprintf(&b, "%d:%s\n", id, rec)
	}
	// Ecriture atomique : une coupure en plein write laisserait un fichier de
	// hashes tronque, donc des comptes qui ne peuvent plus se connecter.
	tmp := a.path + ".tmp"
	if err := os.WriteFile(tmp, []byte(b.String()), 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, a.path); err != nil {
		return err
	}
	// On note NOTRE propre ecriture : sans cela le prochain acces la prendrait
	// pour un changement venu d'ailleurs et relirait inutilement.
	if fi, err := os.Stat(a.path); err == nil {
		a.mtime, a.taille = fi.ModTime(), fi.Size()
	}
	return adopteProprietaireDuDossier(a.path)
}

// UserByHandle resout un pseudonyme. Ne rend JAMAIS un compte desactive.
func (s *Store) UserByHandle(handle string) (int64, error) {
	var id int64
	err := s.db.QueryRow(
		`SELECT id FROM users WHERE handle = ? AND disabled_at IS NULL`, handle).Scan(&id)
	return id, err
}

// UserInfo : ce qu'il faut pour afficher un bandeau, rien de plus.
type UserInfo struct {
	ID        int64
	Handle    string
	Display   string
	Role      Role
	LastLogin int64
}

func (s *Store) UserInfo(id int64) (UserInfo, error) {
	var u UserInfo
	var role string
	err := s.db.QueryRow(
		`SELECT id, handle, display_name, role, COALESCE(last_login_at,0) FROM users
		 WHERE id = ? AND disabled_at IS NULL`, id).
		Scan(&u.ID, &u.Handle, &u.Display, &role, &u.LastLogin)
	u.Role = Role(role)
	return u, err
}

// CloseSession revoque une session precise (deconnexion).
func (s *Store) CloseSession(token string) error {
	sum := sha256.Sum256([]byte(token))
	_, err := s.db.Exec(`DELETE FROM sessions WHERE token_sha256 = ?`, sum[:])
	return err
}

// ChangePassword remplace un mot de passe APRES verification de l'ancien.
//
// La session prouve qu'on est entre ; elle ne prouve pas qu'on est le
// titulaire. Sans cette verification, un navigateur laisse ouvert suffit a
// verrouiller le compte de son proprietaire.
func (a *Auth) ChangePassword(userID int64, ancien, nouveau string) error {
	if !a.Verify(userID, ancien) {
		return errors.New("mot de passe actuel incorrect")
	}
	// AUCUNE LONGUEUR MINIMALE — retiree sur demande de l'exploitant.
	//
	// Seul le mot de passe VIDE reste refuse, et ce n'est pas une limite de
	// longueur : c'est la difference entre avoir un mot de passe et ne pas en
	// avoir. L'accepter creerait un compte ou la chaine vide authentifie.
	if nouveau == "" {
		return errors.New("nouveau mot de passe vide")
	}
	if nouveau == ancien {
		return errors.New("le nouveau mot de passe est identique a l'ancien")
	}
	return a.SetPassword(userID, nouveau)
}

// RevokeOtherSessions ferme toutes les sessions SAUF celle qui agit.
//
// On change son mot de passe surtout quand on craint qu'il ait fuite. Laisser
// vivre les sessions ouvertes ailleurs viderait le geste de son sens : celui
// qui detient le mot de passe vole resterait connecte.
//
// La session courante SURVIT : la revoquer deconnecterait l'utilisateur au
// moment ou il vient de faire ce qu'il fallait.
func (s *Store) RevokeOtherSessions(userID int64, garder string) error {
	sum := sha256.Sum256([]byte(garder))
	_, err := s.db.Exec(
		`DELETE FROM sessions WHERE user_id = ? AND token_sha256 <> ?`, userID, sum[:])
	return err
}

// NoteLogin enregistre une connexion reussie.
//
// UNE seule adresse est conservee, pas un historique : garder la trace de tous
// les acces d'un membre serait une surveillance que personne n'a demandee, et
// ferait de cette base une cible.
func (s *Store) NoteLogin(userID int64, ip string) error {
	if i := strings.LastIndexByte(ip, ':'); i > 0 && strings.Count(ip, ":") == 1 {
		ip = ip[:i] // retirer le port, sans casser une adresse IPv6
	}
	_, err := s.db.Exec(
		`UPDATE users SET last_login_at = unixepoch(), last_login_ip = ? WHERE id = ?`,
		ip, userID)
	return err
}

// EnableUser reactive un compte. Desactiver doit rester REVERSIBLE, sinon
// personne n'ose desactiver et les comptes s'accumulent.
func (s *Store) EnableUser(userID int64) error {
	_, err := s.db.Exec(`UPDATE users SET disabled_at = NULL WHERE id = ?`, userID)
	return err
}

// Compte : ce qu'une console d'administration a besoin de montrer.
// Aucun element d'authentification n'y figure, meme tronque.
type Compte struct {
	ID        int64
	Handle    string
	Display   string
	Role      Role
	Disabled  bool
	LastLogin int64
	LastIP    string
	Sessions  int
	// Source : 'local' (mot de passe verifie ici) ou 'secubox' (delegue a
	// secubox-auth). Le BBS ne copie AUCUN mot de passe : reinitialiser celui
	// d'un compte delegue n'aurait aucun effet a la connexion, puisque la
	// verification part ailleurs. La console doit donc le dire, pas l'offrir.
	Source    string
	CreatedAt int64
}

func (s *Store) Users() ([]Compte, error) {
	rows, err := s.db.Query(`SELECT u.id, u.handle, u.display_name, u.role,
		u.disabled_at IS NOT NULL, COALESCE(u.last_login_at,0), COALESCE(u.last_login_ip,''),
		(SELECT count(*) FROM sessions x WHERE x.user_id = u.id AND x.expires_at > unixepoch()),
		u.created_at, u.auth_source
		FROM users u ORDER BY u.disabled_at IS NOT NULL, u.handle`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Compte
	for rows.Next() {
		var c Compte
		var role string
		if err := rows.Scan(&c.ID, &c.Handle, &c.Display, &role, &c.Disabled,
			&c.LastLogin, &c.LastIP, &c.Sessions, &c.CreatedAt, &c.Source); err != nil {
			return nil, err
		}
		c.Role = Role(role)
		out = append(out, c)
	}
	return out, rows.Err()
}

// nilSiVide rend NULL plutot qu'une chaine vide : en base, « inconnu » et
// « vide » ne sont pas la meme chose, et une colonne pleine de chaines vides
// empeche de distinguer les deux plus tard.
func nilSiVide(s string) any {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	return strings.TrimSpace(s)
}

// Invitation : ce qu'une console peut montrer. Le CODE N'Y EST PAS — seule son
// empreinte est conservee, et le rendre ici reviendrait a la garder en clair.
type Invitation struct {
	Code      string // toujours vide : rappel explicite que le code n'est pas conservable
	Label     string
	IssuedAt  int64
	ExpiresAt int64
	Used      bool
	// Emetteur : QUI a invite. Vide pour les invitations emises par `bbsctl`,
	// qui tourne sans session.
	//
	// Depuis #1008 tout membre peut inviter, sans quota. La tracabilite de
	// l'emetteur est la contrepartie de ce choix : sans elle, une inscription
	// en cascade — un compte en invite dix, chacun en invite dix — serait
	// indebrouillable, et le sysop n'aurait aucun moyen de savoir par ou la
	// porte s'est ouverte.
	Emetteur string
	// Beneficiaire : qui s'en est servi. Ferme la chaine : on peut suivre le
	// fil de A invite B invite C.
	Beneficiaire string
}

func (s *Store) Invites() ([]Invitation, error) {
	rows, err := s.db.Query(`SELECT COALESCE(i.label,''), i.issued_at, i.expires_at,
		i.used_at IS NOT NULL, COALESCE(e.handle,''), COALESCE(b.handle,'')
		FROM invites i
		LEFT JOIN users e ON e.id = i.issued_by
		LEFT JOIN users b ON b.id = i.used_by
		ORDER BY i.issued_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Invitation
	for rows.Next() {
		var i Invitation
		if err := rows.Scan(&i.Label, &i.IssuedAt, &i.ExpiresAt, &i.Used,
			&i.Emetteur, &i.Beneficiaire); err != nil {
			return nil, err
		}
		out = append(out, i)
	}
	return out, rows.Err()
}
