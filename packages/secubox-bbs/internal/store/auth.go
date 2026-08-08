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

func (s *Store) NewInvite(issuedBy int64) (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	code := base64.RawURLEncoding.EncodeToString(raw)
	sum := sha256.Sum256([]byte(code))
	_, err := s.db.Exec(
		`INSERT INTO invites(code_sha256, issued_by, issued_at, expires_at)
		 VALUES(?,?,unixepoch(),unixepoch()+?)`,
		sum[:], issuedBy, int64(inviteTTL/time.Second))
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
}

func OpenAuth(path string) (*Auth, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	a := &Auth{path: path, m: map[int64]string{}}
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return a, nil
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
		a.m[n] = rec
	}
	return a, sc.Err()
}

func (a *Auth) SetPassword(userID int64, password string) error {
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

func (a *Auth) Verify(userID int64, password string) bool {
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
	return os.Rename(tmp, a.path)
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
	ID      int64
	Handle  string
	Display string
	Role    Role
}

func (s *Store) UserInfo(id int64) (UserInfo, error) {
	var u UserInfo
	var role string
	err := s.db.QueryRow(
		`SELECT id, handle, display_name, role FROM users
		 WHERE id = ? AND disabled_at IS NULL`, id).Scan(&u.ID, &u.Handle, &u.Display, &role)
	u.Role = Role(role)
	return u, err
}

// CloseSession revoque une session precise (deconnexion).
func (s *Store) CloseSession(token string) error {
	sum := sha256.Sum256([]byte(token))
	_, err := s.db.Exec(`DELETE FROM sessions WHERE token_sha256 = ?`, sum[:])
	return err
}
