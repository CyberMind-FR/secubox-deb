package store

// Synchronisation des comptes SecuBox vers le BBS.
//
// UNE SEULE IDENTITE, DEUX ROLES DISTINCTS. Les comptes SecuBox — ceux du
// companion et des webui — deviennent des comptes BBS, mais leur mot de passe
// reste verifie par secubox-auth. Le BBS n'en garde aucune copie.
//
// POURQUOI NE PAS RECOPIER L'EMPREINTE : une seconde copie devient fausse des
// le premier changement. Un mot de passe modifie chez SecuBox ne s'y
// refleterait pas ; une revocation non plus, et le compte resterait ouvert ici
// apres avoir ete ferme la-bas. On delegue, ou on ne synchronise pas.

import (
	"database/sql"
	"fmt"
	"strings"
)

type ExternalUser struct {
	Handle   string
	Display  string
	Role     Role
	Disabled bool
}

type SyncResult struct {
	Vus, Crees, MisAJour, Desactives, Reactives int
}

// SyncExternalUsers aligne les comptes d'origine SecuBox sur la liste fournie.
//
// LES COMPTES LOCAUX NE SONT JAMAIS TOUCHES. Les membres venus par invitation
// n'existent pas chez SecuBox ; les desactiver parce qu'ils sont « absents de
// la liste » viderait le BBS de ses membres au premier passage.
func (s *Store) SyncExternalUsers(liste []ExternalUser) (SyncResult, error) {
	var r SyncResult
	vus := map[string]bool{}

	for _, u := range liste {
		h := strings.TrimSpace(u.Handle)
		if h == "" {
			continue
		}
		r.Vus++
		vus[strings.ToLower(h)] = true

		var id int64
		var source string
		var desactive bool
		err := s.db.QueryRow(`SELECT id, auth_source, disabled_at IS NOT NULL
			FROM users WHERE handle = ?`, h).Scan(&id, &source, &desactive)
		switch {
		case err != nil:
			// Nouveau compte. Aucun mot de passe local n'est pose : il n'y en
			// a pas a poser, et un compte sans empreinte ne peut pas se
			// connecter localement — ce qui est exactement voulu.
			res, e := s.db.Exec(`INSERT INTO users(handle,display_name,role,created_at,
				auth_source,disabled_at) VALUES(?,?,?,unixepoch(),'secubox',?)`,
				h, orElse(u.Display, h), string(u.Role), nilSiFaux(u.Disabled))
			if e != nil {
				return r, e
			}
			_ = res
			r.Crees++

		case source != "secubox":
			// Un compte LOCAL portant le meme pseudonyme. On ne le convertit
			// pas : cela transfererait silencieusement son authentification a
			// un autre systeme, et un homonyme suffirait a prendre sa place.
			continue

		default:
			if _, e := s.db.Exec(`UPDATE users SET display_name = ?, role = ? WHERE id = ?`,
				orElse(u.Display, h), string(u.Role), id); e != nil {
				return r, e
			}
			r.MisAJour++
			switch {
			case u.Disabled && !desactive:
				if err := s.DisableUser(id); err != nil {
					return r, err
				}
				r.Desactives++
			case !u.Disabled && desactive:
				if err := s.EnableUser(id); err != nil {
					return r, err
				}
				r.Reactives++
			}
		}
	}

	// Un compte d'origine SecuBox DISPARU de la liste est desactive : il a ete
	// supprime la-bas, et le laisser ouvert ici serait la faille que toute
	// cette synchronisation cherche a eviter.
	rows, err := s.db.Query(
		`SELECT id, handle FROM users WHERE auth_source = 'secubox' AND disabled_at IS NULL`)
	if err != nil {
		return r, err
	}
	type absent struct {
		id int64
		h  string
	}
	var aCouper []absent
	for rows.Next() {
		var a absent
		if err := rows.Scan(&a.id, &a.h); err != nil {
			rows.Close()
			return r, err
		}
		if !vus[strings.ToLower(a.h)] {
			aCouper = append(aCouper, a)
		}
	}
	rows.Close()
	for _, a := range aCouper {
		if err := s.DisableUser(a.id); err != nil {
			return r, err
		}
		r.Desactives++
	}
	return r, nil
}

// AuthSource dit qui verifie le mot de passe de ce compte.
func (s *Store) AuthSource(handle string) (string, error) {
	var src string
	err := s.db.QueryRow(`SELECT auth_source FROM users WHERE handle = ?`, handle).Scan(&src)
	return src, err
}

// AuthSourceParID : meme question, posee par identifiant.
//
// L'API du panneau d'administration designe les comptes par identifiant, pas
// par pseudonyme — un pseudonyme peut changer, un identifiant non. Faire
// resoudre l'un vers l'autre par l'appelant l'aurait oblige a une requete de
// plus, et surtout a supposer que le pseudonyme lu quelques instants plus tot
// designe encore le meme compte.
func (s *Store) AuthSourceParID(id int64) (string, error) {
	var src string
	err := s.db.QueryRow(`SELECT auth_source FROM users WHERE id = ?`, id).Scan(&src)
	return src, err
}

func orElse(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b
}

func nilSiFaux(b bool) any {
	if !b {
		return nil
	}
	return 1
}

// SetAuthSourceLocale reprend un compte delegue en LOCAL.
//
// Un compte issu de `sync-users` delegue sa verification a secubox-auth : le
// BBS n'en detient aucun mot de passe. C'est defendable — une seule copie du
// secret — mais cela rend le compte INGERABLE depuis le BBS : impossible de
// reinitialiser son mot de passe, impossible de depanner son titulaire si
// secubox-auth ne repond pas, et le panneau doit afficher « delegue » la ou
// l'exploitant attend un bouton.
//
// Ce basculement rend le compte autonome. L'appelant DOIT poser un mot de passe
// local avant ou juste apres : sans lui, le compte devient un compte local sans
// empreinte, donc un compte qui ne peut plus se connecter du tout.
//
// La prochaine synchronisation ne le reprendra pas : `SyncExternalUsers` ne
// touche que les comptes dont `auth_source = 'secubox'`.
func (s *Store) SetAuthSourceLocale(id int64) error {
	_, err := s.db.Exec(`UPDATE users SET auth_source = 'local' WHERE id = ?`, id)
	return err
}

// UserSecuboxParHandle : le compte d'origine SecuBox actif portant ce nom, et
// lui seul. Sert a reconnaitre la session du Hall (#1369) : un compte LOCAL
// homonyme n'est jamais rendu.
func (s *Store) UserSecuboxParHandle(handle string) (int64, error) {
	var id int64
	err := s.db.QueryRow(`SELECT id FROM users WHERE handle = ? COLLATE NOCASE
		AND auth_source = 'secubox' AND disabled_at IS NULL`, strings.TrimSpace(handle)).Scan(&id)
	return id, err
}

// EtatCompte : ce que la BBS sait d'un nom de compte, pour l'ecran des acces.
type EtatCompte struct {
	Existe    bool   `json:"existe"`
	Role      string `json:"role,omitempty"`
	Source    string `json:"source,omitempty"`
	Desactive bool   `json:"desactive"`
}

// EtatComptes rend l'etat de chaque nom demande ; un nom inconnu vaut
// `existe: false`, jamais une erreur.
func (s *Store) EtatComptes(handles []string) (map[string]EtatCompte, error) {
	out := make(map[string]EtatCompte, len(handles))
	for _, h := range handles {
		h = strings.TrimSpace(h)
		if h == "" {
			continue
		}
		var e EtatCompte
		err := s.db.QueryRow(`SELECT role, auth_source, disabled_at IS NOT NULL
			FROM users WHERE handle = ? COLLATE NOCASE`, h).Scan(&e.Role, &e.Source, &e.Desactive)
		if err == nil {
			e.Existe = true
		} else if err != sql.ErrNoRows {
			return out, err
		}
		out[h] = e
	}
	return out, nil
}

// AdopteCompte fait passer un compte LOCAL a l'origine SecuBox (#1369).
//
// C'est le geste inverse de SetAuthSourceLocale, et il est EXPLICITE : c'est
// l'administrateur qui affirme que le « gk2 » local et le « gk2 » SecuBox sont
// la meme personne. Des lors le mot de passe est verifie par secubox-auth, la
// session du Hall ouvre ce compte, et la synchronisation le tient a jour.
func (s *Store) AdopteCompte(handle string) error {
	res, err := s.db.Exec(`UPDATE users SET auth_source = 'secubox'
		WHERE handle = ? COLLATE NOCASE AND auth_source <> 'secubox'`, strings.TrimSpace(handle))
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("aucun compte local nommé %q", handle)
	}
	return nil
}
