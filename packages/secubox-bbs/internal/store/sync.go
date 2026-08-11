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

import "strings"

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
