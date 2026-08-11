// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// SecuBox-Deb :: BBS — administration en ligne de commande.
//
// RECONSTRUIT LE 2026-08-11, comme cmd/secubox-bbsd : le `.gitignore` du paquet
// portait un motif NU `bbsctl`, destine au binaire construit, qui attrapait
// aussi le REPERTOIRE `cmd/bbsctl/`. Voir l'en-tete du daemon pour le detail.
//
// Reconstruit a partir de l'aide du binaire deploye sur gk2 (liste des verbes,
// textes identiques) et de l'API des paquets internes, qui sont suivis.
//
// SORTIE EN JSON, toujours. Cet outil est appele a la main mais aussi depuis
// des scripts et des unites systemd : un format stable vaut mieux qu'une prose
// qui change.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/CyberMind-FR/secubox-deb/secubox-bbs/internal/ingest"
	"github.com/CyberMind-FR/secubox-deb/secubox-bbs/internal/store"
)

func sortie(v any) {
	b, _ := json.MarshalIndent(v, "", "  ")
	fmt.Println(string(b))
}

func verifie(err error) {
	if err != nil {
		sortie(map[string]any{"ok": false, "error": err.Error()})
		os.Exit(1)
	}
}

func arg(a []string, i int) string {
	if i < len(a) {
		return a[i]
	}
	return ""
}

// lisMotDePasse lit STDIN. Le mot de passe n'est JAMAIS un argument : les
// arguments sont visibles dans la table des processus et restent dans
// l'historique du shell.
func lisMotDePasse() string {
	b, _ := io.ReadAll(os.Stdin)
	return strings.TrimRight(string(b), "\r\n")
}

func cmdHelp() {
	fmt.Print(`bbsctl — administration du BBS SecuBox

  status                     Compteurs
  integrity                  Compare le disque et l'index, sans rien modifier
  reindex                    Reconstruit l'index depuis content/
  backup <archive.tar.gz>    Archive transportable (ni base, ni secrets)
  invite [pour-qui]          Émet une invitation — code affiché UNE fois
  salon <slug> <titre> [desc]
  user-add <pseudo> [sysop]  MOT DE PASSE SUR STDIN
  user-disable <id>          Désactive, ne supprime jamais
  user-passwd <pseudo>       Réinitialise — MOT DE PASSE SUR STDIN
  user-local <pseudo>        Reprend un compte délégué en local — MOT DE PASSE SUR STDIN
  ingest [source|all]        Passerelles : billets, peertube, podcaster
  ingest-log                 Dernières exécutions d'import
  sync-users                 Aligne les comptes SecuBox (aucun mot de passe copié)

  printf '%s' 'une phrase de passe' | bbsctl user-add gk2 sysop
`)
}

func main() {
	racine := os.Getenv("SECUBOX_BBS_ROOT")
	if racine == "" {
		racine = "/var/lib/secubox/bbs"
	}
	secrets := os.Getenv("SECUBOX_BBS_SECRETS")
	if secrets == "" {
		secrets = "/etc/secubox/secrets/bbs"
	}

	args := os.Args[1:]
	if len(args) == 0 || args[0] == "--help" || args[0] == "-h" || args[0] == "help" {
		cmdHelp()
		return
	}

	st, err := store.Open(filepath.Join(racine, "index.db"))
	verifie(err)
	defer st.Close()

	switch args[0] {
	case "status":
		s, err := st.Stats()
		verifie(err)
		v, _ := st.Version()
		sortie(map[string]any{"ok": true, "schema": v, "stats": s})

	case "integrity":
		i, err := st.Integrity()
		verifie(err)
		sortie(map[string]any{"ok": true, "integrite": i})

	case "reindex":
		verifie(st.Reindex())
		i, _ := st.Integrity()
		sortie(map[string]any{"ok": true, "integrite": i})

	case "backup":
		dest := arg(args, 1)
		if dest == "" {
			sortie(map[string]any{"ok": false, "error": "chemin d'archive attendu"})
			os.Exit(2)
		}
		verifie(st.Backup(dest))
		sortie(map[string]any{"ok": true, "archive": dest})

	case "invite":
		// L'emetteur est FACULTATIF : `bbsctl` tourne sans session, il n'a
		// personne a qui attribuer l'invitation. Le libelle ne la lie a
		// personne — quiconque detient le code peut s'en servir ; il sert a
		// savoir laquelle revoquer.
		code, err := st.NewInviteFor(0, arg(args, 1))
		verifie(err)
		sortie(map[string]any{"ok": true, "code": code,
			"note": "affiche UNE fois — seule son empreinte est conservee"})

	case "salon":
		slug, titre := arg(args, 1), arg(args, 2)
		if slug == "" || titre == "" {
			sortie(map[string]any{"ok": false, "error": "slug et titre attendus"})
			os.Exit(2)
		}
		id, err := st.CreateCategory(slug, titre, arg(args, 3))
		verifie(err)
		sortie(map[string]any{"ok": true, "id": id, "slug": slug})

	case "user-add":
		handle := arg(args, 1)
		if handle == "" {
			sortie(map[string]any{"ok": false, "error": "pseudonyme attendu"})
			os.Exit(2)
		}
		role := store.RoleMember
		if arg(args, 2) == "sysop" {
			role = store.RoleSysop
		}
		pw := lisMotDePasse()
		if pw == "" {
			sortie(map[string]any{"ok": false, "error": "mot de passe vide"})
			os.Exit(2)
		}
		id, err := st.CreateUser(handle, handle, role)
		verifie(err)
		auth, err := store.OpenAuth(filepath.Join(secrets, "passwd"))
		verifie(err)
		verifie(auth.SetPassword(id, pw))
		sortie(map[string]any{"ok": true, "id": id, "handle": handle, "role": role})

	case "user-disable":
		var id int64
		fmt.Sscanf(arg(args, 1), "%d", &id)
		if id == 0 {
			sortie(map[string]any{"ok": false, "error": "identifiant attendu"})
			os.Exit(2)
		}
		verifie(st.DisableUser(id))
		sortie(map[string]any{"ok": true, "id": id, "desactive": true})

	case "user-passwd":
		// LE CHEMIN DE SECOURS. La console sysop reinitialise deja les mots de
		// passe, mais elle exige une session : quand plus personne ne peut
		// entrer — et c'est precisement le jour ou l'on en a besoin — elle ne
		// sert a rien.
		handle := arg(args, 1)
		if handle == "" {
			sortie(map[string]any{"ok": false, "error": "pseudonyme attendu"})
			os.Exit(2)
		}
		id, err := st.UserByHandle(handle)
		if err != nil {
			sortie(map[string]any{"ok": false, "error": "compte inconnu : " + handle})
			os.Exit(2)
		}
		auth, err := store.OpenAuth(filepath.Join(secrets, "passwd"))
		verifie(err)
		if err := auth.ResetPassword(id, lisMotDePasse()); err != nil {
			sortie(map[string]any{"ok": false, "error": err.Error()})
			os.Exit(2)
		}
		// Les sessions du compte sont fermees : on reinitialise soit apres une
		// fuite, soit pour reprendre la main. Dans les deux cas, laisser vivre
		// une session ouverte ailleurs viderait le geste de son sens.
		verifie(st.RevokeOtherSessions(id, ""))
		sortie(map[string]any{"ok": true, "id": id, "handle": handle,
			"sessions_fermees": true})

	case "user-local":
		// REPRENDRE UN COMPTE DELEGUE EN LOCAL.
		//
		// Un compte issu de `sync-users` delegue sa verification a
		// secubox-auth : le BBS n'en detient aucun mot de passe, donc ne peut
		// ni le reinitialiser ni depanner son titulaire. C'est defendable tant
		// que secubox-auth repond — et ingerable des qu'il faut agir depuis le
		// BBS seul. Ce verbe rend le compte autonome, avec un mot de passe
		// local.
		handle := arg(args, 1)
		if handle == "" {
			sortie(map[string]any{"ok": false, "error": "pseudonyme attendu"})
			os.Exit(2)
		}
		id, err := st.UserByHandle(handle)
		if err != nil {
			sortie(map[string]any{"ok": false, "error": "compte inconnu : " + handle})
			os.Exit(2)
		}
		pw := lisMotDePasse()
		if pw == "" {
			sortie(map[string]any{"ok": false, "error": "mot de passe vide"})
			os.Exit(2)
		}
		auth, err := store.OpenAuth(filepath.Join(secrets, "passwd"))
		verifie(err)
		verifie(auth.SetPassword(id, pw))
		verifie(st.SetAuthSourceLocale(id))
		verifie(st.RevokeOtherSessions(id, ""))
		sortie(map[string]any{"ok": true, "id": id, "handle": handle, "source": "local"})

	case "ingest":
		quoi := arg(args, 1)
		if quoi == "" {
			quoi = "all"
		}
		res, err := importeSources(st, quoi)
		verifie(err)
		sortie(map[string]any{"ok": true, "resultat": res})

	case "ingest-log":
		n := 12
		if v := arg(args, 1); v != "" {
			if k, err := strconv.Atoi(v); err == nil {
				n = k
			}
		}
		runs, err := st.IngestRuns(n)
		verifie(err)
		sortie(map[string]any{"ok": true, "executions": runs})

	case "sync-users":
		// AUCUN MOT DE PASSE N'EST COPIE. Recopier une empreinte creerait une
		// seconde copie a maintenir : un changement cote SecuBox ne s'y
		// refleterait pas, une revocation non plus.
		liste, err := chargeComptesSecubox()
		verifie(err)
		res, err := st.SyncExternalUsers(liste)
		verifie(err)
		sortie(map[string]any{"ok": true, "resultat": res})

	default:
		cmdHelp()
		os.Exit(2)
	}
}

// chargeComptesSecubox lit le magasin de secubox-auth.
//
// LECTURE SEULE, et seulement le pseudonyme, le nom et l'etat : ni empreinte,
// ni secret TOTP. Le fichier appartient a `secubox` et n'est pas lisible par
// tout le monde — un echec de lecture est rendu tel quel plutot que traite
// comme « aucun compte », qui desactiverait en masse les comptes synchronises.
func chargeComptesSecubox() ([]store.ExternalUser, error) {
	chemin := os.Getenv("SECUBOX_USERS_JSON")
	if chemin == "" {
		chemin = "/etc/secubox/users.json"
	}
	b, err := os.ReadFile(chemin)
	if err != nil {
		return nil, fmt.Errorf("lecture de %s : %w", chemin, err)
	}
	var brut struct {
		Users []struct {
			Handle   string `json:"username"`
			Nom      string `json:"display_name"`
			Role     string `json:"role"`
			Disabled bool   `json:"disabled"`
		} `json:"users"`
	}
	if err := json.Unmarshal(b, &brut); err != nil {
		return nil, fmt.Errorf("format de %s : %w", chemin, err)
	}
	out := make([]store.ExternalUser, 0, len(brut.Users))
	for _, u := range brut.Users {
		if u.Handle == "" {
			continue
		}
		nom := u.Nom
		if nom == "" {
			nom = u.Handle
		}
		role := store.RoleMember
		if u.Role == "admin" || u.Role == "sysop" {
			role = store.RoleSysop
		}
		out = append(out, store.ExternalUser{
			Handle: u.Handle, Display: nom, Role: role, Disabled: u.Disabled,
		})
	}
	return out, nil
}

// passerelles decrit ou atterrit chaque source.
//
// Le compte auteur est `passerelle` — un compte DESACTIVE et dedie : les fils
// importes portent une signature reconnaissable, et ce compte ne peut pas se
// connecter. Attribuer les imports a un vrai membre melangerait ce qu'il a
// ecrit et ce qu'une machine a recopie.
//
// LA VISIBILITE EST DELIBEREE, source par source, et c'est le choix le plus
// lourd de ce fichier : `emissions` reste LOCAL parce que le parc du podcaster
// contient des enregistrements qui n'ont pas vocation a sortir, alors que
// `archives` (billets deja publies) et `videos` (PeerTube deja public) sont
// publics puisqu'ils le sont deja ailleurs. Un defaut public partout aurait
// publie le podcast entier au premier import.
type passerelle struct {
	nom        string
	salon      string
	visibilite store.Visibility
	items      func() ([]ingest.Item, error)
}

func env(cle, defaut string) string {
	if v := os.Getenv(cle); v != "" {
		return v
	}
	return defaut
}

func importeSources(st *store.Store, quoi string) (map[string]ingest.Resultat, error) {
	base := env("SECUBOX_BBS_BASE", "https://bbs.gk2.secubox.in")
	ps := []passerelle{
		{"billets", "archives", store.VisPublic, func() ([]ingest.Item, error) {
			return ingest.DepuisBillets(env("SECUBOX_BILLETS_SOCKET", "/run/secubox/billets.sock"), base)
		}},
		{"peertube", "videos", store.VisPublic, func() ([]ingest.Item, error) {
			return ingest.DepuisPeerTube(env("SECUBOX_PEERTUBE_BASE", "https://peertube.gk2.secubox.in"), 100)
		}},
		{"podcaster", "emissions", store.VisLocal, func() ([]ingest.Item, error) {
			return ingest.DepuisPodcaster(env("SECUBOX_PODCASTER_DB", "/var/lib/secubox/podcaster/podcaster.db"), 200)
		}},
	}

	auteur, err := st.UserByHandle("passerelle")
	if err != nil {
		// Le compte est desactive : `UserByHandle` ne le rend pas. On le
		// retrouve donc directement — sans quoi aucun import ne serait
		// possible, ce qui serait un comble pour un compte cree pour ca.
		if err := st.QueryRowScan(&auteur,
			`SELECT id FROM users WHERE handle = 'passerelle'`); err != nil {
			return nil, fmt.Errorf("compte 'passerelle' introuvable : %w", err)
		}
	}

	out := map[string]ingest.Resultat{}
	for _, p := range ps {
		if quoi != "all" && quoi != p.nom {
			continue
		}
		cat, err := st.CreateCategory(p.salon, strings.ToUpper(p.salon[:1])+p.salon[1:], "")
		if err != nil {
			// Le salon existe deja : c'est le cas normal apres le premier
			// import. On le retrouve plutot que d'echouer.
			if err := st.QueryRowScan(&cat,
				`SELECT id FROM categories WHERE slug = ?`, p.salon); err != nil {
				return out, fmt.Errorf("salon %s : %w", p.salon, err)
			}
		}
		items, err := p.items()
		if err != nil {
			// UNE PASSERELLE MUETTE N'INTERROMPT PAS LES AUTRES. PeerTube
			// injoignable ne doit pas empecher l'import des billets.
			out[p.nom] = ingest.Resultat{Erreurs: []string{err.Error()}}
			st.LogIngest(p.nom, 0, 0, 0, err.Error())
			continue
		}
		r, err := ingest.Importer(st, ingest.Source{
			Nom: p.nom, Categorie: cat, Auteur: auteur, Visibilite: p.visibilite,
		}, items)
		if err != nil {
			out[p.nom] = ingest.Resultat{Erreurs: []string{err.Error()}}
			st.LogIngest(p.nom, len(items), 0, 0, err.Error())
			continue
		}
		out[p.nom] = r
		st.LogIngest(p.nom, r.Vus, r.Crees, r.Ignores, "")
	}
	return out, nil
}
