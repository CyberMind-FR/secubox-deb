// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// API du panneau d'administration : ce que la console sysop sait faire, rendu
// disponible a la webui d'admin (#1008).
//
// POURQUOI DUPLIQUER LA CONSOLE PLUTOT QUE RENVOYER VERS ELLE.
//
// Les deux surfaces ne s'adressent pas au meme moment. La console `/sysop` vit
// sur le BBS public et suppose une session BBS ; le panneau d'admin vit sur
// admin.<board> derriere le JWT du parc, la ou l'exploitant regarde deja les
// cent autres modules. Obliger a changer de site — et a detenir deux
// authentifications — pour desactiver un compte revient a ne pas offrir la
// fonction du tout.
//
// Les DEUX passent par les memes fonctions de magasin : c'est la seule facon
// que les garde-fous (politique de longueur, fermeture des sessions, refus des
// liens non http) valent pour les deux portes.
package web

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/CyberMind-FR/secubox-deb/secubox-bbs/internal/store"
)

func (s *Server) routesAPISysop() {
	s.mux.HandleFunc("/api/v1/bbs/users", s.jwt(s.apiUsers))
	s.mux.HandleFunc("/api/v1/bbs/users/", s.jwt(s.apiUsersAction))
	s.mux.HandleFunc("/api/v1/bbs/invites", s.jwt(s.apiInvites))
	s.mux.HandleFunc("/api/v1/bbs/settings", s.jwt(s.apiSettings))
}

type userJSON struct {
	ID        int64  `json:"id"`
	Handle    string `json:"handle"`
	Nom       string `json:"nom"`
	Role      string `json:"role"`
	Desactive bool   `json:"desactive"`
	Source    string `json:"source"`
	LastLogin int64  `json:"derniere_connexion"`
	LastIP    string `json:"derniere_ip"`
	Sessions  int    `json:"sessions"`
}

func (s *Server) apiUsers(w http.ResponseWriter, r *http.Request) {
	cs, err := s.st.Users()
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := make([]userJSON, 0, len(cs))
	for _, c := range cs {
		out = append(out, userJSON{
			ID: c.ID, Handle: c.Handle, Nom: c.Display, Role: string(c.Role),
			Desactive: c.Disabled, Source: c.Source, LastLogin: c.LastLogin,
			LastIP: c.LastIP, Sessions: c.Sessions,
		})
	}
	jsonOK(w, map[string]any{"ok": true, "users": out})
}

// apiUsersAction : /api/v1/bbs/users/{disable,enable,password}
func (s *Server) apiUsersAction(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonErr(w, http.StatusMethodNotAllowed, "POST attendu")
		return
	}
	var corps struct {
		ID       int64  `json:"id"`
		Password string `json:"password"`
	}
	json.NewDecoder(r.Body).Decode(&corps)
	if corps.ID == 0 {
		// Accepte aussi le formulaire : le panneau peut poster l'un ou l'autre,
		// et un identifiant absent conduirait sinon a agir sur le compte 0 —
		// qui n'existe pas, mais dont l'echec ne dirait pas pourquoi.
		if v := r.PostFormValue("id"); v != "" {
			corps.ID, _ = strconv.ParseInt(v, 10, 64)
		}
		if corps.Password == "" {
			corps.Password = r.PostFormValue("password")
		}
	}
	if corps.ID == 0 {
		jsonErr(w, http.StatusBadRequest, "identifiant de compte attendu")
		return
	}

	switch strings.TrimPrefix(r.URL.Path, "/api/v1/bbs/users/") {
	case "disable":
		if err := s.st.DisableUser(corps.ID); err != nil {
			jsonErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		jsonOK(w, map[string]any{"ok": true, "desactive": true})
	case "enable":
		if err := s.st.EnableUser(corps.ID); err != nil {
			jsonErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		jsonOK(w, map[string]any{"ok": true, "desactive": false})
	case "delete":
		// SUPPRESSION REELLE, demandee par l'exploitant. Le contenu n'est pas
		// efface : il est reattribue a un compte tombeau (cf.
		// store.DeleteUser). Un membre qui s'en va n'emporte pas les reponses
		// qu'on lui a faites.
		if err := s.st.DeleteUser(corps.ID); err != nil {
			jsonErr(w, http.StatusConflict, err.Error())
			return
		}
		// L'empreinte vit hors de la base : sans cet oubli, un secret
		// survivrait a son compte et serait attribue au prochain compte
		// recevant le meme identifiant.
		if err := s.auth.Oublie(corps.ID); err != nil {
			jsonErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		jsonOK(w, map[string]any{"ok": true, "supprime": true})
	case "local":
		// REPRENDRE UN COMPTE DELEGUE EN LOCAL. Un compte issu de `sync-users`
		// delegue sa verification a secubox-auth : le BBS n'en detient aucun
		// mot de passe, donc ne peut ni le reinitialiser ni depanner son
		// titulaire. Ce basculement le rend autonome.
		//
		// Le mot de passe est pose DANS LA FOULEE : un compte bascule sans
		// empreinte locale ne pourrait plus se connecter du tout.
		if corps.Password == "" {
			jsonErr(w, http.StatusBadRequest,
				"mot de passe requis : un compte repris sans empreinte locale ne peut plus se connecter")
			return
		}
		if err := s.auth.ResetPassword(corps.ID, corps.Password); err != nil {
			jsonErr(w, http.StatusBadRequest, err.Error())
			return
		}
		if err := s.st.SetAuthSourceLocale(corps.ID); err != nil {
			jsonErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		s.st.RevokeOtherSessions(corps.ID, "")
		jsonOK(w, map[string]any{"ok": true, "source": "local"})
	case "password":
		// UN COMPTE DELEGUE N'EST PAS REINITIALISABLE ICI. Le BBS ne copie aucun
		// mot de passe : la verification part vers secubox-auth. En poser un
		// localement laisserait croire au succes alors que la connexion
		// continuerait d'echouer — le pire des retours.
		src, err := s.st.AuthSourceParID(corps.ID)
		if err != nil {
			jsonErr(w, http.StatusNotFound, "compte inconnu")
			return
		}
		if src == "secubox" {
			jsonErr(w, http.StatusConflict,
				"compte delegue a secubox-auth : le mot de passe se change la-bas")
			return
		}
		// Meme politique que le libre-service et que la console : une seule
		// regle, un seul endroit.
		if err := s.auth.ResetPassword(corps.ID, corps.Password); err != nil {
			jsonErr(w, http.StatusBadRequest, err.Error())
			return
		}
		s.st.RevokeOtherSessions(corps.ID, "")
		jsonOK(w, map[string]any{"ok": true, "sessions_fermees": true})
	default:
		jsonErr(w, http.StatusNotFound, "action inconnue")
	}
}

func (s *Server) apiInvites(w http.ResponseWriter, r *http.Request) {
	invs, err := s.st.Invites()
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := make([]map[string]any, 0, len(invs))
	for _, i := range invs {
		out = append(out, map[string]any{
			"emetteur": i.Emetteur, "beneficiaire": i.Beneficiaire,
			"emise_le": i.IssuedAt, "expire_le": i.ExpiresAt, "utilisee": i.Used,
			"libelle": i.Label,
		})
	}
	jsonOK(w, map[string]any{"ok": true, "invites": out})
}

// apiSettings lit (GET) ou pose (POST) les reglages du module Mastodon.
func (s *Server) apiSettings(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		var corps struct {
			Instance   string `json:"instance"`
			Invitation string `json:"invitation"`
		}
		json.NewDecoder(r.Body).Decode(&corps)
		for cle, val := range map[string]string{
			store.CleMastodonInstance: corps.Instance,
			store.CleMastodonInvite:   corps.Invitation,
		} {
			val = strings.TrimSpace(val)
			// LA VALIDATION EST LA MEME QUE DANS LA CONSOLE, et posee AU
			// STOCKAGE. Une seconde porte d'ecriture qui ne validerait pas
			// rendrait la premiere inutile : le lien finit dans un href servi a
			// tous les membres, d'ou qu'il vienne.
			if val != "" && !store.LienExterneValide(val) {
				jsonErr(w, http.StatusBadRequest,
					"lien refuse : seuls http et https sont acceptes")
				return
			}
			if err := s.st.PoseReglage(cle, val); err != nil {
				jsonErr(w, http.StatusInternalServerError, err.Error())
				return
			}
		}
	}
	inst, _ := s.st.Reglage(store.CleMastodonInstance)
	inv, _ := s.st.Reglage(store.CleMastodonInvite)
	jsonOK(w, map[string]any{"ok": true, "instance": inst, "invitation": inv})
}
