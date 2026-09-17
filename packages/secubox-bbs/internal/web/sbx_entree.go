// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// SecuBox-Deb :: BBS — ENTRER AVEC SA SESSION SECUBOX (#1360).
//
// CE QUE ÇA REMPLACE. Quelqu'un entré dans SBX OS — par signature, sans mot de
// passe — arrivait au BBS et se voyait demander un pseudonyme et un mot de
// passe qu'il n'a jamais eus. Deux authentifications pour une seule personne,
// dont l'une n'était pas franchissable.
//
// POURQUOI L'EN-TÊTE EST DIGNE DE FOI ICI, ET NULLE PART AILLEURS.
//
// Le démon n'écoute QUE sur un socket unix : aucun client ne l'atteint
// directement, seul nginx lui parle. Et nginx POSE l'en-tête à partir de sa
// propre vérification (`auth_request` vers /auth/verify), en ÉCRASANT ce que le
// client aurait pu envoyer. Un en-tête forgé par un navigateur n'arrive donc
// jamais jusqu'ici.
//
// Cette confiance tient à ces deux conditions ENSEMBLE. Si le démon venait à
// écouter sur un port TCP, ou si la `location` cessait d'écraser l'en-tête,
// cette route deviendrait une porte ouverte à qui sait écrire `X-Sbx-Membre`.
// C'est pourquoi elle refuse tout en-tête qui ne ressemble pas à un compte
// d'appareil ou d'utilisateur SecuBox, et pourquoi elle ne crée jamais de
// sysop.
package web

import (
	"net/http"
	"regexp"
	"strings"

	"github.com/CyberMind-FR/secubox-deb/secubox-bbs/internal/store"
)

// L'en-tête que nginx pose depuis `Remote-User`.
const enteteMembreSbx = "X-Sbx-Membre"

// Et celui qui porte le profil, depuis `Remote-Groups`.
const enteteProfilSbx = "X-Sbx-Profil"

// Un nom de compte SecuBox : `sbx-…` pour un appareil, un nom simple pour un
// utilisateur. On borne sévèrement — ce nom devient un pseudonyme affiché, et
// il sert de clé.
var reCompteSbx = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{2,63}$`)

// roleDepuisProfil traduit le profil SecuBox en rôle BBS.
//
// JAMAIS SYSOP, quoi que dise l'en-tête. Un administrateur SecuBox n'est pas
// d'office administrateur du forum : ce sont deux responsabilités distinctes,
// et les confondre donnerait le pouvoir de modération à quiconque obtient
// l'administration de la box. La promotion en sysop reste un geste fait DANS le
// BBS, par un sysop.
func roleDepuisProfil(profil string) store.Role {
	switch strings.ToLower(strings.TrimSpace(profil)) {
	case "user", "admin":
		return store.RoleMember
	default:
		return store.RoleGuest
	}
}

// sbxEntree ouvre une session BBS pour le porteur d'une session SecuBox.
func (s *Server) sbxEntree(w http.ResponseWriter, r *http.Request) {
	compte := strings.ToLower(strings.TrimSpace(r.Header.Get(enteteMembreSbx)))
	if !reCompteSbx.MatchString(compte) {
		// SANS EN-TÊTE VALIDE, ON RENVOIE AU FORMULAIRE — pas une erreur. Le cas
		// normal est quelqu'un qui n'a pas de session SecuBox : lui montrer une
		// page d'erreur pour ça serait absurde.
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	id, err := s.st.UserByHandle(compte)
	if err != nil {
		// PREMIÈRE VENUE : on crée le membre. Le nom affiché est le compte —
		// le nom « humain » déclaré à l'admission vit côté SecuBox et n'est pas
		// à nous ; l'afficher ici obligerait le BBS à le tenir à jour.
		id, err = s.st.CreateUser(compte, compte, roleDepuisProfil(r.Header.Get(enteteProfilSbx)))
		if err != nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
	}

	s.st.NoteLogin(id, r.RemoteAddr)
	jeton, err := s.st.NewSession(id, r.RemoteAddr, r.UserAgent())
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: cookieSession, Value: jeton, Path: "/",
		HttpOnly: true, SameSite: s.sameSite(),
		Secure: s.opt.DerriereTLS, MaxAge: 30 * 24 * 3600,
	})

	// ON REVIENT D'OÙ L'ON VENAIT, quand c'est un chemin INTERNE. Un `?vers=`
	// venu de l'extérieur ferait de cette route un tremplin de redirection : on
	// n'accepte donc qu'un chemin absolu sans hôte, et sans `//` qui en
	// introduirait un.
	vers := r.URL.Query().Get("vers")
	if !strings.HasPrefix(vers, "/") || strings.HasPrefix(vers, "//") {
		vers = "/"
	}
	http.Redirect(w, r, vers, http.StatusSeeOther)
}
