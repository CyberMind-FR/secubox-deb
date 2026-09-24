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
	"encoding/json"
	"net/http"
	"os"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

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

	vers := r.URL.Query().Get("vers")
	s.ouvreSessionSbx(w, r, compte, r.Header.Get(enteteProfilSbx), vers)
}

// ouvreSessionSbx : le compte SecuBox vérifié devient une session BBS. Commun à
// /sbx/entrer (vérifié par nginx) et /sbx/auto (vérifié par le démon).
func (s *Server) ouvreSessionSbx(w http.ResponseWriter, r *http.Request, compte, profil, vers string) {
	// UN APPAREIL A UN NOM (#1373). Admis par le Hall, il a déclaré « Gandalf »
	// ou « Gk2 » : c'est ce qu'on affiche, pas « sbx-ff90aec2d8d8 ». Lu dans le
	// registre des appareils, posé à la création, et repris tant que le membre
	// n'a pas choisi lui-même son nom dans « Mon compte ».
	nom := nomAppareil(compte)
	id, err := s.st.UserByHandle(compte)
	if err != nil {
		// PREMIÈRE VENUE : on crée le membre — rédacteur s'il est `user` au
		// Hall, lecteur s'il n'est que `guest` (roleDepuisProfil).
		id, err = s.st.CreateUser(compte, orNom(nom, compte), roleDepuisProfil(profil))
		if err != nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
	} else if nom != "" {
		if u, e := s.st.UserInfo(id); e == nil && u.Display == u.Handle {
			s.st.PoseNomAffiche(id, nom)
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
	http.Redirect(w, r, cheminInterne(vers), http.StatusSeeOther)
}

// ON REVIENT D'OÙ L'ON VENAIT, quand c'est un chemin INTERNE. Un `?vers=` venu
// de l'extérieur ferait de ces routes un tremplin de redirection : on n'accepte
// donc qu'un chemin absolu sans hôte, et sans `//` ni `\` qui en introduiraient un.
func cheminInterne(vers string) string {
	if !strings.HasPrefix(vers, "/") || strings.HasPrefix(vers, "//") || strings.Contains(vers, "\\") {
		return "/"
	}
	return vers
}

// ── ENTRÉE AUTOMATIQUE, EMBARQUÉ DANS LE HALL (#1373) ───────────────────────
//
// Encadrée par le Hall, la BBS masque son en-tête — et avec lui « Entrer ». La
// seule entrée restait sur /login, que personne n'atteint depuis le cadre :
// l'iPhone connecté au Hall lisait la BBS en anonyme, sans un bouton.
//
// /sbx/auto fait ce que ferait le clic sur « Entrer avec ma session SecuBox »,
// sans nginx : le démon soumet LUI-MÊME le cookie secubox_session à
// /auth/verify (s.verif). Pas de session Hall, ou refus : on rend la page
// demandée telle quelle, et un drapeau court empêche de réessayer en boucle.

// Drapeau anti-boucle, LISIBLE par le script (pas HttpOnly) : c'est lui qui
// décide de tenter l'entrée. Il ne porte aucun secret.
const cookieAutoNon = "sbx_auto_non"

func (s *Server) sbxAuto(w http.ResponseWriter, r *http.Request) {
	vers := cheminInterne(r.URL.Query().Get("vers"))
	refus := func() {
		http.SetCookie(w, &http.Cookie{
			Name: cookieAutoNon, Value: "1", Path: "/", MaxAge: 600,
			SameSite: s.sameSite(), Secure: s.opt.DerriereTLS,
		})
		http.Redirect(w, r, vers, http.StatusSeeOther)
	}
	if s.verif == nil {
		refus()
		return
	}
	c, err := r.Cookie("secubox_session")
	if err != nil || c.Value == "" {
		refus()
		return
	}
	ses, ok := s.verif(c.Value)
	compte := strings.ToLower(strings.TrimSpace(ses.User))
	if !ok || !reCompteSbx.MatchString(compte) {
		refus()
		return
	}
	s.ouvreSessionSbx(w, r, compte, ses.Groupes, vers)
}

// cheminAppareils : le registre tenu par secubox-acces (0640 secubox ; le
// compte secubox-bbs est du groupe). Variable pour les tests.
var cheminAppareils = "/etc/secubox/appareils.json"

// nomAppareil rend le nom déclaré d'un compte d'appareil, nettoyé, ou "".
// Registre absent ou illisible : "" — le compte garde son nom technique.
func nomAppareil(compte string) string {
	if !strings.HasPrefix(compte, "sbx-") {
		return ""
	}
	b, err := os.ReadFile(cheminAppareils)
	if err != nil {
		return ""
	}
	var reg struct {
		Appareils []struct {
			Compte string `json:"compte"`
			Nom    string `json:"nom"`
		} `json:"appareils"`
	}
	if json.Unmarshal(b, &reg) != nil {
		return ""
	}
	for _, a := range reg.Appareils {
		if a.Compte == compte {
			n, ok := nomAffichable(a.Nom)
			if ok {
				return n
			}
		}
	}
	return ""
}

// nomAffichable : 1 à 40 caractères imprimables, espaces resserrés. Le nom
// vient d'un formulaire ouvert (la demande d'accès) : on le borne ici aussi.
func nomAffichable(nom string) (string, bool) {
	nom = strings.Join(strings.Fields(nom), " ")
	if nom == "" || utf8.RuneCountInString(nom) > 40 {
		return "", false
	}
	for _, r := range nom {
		if unicode.IsControl(r) {
			return "", false
		}
	}
	return nom, true
}

func orNom(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
