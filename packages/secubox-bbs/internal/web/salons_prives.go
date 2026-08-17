package web

import (
	"net/http"
	"net/url"
)

// rejoindreSalon consomme une invitation de salon.
//
// IL FAUT DEJA ETRE CONNECTE, et c'est la garantie centrale : une invitation de
// salon n'ouvre AUCUN compte. Quelqu'un qui ramasse le lien sans avoir de compte
// sur cette board n'obtient rien — on l'envoie se connecter, et le code ne sera
// consomme qu'ensuite, par une personne identifiee.
//
// L'IDENTIFIANT VIENT DE LA SESSION, jamais de l'adresse : un lien qui porterait
// « qui » en plus de « quoi » permettrait de se faire passer pour un autre en le
// modifiant.
func (s *Server) rejoindreSalon(w http.ResponseWriter, r *http.Request) {
	v := s.qui(r)
	code := r.URL.Query().Get("code")
	if code == "" {
		http.NotFound(w, r)
		return
	}
	if !v.Connecte {
		// On garde le code dans l'adresse de retour : apres connexion, le geste
		// aboutit sans qu'il faille recliquer sur le courriel.
		http.Redirect(w, r, "/login?retour="+url.QueryEscape(r.URL.RequestURI()),
			http.StatusSeeOther)
		return
	}
	cat, err := s.st.RejoinsSalon(code, v.ID)
	if err != nil {
		// ON NE DIT PAS POURQUOI. Distinguer « code inconnu » de « code deja
		// servi » apprendrait a un curieux si un code existe — et le laisserait
		// sonder la base un essai a la fois.
		http.Redirect(w, r, "/?err="+url.QueryEscape(
			"invitation invalide ou expirée"), http.StatusSeeOther)
		return
	}
	slug, err := s.st.SlugDuSalon(cat)
	if err != nil || slug == "" {
		http.Redirect(w, r, "/?msg="+url.QueryEscape("salon rejoint"), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/c/"+slug+"?msg="+url.QueryEscape("vous avez rejoint ce salon"),
		http.StatusSeeOther)
}
