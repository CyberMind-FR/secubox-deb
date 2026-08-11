// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// Vues de la messagerie interne et du module Mastodon (#1008).
package web

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/CyberMind-FR/secubox-deb/secubox-bbs/internal/store"
)

// mp affiche la boite de reception, ou une conversation si l'adresse porte un
// pseudo : /mp/alice.
//
// La conversation est marquee lue A L'AFFICHAGE et pas a l'envoi : le compteur
// doit refleter ce qui a ete VU, sinon il retombe a zero des qu'on repond et
// reste a zero sur ce qu'on n'a jamais ouvert.
func (s *Server) mp(w http.ResponseWriter, r *http.Request) {
	p, _ := s.base(r, "mp")
	if !p.V.Connecte {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	p.Titre = "Messages"
	p.Intro = "Entre membres. Jamais repris dans un export."
	p.Msg = r.URL.Query().Get("msg")
	p.Err = r.URL.Query().Get("err")
	p.Corres, _ = s.st.Correspondants(p.V.ID)

	pseudo := strings.Trim(strings.TrimPrefix(r.URL.Path, "/mp"), "/")
	if pseudo == "" {
		p.Convs, _ = s.st.Conversations(p.V.ID)
		p.Vide = "Aucun message."
		s.rend(w, r, "mp", p)
		return
	}

	id, err := s.st.UserByHandle(pseudo)
	if err != nil || id == p.V.ID {
		// Un pseudo inconnu renvoie a la boite plutot qu'a un 404 : l'adresse
		// vient d'un lien qu'on a pu taper de travers, pas d'une ressource
		// manquante.
		http.Redirect(w, r, "/mp?err="+url.QueryEscape("interlocuteur inconnu"),
			http.StatusSeeOther)
		return
	}
	s.st.MarquerLu(p.V.ID, id)
	p.Fil, _ = s.st.Conversation(p.V.ID, id)
	for _, c := range p.Corres {
		if c.ID == id {
			p.Avec = c
		}
	}
	if p.Avec.ID == 0 {
		// Correspondants exclut les comptes fermes : on garde la conversation
		// lisible, mais l'interlocuteur est signale comme injoignable plutot
		// que d'afficher un formulaire dont l'envoi echouerait.
		p.Avec = store.Compte{ID: id, Handle: pseudo, Display: pseudo, Disabled: true}
	}
	p.Titre = "Messages · " + p.Avec.Display
	p.Convs, _ = s.st.Conversations(p.V.ID)
	s.rend(w, r, "mp", p)
}

func (s *Server) mpEnvoyer(w http.ResponseWriter, r *http.Request) {
	v := s.qui(r)
	if !v.Connecte {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	if err := s.verifieCSRF(r); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	vers := strings.TrimSpace(r.PostFormValue("vers"))
	id, err := s.st.UserByHandle(vers)
	if err != nil {
		http.Redirect(w, r, "/mp?err="+url.QueryEscape("interlocuteur inconnu"),
			http.StatusSeeOther)
		return
	}
	if _, err := s.st.Envoyer(v.ID, id, r.PostFormValue("corps")); err != nil {
		http.Redirect(w, r, "/mp/"+url.PathEscape(vers)+"?err="+
			url.QueryEscape("message non envoye : "+err.Error()), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/mp/"+url.PathEscape(vers), http.StatusSeeOther)
}

// mastodon presente l'instance federee de la board et le lien d'invitation.
//
// Le lien n'est montre qu'aux MEMBRES CONNECTES. Une invitation Mastodon est a
// usage multiple et ne se revoque pas depuis le BBS : l'afficher publiquement
// reviendrait a ouvrir l'instance a qui passe, ce qui n'est ni le choix de
// l'instance ni celui du BBS.
func (s *Server) mastodon(w http.ResponseWriter, r *http.Request) {
	p, _ := s.base(r, "mastodon")
	p.Titre = "Mastodon"
	p.Intro = "L'instance fédérée de la board. Même communauté, autre porte."
	p.MastoInstance, _ = s.st.Reglage(store.CleMastodonInstance)
	if p.V.Connecte {
		p.MastoInvite, _ = s.st.Reglage(store.CleMastodonInvite)
	}
	switch {
	case p.MastoInstance == "":
		p.Vide = "Aucune instance déclarée. Le sysop la renseigne depuis la console."
	case !p.V.Connecte:
		p.Note = "Le lien d'invitation est réservé aux membres connectés."
	case p.MastoInvite == "":
		p.Vide = "Aucune invitation ouverte pour l'instant."
	}
	s.rend(w, r, "mastodon", p)
}
