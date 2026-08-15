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
	"time"
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
	// LE CARNET REMPLACE LE MUR DE PASTILLES. `Correspondants` rendait TOUS les
	// comptes ouverts : tenable a cinq membres, illisible a cinquante. Le
	// carnet nomme ce qu'on utilise vraiment ; l'annuaire complet est une
	// recherche, sur sa propre page.
	p.Carnet, _ = s.st.Carnet(p.V.ID)

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
	// L'ETAT DE L'INTERLOCUTEUR SE DEMANDE, IL NE SE DEDUIT PAS D'UNE LISTE.
	//
	// Le premier jet le cherchait dans `Corres` — tous les comptes joignables —
	// et concluait « compte ferme » quand il ne l'y trouvait pas. Le jour ou
	// cette liste a ete remplacee par le CARNET, tout interlocuteur hors carnet
	// s'est retrouve annonce comme ferme, avec un formulaire d'envoi retire.
	// Constate sur cedre83, compte parfaitement actif.
	//
	// Une absence dans une liste ne prouve rien sur un compte : elle ne dit que
	// ce que la liste contient.
	if u, err := s.st.UserInfo(id); err == nil {
		p.Avec = store.Compte{ID: u.ID, Handle: u.Handle, Display: u.Display, Role: u.Role}
		_, p.AvecAvatar = s.st.AuteurEtAvatar(id)
	} else {
		// `UserInfo` ne rend pas les comptes desactives : la conversation reste
		// lisible, mais l'envoi est retire plutot que d'echouer apres coup.
		p.Avec = store.Compte{ID: id, Handle: pseudo, Display: pseudo, Disabled: true}
	}
	p.Titre = "Messages · " + p.Avec.Display
	p.Convs, _ = s.st.Conversations(p.V.ID)
	s.rend(w, r, "mp", p)
}

// annuaire : la recherche de membres, bornee.
//
// Sur SA PROPRE PAGE et non dans la colonne : une recherche qui rend des
// resultats a besoin de place, et la colonne doit rester la ou l'on revient.
func (s *Server) mpAnnuaire(w http.ResponseWriter, r *http.Request) {
	p, _ := s.base(r, "mp")
	if !p.V.Connecte {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	p.Titre = "Annuaire"
	p.Intro = "Chercher un membre, et le garder sous la main."
	p.Q = strings.TrimSpace(r.URL.Query().Get("q"))
	p.Msg = r.URL.Query().Get("msg")
	p.Carnet, _ = s.st.Carnet(p.V.ID)
	p.Convs, _ = s.st.Conversations(p.V.ID)
	// 40 : de quoi parcourir sans faire defiler une page entiere. Au-dela, on
	// affine la recherche — c'est le propre d'un annuaire.
	p.Annuaire, _ = s.st.Annuaire(p.V.ID, p.Q, 40)
	s.rend(w, r, "annuaire", p)
}

// mpCarnet ajoute ou retire un contact.
func (s *Server) mpCarnet(w http.ResponseWriter, r *http.Request) {
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
	id, err := s.st.UserByHandle(strings.TrimSpace(r.PostFormValue("qui")))
	if err != nil {
		http.Redirect(w, r, "/mp/annuaire?msg="+url.QueryEscape("membre inconnu"),
			http.StatusSeeOther)
		return
	}
	msg := "ajouté au carnet"
	if r.PostFormValue("action") == "retirer" {
		s.st.RetireDuCarnet(v.ID, id)
		msg = "retiré du carnet"
	} else {
		s.st.AjouteAuCarnet(v.ID, id, r.PostFormValue("note"))
	}
	// ON REVIENT D'OU L'ON VIENT. Renvoyer toujours vers l'annuaire ferait
	// perdre sa recherche a qui ajoutait un contact depuis une conversation.
	retour := r.PostFormValue("retour")
	if retour == "" || !strings.HasPrefix(retour, "/") || strings.HasPrefix(retour, "//") {
		retour = "/mp/annuaire"
	}
	sep := "?"
	if strings.Contains(retour, "?") {
		sep = "&"
	}
	http.Redirect(w, r, retour+sep+"msg="+url.QueryEscape(msg), http.StatusSeeOther)
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

		// LE LIEN PERSONNEL (#1044). Son absence n'est pas une anomalie : c'est
		// l'etat par defaut, et le seul acceptable tant que le membre n'a pas
		// fait l'aller-retour OAuth. On ne rapproche JAMAIS son compte d'un
		// compte Mastodon portant le meme pseudonyme.
		if c, err := s.st.CompteMastodonDe(p.V.ID); err == nil {
			p.MastoLie = true
			p.MastoCompte = "@" + c.Acct + "@" + c.Instance
			p.MastoLieLe = time.Unix(c.LieLe, 0).Format("02/01/2006")
		}
	}
	// Les retours de la passerelle passent par l'adresse : l'aller-retour chez
	// l'instance fait perdre tout etat de session applicative.
	q := r.URL.Query()
	p.MastoErr = q.Get("err")
	switch {
	case q.Get("lie") != "":
		p.MastoInfo = "Compte relié. Vous pouvez republier un fil public sous votre propre identité."
	case q.Get("delie") != "":
		p.MastoInfo = "Lien retiré ici. Pensez à révoquer aussi l'autorisation " +
			"dans les réglages de votre compte Mastodon : le BBS ne peut pas le faire à votre place."
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
