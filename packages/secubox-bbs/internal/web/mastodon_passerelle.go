package web

// Passerelle Mastodon : un lien PERSONNEL entre un membre et son compte
// fediverse, puis la republication d'un fil sous SA propre identite (#1044).
//
// LE MODELE EST CELUI DES BILLETS, pousse d'un cran. Chez billets, ce qui sort
// part sous l'autorite de L'OPERATEUR qui declenche la publication : le BBS n'a
// pas d'identite propre chez lui. Ici l'autorite n'est meme plus celle d'un
// operateur mais celle du MEMBRE lui-meme — c'est son compte, son jeton, sa
// parole. Le BBS ne fait que porter le texte.
//
// CE QUI A ETE ECARTE, ET POURQUOI C'ETAIT TENTANT. Un seul jeton
// d'administration, range dans les reglages a cote de l'invitation, aurait
// demande dix lignes au lieu de ce fichier. Il aurait fait publier tout le
// monde sous une identite unique, empeche quiconque de revoquer sa part, et
// donne — le jour d'une fuite — la parole publique au nom de la communaute
// entiere. Le cout de la version juste est ce fichier ; il est paye une fois.

import (
	"context"
	"errors"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/CyberMind-FR/secubox-deb/secubox-bbs/internal/mastodon"
	"github.com/CyberMind-FR/secubox-deb/secubox-bbs/internal/store"
)

// cheminRetourMastodon : l'adresse ou l'instance renvoie le membre. Doit etre
// IDENTIQUE a l'enregistrement de l'application et a la demande d'autorisation,
// sinon l'instance refuse l'echange — c'est voulu de sa part.
const cheminRetourMastodon = "/mastodon/retour"

// passerelle route les gestes de la passerelle. Un seul point d'entree pour
// pouvoir y poser une fois les gardes communes.
func (s *Server) mastodonPasserelle(w http.ResponseWriter, r *http.Request) {
	switch {
	case strings.HasSuffix(r.URL.Path, "/lier"):
		s.mastodonLier(w, r)
	case strings.HasSuffix(r.URL.Path, "/retour"):
		s.mastodonRetour(w, r)
	case strings.HasSuffix(r.URL.Path, "/delier"):
		s.mastodonDelier(w, r)
	default:
		http.NotFound(w, r)
	}
}

// retourAbsolu reconstruit l'adresse de retour telle que l'instance la verra.
func (s *Server) retourAbsolu(r *http.Request) string {
	schema := "https"
	// Derriere le TLS de HAProxy la requete arrive en clair : c'est l'option du
	// demon qui dit la verite, pas `r.TLS`.
	if !s.opt.DerriereTLS && r.TLS == nil {
		schema = "http"
	}
	return schema + "://" + r.Host + cheminRetourMastodon
}

// clientMastodon construit un client vers une instance, en lui disant laquelle
// est celle de la maison — la seule joignable sur une adresse privee.
func (s *Server) clientMastodon(instance string) (*mastodon.Client, error) {
	interne, _ := s.st.Reglage(store.CleMastodonInstance)
	return mastodon.Nouveau(store.NormaliseInstance(instance),
		store.NormaliseInstance(interne))
}

// mastodonLier ouvre l'aller-retour d'autorisation.
func (s *Server) mastodonLier(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "methode refusee", http.StatusMethodNotAllowed)
		return
	}
	v := s.qui(r)
	if !v.Connecte {
		http.Redirect(w, r, "/login?retour=/mastodon", http.StatusSeeOther)
		return
	}
	if err := s.verifieCSRF(r); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}

	// L'instance de la maison est le defaut ; un membre peut en nommer une
	// autre — le fediverse n'a pas de centre, et forcer la notre reviendrait a
	// exiger un compte ici pour parler ailleurs.
	inst := store.NormaliseInstance(r.PostFormValue("instance"))
	if inst == "" {
		inst, _ = s.st.Reglage(store.CleMastodonInstance)
		inst = store.NormaliseInstance(inst)
	}
	if inst == "" {
		s.messageMastodon(w, r, "Aucune instance : indiquez-en une, ou demandez au sysop de déclarer celle de la maison.")
		return
	}

	cli, err := s.clientMastodon(inst)
	if err != nil {
		s.messageMastodon(w, r, err.Error())
		return
	}

	retour := s.retourAbsolu(r)
	idClient, secret, err := s.st.AppMastodon(inst)
	if err != nil {
		s.messageMastodon(w, r, "lecture de l'application impossible")
		return
	}
	if idClient == "" {
		// PREMIERE FOIS POUR CETTE INSTANCE : on s'y declare. Une seule fois —
		// le refaire a chaque lien y laisserait une application morte par
		// membre.
		app, err := cli.EnregistreApp(r.Context(), s.opt.Titre+" (BBS)", "https://"+r.Host, retour)
		if err != nil {
			s.messageMastodon(w, r, "l'instance a refusé l'enregistrement : "+err.Error())
			return
		}
		if err := s.st.PoseAppMastodon(inst, app.ClientID, app.ClientSecret); err != nil {
			s.messageMastodon(w, r, "enregistrement non retenu")
			return
		}
		idClient, secret = app.ClientID, app.ClientSecret
	}
	_ = secret

	etat, err := s.st.NouvelEtatMastodon(v.ID, inst)
	if err != nil {
		s.messageMastodon(w, r, "ouverture de l'autorisation impossible")
		return
	}
	_ = s.st.PurgeEtatsMastodon()
	http.Redirect(w, r, cli.URLAutorisation(idClient, retour, etat), http.StatusSeeOther)
}

// mastodonRetour recoit le membre au retour de l'instance.
//
// TROIS VERIFICATIONS, ET AUCUNE N'EST DE CONFORT :
//  1. l'etat existe, n'a pas servi, n'est pas perime ;
//  2. il a ete ouvert par LE MEMBRE DE CETTE SESSION — sans quoi on attacherait
//     le compte Mastodon d'un attaquant a la session de sa victime, qui
//     publierait ensuite chez lui de bonne foi ;
//  3. l'instance NOMME elle-meme le compte lie. On ne le deduit jamais du
//     pseudonyme local.
func (s *Server) mastodonRetour(w http.ResponseWriter, r *http.Request) {
	v := s.qui(r)
	if !v.Connecte {
		http.Redirect(w, r, "/login?retour=/mastodon", http.StatusSeeOther)
		return
	}
	if e := r.URL.Query().Get("error"); e != "" {
		// Un refus de consentement n'est pas une panne : c'est une reponse.
		s.messageMastodon(w, r, "Autorisation refusée sur l'instance. Rien n'a été lié.")
		return
	}

	proprio, inst, err := s.st.ConsommeEtatMastodon(r.URL.Query().Get("state"))
	if err != nil {
		s.messageMastodon(w, r, "Ce retour d'autorisation n'est plus valable. Relancez la liaison.")
		return
	}
	if proprio != v.ID {
		// ON NE DIT PAS A QUI IL APPARTIENT. Le refus suffit ; le detail
		// renseignerait sur les autres membres.
		log.Printf("bbs: retour Mastodon presente dans une autre session (etat du membre %d, session %d)",
			proprio, v.ID)
		s.messageMastodon(w, r, "Ce retour d'autorisation ne correspond pas à votre session.")
		return
	}

	code := r.URL.Query().Get("code")
	if code == "" {
		s.messageMastodon(w, r, "L'instance n'a pas renvoyé de code d'autorisation.")
		return
	}
	cli, err := s.clientMastodon(inst)
	if err != nil {
		s.messageMastodon(w, r, err.Error())
		return
	}
	idClient, secret, err := s.st.AppMastodon(inst)
	if err != nil || idClient == "" {
		s.messageMastodon(w, r, "Application inconnue pour cette instance. Relancez la liaison.")
		return
	}

	jeton, portee, err := cli.EchangeCode(r.Context(), idClient, secret, code, s.retourAbsolu(r))
	if err != nil {
		s.messageMastodon(w, r, "Échange du code refusé : "+err.Error())
		return
	}
	// C'EST ICI, ET NULLE PART AILLEURS, QUE L'IDENTITE S'ETABLIT.
	compte, err := cli.QuiSuisJe(r.Context(), jeton)
	if err != nil {
		s.messageMastodon(w, r, "L'instance n'a pas confirmé le compte : "+err.Error())
		return
	}

	err = s.st.LieCompteMastodon(v.ID, store.CompteMastodon{
		Instance: inst, Acct: compte.Acct, CompteID: compte.ID, Portee: portee,
	}, jeton)
	if errors.Is(err, store.ErrIdentitePrise) {
		s.messageMastodon(w, r, "Ce compte Mastodon est déjà lié à un autre membre.")
		return
	}
	if err != nil {
		s.messageMastodon(w, r, "Lien non retenu : "+err.Error())
		return
	}
	oublieFilMastodon(v.ID)
	http.Redirect(w, r, "/mastodon?lie=1", http.StatusSeeOther)
}

// mastodonDelier retire le lien cote BBS.
func (s *Server) mastodonDelier(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "methode refusee", http.StatusMethodNotAllowed)
		return
	}
	v := s.qui(r)
	if !v.Connecte {
		http.Redirect(w, r, "/login?retour=/mastodon", http.StatusSeeOther)
		return
	}
	if err := s.verifieCSRF(r); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	oublieFilMastodon(v.ID)
	if err := s.st.DelieCompteMastodon(v.ID); err != nil {
		s.messageMastodon(w, r, "Le lien n'a pas pu être retiré.")
		return
	}
	http.Redirect(w, r, "/mastodon?delie=1", http.StatusSeeOther)
}

// republierMastodon pousse un fil sur le compte du membre.
//
// QUATRE GARDES, VOLONTAIREMENT REDONDANTES avec celles de `publier` :
//  1. le membre est connecte et a lie SON compte ;
//  2. le fil est public — republier un fil local le mettrait sur internet ;
//  3. le salon n'est pas prive, meme si le fil s'y dit public : un fil public
//     dans un salon ferme n'est public QUE pour ceux qui voient le salon ;
//  4. ce qui sort est le TITRE et un LIEN, plus la note du membre — jamais le
//     texte des autres.
//
// Le point 4 merite d'etre dit franchement : republier le corps des messages
// d'autrui sous SON propre compte serait une usurpation douce, et un statut
// Mastodon est de toute facon trop court pour un fil. Ce qui circule, c'est une
// invitation a venir lire — ce que « republier » veut dire sur un micro-blog.
func (s *Server) republierMastodon(w http.ResponseWriter, r *http.Request, id int64) {
	if r.Method != http.MethodPost {
		http.Error(w, "methode refusee", http.StatusMethodNotAllowed)
		return
	}
	v := s.qui(r)
	if !v.Connecte {
		http.Error(w, "connectez-vous pour republier", http.StatusForbidden)
		return
	}
	if err := s.verifieCSRF(r); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}

	t, err := s.st.ThreadByID(id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if t.Visibility != store.VisPublic {
		http.Error(w, "un fil local ne se republie pas : rendez-le public d'abord",
			http.StatusForbidden)
		return
	}
	// LE SALON COMMANDE, MEME SUR UN FIL PUBLIC. Sans cette garde, un salon
	// ferme laisserait fuir ses sujets par la porte du fediverse — le fil se dit
	// public, mais il ne l'est que pour qui voit le salon.
	if prive, err := s.st.EstPrive(t.CategoryID); err != nil || prive {
		http.Error(w, "ce salon est privé : son contenu ne se republie pas",
			http.StatusForbidden)
		return
	}

	jeton, inst, err := s.st.JetonMastodon(v.ID)
	if err != nil {
		http.Error(w, "reliez d'abord votre compte Mastodon depuis /mastodon",
			http.StatusPreconditionRequired)
		return
	}
	cli, err := s.clientMastodon(inst)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}

	lien := "https://" + r.Host + "/t/" + itoa64(id)
	texte := composeStatut(r.PostFormValue("note"), t.Title, lien)
	visibilite := r.PostFormValue("visibilite")

	ctx, annule := context.WithTimeout(r.Context(), 15*time.Second)
	defer annule()
	st, err := cli.Publie(ctx, jeton, texte, visibilite)
	if err != nil {
		if errors.Is(err, mastodon.ErrPasAutorise) {
			// LE JETON N'EST PLUS BON : le membre a revoque l'application chez
			// Mastodon. On retire le lien mort plutot que de le laisser echouer
			// a chaque essai sans jamais dire pourquoi.
			_ = s.st.DelieCompteMastodon(v.ID)
			http.Error(w, "l'instance a refusé le jeton — le lien a été retiré, reliez votre compte",
				http.StatusPreconditionRequired)
			return
		}
		// PAS 502 : nginx intercepte 502/503/504 et les remplace par la page de
		// reveil, qui n'accepte que GET.
		http.Error(w, "republication refusée : "+err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, st.URL, http.StatusSeeOther)
}

// LongueurStatut : la borne classique d'un statut Mastodon.
//
// Les instances peuvent l'elargir, jamais la reduire en dessous. On coupe donc
// a 500 : un statut refuse pour depassement se perd, et le membre a deja quitte
// la page.
const LongueurStatut = 500

// composeStatut assemble ce qui sort : la note du membre, le titre, le lien.
//
// LE LIEN N'EST JAMAIS SACRIFIE. C'est la seule partie indispensable — un
// statut tronque garde son interet tant qu'il mene au fil ; ampute du lien, il
// ne mene nulle part. On rogne donc la note, puis le titre, jamais l'adresse.
func composeStatut(note, titre, lien string) string {
	note = strings.TrimSpace(note)
	titre = strings.TrimSpace(titre)

	reste := LongueurStatut - len([]rune(lien)) - 2 // deux retours a la ligne
	if reste < 0 {
		return lien
	}
	tete := titre
	if note != "" {
		tete = note
		if titre != "" {
			tete = note + "\n\n" + titre
		}
	}
	if r := []rune(tete); len(r) > reste {
		if reste <= 1 {
			return lien
		}
		tete = strings.TrimSpace(string(r[:reste-1])) + "…"
	}
	if tete == "" {
		return lien
	}
	return tete + "\n\n" + lien
}

// messageMastodon rend la page de la passerelle avec une explication.
//
// PLUTOT QU'UN `http.Error` NU : le membre arrive ici depuis un aller-retour
// chez un tiers, souvent sans comprendre ce qui vient d'echouer. Une page qui
// garde la navigation et propose de recommencer vaut mieux qu'un texte brut
// dans une fenetre vide.
func (s *Server) messageMastodon(w http.ResponseWriter, r *http.Request, msg string) {
	http.Redirect(w, r, "/mastodon?err="+url.QueryEscape(msg), http.StatusSeeOther)
}
