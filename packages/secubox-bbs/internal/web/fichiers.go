// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// Depot et service des pieces jointes (#1008).
//
// La partie SENSIBLE est le service, pas l'envoi : un fichier depose par un
// membre est ensuite servi depuis l'origine du BBS, donc avec la session des
// autres lecteurs. Trois protections, toutes indispensables ensemble :
//
//   - le type est celui que le MAGASIN a reconnu au depot, jamais celui de la
//     requete ni de l'extension ;
//   - `X-Content-Type-Options: nosniff` interdit au navigateur de re-deviner
//     autre chose que ce qu'on annonce — sans lui, un navigateur indulgent peut
//     traiter en HTML un fichier annonce en image ;
//   - le chemin vient de la BASE, jamais de l'adresse : la traversee de
//     repertoire est impossible par construction, pas par filtrage.
package web

import (
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// tailleFormulaire borne ce que le serveur accepte de bufferiser avant meme de
// regarder le contenu. Sans elle, un envoi de plusieurs gigaoctets occuperait
// la memoire de la board bien avant que la borne du magasin ne s'applique.
const tailleFormulaire = 80 << 20 // 80 Mio : la borne du magasin est a 64

// extensionDe rend le suffixe d'affichage d'un type. Volontairement limite aux
// types que le magasin accepte : un type inconnu ne peut pas arriver ici.
func extensionDe(mime string) string {
	switch mime {
	case "image/png":
		return ".png"
	case "image/jpeg":
		return ".jpg"
	case "image/gif":
		return ".gif"
	case "image/webp":
		return ".webp"
	case "audio/mpeg":
		return ".mp3"
	case "audio/ogg":
		return ".ogg"
	case "audio/wav":
		return ".wav"
	case "audio/flac":
		return ".flac"
	case "audio/webm":
		return ".weba"
	case "video/mp4":
		return ".mp4"
	case "video/ogg":
		return ".ogv"
	case "video/webm":
		return ".webm"
	}
	return ""
}

func (s *Server) routesFichiers() {
	s.mux.HandleFunc("/f/", s.servirFichier)
	s.mux.HandleFunc("/f/envoi", s.deposerFichier)
	s.mux.HandleFunc("/compte/avatar", s.poserAvatar)
}

// servirFichier rend une piece jointe.
//
// LECTURE RESERVEE AUX MEMBRES. Le BBS a une surface publique, mais les pieces
// jointes suivent le contenu local : les servir a tout venant rendrait
// publiques les images d'un fil qui ne l'est pas — et l'adresse d'un fichier
// est un simple numero, donc devinable.
func (s *Server) servirFichier(w http.ResponseWriter, r *http.Request) {
	v := s.qui(r)
	brut := strings.TrimPrefix(r.URL.Path, "/f/")
	if i := strings.IndexByte(brut, '/'); i >= 0 {
		brut = brut[:i]
	}
	// L'extension est DECORATIVE : elle aide l'affichage et le telechargement,
	// elle ne designe rien. L'identifiant seul resout le fichier, et le type
	// servi vient de la base — pas de cette extension, qui est fournie par
	// l'adresse donc par le client.
	if i := strings.IndexByte(brut, '.'); i >= 0 {
		brut = brut[:i]
	}
	id, err := strconv.ParseInt(brut, 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	f, err := s.st.Fichier(id)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	// ACCES : un fichier PUBLIC (cité dans un post public d'un fil public) est
	// servi à tout venant — aussi accessible que le message qui le porte (#1114).
	// Un fichier 'local' reste réservé aux membres : un fil non public ne doit
	// pas voir ses images fuiter, et l'adresse `/f/NN` est un simple numéro
	// devinable.
	if !v.Connecte && f.Visibility != "public" {
		http.Error(w, "reserve aux membres", http.StatusForbidden)
		return
	}

	// Le type vient du MAGASIN : c'est celui reconnu au depot, apres reniflage.
	w.Header().Set("Content-Type", f.Mime)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	// Le nom d'origine ne sert qu'a la sauvegarde cote lecteur, et il est
	// echappe : un nom peut contenir des guillemets ou des retours a la ligne,
	// qui couperaient l'en-tete en deux.
	w.Header().Set("Content-Disposition",
		fmt.Sprintf("inline; filename*=UTF-8''%s", url.PathEscape(f.Name)))
	// Une piece jointe ne change jamais : son contenu est fige a l'identifiant.
	// `immutable` evite une revalidation par image sur un fil qui en porte
	// vingt — ce qui compte sur une board a quatre coeurs.
	w.Header().Set("Cache-Control", "private, max-age=604800, immutable")
	http.ServeFile(w, r, s.st.CheminFichier(f))
}

// deposerFichier recoit un envoi et rend l'adresse a inserer.
//
// Repond en JSON quand le client le demande (l'editeur), en redirection sinon
// (formulaire sans JavaScript) : les deux chemins doivent marcher, sans quoi
// l'envoi devient une fonction reservee aux navigateurs recents.
func (s *Server) deposerFichier(w http.ResponseWriter, r *http.Request) {
	v := s.qui(r)
	if !v.Connecte {
		http.Error(w, "reserve aux membres", http.StatusForbidden)
		return
	}
	if r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	if err := r.ParseMultipartForm(tailleFormulaire); err != nil {
		s.reponseDepot(w, r, "", "envoi illisible : "+err.Error())
		return
	}
	// LE JETON ANTI-REJEU EST VERIFIE APRES l'analyse du formulaire : il y est
	// contenu. L'ordre inverse ferait echouer toute verification.
	if err := s.verifieCSRF(r); err != nil {
		s.reponseDepot(w, r, "", err.Error())
		return
	}
	fh, entete, err := r.FormFile("fichier")
	if err != nil {
		s.reponseDepot(w, r, "", "aucun fichier recu")
		return
	}
	defer fh.Close()

	f, err := s.st.DeposeFichier(v.ID, entete.Filename,
		entete.Header.Get("Content-Type"), fh)
	if err != nil {
		s.reponseDepot(w, r, "", err.Error())
		return
	}
	// L'ADRESSE PORTE L'EXTENSION. Le serveur connait le type ; l'adresse nue
	// `/f/12` ne le dit pas, et l'affichage ne saurait alors pas s'il faut une
	// image, un lecteur audio ou une video. Faire deviner au rendu ce que le
	// depot savait deja etait le defaut du premier jet : la piece jointe
	// restait un lien mort dans le message.
	s.reponseDepot(w, r, "/f/"+strconv.FormatInt(f.ID, 10)+extensionDe(f.Mime), "")
}

func (s *Server) reponseDepot(w http.ResponseWriter, r *http.Request, url_, erreur string) {
	if strings.Contains(r.Header.Get("Accept"), "application/json") {
		w.Header().Set("Content-Type", "application/json")
		if erreur != "" {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintf(w, `{"ok":false,"error":%q}`, erreur)
			return
		}
		fmt.Fprintf(w, `{"ok":true,"url":%q}`, url_)
		return
	}
	// Sans JavaScript : on revient d'ou l'on vient, avec le resultat en clair.
	retour := r.FormValue("retour")
	if retour == "" || !strings.HasPrefix(retour, "/") || strings.HasPrefix(retour, "//") {
		retour = "/"
	}
	sep := "?"
	if strings.Contains(retour, "?") {
		sep = "&"
	}
	if erreur != "" {
		http.Redirect(w, r, retour+sep+"err="+url.QueryEscape(erreur), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, retour+sep+"msg="+url.QueryEscape("fichier déposé : "+url_),
		http.StatusSeeOther)
}

// poserAvatar remplace l'icone d'initiales par une image.
//
// L'avatar n'est qu'une piece jointe DONT ON RETIENT L'IDENTIFIANT : meme
// reniflage, meme liste blanche, meme borne. Un chemin d'envoi separe aurait
// duplique ces trois regles, donc fini par en oublier une.
func (s *Server) poserAvatar(w http.ResponseWriter, r *http.Request) {
	v := s.qui(r)
	if !v.Connecte {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	if err := r.ParseMultipartForm(tailleFormulaire); err != nil {
		http.Redirect(w, r, "/compte?err="+url.QueryEscape("envoi illisible"), http.StatusSeeOther)
		return
	}
	if err := s.verifieCSRF(r); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	if r.FormValue("action") == "retirer" {
		s.st.PoseAvatar(v.ID, 0)
		http.Redirect(w, r, "/compte?msg="+url.QueryEscape("avatar retiré"), http.StatusSeeOther)
		return
	}
	fh, entete, err := r.FormFile("avatar")
	if err != nil {
		http.Redirect(w, r, "/compte?err="+url.QueryEscape("aucune image reçue"), http.StatusSeeOther)
		return
	}
	defer fh.Close()

	f, err := s.st.DeposeFichier(v.ID, entete.Filename,
		entete.Header.Get("Content-Type"), fh)
	if err != nil {
		http.Redirect(w, r, "/compte?err="+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}
	// UNE IMAGE, PAS UN SON. La liste blanche du magasin accepte aussi l'audio
	// et la video : un avatar sonore serait accepte au depot et ne s'afficherait
	// nulle part.
	if !f.EstImage() {
		s.st.SupprimeFichier(v.ID, f.ID)
		http.Redirect(w, r, "/compte?err="+url.QueryEscape("un avatar doit être une image"),
			http.StatusSeeOther)
		return
	}
	if err := s.st.PoseAvatar(v.ID, f.ID); err != nil {
		http.Redirect(w, r, "/compte?err="+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/compte?msg="+url.QueryEscape("avatar posé"), http.StatusSeeOther)
}
