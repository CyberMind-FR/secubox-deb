// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
//
// Article collaboratif (#1056 stage 3) : écrire À PLUSIEURS MAINS un article à
// partir d'un dossier, puis le PUBLIER vers billets (la face publique). Chaque
// contribution est attribuée ; l'article reste privé (BBS) tant qu'il n'est pas
// publié. Réservé aux membres.
package web

import (
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/CyberMind-FR/secubox-deb/secubox-bbs/internal/billets"
	"github.com/CyberMind-FR/secubox-deb/secubox-bbs/internal/store"
)

// article dispatche /article/nouveau, /article/{id}, /article/{id}/part,
// /article/{id}/publier.
func (s *Server) article(w http.ResponseWriter, r *http.Request) {
	v := s.qui(r)
	if !v.Connecte {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	rest := strings.TrimPrefix(r.URL.Path, "/article/")
	if rest == "nouveau" {
		s.articleNouveau(w, r, v)
		return
	}
	seg := strings.SplitN(rest, "/", 2)
	var id int64
	fmtSscan(seg[0], &id)
	if id == 0 {
		http.NotFound(w, r)
		return
	}
	action := ""
	if len(seg) == 2 {
		action = seg[1]
	}
	switch {
	case action == "part" && r.Method == http.MethodPost:
		s.articlePart(w, r, v, id)
	case action == "publier" && r.Method == http.MethodPost:
		s.articlePublier(w, r, v, id)
	default:
		s.articleVue(w, r, v, id)
	}
}

func fmtSscan(s string, id *int64) {
	if n, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64); err == nil {
		*id = n
	}
}

// articleNouveau : GET rend le composeur (titre + première contribution),
// éventuellement pré-rempli depuis un dossier (?t=<threadID>) ; POST crée
// l'article et sa première contribution, puis ouvre l'éditeur.
func (s *Server) articleNouveau(w http.ResponseWriter, r *http.Request, v visiteur) {
	p, _ := s.base(r, "article")
	p.Titre = "Co-écrire un article"
	if r.Method != http.MethodPost {
		if t := r.URL.Query().Get("t"); t != "" {
			var tid int64
			fmtSscan(t, &tid)
			if th, err := s.st.ThreadByID(tid); err == nil {
				p.Art = store.Article{ThreadID: tid, Title: th.Title}
			}
		}
		s.rendDef(w, r, "article", "article", p)
		return
	}
	if err := s.verifieCSRF(r); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	titre := strings.TrimSpace(r.PostFormValue("title"))
	corps := strings.TrimSpace(r.PostFormValue("body"))
	var tid int64
	fmtSscan(r.PostFormValue("thread_id"), &tid)
	if titre == "" || corps == "" {
		p.Err = "Un titre et une première contribution sont nécessaires."
		p.Art = store.Article{ThreadID: tid, Title: titre}
		s.rendDef(w, r, "article", "article", p)
		return
	}
	id, err := s.st.CreerArticle(titre, tid, v.ID)
	if err != nil {
		p.Err = "Création impossible : " + err.Error()
		s.rendDef(w, r, "article", "article", p)
		return
	}
	if err := s.st.AjouterPart(id, v.ID, corps); err != nil {
		p.Err = "La première contribution n'a pas pu être enregistrée : " + err.Error()
	}
	http.Redirect(w, r, "/article/"+itoa64(id), http.StatusSeeOther)
}

// articleVue rend l'éditeur : entête, co-auteurs, contributions attribuées,
// et le formulaire pour ajouter la sienne (ou publier).
func (s *Server) articleVue(w http.ResponseWriter, r *http.Request, v visiteur, id int64) {
	p, _ := s.base(r, "article")
	a, parts, err := s.st.Article(id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	p.Art = a
	p.Parts = parts
	p.Titre = a.Title
	s.rendDef(w, r, "article", "article", p)
}

// articlePart ajoute une contribution attribuée à l'appelant.
func (s *Server) articlePart(w http.ResponseWriter, r *http.Request, v visiteur, id int64) {
	if err := s.verifieCSRF(r); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	corps := strings.TrimSpace(r.PostFormValue("body"))
	if corps != "" {
		if err := s.st.AjouterPart(id, v.ID, corps); err != nil {
			http.Error(w, "contribution refusée", http.StatusInternalServerError)
			return
		}
	}
	http.Redirect(w, r, "/article/"+itoa64(id), http.StatusSeeOther)
}

// articlePublier assemble les contributions et PUBLIE l'article vers billets —
// la face publique. On relaie la session de l'opérateur (le BBS n'a pas
// d'identité propre chez billets). L'article passe alors « publié ».
func (s *Server) articlePublier(w http.ResponseWriter, r *http.Request, v visiteur, id int64) {
	if err := s.verifieCSRF(r); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	if s.bil == nil {
		http.Error(w, "module billets non configuré", http.StatusServiceUnavailable)
		return
	}
	a, parts, err := s.st.Article(id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if a.Status == "published" && a.PublishedURL != "" {
		http.Redirect(w, r, a.PublishedURL, http.StatusSeeOther)
		return
	}
	// Assemblage : les contributions dans l'ordre, chacune précédée de sa
	// signature. Un article à plusieurs mains dit qui a écrit quoi.
	var b strings.Builder
	for _, pt := range parts {
		if pt.Auteur != "" {
			b.WriteString("**" + pt.Auteur + "**\n\n")
		}
		b.WriteString(pt.Body)
		b.WriteString("\n\n")
	}
	var session string
	if c, err := r.Cookie("secubox_session"); err == nil {
		session = c.Value
	}
	f := billets.Fil{
		ID: id, Titre: a.Title, Public: true, Session: session, Attribuer: true,
		Retour:   "https://" + r.Host + "/article/" + itoa64(id),
		Messages: []billets.Message{{Auteur: strings.Join(a.CoAuteurs, ", "), Corps: b.String(), Public: true}},
	}
	res, err := s.bil.Publier(f)
	if err != nil {
		p, _ := s.base(r, "article")
		p.Art, p.Parts = a, parts
		p.Err = "Publication refusée par billets : " + err.Error()
		s.rendDef(w, r, "article", "article", p)
		return
	}
	if err := s.st.MarquerArticlePublie(id, res.URL); err != nil {
		// Publié chez billets mais non marqué ici : on n'échoue pas la vue, on
		// redirige quand même vers l'adresse publique.
		log.Printf("article %d publié mais non marqué : %v", id, err)
	}
	if res.URL != "" {
		http.Redirect(w, r, res.URL, http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/article/"+itoa64(id), http.StatusSeeOther)
}
