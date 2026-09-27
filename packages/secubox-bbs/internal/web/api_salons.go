// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// SecuBox-Deb :: BBS — salons, passerelles et journal pour la webui d'admin (#1523)
//
// La console /sysop gérait seule les salons et sous-salons, les salons privés
// (membres, communautés SBX OS, liens d'invitation), les passerelles et le
// journal de modération ; la page BBS de la webui d'administration n'en avait
// rien. Ces routes en sont le pendant JSON : MÊMES fonctions du store que les
// formulaires /mod/*, donc mêmes règles et même journal. Rien de neuf côté
// données — seulement une seconde porte, gardée comme les autres routes admin.
package web

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/CyberMind-FR/secubox-deb/secubox-bbs/internal/store"
)

// adminActeur : la garde de `admin`, plus QUI agit. Le journal de modération
// nomme un compte BBS : celui lié à la personne SBX OS de l'administrateur, à
// défaut son nom SecuBox (« gk2 »). Sans compte BBS, on refuse : un geste
// journalisé au nom de personne n'est pas un geste encadré.
func (s *Server) adminActeur(h func(http.ResponseWriter, *http.Request, int64)) http.HandlerFunc {
	return s.admin(func(w http.ResponseWriter, r *http.Request) {
		ses, _ := s.verif(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
		for _, nom := range []string{ses.Bbs, ses.User} {
			if strings.TrimSpace(nom) == "" {
				continue
			}
			if id, err := s.st.UserByHandleNocase(nom); err == nil {
				h(w, r, id)
				return
			}
		}
		jsonErr(w, http.StatusForbidden, "aucun compte BBS pour cet administrateur — le journal doit nommer quelqu'un")
	})
}

func (s *Server) routesSalonsAdmin() {
	s.mux.HandleFunc("GET /api/v1/bbs/admin/salons", s.admin(s.apiSalonsLister))
	s.mux.HandleFunc("POST /api/v1/bbs/admin/salons", s.adminActeur(s.apiSalonCreer))
	s.mux.HandleFunc("POST /api/v1/bbs/admin/salons/{id}/prive", s.adminActeur(s.apiSalonPrive))
	s.mux.HandleFunc("POST /api/v1/bbs/admin/salons/{id}/membres", s.adminActeur(s.apiSalonMembre))
	s.mux.HandleFunc("POST /api/v1/bbs/admin/salons/{id}/communautes", s.adminActeur(s.apiSalonCommunaute))
	s.mux.HandleFunc("POST /api/v1/bbs/admin/salons/{id}/invitation", s.adminActeur(s.apiSalonInvitation))
	s.mux.HandleFunc("GET /api/v1/bbs/admin/passerelles", s.admin(s.apiPasserelles))
	s.mux.HandleFunc("GET /api/v1/bbs/admin/moderation", s.admin(s.apiModerations))
}

type salonVue struct {
	ID          int64               `json:"id"`
	Slug        string              `json:"slug"`
	Titre       string              `json:"titre"`
	Desc        string              `json:"desc"`
	Fils        int                 `json:"fils"`
	Public      bool                `json:"public"`
	Prive       bool                `json:"prive"`
	Parent      int64               `json:"parent"`
	Profondeur  int                 `json:"profondeur"`
	Membres     []map[string]any    `json:"membres"`
	Communautes []map[string]string `json:"communautes"`
}

// GET /api/v1/bbs/admin/salons — l'arbre à plat (profondeur), avec pour chaque
// salon privé ses membres nommés et ses communautés. Plus les listes dont
// l'écran a besoin pour convier : comptes actifs, communautés SBX OS actives.
func (s *Server) apiSalonsLister(w http.ResponseWriter, r *http.Request) {
	cats, err := s.st.Categories(false)
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := make([]salonVue, 0, len(cats))
	for _, c := range cats {
		v := salonVue{ID: c.ID, Slug: c.Slug, Titre: c.Title, Desc: c.Desc, Fils: c.Threads,
			Public: c.Public, Prive: c.Prive, Parent: c.ParentID, Profondeur: c.Profondeur,
			Membres: []map[string]any{}, Communautes: []map[string]string{}}
		if c.Prive {
			if ms, e := s.st.MembresDuSalon(c.ID); e == nil {
				for _, m := range ms {
					v.Membres = append(v.Membres, map[string]any{"id": m.ID, "handle": m.Handle})
				}
			}
			if cs, e := s.st.CommunautesDuSalon(c.ID); e == nil {
				for _, x := range cs {
					v.Communautes = append(v.Communautes, map[string]string{"uuid": x.UUID, "nom": x.Nom})
				}
			}
		}
		out = append(out, v)
	}
	comptes := []map[string]any{}
	if us, e := s.st.Users(); e == nil {
		for _, u := range us {
			if !u.Disabled {
				comptes = append(comptes, map[string]any{"id": u.ID, "handle": u.Handle})
			}
		}
	}
	comms := []map[string]string{}
	if cs, e := s.st.CommunautesActives(); e == nil {
		for _, x := range cs {
			comms = append(comms, map[string]string{"uuid": x.UUID, "nom": x.Nom})
		}
	}
	jsonOK(w, map[string]any{"ok": true, "salons": out, "comptes": comptes, "communautes": comms})
}

func lisCorps(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(v); err != nil {
		jsonErr(w, http.StatusBadRequest, "corps JSON illisible")
		return false
	}
	return true
}

func idSalon(w http.ResponseWriter, r *http.Request) (int64, bool) {
	var id int64
	for _, ch := range r.PathValue("id") {
		if ch < '0' || ch > '9' {
			jsonErr(w, http.StatusBadRequest, "salon invalide")
			return 0, false
		}
		id = id*10 + int64(ch-'0')
		if id > 1<<40 {
			jsonErr(w, http.StatusBadRequest, "salon invalide")
			return 0, false
		}
	}
	if id == 0 {
		jsonErr(w, http.StatusBadRequest, "salon invalide")
		return 0, false
	}
	return id, true
}

// resultat : l'erreur du store est DITE, comme sur /mod/* (un geste qui échoue
// en silence laisse croire qu'il a porté).
func resultat(w http.ResponseWriter, err error, v map[string]any) {
	if err != nil {
		code := http.StatusBadRequest
		if errors.Is(err, store.ErrIntrouvable) {
			code = http.StatusNotFound
		}
		jsonErr(w, code, err.Error())
		return
	}
	if v == nil {
		v = map[string]any{}
	}
	v["ok"] = true
	jsonOK(w, v)
}

// POST /api/v1/bbs/admin/salons {slug, titre, desc, parent}
func (s *Server) apiSalonCreer(w http.ResponseWriter, r *http.Request, acteur int64) {
	var c struct {
		Slug, Titre, Desc string
		Parent            int64
	}
	if !lisCorps(w, r, &c) {
		return
	}
	id, err := s.st.CreeSousSalon(acteur, c.Slug, c.Titre, c.Desc, c.Parent)
	resultat(w, err, map[string]any{"id": id})
}

// POST …/{id}/prive {prive: true|false} — le rang n'est pas touché.
func (s *Server) apiSalonPrive(w http.ResponseWriter, r *http.Request, acteur int64) {
	id, ok := idSalon(w, r)
	var c struct{ Prive bool }
	if !ok || !lisCorps(w, r, &c) {
		return
	}
	resultat(w, s.st.RendPrive(id, c.Prive), nil)
}

// POST …/{id}/membres {membre, action: ajouter|retirer}
func (s *Server) apiSalonMembre(w http.ResponseWriter, r *http.Request, acteur int64) {
	id, ok := idSalon(w, r)
	var c struct {
		Membre int64
		Action string
	}
	if !ok || !lisCorps(w, r, &c) {
		return
	}
	if c.Action == "retirer" {
		resultat(w, s.st.RetireMembre(id, c.Membre), nil)
		return
	}
	resultat(w, s.st.AjouteMembre(id, c.Membre, acteur), nil)
}

// POST …/{id}/communautes {communaute, action} — le nom vient de sbx.db, jamais
// du corps : on n'ouvre qu'à une communauté qui existe et n'est pas archivée.
func (s *Server) apiSalonCommunaute(w http.ResponseWriter, r *http.Request, acteur int64) {
	id, ok := idSalon(w, r)
	var c struct{ Communaute, Action string }
	if !ok || !lisCorps(w, r, &c) {
		return
	}
	if c.Action == "retirer" {
		resultat(w, s.st.FermeACommunaute(id, c.Communaute), nil)
		return
	}
	comms, err := s.st.CommunautesActives()
	if err != nil {
		resultat(w, err, nil)
		return
	}
	for _, x := range comms {
		if x.UUID == c.Communaute {
			resultat(w, s.st.OuvreACommunaute(id, x, acteur), nil)
			return
		}
	}
	jsonErr(w, http.StatusNotFound, "communauté inconnue ou archivée")
}

// POST …/{id}/invitation — le code n'est rendu QU'UNE fois (la base n'en garde
// que l'empreinte) ; il n'ouvre aucun compte.
func (s *Server) apiSalonInvitation(w http.ResponseWriter, r *http.Request, acteur int64) {
	id, ok := idSalon(w, r)
	if !ok {
		return
	}
	code, err := s.st.NouvelleInvitationSalon(id, acteur)
	resultat(w, err, map[string]any{"lien": "/salon/rejoindre?code=" + code})
}

// GET /api/v1/bbs/admin/passerelles — les derniers imports (comme /sysop).
func (s *Server) apiPasserelles(w http.ResponseWriter, r *http.Request) {
	runs, err := s.st.IngestRuns(24)
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := make([]map[string]any, 0, len(runs))
	for _, x := range runs {
		out = append(out, map[string]any{"source": x.Source, "a": x.RanAt, "vus": x.Seen,
			"crees": x.Created, "ignores": x.Skipped, "erreur": x.Error})
	}
	jsonOK(w, map[string]any{"ok": true, "passerelles": out})
}

// GET /api/v1/bbs/admin/moderation — le journal n'a de valeur que s'il est LU.
func (s *Server) apiModerations(w http.ResponseWriter, r *http.Request) {
	ms, err := s.st.Moderations(100)
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := make([]map[string]any, 0, len(ms))
	for _, m := range ms {
		out = append(out, map[string]any{"a": m.At, "acteur": m.Acteur, "geste": m.Action,
			"cible": m.Cible, "detail": m.Detail})
	}
	jsonOK(w, map[string]any{"ok": true, "journal": out})
}
