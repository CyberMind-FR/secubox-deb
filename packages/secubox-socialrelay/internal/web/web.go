// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// Package web : API HTTP + interface embarquée de SocialRelay.
package web

import (
	"embed"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/CyberMind-FR/secubox-deb/secubox-socialrelay/internal/fbauth"
	"github.com/CyberMind-FR/secubox-deb/secubox-socialrelay/internal/linker"
	"github.com/CyberMind-FR/secubox-deb/secubox-socialrelay/internal/mediacache"
	"github.com/CyberMind-FR/secubox-deb/secubox-socialrelay/internal/store"
)

//go:embed static/*
var assets embed.FS

// Options du serveur.
type Options struct {
	JWTSecret string
	PubURL    string // base publique HTTPS, pour composer les URLs de médias
}

// Serveur SocialRelay.
type Serveur struct {
	st      *store.Store
	cache   *mediacache.Cache
	opt     Options
	mux     *http.ServeMux
	jr      *log.Logger
	version string
	fb      *fbauth.Store
}

// New construit le serveur.
func New(st *store.Store, cache *mediacache.Cache, opt Options, jr *log.Logger, version string) *Serveur {
	s := &Serveur{st: st, cache: cache, opt: opt, mux: http.NewServeMux(), jr: jr, version: version}
	s.routes()
	return s
}

// Handler expose le routeur.
func (s *Serveur) Handler() http.Handler { return s.mux }

func (s *Serveur) routes() {
	const p = "/api/v1/socialrelay"
	s.mux.HandleFunc("GET "+p+"/health", s.health)
	s.mux.HandleFunc("GET "+p+"/status", s.status)
	s.mux.HandleFunc("GET "+p+"/feed", s.feed)
	s.mux.HandleFunc("GET "+p+"/sources", s.sources)
	s.mux.HandleFunc("GET "+p+"/media/{hash}", s.media)
	s.mux.HandleFunc("GET "+p+"/covers", s.covers)
	s.mux.HandleFunc("POST "+p+"/sources", s.jwt(s.sourceAdd))
	s.mux.HandleFunc("PATCH "+p+"/sources/{id}", s.jwt(s.sourcePatch))
	s.mux.HandleFunc("DELETE "+p+"/sources/{id}", s.jwt(s.sourceDelete))
	s.mux.HandleFunc("GET /micro", s.micro)
	s.mux.HandleFunc("GET /", s.ui)
	s.mux.Handle("GET /static/", http.FileServer(http.FS(assets)))
}

func ecrire(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func (s *Serveur) jwt(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if verifierJeton(r.Header.Get("Authorization"), s.opt.JWTSecret) != nil {
			ecrire(w, http.StatusUnauthorized, map[string]any{"ok": false, "erreur": "jwt"})
			return
		}
		h(w, r)
	}
}

func (s *Serveur) health(w http.ResponseWriter, _ *http.Request) {
	ecrire(w, 200, map[string]any{"ok": true, "module": "socialrelay", "version": s.version})
}

func (s *Serveur) status(w http.ResponseWriter, _ *http.Request) {
	srcs, _ := s.st.Sources()
	posts, _ := s.st.PostsRecents(100000)
	ecrire(w, 200, map[string]any{"ok": true, "module": "socialrelay", "version": s.version,
		"sources": len(srcs), "posts": len(posts)})
}

type mediaLocal struct {
	Hash string `json:"hash"`
	Kind string `json:"kind"`
	Orig string `json:"orig"`
}

func (s *Serveur) feed(w http.ResponseWriter, r *http.Request) {
	limit := 40
	if n, _ := strconv.Atoi(r.URL.Query().Get("limit")); n > 0 && n <= 100 {
		limit = n
	}
	posts, _ := s.st.PostsRecents(limit)
	srcs, _ := s.st.Sources()
	nom := map[int64]string{}
	kind := map[int64]string{}
	for _, x := range srcs {
		nom[x.ID] = x.Name
		kind[x.ID] = x.Kind
	}
	out := make([]map[string]any, 0, len(posts))
	for _, po := range posts {
		var ml []mediaLocal
		_ = json.Unmarshal([]byte(po.Media), &ml)
		var medias []map[string]any
		for _, m := range ml {
			medias = append(medias, map[string]any{
				"url": "/api/v1/socialrelay/media/" + m.Hash, "kind": m.Kind,
			})
		}
		out = append(out, map[string]any{
			"id": po.ID, "author": po.Author, "text": po.Text, "url": po.URL,
			"published_at": po.PublishedAt, "source": nom[po.SourceID], "network": kind[po.SourceID],
			"medias": medias, "bbs_thread_id": po.BBSThreadID,
		})
	}
	ecrire(w, 200, map[string]any{"ok": true, "posts": out})
}

func (s *Serveur) sources(w http.ResponseWriter, _ *http.Request) {
	srcs, _ := s.st.Sources()
	out := make([]map[string]any, 0, len(srcs))
	for _, x := range srcs {
		out = append(out, map[string]any{
			"id": x.ID, "slug": x.Slug, "name": x.Name, "kind": x.Kind, "handle": x.Handle,
			"url": x.URL, "enabled": x.Enabled, "mode": linker.Mode(x.Kind), "salon": x.Salon,
			"last_error": x.LastError,
		})
	}
	ecrire(w, 200, map[string]any{"ok": true, "sources": out})
}

func (s *Serveur) media(w http.ResponseWriter, r *http.Request) {
	s.cache.Servir(w, r, r.PathValue("hash"))
}

// covers : pour une liste d'ID de fils BBS (?tids=1,2,3), rend l'URL PUBLIQUE
// LOCALE de la première image cachée de chaque post. Le BBS s'en sert pour
// afficher la vignette d'un fil-passerelle, anciens comme nouveaux.
func (s *Serveur) covers(w http.ResponseWriter, r *http.Request) {
	var ids []int64
	for _, part := range strings.Split(r.URL.Query().Get("tids"), ",") {
		if n, err := strconv.ParseInt(strings.TrimSpace(part), 10, 64); err == nil && n > 0 {
			ids = append(ids, n)
		}
	}
	if len(ids) > 240 {
		ids = ids[:240]
	}
	m, _ := s.st.CoversParFil(ids)
	base := strings.TrimRight(s.opt.PubURL, "/")
	out := make(map[string]string, len(m))
	for tid, hash := range m {
		out[strconv.FormatInt(tid, 10)] = base + "/api/v1/socialrelay/media/" + hash
	}
	ecrire(w, 200, map[string]any{"ok": true, "covers": out})
}

func (s *Serveur) sourceAdd(w http.ResponseWriter, r *http.Request) {
	var in store.Source
	if json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&in) != nil {
		ecrire(w, 400, map[string]any{"ok": false, "erreur": "corps"})
		return
	}
	if in.Handle == "" && in.URL == "" {
		ecrire(w, 400, map[string]any{"ok": false, "erreur": "handle ou url requis"})
		return
	}
	if in.Slug == "" {
		in.Slug = slug(in.Name, in.Handle+in.URL)
	}
	id, err := s.st.AddSource(in)
	if err != nil {
		ecrire(w, 400, map[string]any{"ok": false, "erreur": err.Error()})
		return
	}
	ecrire(w, 200, map[string]any{"ok": true, "id": id})
}

func (s *Serveur) sourcePatch(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	srcs, _ := s.st.Sources()
	var cur *store.Source
	for i := range srcs {
		if srcs[i].ID == id {
			cur = &srcs[i]
		}
	}
	if cur == nil {
		ecrire(w, 404, map[string]any{"ok": false})
		return
	}
	_ = json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(cur)
	cur.ID = id
	if err := s.st.UpdateSource(*cur); err != nil {
		ecrire(w, 400, map[string]any{"ok": false, "erreur": err.Error()})
		return
	}
	ecrire(w, 200, map[string]any{"ok": true})
}

func (s *Serveur) sourceDelete(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err := s.st.DeleteSource(id); err != nil {
		ecrire(w, 400, map[string]any{"ok": false, "erreur": err.Error()})
		return
	}
	ecrire(w, 200, map[string]any{"ok": true})
}

// micro sert la carte que SocialRelay affiche dans le Hall (#1264).
//
// Une passerelle qui agrege plusieurs reseaux n'est pas visible dans un post
// fige : elle l'est dans le DEFILEMENT. La carte tourne, et chaque tour dit
// aussi de quel reseau vient ce qu'on lit.
func (s *Serveur) micro(w http.ResponseWriter, r *http.Request) {
	b, err := assets.ReadFile("static/micro.html")
	if err != nil {
		http.Error(w, "micro", 500)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	// UNE CARTE EST UNE VUE VIVANTE (#1298). Sans en-tete de fraicheur, le
	// navigateur lui applique son cache heuristique : le cadre gardait une
	// version d'il y a des heures, et une correction deployee ne se voyait
	// jamais — on croyait le correctif rate alors qu'il n'etait pas relu.
	w.Header().Set("Cache-Control", "no-cache")
	_, _ = w.Write(b)
}

func (s *Serveur) ui(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	b, _ := assets.ReadFile("static/index.html")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(b)
}

func slug(name, alt string) string {
	base := strings.ToLower(name)
	if base == "" {
		base = strings.ToLower(alt)
	}
	var b strings.Builder
	for _, r := range base {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			b.WriteRune(r)
		} else if b.Len() > 0 && !strings.HasSuffix(b.String(), "-") {
			b.WriteByte('-')
		}
	}
	out := strings.Trim(b.String(), "-")
	if len(out) > 40 {
		out = out[:40]
	}
	if out == "" {
		out = "src" + strconv.FormatInt(time.Now().UnixNano()%100000, 10)
	}
	return out
}
