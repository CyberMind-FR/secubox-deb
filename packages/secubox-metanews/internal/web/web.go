// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// Package web : API HTTP + interface embarquée de MetaNews.
package web

import (
	"bytes"
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/CyberMind-FR/secubox-deb/secubox-metanews/internal/pipeline"
	"github.com/CyberMind-FR/secubox-deb/secubox-metanews/internal/store"
)

//go:embed static/*
var assets embed.FS

// Options de configuration du serveur.
type Options struct {
	JWTSecret string
	BBSSocket string // /run/secubox/bbs.sock
	BBSCat    int64  // catégorie BBS des fils MetaNews
}

// Serveur MetaNews.
type Serveur struct {
	st      *store.Store
	pipe    *pipeline.Pipe
	opt     Options
	mux     *http.ServeMux
	jr      *log.Logger
	version string
}

// New construit le serveur et enregistre les routes.
func New(st *store.Store, pipe *pipeline.Pipe, opt Options, jr *log.Logger, version string) *Serveur {
	s := &Serveur{st: st, pipe: pipe, opt: opt, mux: http.NewServeMux(), jr: jr, version: version}
	s.routes()
	return s
}

// Handler expose le routeur.
func (s *Serveur) Handler() http.Handler { return s.mux }

func (s *Serveur) routes() {
	const p = "/api/v1/metanews"
	// Public (lecture).
	s.mux.HandleFunc("GET "+p+"/health", s.health)
	s.mux.HandleFunc("GET "+p+"/status", s.status)
	s.mux.HandleFunc("GET "+p+"/topics", s.topics)
	s.mux.HandleFunc("GET "+p+"/topics/{id}", s.topic)
	s.mux.HandleFunc("GET "+p+"/topics/{id}/sources", s.topicSources)
	s.mux.HandleFunc("GET "+p+"/categories", s.categories)
	s.mux.HandleFunc("GET "+p+"/tags", s.tags)
	s.mux.HandleFunc("GET "+p+"/search", s.search)
	s.mux.HandleFunc("GET "+p+"/sources", s.sources)
	// Écriture (JWT).
	s.mux.HandleFunc("POST "+p+"/sources", s.jwt(s.sourceAdd))
	s.mux.HandleFunc("PATCH "+p+"/sources/{id}", s.jwt(s.sourcePatch))
	s.mux.HandleFunc("DELETE "+p+"/sources/{id}", s.jwt(s.sourceDelete))
	s.mux.HandleFunc("POST "+p+"/sources/{id}/test", s.jwt(s.sourceTest))
	s.mux.HandleFunc("POST "+p+"/topics/{id}/discuss", s.jwt(s.discuss))
	// UI.
	s.mux.HandleFunc("GET /", s.ui)
	s.mux.Handle("GET /static/", http.FileServer(http.FS(assets)))
}

// ── util ─────────────────────────────────────────────────────────────────────

func ecrire(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func (s *Serveur) jwt(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if _, err := verifierJeton(tok, s.opt.JWTSecret); err != nil {
			ecrire(w, http.StatusUnauthorized, map[string]any{"ok": false, "erreur": "jwt"})
			return
		}
		h(w, r)
	}
}

// ── lecture ──────────────────────────────────────────────────────────────────

func (s *Serveur) health(w http.ResponseWriter, _ *http.Request) {
	ecrire(w, 200, map[string]any{"ok": true, "module": "metanews", "version": s.version})
}

func (s *Serveur) status(w http.ResponseWriter, _ *http.Request) {
	srcs, _ := s.st.Sources()
	tops, _ := s.st.SujetsListe("", 100000)
	ecrire(w, 200, map[string]any{"ok": true, "module": "metanews", "version": s.version,
		"sources": len(srcs), "topics": len(tops)})
}

func (s *Serveur) topics(w http.ResponseWriter, r *http.Request) {
	cat := r.URL.Query().Get("category")
	tops, err := s.st.SujetsListe(cat, 60)
	if err != nil {
		ecrire(w, 500, map[string]any{"ok": false, "erreur": err.Error()})
		return
	}
	noms := s.nomsSources()
	vues := make([]map[string]any, 0, len(tops))
	for _, t := range tops {
		vues = append(vues, s.vueTopic(t, noms, false))
	}
	ecrire(w, 200, map[string]any{"ok": true, "topics": vues})
}

func (s *Serveur) topic(w http.ResponseWriter, r *http.Request) {
	t, err := s.st.SujetParID(r.PathValue("id"))
	if err != nil {
		ecrire(w, 404, map[string]any{"ok": false, "erreur": "introuvable"})
		return
	}
	v := s.vueTopic(t, s.nomsSources(), true)
	tl, _ := s.st.Timeline(t.ID)
	v["timeline"] = tl
	ecrire(w, 200, map[string]any{"ok": true, "topic": v})
}

func (s *Serveur) topicSources(w http.ResponseWriter, r *http.Request) {
	ecrire(w, 200, map[string]any{"ok": true, "sources": s.sourcesDuSujet(r.PathValue("id"))})
}

func (s *Serveur) categories(w http.ResponseWriter, _ *http.Request) {
	srcs, _ := s.st.Sources()
	cnt := map[string]int{}
	for _, x := range srcs {
		cnt[x.Category]++
	}
	ecrire(w, 200, map[string]any{"ok": true, "categories": cnt})
}

func (s *Serveur) tags(w http.ResponseWriter, _ *http.Request) {
	tops, _ := s.st.SujetsListe("", 500)
	cnt := map[string]int{}
	for _, t := range tops {
		for _, g := range t.Tags {
			cnt[g]++
		}
	}
	type kv struct {
		Tag string `json:"tag"`
		N   int    `json:"n"`
	}
	var out []kv
	for k, v := range cnt {
		out = append(out, kv{k, v})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].N > out[j].N })
	if len(out) > 40 {
		out = out[:40]
	}
	ecrire(w, 200, map[string]any{"ok": true, "tags": out})
}

func (s *Serveur) search(w http.ResponseWriter, r *http.Request) {
	q := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q")))
	tops, _ := s.st.SujetsListe("", 500)
	noms := s.nomsSources()
	var out []map[string]any
	for _, t := range tops {
		hay := strings.ToLower(t.Title + " " + t.Summary + " " + strings.Join(t.Tags, " ") + " " + strings.Join(t.Entities, " "))
		if q == "" || strings.Contains(hay, q) {
			out = append(out, s.vueTopic(t, noms, false))
		}
	}
	ecrire(w, 200, map[string]any{"ok": true, "topics": out})
}

func (s *Serveur) sources(w http.ResponseWriter, _ *http.Request) {
	srcs, _ := s.st.Sources()
	ecrire(w, 200, map[string]any{"ok": true, "sources": srcs})
}

// ── écriture ─────────────────────────────────────────────────────────────────

func (s *Serveur) sourceAdd(w http.ResponseWriter, r *http.Request) {
	var in store.Source
	if json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&in) != nil || in.URL == "" {
		ecrire(w, 400, map[string]any{"ok": false, "erreur": "url requise"})
		return
	}
	if in.Slug == "" {
		in.Slug = slug(in.Name, in.URL)
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

func (s *Serveur) sourceTest(w http.ResponseWriter, r *http.Request) {
	var in struct {
		URL string `json:"url"`
	}
	_ = json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&in)
	items, err := s.pipe.TesterURL(in.URL)
	if err != nil {
		ecrire(w, 200, map[string]any{"ok": false, "erreur": err.Error()})
		return
	}
	ecrire(w, 200, map[string]any{"ok": true, "articles": items})
}

// discuss ouvre (ou retrouve) le fil BBS d'un sujet.
func (s *Serveur) discuss(w http.ResponseWriter, r *http.Request) {
	t, err := s.st.SujetParID(r.PathValue("id"))
	if err != nil {
		ecrire(w, 404, map[string]any{"ok": false})
		return
	}
	if t.BBSThreadID != 0 { // idempotent
		ecrire(w, 200, map[string]any{"ok": true, "thread_id": t.BBSThreadID, "slug": t.BBSSlug, "existant": true})
		return
	}
	corps := s.corpsFil(t)
	tid, slug, err := s.pousserFilBBS(t.Title, corps, s.leadURL(t.ID))
	if err != nil {
		ecrire(w, 502, map[string]any{"ok": false, "erreur": "BBS: " + err.Error()})
		return
	}
	_ = s.st.FixerFilBBS(t.ID, tid, slug)
	ecrire(w, 200, map[string]any{"ok": true, "thread_id": tid, "slug": slug})
}

// pousserFilBBS = le POKE vers le BBS : POST /api/v1/bbs/threads via la socket.
func (s *Serveur) pousserFilBBS(titre, corps, srcURL string) (int64, string, error) {
	body, _ := json.Marshal(map[string]any{
		"title": titre, "body": corps, "category": s.opt.BBSCat,
		"source_url": srcURL, "visibility": "local",
	})
	cli := &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", s.opt.BBSSocket)
		}}}
	req, _ := http.NewRequest("POST", "http://bbs/api/v1/bbs/threads", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+signerJeton(s.opt.JWTSecret, "metanews", 2*time.Minute))
	resp, err := cli.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode != 200 {
		return 0, "", fmt.Errorf("HTTP %d %s", resp.StatusCode, strings.TrimSpace(string(rb)))
	}
	var out struct {
		ThreadID int64  `json:"thread_id"`
		Slug     string `json:"slug"`
	}
	_ = json.Unmarshal(rb, &out)
	return out.ThreadID, out.Slug, nil
}

func (s *Serveur) corpsFil(t store.Topic) string {
	var b strings.Builder
	fmt.Fprintf(&b, "MetaNews · %s\n\nRésumé :\n%s\n\nSources :\n",
		time.Unix(t.UpdatedAt, 0).UTC().Format("2006-01-02"), t.Summary)
	for _, srcv := range s.sourcesDuSujet(t.ID) {
		fmt.Fprintf(&b, "• %s — %s\n", srcv["name"], srcv["url"])
	}
	if len(t.Tags) > 0 {
		b.WriteString("\n")
		for _, g := range t.Tags {
			fmt.Fprintf(&b, "#%s ", g)
		}
	}
	return b.String()
}

// ── vues ─────────────────────────────────────────────────────────────────────

func (s *Serveur) nomsSources() map[int64]string {
	srcs, _ := s.st.Sources()
	m := map[int64]string{}
	for _, x := range srcs {
		m[x.ID] = x.Name
	}
	return m
}

func (s *Serveur) sourcesDuSujet(topicID string) []map[string]any {
	arts, _ := s.st.ArticlesDuSujet(topicID)
	noms := s.nomsSources()
	vu := map[string]bool{}
	var out []map[string]any
	for _, a := range arts {
		if vu[a.Fingerprint] { // clones fondus
			continue
		}
		vu[a.Fingerprint] = true
		out = append(out, map[string]any{
			"name": noms[a.SourceID], "title": a.Title, "url": a.URL, "published_at": a.PublishedAt,
		})
	}
	return out
}

func (s *Serveur) leadURL(topicID string) string {
	if ss := s.sourcesDuSujet(topicID); len(ss) > 0 {
		return fmt.Sprint(ss[0]["url"])
	}
	return ""
}

func (s *Serveur) vueTopic(t store.Topic, noms map[int64]string, complet bool) map[string]any {
	v := map[string]any{
		"id": t.ID, "title": t.Title, "summary": t.Summary,
		"tags": dieze(t.Tags), "sources_count": t.SourcesCount,
		"updated_at": t.UpdatedAt, "confidence": t.Confidence, "importance": t.Importance,
		"bbs_thread_id": t.BBSThreadID, "bbs_slug": t.BBSSlug,
	}
	src := s.sourcesDuSujet(t.ID)
	var noms2 []string
	for _, x := range src {
		noms2 = append(noms2, fmt.Sprint(x["name"]))
	}
	v["source_names"] = noms2
	if complet {
		v["sources"] = src
	}
	return v
}

func dieze(tags []string) []string {
	out := make([]string, 0, len(tags))
	for _, t := range tags {
		out = append(out, "#"+t)
	}
	if len(out) > 6 {
		out = out[:6]
	}
	return out
}

func (s *Serveur) ui(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	b, err := assets.ReadFile("static/index.html")
	if err != nil {
		http.Error(w, "ui", 500)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(b)
}

func slug(name, url string) string {
	base := name
	if base == "" {
		base = url
	}
	base = strings.ToLower(base)
	var b strings.Builder
	for _, r := range base {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			b.WriteRune(r)
		} else if b.Len() > 0 && b.String()[b.Len()-1] != '-' {
			b.WriteByte('-')
		}
	}
	out := strings.Trim(b.String(), "-")
	if len(out) > 40 {
		out = out[:40]
	}
	if out == "" {
		out = fmt.Sprintf("src%d", time.Now().UnixNano()%100000)
	}
	return out
}
