// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package web

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// metaVue : un événement MetaNews tel que la rédaction l'affiche — titre,
// résumé court, et surtout le NOMBRE et le NOM des sources corrélées (le cœur
// de MetaNews : plusieurs sources → un événement).
type metaVue struct {
	ID       string
	Titre    string
	Resume   string
	NbSrc    int64
	Sources  []string
	Tags     []string
	Lien     string
}

// Multi indique un événement corrélé sur PLUSIEURS sources (mis en avant).
func (m metaVue) Multi() bool { return m.NbSrc > 1 }

// vitrineMetaNews récupère une dizaine d'événements récents depuis la socket du
// module MetaNews (déjà classés par importance : le multi-source remonte). Une
// panne rend un message, jamais une page cassée — même patron que les billets.
func (s *Server) vitrineMetaNews() ([]metaVue, string) {
	if s.opt.MetaNewsSocket == "" {
		return nil, "module metanews non configuré."
	}
	cli := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", s.opt.MetaNewsSocket)
		}}}
	resp, err := cli.Get("http://metanews/api/v1/metanews/topics?category=une")
	if err != nil {
		return nil, "le flux MetaNews n'a pas pu être lu : " + err.Error()
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, "MetaNews a répondu " + resp.Status
	}
	var d struct {
		Topics []struct {
			ID       string   `json:"id"`
			Title    string   `json:"title"`
			Summary  string   `json:"summary"`
			NbSrc    int64    `json:"sources_count"`
			Sources  []string `json:"source_names"`
			Tags     []string `json:"tags"`
		} `json:"topics"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&d); err != nil {
		return nil, "réponse MetaNews illisible : " + err.Error()
	}
	base := strings.TrimRight(s.opt.MetaNewsBase, "/")
	out := make([]metaVue, 0, 10)
	for i, t := range d.Topics {
		if i >= 10 {
			break
		}
		lien := base + "/"
		if base == "" {
			lien = "/" // dégradé : au moins un lien non cassé
		}
		out = append(out, metaVue{
			ID: t.ID, Titre: t.Title, Resume: t.Summary,
			NbSrc: t.NbSrc, Sources: t.Sources, Tags: t.Tags, Lien: lien,
		})
	}
	return out, ""
}
