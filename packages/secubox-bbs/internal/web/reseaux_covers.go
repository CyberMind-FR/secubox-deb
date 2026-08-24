// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package web

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

func (s *Server) clientSocialRelay() *http.Client {
	return &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", s.opt.SocialRelaySocket)
		},
	}}
}

// enrichirCoversReseaux pose la vignette d'un fil-passerelle SANS média : il
// demande à SocialRelay, en UN appel, le média caché local correspondant à
// chaque ID de fil BBS, et le relaie same-origin. Le lien fil↔média vit dans
// SocialRelay (indexé par bbs_thread_id) — donc ça marche pour les ANCIENS fils
// comme pour les nouveaux, sans marqueur dans le corps ni backfill.
//
// Vaut pour les DEUX surfaces (#1187). Le relais /media-vignette n'est plus
// réservé aux membres — son garde-fou est la liste blanche d'origines, pas la
// session — et la surface publique ne porte que des messages publics
// (`PublicPostsOf`). Les vignettes publiques étaient donc absentes pour rien.
func (s *Server) enrichirCoversReseaux(items []NewsItem) {
	if s.opt.SocialRelaySocket == "" || len(items) == 0 {
		return
	}
	var ids []string
	idx := map[int64]int{}
	for i := range items {
		if items[i].Fil == nil {
			continue
		}
		aImage := false
		for _, m := range items[i].Medias {
			if m.Kind == "image" {
				aImage = true
				break
			}
		}
		if aImage { // ne jamais écraser un média déjà présent (pièce, marqueur)
			continue
		}
		ids = append(ids, strconv.FormatInt(items[i].Fil.ID, 10))
		idx[items[i].Fil.ID] = i
	}
	if len(ids) == 0 {
		return
	}
	req, err := http.NewRequest(http.MethodGet, "http://unix/api/v1/socialrelay/covers?tids="+strings.Join(ids, ","), nil)
	if err != nil {
		return
	}
	resp, err := s.clientSocialRelay().Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	var out struct {
		Covers map[string]string `json:"covers"`
	}
	if json.NewDecoder(resp.Body).Decode(&out) != nil {
		return
	}
	for tidStr, u := range out.Covers {
		tid, _ := strconv.ParseInt(tidStr, 10, 64)
		i, ok := idx[tid]
		if !ok || u == "" {
			continue
		}
		pu, err := url.Parse(u)
		if err != nil || !origineAdmise(pu, s.opt.MediaOrigines) {
			continue
		}
		items[i].Medias = append(items[i].Medias, cardMedia{Ref: "/media-vignette?u=" + url.QueryEscape(u), Kind: "image"})
	}
}
