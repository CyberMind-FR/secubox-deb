// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package linker

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Mastodon : connecteur OPEN — contenu PUBLIC via l'API Mastodon (aucune auth
// requise). Handle « @user@instance » (compte) ou « #tag@instance » (hashtag).
type Mastodon struct {
	cli   *http.Client
	garde func(string) error
}

// NewMastodon crée le connecteur (garde SSRF facultative).
func NewMastodon(garde func(string) error) *Mastodon {
	return &Mastodon{cli: &http.Client{Timeout: 20 * time.Second}, garde: garde}
}

// ID identifie le connecteur.
func (m *Mastodon) ID() string { return "mastodon" }

type mastoStatut struct {
	ID        string `json:"id"`
	URL       string `json:"url"`
	Content   string `json:"content"`
	CreatedAt string `json:"created_at"`
	Account   struct {
		DisplayName string `json:"display_name"`
		Acct        string `json:"acct"`
		Username    string `json:"username"`
	} `json:"account"`
	MediaAttachments []struct {
		Type        string `json:"type"`
		URL         string `json:"url"`
		Description  string `json:"description"`
	} `json:"media_attachments"`
	Reblog *mastoStatut `json:"reblog"`
}

// Peek récupère les derniers posts publics du handle.
func (m *Mastodon) Peek(handle string) ([]Contenu, error) {
	instance, cible, tag, err := decouperHandle(handle)
	if err != nil {
		return nil, err
	}
	if m.garde != nil {
		if err := m.garde(instance); err != nil {
			return nil, err
		}
	}
	base := "https://" + instance
	var api string
	if tag {
		api = fmt.Sprintf("%s/api/v1/timelines/tag/%s?limit=20", base, url.PathEscape(cible))
	} else {
		id, err := m.lookup(base, cible)
		if err != nil {
			return nil, err
		}
		api = fmt.Sprintf("%s/api/v1/accounts/%s/statuses?exclude_replies=true&limit=20", base, url.PathEscape(id))
	}
	var statuts []mastoStatut
	if err := m.getJSON(api, &statuts); err != nil {
		return nil, err
	}
	out := make([]Contenu, 0, len(statuts))
	for _, s := range statuts {
		st := s
		if st.Reblog != nil { // un partage : on relaie l'original
			st = *st.Reblog
		}
		auteur := st.Account.DisplayName
		if auteur == "" {
			auteur = st.Account.Username
		}
		if st.Account.Acct != "" {
			auteur += " (@" + st.Account.Acct + ")"
		}
		c := Contenu{
			Auteur: auteur, URL: st.URL, Ref: st.ID,
			Texte: nettoyerHTML(st.Content), PublieLe: epoch(st.CreatedAt), Reseau: "mastodon",
		}
		for _, a := range st.MediaAttachments {
			if a.URL == "" {
				continue
			}
			c.Medias = append(c.Medias, Media{URL: a.URL, Kind: a.Type, Desc: a.Description})
		}
		out = append(out, c)
	}
	return out, nil
}

func (m *Mastodon) lookup(base, acct string) (string, error) {
	var a struct {
		ID string `json:"id"`
	}
	if err := m.getJSON(base+"/api/v1/accounts/lookup?acct="+url.QueryEscape(acct), &a); err != nil {
		return "", err
	}
	if a.ID == "" {
		return "", fmt.Errorf("compte introuvable : %s", acct)
	}
	return a.ID, nil
}

func (m *Mastodon) getJSON(u string, v any) error {
	req, _ := http.NewRequest("GET", u, nil)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "secubox-socialrelay/1.0 (+secubox)")
	resp, err := m.cli.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(v)
}

// decouperHandle : « @user@instance » → (instance, user, false) ;
// « #tag@instance » → (instance, tag, true).
func decouperHandle(h string) (instance, cible string, tag bool, err error) {
	h = strings.TrimSpace(h)
	if strings.HasPrefix(h, "#") {
		tag = true
		h = h[1:]
	} else {
		h = strings.TrimPrefix(h, "@")
	}
	parts := strings.SplitN(h, "@", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", false, fmt.Errorf("handle attendu « @user@instance » ou « #tag@instance », reçu %q", h)
	}
	return parts[1], parts[0], tag, nil
}

func epoch(s string) int64 {
	for _, f := range []string{time.RFC3339, time.RFC3339Nano, "2006-01-02T15:04:05.000Z"} {
		if t, err := time.Parse(f, s); err == nil {
			return t.Unix()
		}
	}
	return 0
}
