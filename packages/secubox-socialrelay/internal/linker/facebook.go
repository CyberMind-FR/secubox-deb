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
	"os"
	"strings"
	"time"
)

// Facebook : connecteur CONSENT — API GRAPH OFFICIELLE avec un JETON fourni par
// l'opérateur. AUCUN scraping : sans jeton valide, ce connecteur ne rapporte
// rien (et c'est voulu). Fonctionne pour les PAGES ; pour un GROUPE, il faut que
// l'app de l'opérateur y soit installée par un admin (restriction Facebook).
//
// Le handle d'une source = l'ID de l'objet (page/groupe), ex. « 473694028670754 »
// ou « 61560790047791 ». Le jeton est lu d'un fichier de secret (hors base, hors
// code), jamais reçu par l'API.
type Facebook struct {
	cli        *http.Client
	jetonFn    func() string // fournit le jeton actif (OAuth caché → repli manuel)
	cookiePath string        // cookies de session opérateur (mode cookie-replay)
}

// NewFacebook crée le connecteur ; jetonFn fournit le jeton Graph courant
// (jeton OAuth mis en cache par le wizard, ou jeton manuel déposé).
func NewFacebook(jetonFn func() string) *Facebook {
	return &Facebook{
		cli:        &http.Client{Timeout: 25 * time.Second},
		jetonFn:    jetonFn,
		cookiePath: "/etc/secubox/secrets/socialrelay-facebook-cookies",
	}
}

// cookies rend l'en-tête Cookie déposé par l'opérateur (une seule ligne
// « c_user=…; xs=…; … »), ou "" s'il n'y en a pas.
func (f *Facebook) cookies() string {
	if f.cookiePath == "" {
		return ""
	}
	b, err := os.ReadFile(f.cookiePath)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// ID identifie le connecteur.
func (f *Facebook) ID() string { return "facebook" }

func (f *Facebook) jeton() string {
	if f.jetonFn == nil {
		return ""
	}
	return strings.TrimSpace(f.jetonFn())
}

type fbPost struct {
	ID          string `json:"id"`
	Message     string `json:"message"`
	Story       string `json:"story"`
	CreatedTime string `json:"created_time"`
	Permalink   string `json:"permalink_url"`
	FullPicture string `json:"full_picture"`
	Attachments struct {
		Data []struct {
			Type  string `json:"type"`
			URL   string `json:"url"`
			Media struct {
				Image struct {
					Src string `json:"src"`
				} `json:"image"`
				Source string `json:"source"`
			} `json:"media"`
		} `json:"data"`
	} `json:"attachments"`
}

// Peek lit le fil de l'objet Facebook (page/groupe) via l'API Graph.
func (f *Facebook) Peek(objectID string) ([]Contenu, error) {
	objectID = strings.TrimSpace(objectID)
	// PRIORITÉ au mode cookie-replay si l'opérateur a déposé ses cookies : c'est
	// le recours quand l'API Graph lui est administrativement fermée.
	if ck := f.cookies(); ck != "" {
		return f.peekCookie(objectID, ck)
	}
	tok := f.jeton()
	if tok == "" {
		return nil, fmt.Errorf("Facebook : ni cookies (déposez-les dans %s pour le mode cookie-replay) ni jeton (wizard OAuth)", f.cookiePath)
	}
	champs := "id,message,story,created_time,permalink_url,full_picture,attachments{type,url,media}"
	api := fmt.Sprintf("https://graph.facebook.com/v20.0/%s/feed?fields=%s&limit=20&access_token=%s",
		url.PathEscape(objectID), url.QueryEscape(champs), url.QueryEscape(tok))
	req, _ := http.NewRequest("GET", api, nil)
	req.Header.Set("Accept", "application/json")
	resp, err := f.cli.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode != 200 {
		// Graph renvoie un message d'erreur clair (jeton, permission, objet).
		var e struct {
			Error struct {
				Message string `json:"message"`
			} `json:"error"`
		}
		_ = json.Unmarshal(body, &e)
		msg := e.Error.Message
		if msg == "" {
			msg = fmt.Sprintf("HTTP %d", resp.StatusCode)
		}
		return nil, fmt.Errorf("Graph: %s", msg)
	}
	var d struct {
		Data []fbPost `json:"data"`
	}
	if err := json.Unmarshal(body, &d); err != nil {
		return nil, err
	}
	out := make([]Contenu, 0, len(d.Data))
	for _, p := range d.Data {
		txt := p.Message
		if txt == "" {
			txt = p.Story
		}
		lien := p.Permalink
		if lien == "" {
			lien = "https://www.facebook.com/" + p.ID
		}
		c := Contenu{
			Auteur: "Facebook", URL: lien, Ref: p.ID, Texte: strings.TrimSpace(txt),
			PublieLe: epoch(p.CreatedTime), Reseau: "facebook",
		}
		if p.FullPicture != "" {
			c.Medias = append(c.Medias, Media{URL: p.FullPicture, Kind: "image"})
		}
		for _, a := range p.Attachments.Data {
			if a.Media.Image.Src != "" {
				c.Medias = append(c.Medias, Media{URL: a.Media.Image.Src, Kind: "image"})
			} else if a.Media.Source != "" {
				c.Medias = append(c.Medias, Media{URL: a.Media.Source, Kind: "video"})
			}
		}
		out = append(out, c)
	}
	return out, nil
}
