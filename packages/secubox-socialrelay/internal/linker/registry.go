// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package linker

import (
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Registre : aiguille un Peek vers le bon connecteur selon le KIND de la source.
type Registre struct {
	masto *Mastodon
	fb    *Facebook
	cli   *http.Client
	garde func(string) error
}

// NewRegistre construit le registre. fbJeton = fichier du jeton Graph (consent).
func NewRegistre(garde func(string) error, fbJeton string) *Registre {
	return &Registre{
		masto: NewMastodon(garde),
		fb:    NewFacebook(fbJeton),
		cli:   &http.Client{Timeout: 20 * time.Second},
		garde: garde,
	}
}

// Mode rend le mode d'accès déclaré d'un kind (pour l'UI honnête).
func Mode(kind string) string {
	switch kind {
	case "facebook":
		return "consent"
	case "bridge":
		return "bridge"
	default: // mastodon, bluesky, peertube, youtube, rss
		return "open"
	}
}

// Peek récupère les posts d'une source selon son kind.
func (r *Registre) Peek(kind, handle, u string) ([]Contenu, error) {
	switch kind {
	case "mastodon":
		return r.masto.Peek(handle)
	case "facebook":
		return r.fb.Peek(handle)
	case "bridge", "rss":
		return r.bridge(u)
	default:
		return nil, fmt.Errorf("connecteur inconnu : %q", kind)
	}
}

// bridge lit un flux RSS produit par un PONT que l'OPÉRATEUR héberge lui-même
// (ex. RSS-Bridge). SocialRelay ne fait que consommer un flux — il ne scrape
// jamais lui-même. L'URL est fournie par l'opérateur.
func (r *Registre) bridge(u string) ([]Contenu, error) {
	pu, err := url.Parse(u)
	if err != nil || (pu.Scheme != "http" && pu.Scheme != "https") {
		return nil, fmt.Errorf("URL de pont invalide")
	}
	if r.garde != nil {
		if err := r.garde(pu.Hostname()); err != nil {
			return nil, err
		}
	}
	req, _ := http.NewRequest("GET", u, nil)
	req.Header.Set("User-Agent", "secubox-socialrelay/1.0 (+secubox)")
	resp, err := r.cli.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	corps, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	var doc struct {
		Channel struct {
			Items []struct {
				Title     string `xml:"title"`
				Link      string `xml:"link"`
				GUID      string `xml:"guid"`
				Desc      string `xml:"description"`
				PubDate   string `xml:"pubDate"`
				Enclosure struct {
					URL  string `xml:"url,attr"`
					Type string `xml:"type,attr"`
				} `xml:"enclosure"`
			} `xml:"item"`
		} `xml:"channel"`
	}
	if err := xml.Unmarshal(corps, &doc); err != nil {
		return nil, err
	}
	var out []Contenu
	for _, it := range doc.Channel.Items {
		ref := it.GUID
		if ref == "" {
			ref = it.Link
		}
		c := Contenu{
			Auteur: "", URL: it.Link, Ref: ref, Texte: nettoyerHTML(firstNonEmpty(it.Title, it.Desc)),
			PublieLe: epochRSS(it.PubDate), Reseau: "bridge",
		}
		if it.Enclosure.URL != "" && strings.HasPrefix(it.Enclosure.Type, "image") {
			c.Medias = append(c.Medias, Media{URL: it.Enclosure.URL, Kind: "image"})
		}
		out = append(out, c)
	}
	return out, nil
}

func firstNonEmpty(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b
}

func epochRSS(s string) int64 {
	for _, f := range []string{time.RFC1123Z, time.RFC1123, time.RFC3339} {
		if t, err := time.Parse(f, strings.TrimSpace(s)); err == nil {
			return t.Unix()
		}
	}
	return 0
}
