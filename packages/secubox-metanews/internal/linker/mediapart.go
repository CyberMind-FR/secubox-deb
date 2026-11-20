// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package linker

import (
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// Mediapart ne publie plus de flux RSS par blog (« Le Club ») : seul le flux du
// journal (/articles/feed) existe. Pour suivre un blog comme
// blogs.mediapart.fr/<slug>, on lit la liste publique de ses billets
// (/<slug>/blog) et on en fait des Contenu, exactement comme on lirait un flux.
//
// C'est volontairement fragile (cela dépend du HTML de Mediapart) : tout est
// isolé ici, de sorte qu'un changement de gabarit côté Mediapart ne se corrige
// qu'à un seul endroit. On lit une page PUBLIQUE déclarée par l'auteur, pas une
// page protégée ; se présenter en navigateur est légitime, comme pour le RSS.

// EstBlogMediapart : l'URL pointe-t-elle un blog du Club Mediapart ?
func EstBlogMediapart(u string) bool {
	pu, err := url.Parse(u)
	if err != nil {
		return false
	}
	return strings.EqualFold(pu.Hostname(), "blogs.mediapart.fr")
}

// Collecter choisit le bon lecteur selon le type de source (ou, à défaut, l'hôte)
// et renvoie des Contenu normalisés. Les sources classiques passent par Flux
// (RSS/Atom) ; un blog Mediapart passe par MediapartBlog.
func (r *RSS) Collecter(typ, u string) ([]Contenu, error) {
	if typ == "mediapart-blog" || EstBlogMediapart(u) {
		return r.MediapartBlog(u)
	}
	return r.Flux(u)
}

// MediapartBlog lit la page des billets d'un blog Mediapart et renvoie des Contenu.
func (r *RSS) MediapartBlog(u string) ([]Contenu, error) {
	pu, err := url.Parse(u)
	if err != nil || (pu.Scheme != "http" && pu.Scheme != "https") {
		return nil, fmt.Errorf("URL non http(s) : %q", u)
	}
	if r.garde != nil {
		if err := r.garde(pu.Hostname()); err != nil {
			return nil, err
		}
	}
	req, _ := http.NewRequest("GET", u, nil)
	// Même posture que le lecteur RSS : navigateur, car Mediapart renvoie 403 aux
	// clients « robot » sur ses pages publiques.
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	resp, err := r.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	corps, err := io.ReadAll(io.LimitReader(resp.Body, maxFlux))
	if err != nil {
		return nil, err
	}
	items := AnalyserBlogMediapart(string(corps), pu)
	r.vus += len(items)
	return items, nil
}

var (
	// Chaque billet est un <li data-type="blog" data-id="…"> : le billet « à la
	// une » porte en plus class="teaser", les autres non. On s'appuie donc sur
	// data-type="blog", commun à tous.
	reTeaserMP = regexp.MustCompile(`(?is)<li\b([^>]*\bdata-type="blog"[^>]*)>(.*?)</li>`)
	reDataIDMP = regexp.MustCompile(`(?i)\bdata-id="([0-9]+)"`)
	reTitreMP  = regexp.MustCompile(`(?is)<h3\b[^>]*\bclass="[^"]*\btitle\b[^"]*"[^>]*>\s*<a\b[^>]+href="([^"]+)"[^>]*>(.*?)</a>`)
	reDateMP   = regexp.MustCompile(`(?i)<time\b[^>]+datetime="([0-9]{4}-[0-9]{2}-[0-9]{2})"`)
	reAuteurMP = regexp.MustCompile(`(?is)rel="author"[^>]*>(.*?)</a>`)
	reImgMP    = regexp.MustCompile(`(?i)<img\b[^>]+src="(https://[^"]*static\.mediapart\.fr/[^"]+)"`)
	reBalisesMP = regexp.MustCompile(`(?s)<[^>]+>`)
)

// AnalyserBlogMediapart extrait les billets (li.teaser) d'une page de blog.
// `base` sert à absolutiser les liens relatifs.
func AnalyserBlogMediapart(corps string, base *url.URL) []Contenu {
	var out []Contenu
	vus := make(map[string]bool)
	for _, m := range reTeaserMP.FindAllStringSubmatch(corps, -1) {
		attrs, inner := m[1], m[2]
		tt := reTitreMP.FindStringSubmatch(inner)
		if tt == nil {
			continue
		}
		titre := texteMediapart(tt[2])
		lien := absolutiser(base, strings.TrimSpace(tt[1]))
		if titre == "" || lien == "" {
			continue
		}
		ref := lien
		if id := reDataIDMP.FindStringSubmatch(attrs); id != nil {
			ref = "mediapart-blog:" + id[1]
		}
		if vus[ref] {
			continue
		}
		vus[ref] = true
		c := Contenu{
			Titre:      titre,
			URL:        lien,
			Ref:        ref,
			Langue:     "fr",
			Connecteur: "mediapart-blog",
		}
		if d := reDateMP.FindStringSubmatch(inner); d != nil {
			if t, err := time.Parse("2006-01-02", d[1]); err == nil {
				c.PublieLe = t.Unix()
			}
		}
		if a := reAuteurMP.FindStringSubmatch(inner); a != nil {
			c.Auteur = texteMediapart(a[1])
		}
		if img := reImgMP.FindStringSubmatch(inner); img != nil {
			c.Vignette = img[1]
		}
		out = append(out, c)
	}
	return out
}

// absolutiser rend un href absolu à partir de la page de base. Les liens de
// Mediapart contiennent parfois des espaces/retours à la ligne internes.
func absolutiser(base *url.URL, href string) string {
	href = strings.TrimSpace(href)
	if href == "" {
		return ""
	}
	ref, err := url.Parse(href)
	if err != nil {
		return ""
	}
	if base != nil {
		return base.ResolveReference(ref).String()
	}
	return ref.String()
}

// texteMediapart retire les balises, dé-échappe les entités et normalise les
// espaces d'un fragment HTML.
func texteMediapart(s string) string {
	s = reBalisesMP.ReplaceAllString(s, " ")
	s = html.UnescapeString(s)
	return strings.Join(strings.Fields(s), " ")
}
