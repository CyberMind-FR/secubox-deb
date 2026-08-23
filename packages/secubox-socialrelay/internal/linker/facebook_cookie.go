// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package linker

// Mode COOKIE-REPLAY de Facebook — recours quand l'API Graph est
// administrativement inaccessible (Meta refuse d'enregistrer l'app dev).
//
// L'OPÉRATEUR fournit SES PROPRES cookies de session (déposés dans un secret) :
// le connecteur agit alors comme un navigateur automatisé DE SON compte, pour
// lire SES propres groupes/pages. On tape `mbasic.facebook.com` (le HTML léger,
// le plus parsable). C'est fragile PAR NATURE (ça casse quand Facebook change son
// HTML) et contraire aux CGU d'accès automatisé — à n'utiliser que pour SON
// compte, sur SON infra. Ce n'est jamais activé sans le fichier de cookies.

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"golang.org/x/net/html"
)

const mbasic = "https://mbasic.facebook.com/"

// peekCookie lit le fil d'un objet Facebook via mbasic, avec les cookies de
// l'opérateur. `handle` = le chemin tel qu'il apparaît dans l'URL Facebook :
// « groups/473694028670754 », « profile.php?id=61560790047791 », ou un nom de
// page. Un id nu est passé tel quel (Facebook redirige).
func (f *Facebook) peekCookie(handle, cookies string) ([]Contenu, error) {
	handle = strings.TrimSpace(strings.TrimPrefix(handle, "/"))
	req, err := http.NewRequest(http.MethodGet, mbasic+handle, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Cookie", cookies)
	// UA mobile : mbasic ne sert son HTML léger qu'à un navigateur mobile.
	req.Header.Set("User-Agent", "Mozilla/5.0 (Android 13; Mobile; rv:120.0) Gecko/120.0 Firefox/120.0")
	req.Header.Set("Accept", "text/html,application/xhtml+xml")
	req.Header.Set("Accept-Language", "fr-FR,fr;q=0.9,en;q=0.8")
	resp, err := f.cli.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("mbasic HTTP %d (cookies périmés ? re-déposer les cookies)", resp.StatusCode)
	}
	corps, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, err
	}
	root, err := html.Parse(strings.NewReader(string(corps)))
	if err != nil {
		return nil, err
	}
	// Détecter une page de login (cookies invalides) : mbasic renvoie un
	// formulaire de connexion plutôt qu'un fil.
	if strings.Contains(string(corps), "name=\"login\"") && !strings.Contains(string(corps), "/story.php") {
		return nil, fmt.Errorf("mbasic a renvoyé un écran de connexion — cookies invalides/expirés")
	}
	return extraireMbasic(root, time.Now().Unix()), nil
}

// extraireMbasic parcourt l'arbre mbasic et rend un Contenu par « article ».
// mbasic enveloppe chaque post dans un conteneur qui porte un permalien
// (story.php / permalink / posts / photo.php) : c'est notre ancre.
func extraireMbasic(n *html.Node, now int64) []Contenu {
	var out []Contenu
	vus := map[string]bool{}
	var walk func(*html.Node)
	walk = func(nd *html.Node) {
		if nd.Type == html.ElementNode && (nd.Data == "article" || aRole(nd, "article")) {
			if c, ok := postDepuis(nd, now); ok && !vus[c.Ref] {
				vus[c.Ref] = true
				out = append(out, c)
				return // ne pas redescendre dans un article déjà pris
			}
		}
		for e := nd.FirstChild; e != nil; e = e.NextSibling {
			walk(e)
		}
	}
	walk(n)
	return out
}

// postDepuis extrait texte + permalien + première image d'un conteneur d'article.
func postDepuis(nd *html.Node, now int64) (Contenu, bool) {
	var texte strings.Builder
	perma, img := "", ""
	var walk func(*html.Node)
	walk = func(x *html.Node) {
		if x.Type == html.TextNode {
			t := strings.TrimSpace(x.Data)
			if t != "" {
				texte.WriteString(t)
				texte.WriteByte(' ')
			}
		}
		if x.Type == html.ElementNode {
			switch x.Data {
			case "a":
				if perma == "" {
					if h := attr(x, "href"); estPermalien(h) {
						perma = normaliserLien(h)
					}
				}
			case "img":
				if img == "" {
					if s := attr(x, "src"); strings.Contains(s, "scontent") || strings.Contains(s, "/safe_image") {
						img = s
					}
				}
			}
		}
		for e := x.FirstChild; e != nil; e = e.NextSibling {
			walk(e)
		}
	}
	walk(nd)
	if perma == "" {
		return Contenu{}, false // pas d'ancre = pas un post exploitable
	}
	c := Contenu{
		URL: perma, Ref: perma, Texte: nettoyerTexteFB(texte.String()),
		PublieLe: now, Reseau: "facebook",
	}
	if img != "" {
		c.Medias = append(c.Medias, Media{URL: img, Kind: "image"})
	}
	return c, true
}

func estPermalien(h string) bool {
	return strings.Contains(h, "story.php?story_fbid=") ||
		strings.Contains(h, "/permalink/") ||
		strings.Contains(h, "/posts/") ||
		strings.Contains(h, "photo.php?fbid=")
}

// normaliserLien absolutise un lien mbasic relatif et coupe les paramètres de
// suivi (refid, __tn__, eav…) pour un Ref stable.
func normaliserLien(h string) string {
	if strings.HasPrefix(h, "/") {
		h = "https://www.facebook.com" + h
	}
	// ID dans le CHEMIN (permalink/posts) : couper toute la query de suivi.
	if strings.Contains(h, "/permalink/") || strings.Contains(h, "/posts/") {
		if i := strings.IndexByte(h, '?'); i >= 0 {
			h = h[:i]
		}
		return h
	}
	// ID dans la QUERY (story.php, photo.php) : garder le 1er paramètre, couper
	// le reste (id, refid, __tn__…).
	if i := strings.IndexByte(h, '&'); i >= 0 {
		h = h[:i]
	}
	return h
}

func nettoyerTexteFB(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	// mbasic colle des libellés d'UI ; on coupe raisonnablement.
	if len(s) > 1200 {
		r := []rune(s)
		if len(r) > 1200 {
			s = string(r[:1200]) + "…"
		}
	}
	return s
}

func attr(n *html.Node, k string) string {
	for _, a := range n.Attr {
		if a.Key == k {
			return a.Val
		}
	}
	return ""
}

func aRole(n *html.Node, role string) bool { return attr(n, "role") == role }
