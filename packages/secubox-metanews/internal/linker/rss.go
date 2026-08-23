// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package linker

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const maxFlux = 8 << 20 // 8 Mio : un flux RSS n'a aucune raison d'être plus gros

// RSS : linker RSS/Atom (lecture seule). Un connecteur « à la Mastodon ».
type RSS struct {
	client *http.Client
	garde  func(hote string) error // garde anti-SSRF, facultative
	urls   []string
	vus    int
}

// NewRSS crée le linker. `garde` (facultatif) valide l'hôte avant fetch.
func NewRSS(garde func(hote string) error) *RSS {
	return &RSS{
		client: &http.Client{
			Timeout: 20 * time.Second,
			// On suit AU PLUS 3 redirections (beaucoup de flux 301 vers https ou
			// une nouvelle URL), mais on RE-VALIDE l'hôte de chaque saut avec la
			// garde : une redirection ne doit pas contourner l'anti-SSRF.
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 3 {
					return http.ErrUseLastResponse
				}
				if garde != nil {
					return garde(req.URL.Hostname())
				}
				return nil
			},
		},
		garde: garde,
	}
}

// ID identifie le connecteur.
func (r *RSS) ID() string { return "rss" }

// Ajouter enregistre une URL de flux (pour Peek global).
func (r *RSS) Ajouter(u string) { r.urls = append(r.urls, u) }

// Poke : RSS est en LECTURE SEULE.
func (r *RSS) Poke(OutMsg) (Ref, error) { return Ref{}, ErrLectureSeule }

// Sante : dernier état connu.
func (r *RSS) Sante() Sante { return Sante{OK: true, Vus: r.vus} }

// Peek récupère tous les flux enregistrés et ne garde que ce qui est postérieur
// à `depuis`. En pratique la boucle de sondage appelle plutôt Flux() par source.
func (r *RSS) Peek(depuis int64) ([]Contenu, error) {
	var out []Contenu
	for _, u := range r.urls {
		items, err := r.Flux(u)
		if err != nil {
			continue // un flux cassé n'arrête pas les autres
		}
		for _, it := range items {
			if it.PublieLe > depuis {
				out = append(out, it)
			}
		}
	}
	return out, nil
}

// Flux récupère et analyse UN flux (RSS ou Atom, auto-détecté). Le plus récent
// d'abord.
func (r *RSS) Flux(u string) ([]Contenu, error) {
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
	// UA de navigateur : beaucoup de rédactions (France 24, RFI…) renvoient 403
	// à un client « robot ». On lit un flux PUBLIC déclaré par l'exploitant, pas
	// une page protégée — se présenter en navigateur est légitime ici.
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0")
	req.Header.Set("Accept", "application/rss+xml, application/atom+xml, application/xml, text/xml, */*")
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
	items, err := Analyser(corps)
	if err != nil {
		return nil, err
	}
	r.vus += len(items)
	return items, nil
}

// ── Analyse ─────────────────────────────────────────────────────────────────

type rssDoc struct {
	XMLName xml.Name `xml:"rss"`
	Channel struct {
		Items []struct {
			Title   string `xml:"title"`
			Link    string `xml:"link"`
			GUID    string `xml:"guid"`
			Desc    string `xml:"description"`
			PubDate string `xml:"pubDate"`
			Date    string `xml:"date"`    // dc:date
			Creator string `xml:"creator"` // dc:creator
		} `xml:"item"`
	} `xml:"channel"`
}

type atomDoc struct {
	XMLName xml.Name `xml:"feed"`
	Entries []struct {
		Title     string `xml:"title"`
		ID        string `xml:"id"`
		Summary   string `xml:"summary"`
		Content   string `xml:"content"`
		Updated   string `xml:"updated"`
		Published string `xml:"published"`
		Links     []struct {
			Href string `xml:"href,attr"`
			Rel  string `xml:"rel,attr"`
		} `xml:"link"`
		Author struct {
			Name string `xml:"name"`
		} `xml:"author"`
	} `xml:"entry"`
}

// Analyser détecte RSS ou Atom (sur le contenu, pas l'extension) et normalise.
func Analyser(corps []byte) ([]Contenu, error) {
	tete := corps
	if len(tete) > 4096 {
		tete = tete[:4096]
	}
	atom := bytes.Contains(tete, []byte("<feed")) && !bytes.Contains(tete, []byte("<rss"))
	if atom {
		return analyserAtom(corps)
	}
	return analyserRSS(corps)
}

func analyserRSS(corps []byte) ([]Contenu, error) {
	var d rssDoc
	if err := xml.Unmarshal(corps, &d); err != nil {
		return nil, err
	}
	var out []Contenu
	for _, it := range d.Channel.Items {
		ref := strings.TrimSpace(it.GUID)
		if ref == "" {
			ref = strings.TrimSpace(it.Link)
		}
		date := it.PubDate
		if date == "" {
			date = it.Date
		}
		out = append(out, Contenu{
			Titre:      strings.TrimSpace(it.Title),
			Corps:      nettoyer(it.Desc),
			URL:        strings.TrimSpace(it.Link),
			Ref:        ref,
			Auteur:     strings.TrimSpace(it.Creator),
			PublieLe:   dateEpoch(date),
			Connecteur: "rss",
		})
	}
	return out, nil
}

func analyserAtom(corps []byte) ([]Contenu, error) {
	var d atomDoc
	if err := xml.Unmarshal(corps, &d); err != nil {
		return nil, err
	}
	var out []Contenu
	for _, e := range d.Entries {
		lien := ""
		for _, l := range e.Links {
			if l.Rel == "" || l.Rel == "alternate" {
				lien = l.Href
				break
			}
			if lien == "" {
				lien = l.Href
			}
		}
		date := e.Published
		if date == "" {
			date = e.Updated
		}
		corpsTxt := e.Summary
		if corpsTxt == "" {
			corpsTxt = e.Content
		}
		out = append(out, Contenu{
			Titre:      strings.TrimSpace(e.Title),
			Corps:      nettoyer(corpsTxt),
			URL:        strings.TrimSpace(lien),
			Ref:        firstNon(strings.TrimSpace(e.ID), strings.TrimSpace(lien)),
			Auteur:     strings.TrimSpace(e.Author.Name),
			PublieLe:   dateEpoch(date),
			Connecteur: "atom",
		})
	}
	return out, nil
}

func firstNon(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// dateEpoch analyse une date RSS/Atom vers un epoch (0 si illisible).
func dateEpoch(s string) int64 {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0
	}
	formats := []string{
		time.RFC1123Z, time.RFC1123, time.RFC3339, time.RFC3339Nano,
		"Mon, 02 Jan 2006 15:04:05 -0700", "2006-01-02T15:04:05Z07:00",
		"2006-01-02 15:04:05", "2006-01-02",
	}
	for _, f := range formats {
		if t, err := time.Parse(f, s); err == nil {
			return t.Unix()
		}
	}
	return 0
}

// nettoyer retire les balises HTML grossières d'un résumé (on ne recopie pas
// l'article : on garde un extrait court et propre).
func nettoyer(s string) string {
	var b strings.Builder
	dans := false
	for _, r := range s {
		switch r {
		case '<':
			dans = true
		case '>':
			dans = false
		default:
			if !dans {
				b.WriteRune(r)
			}
		}
	}
	return strings.Join(strings.Fields(b.String()), " ")
}
