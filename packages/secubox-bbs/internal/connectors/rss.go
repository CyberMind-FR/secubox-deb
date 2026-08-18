// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// Package connectors porte les connecteurs de la passerelle média.
//
// Le RSS est écrit le premier, et volontairement : c'est le plus simple, il
// sert de connecteur de référence. Ce qu'il fait bien — résoudre, tirer,
// refuser de publier, se garder du réseau interne — les autres n'ont qu'à le
// refaire pareil.
package connectors

import (
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/CyberMind-FR/secubox-deb/secubox-bbs/internal/gateway"
	"github.com/CyberMind-FR/secubox-deb/secubox-bbs/internal/reseau"
)

// Config paramètre le connecteur.
type Config struct {
	NoeudOrigine string
	// FluxPropres : fragments de titre de flux qui appartiennent à
	// l'utilisateur. Leurs articles sont marqués « à moi » — donc republiables.
	FluxPropres []string
	// HoteInterne : l'instance de la maison, jointe telle quelle par le garde
	// réseau (comme pour Mastodon). Vide en dehors de la production.
	HoteInterne string
	// GardeReseau permet de remplacer le contrôle anti-SSRF. nil = le garde
	// réel, qui refuse le réseau interne. Les tests de PARSING le rendent
	// permissif (httptest sert forcément sur 127.0.0.1, que le garde réel
	// refuse) ; le test anti-SSRF, lui, garde le vrai.
	GardeReseau func(hote string) error
}

// RSS lit des flux RSS et Atom.
type RSS struct {
	gateway.Base
	cfg   Config
	flux  []string
	http  *http.Client
	sante gateway.Sante
}

// NewRSS construit le connecteur. La Sortie reste nil : un flux ne se publie
// pas, et Base.Publier refusera donc poliment.
func NewRSS(cfg Config) (*RSS, error) {
	if strings.TrimSpace(cfg.NoeudOrigine) == "" {
		return nil, fmt.Errorf("rss : nœud d'origine non renseigné")
	}
	return &RSS{
		cfg: cfg,
		http: &http.Client{
			Timeout: 15 * time.Second,
			// On ne suit AUCUNE redirection : une redirection est le moyen
			// classique de contourner le garde réseau (l'URL publique renvoie
			// vers une adresse interne).
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		sante: gateway.Sante{Etat: gateway.EtatSain},
	}, nil
}

func (r *RSS) Manifeste() gateway.Manifeste {
	return gateway.Manifeste{
		Nom:       "rss",
		Version:   "1.0",
		Capacites: []string{gateway.CapResoudre, gateway.CapTirer},
		AuthKind:  gateway.AuthAucune,
		MotifsURL: []string{`(?i)\.(rss|atom|xml)(\?|$)`, `(?i)/(feed|rss|atom)/?`},
	}
}

func (r *RSS) Sante() gateway.Sante { return r.sante }

// Ajouter enregistre un flux à suivre.
func (r *RSS) Ajouter(u string) { r.flux = append(r.flux, u) }

// gardeReseau applique le contrôle anti-SSRF, réel par défaut.
func (r *RSS) gardeReseau(hote string) error {
	if r.cfg.GardeReseau != nil {
		return r.cfg.GardeReseau(hote)
	}
	return reseau.VerifieHote(hote, r.cfg.HoteInterne)
}

// Resoudre rend le PREMIER article d'un flux — la carte riche d'un lien collé.
func (r *RSS) Resoudre(u string) (gateway.Contenu, error) {
	items, err := r.ResoudreFlux(u)
	if err != nil {
		return gateway.Contenu{}, err
	}
	if len(items) == 0 {
		return gateway.Contenu{}, fmt.Errorf("rss : aucun article dans %s", u)
	}
	return items[0], nil
}

// ResoudreFlux lit un flux et rend tous ses articles, du plus récent au plus
// ancien.
func (r *RSS) ResoudreFlux(u string) ([]gateway.Contenu, error) {
	brut, err := r.recuperer(u)
	if err != nil {
		return nil, err
	}
	items, err := analyser(brut)
	if err != nil {
		return nil, err
	}
	if len(items) == 0 {
		return nil, fmt.Errorf("rss : flux vide %s", u)
	}
	propriete := gateway.ProprieteTiers
	if r.estPropre(items[0].fluxTitre) {
		propriete = gateway.ProprieteSoi
	}
	out := make([]gateway.Contenu, 0, len(items))
	for _, it := range items {
		out = append(out, it.versContenu(r.cfg.NoeudOrigine, propriete))
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].PublieLe > out[j].PublieLe })
	return out, nil
}

// Tirer parcourt tous les flux suivis et ne rend que ce qui a paru après
// `depuis` (0 = tout). C'est le tirage incrémental : sans le seuil, chaque
// collecte relirait l'intégralité de chaque flux.
func (r *RSS) Tirer(depuis int64) ([]gateway.Contenu, error) {
	var out []gateway.Contenu
	var echecs int
	for _, u := range r.flux {
		items, err := r.ResoudreFlux(u)
		if err != nil {
			// Un flux cassé n'arrête pas les autres : dégradation gracieuse.
			echecs++
			continue
		}
		for _, c := range items {
			if depuis == 0 || c.PublieLe > depuis {
				out = append(out, c)
			}
		}
	}
	if echecs > 0 && echecs == len(r.flux) {
		r.sante = gateway.Sante{Etat: gateway.EtatDegrade,
			Motif: fmt.Sprintf("%d flux injoignables", echecs)}
	} else {
		r.sante = gateway.Sante{Etat: gateway.EtatSain}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].PublieLe > out[j].PublieLe })
	return out, nil
}

func (r *RSS) estPropre(titre string) bool {
	t := strings.ToLower(titre)
	for _, frag := range r.cfg.FluxPropres {
		if strings.Contains(t, strings.ToLower(frag)) {
			return true
		}
	}
	return false
}

// recuperer va chercher le flux, après avoir vérifié que son hôte est joignable.
func (r *RSS) recuperer(u string) ([]byte, error) {
	parsed, err := url.Parse(strings.TrimSpace(u))
	if err != nil {
		return nil, fmt.Errorf("rss : adresse illisible : %w", err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, fmt.Errorf("rss : schéma refusé : %q", parsed.Scheme)
	}
	// Même garde que Mastodon : un flux ajouté par un membre ne doit pas servir
	// à sonder le réseau interne (SSRF).
	if err := r.gardeReseau(parsed.Hostname()); err != nil {
		return nil, err
	}
	resp, err := r.http.Get(u)
	if err != nil {
		return nil, fmt.Errorf("rss : %s injoignable : %w", parsed.Host, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("rss : %s a répondu %d", parsed.Host, resp.StatusCode)
	}
	// Taille bornée : un flux distant est hostile, on ne se laisse pas noyer.
	return io.ReadAll(io.LimitReader(resp.Body, 8<<20))
}

// ── analyse ──────────────────────────────────────────────────────────────

type article struct {
	titre, lien, ref, resume, fluxTitre string
	publie                              int64
}

func (a article) versContenu(noeud, propriete string) gateway.Contenu {
	ref := a.ref
	if ref == "" {
		// Sans identifiant de flux, le lien fait référence : il ne change pas
		// d'un tirage à l'autre, la déduplication tient donc.
		ref = a.lien
	}
	return gateway.Contenu{
		Genre:        gateway.GenreLien,
		Titre:        a.titre,
		Corps:        a.resume,
		SourceURL:    a.lien,
		Connecteur:   "rss",
		RefNative:    ref,
		PublieLe:     a.publie,
		Propriete:    propriete,
		NoeudOrigine: noeud,
	}
}

// Structures XML minimales : on ne lit que ce dont on se sert.
type rssDoc struct {
	Channel struct {
		Title string `xml:"title"`
		Items []struct {
			Title   string `xml:"title"`
			Link    string `xml:"link"`
			GUID    string `xml:"guid"`
			Desc    string `xml:"description"`
			PubDate string `xml:"pubDate"`
		} `xml:"item"`
	} `xml:"channel"`
}

type atomDoc struct {
	Title   string `xml:"title"`
	Entries []struct {
		Title   string `xml:"title"`
		ID      string `xml:"id"`
		Summary string `xml:"summary"`
		Updated string `xml:"updated"`
		Links   []struct {
			Href string `xml:"href,attr"`
			Rel  string `xml:"rel,attr"`
		} `xml:"link"`
	} `xml:"entry"`
}

// dates acceptées : RSS suit le RFC 1123, Atom le RFC 3339.
var formats = []string{
	time.RFC1123Z, time.RFC1123, time.RFC3339,
	"Mon, 02 Jan 2006 15:04:05 -0700", "2006-01-02T15:04:05Z07:00",
}

func quand(s string) int64 {
	s = strings.TrimSpace(s)
	for _, f := range formats {
		if t, err := time.Parse(f, s); err == nil {
			return t.Unix()
		}
	}
	return 0
}

// analyser reconnaît RSS ou Atom sur le contenu, sans se fier à l'extension.
func analyser(brut []byte) ([]article, error) {
	var rd rssDoc
	if err := xml.Unmarshal(brut, &rd); err == nil && len(rd.Channel.Items) > 0 {
		out := make([]article, 0, len(rd.Channel.Items))
		for _, it := range rd.Channel.Items {
			out = append(out, article{
				titre: it.Title, lien: it.Link, ref: it.GUID,
				resume: it.Desc, publie: quand(it.PubDate), fluxTitre: rd.Channel.Title,
			})
		}
		return out, nil
	}
	var ad atomDoc
	if err := xml.Unmarshal(brut, &ad); err == nil && len(ad.Entries) > 0 {
		out := make([]article, 0, len(ad.Entries))
		for _, e := range ad.Entries {
			out = append(out, article{
				titre: e.Title, lien: lienAtom(e.Links), ref: e.ID,
				resume: e.Summary, publie: quand(e.Updated), fluxTitre: ad.Title,
			})
		}
		return out, nil
	}
	return nil, fmt.Errorf("rss : ni RSS ni Atom lisible")
}

func lienAtom(links []struct {
	Href string `xml:"href,attr"`
	Rel  string `xml:"rel,attr"`
}) string {
	for _, l := range links {
		if l.Rel == "alternate" || l.Rel == "" {
			return l.Href
		}
	}
	if len(links) > 0 {
		return links[0].Href
	}
	return ""
}
