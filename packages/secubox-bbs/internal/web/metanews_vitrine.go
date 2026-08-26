// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package web

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// metaVue : un événement MetaNews tel que la rédaction l'affiche — vignette,
// titre, résumé court, et surtout le NOMBRE et le NOM des sources corrélées (le
// cœur de MetaNews : plusieurs sources → un événement).
type metaVue struct {
	ID       string
	Titre    string
	Resume   string
	NbSrc    int64
	Sources  []string
	Tags     []string
	Vignette string // chemin RELAYÉ (/mn-vignette?u=…) ou vide
	Lien     string
}

// Multi indique un événement corrélé sur PLUSIEURS sources (mis en avant).
func (m metaVue) Multi() bool { return m.NbSrc > 1 }

// newsVue : une news brute d'UNE source (listing « par source »).
type newsVue struct {
	Titre    string
	URL      string
	Vignette string
}

// srcVue : une source et ses dernières news (listing « par source »).
type srcVue struct {
	Nom       string
	Slug      string
	Categorie string
	News      []newsVue
}

// mnClient dialogue avec la socket MetaNews.
func (s *Server) mnClient() *http.Client {
	return &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", s.opt.MetaNewsSocket)
		}}}
}

// signeVignette scelle une URL amont pour le relais.
//
// CE QUI AUTORISE LE RELAIS, C'EST L'URL, PAS LE VISITEUR. /mn-vignette va
// chercher une adresse EXTERNE arbitraire : sans contrainte, c'est un proxy.
// Le garde precedent — « reserve aux membres » — se trompait de cible : il
// n'empechait pas l'abus (tout membre pouvait faire relayer n'importe quelle
// adresse) et il cassait les vignettes des pages PUBLIQUES, ou toutes les
// cartes d'actualite tombaient sur un placeholder.
//
// Le sceau HMAC dit « cette adresse vient d'un flux que NOUS avons publie ».
// Il ferme l'abus pour TOUT LE MONDE, membre compris, et laisse passer
// l'anonyme sur ce que la page affiche deja.
//
// Cle DERIVEE du secret JWT : le meme secret ne doit pas signer deux choses de
// nature differente.
func (s *Server) cleVignette() []byte {
	m := hmac.New(sha256.New, []byte(s.opt.JWTSecret))
	m.Write([]byte("mn-vignette/v1"))
	return m.Sum(nil)
}

func (s *Server) signeVignette(u string) string {
	m := hmac.New(sha256.New, s.cleVignette())
	m.Write([]byte(u))
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil)[:16])
}

// relayVignette transforme une URL d'image EXTERNE en chemin same-origin relayé
// (/mn-vignette?u=…&s=…) : le navigateur ne contacte jamais le média tiers
// (vie privée + `img-src 'self'`). Vide si pas d'image.
func (s *Server) relayVignette(u string) string {
	u = strings.TrimSpace(u)
	if u == "" || !(strings.HasPrefix(u, "http://") || strings.HasPrefix(u, "https://")) {
		return ""
	}
	return "/mn-vignette?u=" + url.QueryEscape(u) + "&s=" + s.signeVignette(u)
}

// vitrineMetaNews récupère une dizaine d'événements récents (déjà classés par
// importance : le multi-source remonte). Panne = message, jamais page cassée.
func (s *Server) vitrineMetaNews() ([]metaVue, string) {
	if s.opt.MetaNewsSocket == "" {
		return nil, "module metanews non configuré."
	}
	resp, err := s.mnClient().Get("http://metanews/api/v1/metanews/topics?category=une")
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
			Vignette string   `json:"vignette"`
		} `json:"topics"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&d); err != nil {
		return nil, "réponse MetaNews illisible : " + err.Error()
	}
	base := strings.TrimRight(s.opt.MetaNewsBase, "/")
	if base == "" {
		base = ""
	}
	out := make([]metaVue, 0, 12)
	for i, t := range d.Topics {
		if i >= 12 {
			break
		}
		// LIEN PAR SUJET, PAS GLOBAL (#1359). Tous les cartouches pointaient
		// vers l'accueil MetaNews (`base + "/"`), en ignorant `t.ID` pourtant
		// disponible : « on va ni sur la bonne source ni sur la bonne ref ».
		// Le front MetaNews route `#<id>` vers le sujet et ses sources. Le
		// premier cartouche (« tout voir ») garde le lien global.
		lien := base + "/#" + url.PathEscape(t.ID)
		out = append(out, metaVue{
			ID: t.ID, Titre: t.Title, Resume: t.Summary,
			NbSrc: t.NbSrc, Sources: t.Sources, Tags: t.Tags,
			Vignette: s.relayVignette(t.Vignette), Lien: lien,
		})
	}
	return out, ""
}

// vitrineMetaSources récupère les dernières news GROUPÉES PAR SOURCE.
func (s *Server) vitrineMetaSources() []srcVue {
	if s.opt.MetaNewsSocket == "" {
		return nil
	}
	resp, err := s.mnClient().Get("http://metanews/api/v1/metanews/by-source")
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	var d struct {
		Sources []struct {
			Name     string `json:"name"`
			Slug     string `json:"slug"`
			Category string `json:"category"`
			Items    []struct {
				Title string `json:"title"`
				URL   string `json:"url"`
				Image string `json:"image"`
			} `json:"items"`
		} `json:"sources"`
	}
	if json.NewDecoder(io.LimitReader(resp.Body, 2<<20)).Decode(&d) != nil {
		return nil
	}
	var out []srcVue
	for _, s0 := range d.Sources {
		v := srcVue{Nom: s0.Name, Slug: s0.Slug, Categorie: s0.Category}
		for _, it := range s0.Items {
			v.News = append(v.News, newsVue{Titre: it.Title, URL: it.URL, Vignette: s.relayVignette(it.Image)})
		}
		out = append(out, v)
	}
	return out
}

// servirMNVignette relaie une image d'article MetaNews : le membre ne contacte
// jamais le média tiers. Réservé aux membres, garde ANTI-SSRF (aucune adresse
// interne), image seulement, taille bornée, en-têtes du membre non transmis.
func (s *Server) servirMNVignette(w http.ResponseWriter, r *http.Request) {
	// SANS SECRET, ON NE PEUT PAS SCELLER : on retombe alors sur le garde
	// historique plutot que d'ouvrir un proxy sur une installation mal reglee.
	brut := r.URL.Query().Get("u")
	if s.opt.JWTSecret == "" {
		if v := s.qui(r); !v.Connecte {
			http.Error(w, "reserve aux membres", http.StatusForbidden)
			return
		}
	} else if !hmac.Equal([]byte(r.URL.Query().Get("s")), []byte(s.signeVignette(brut))) {
		// 404 et non 403 : un sceau invalide ne merite pas de confirmation.
		http.NotFound(w, r)
		return
	}
	u, err := url.Parse(brut)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		http.NotFound(w, r)
		return
	}
	if err := gardeSSRF(u.Hostname()); err != nil {
		http.NotFound(w, r)
		return
	}
	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, u.String(), nil)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	req.Header.Set("Accept", "image/*")
	req.Header.Set("User-Agent", "secubox-bbs/relais")
	res, err := (&http.Client{Timeout: mediaDelai}).Do(req)
	if err != nil {
		http.Error(w, "vignette indisponible", http.StatusBadGateway)
		return
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		http.NotFound(w, r)
		return
	}
	ct := strings.ToLower(strings.TrimSpace(strings.SplitN(res.Header.Get("Content-Type"), ";", 2)[0]))
	if !mediaTypes[ct] {
		http.NotFound(w, r)
		return
	}
	corps, err := io.ReadAll(io.LimitReader(res.Body, mediaMax+1))
	if err != nil || len(corps) > mediaMax {
		http.Error(w, "vignette trop volumineuse", http.StatusBadGateway)
		return
	}
	w.Header().Set("Content-Type", ct)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	// Identique pour tous (aucun en-tete du visiteur transmis) : le cache
	// PARTAGE doit pouvoir l'absorber, c'est lui qui borne l'amplification.
	w.Header().Set("Cache-Control", "public, max-age=86400")
	_, _ = w.Write(corps)
}

// gardeSSRF refuse un hôte qui résout vers une adresse interne (loopback, privé,
// lien-local) — une image d'un flux ne doit jamais faire sonder le réseau local.
func gardeSSRF(hote string) error {
	if hote == "" || strings.EqualFold(hote, "localhost") || strings.HasSuffix(hote, ".local") {
		return fmt.Errorf("hôte interne")
	}
	ips, err := net.LookupIP(hote)
	if err != nil {
		return err
	}
	for _, ip := range ips {
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() {
			return fmt.Errorf("adresse interne")
		}
	}
	return nil
}
