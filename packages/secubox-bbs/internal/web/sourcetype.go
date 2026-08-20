// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
//
// « Déposer une source » (#1056 stage 2). N'importe quelle adresse — un
// article, une vidéo, un podcast, un film, un livre, une conférence — amorce un
// DOSSIER discutable. On DÉDUIT le type de la seule adresse (domaine + chemin) :
// aucune requête vers le tiers n'est faite ici. C'est un choix de sécurité
// autant que de sobriété — le serveur ne va pas chercher une URL fournie par un
// membre (pas de SSRF), et l'adresse voyage dans le premier message où le rendu
// la transforme en lien (ou en lecteur pour une vidéo connue).
package web

import (
	"net/url"
	"strings"
)

// SourceType : le résultat du typage — la valeur `Source` posée sur le fil, son
// glyphe et son étiquette pour la rédaction.
type SourceType struct {
	Source  string // "video" | "podcast" | "film" | "livre" | "conference" | "web"
	Glyphe  string
	Label   string
}

var famillesSource = []struct {
	st    SourceType
	hosts []string
	paths []string
}{
	{SourceType{"video", "🎬", "vidéo"},
		[]string{"youtube.", "youtu.be", "vimeo.", "dailymotion.", "peertube.", "tube.", ".tv"}, nil},
	{SourceType{"podcast", "🎧", "podcast"},
		[]string{"spotify.", "soundcloud.", "podcasts.apple.", "deezer.", "ausha.", "podcloud.", "acast.", "anchor.fm"},
		[]string{"/podcast", "/feed", ".rss", "/rss"}},
	{SourceType{"film", "🎞️", "film"},
		[]string{"imdb.", "letterboxd.", "allocine.", "senscritique.", "themoviedb.", "justwatch."}, nil},
	{SourceType{"livre", "📖", "livre"},
		[]string{"goodreads.", "babelio.", "openlibrary.", "gallica.", "gutenberg.", "thestorygraph."},
		[]string{"/isbn", "/livre", "/book"}},
	{SourceType{"conference", "🎤", "conférence"},
		[]string{"ted.com", "fosdem.", "sched.", "media.ccc.", "conf.", "talks."},
		[]string{"/talk", "/conference", "/keynote", "/session"}},
}

// typerSource déduit le type d'une adresse. Défaut : « web » (🔗 source), qui
// couvre article / site / page — jamais un type inventé.
func typerSource(brut string) SourceType {
	defaut := SourceType{"web", "🔗", "source"}
	u, err := url.Parse(strings.TrimSpace(brut))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return defaut
	}
	host := strings.ToLower(u.Host)
	chemin := strings.ToLower(u.Path)
	for _, f := range famillesSource {
		for _, h := range f.hosts {
			if strings.Contains(host, h) {
				return f.st
			}
		}
		for _, p := range f.paths {
			if strings.Contains(chemin, p) {
				return f.st
			}
		}
	}
	return defaut
}

// adresseSource ne retient qu'une adresse http(s) bien formée — la garde qui
// empêche un « javascript: » ou un chemin local de se faire passer pour une
// source (le rendu du corps refuse déjà ces schémas, ceinture et bretelles).
func adresseSource(brut string) (string, bool) {
	brut = strings.TrimSpace(brut)
	u, err := url.Parse(brut)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return "", false
	}
	return brut, true
}
