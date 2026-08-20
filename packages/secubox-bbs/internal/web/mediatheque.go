// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
//
// Médiathèque : le podcaster rendu EN ARBORESCENCE (#1056). Le salon
// « émissions » montrait 145 fils plats — un par épisode, tous mélangés, du
// plus récent au plus ancien : ni sous-dossiers, ni ordre correct pour un livre
// audio (qui se lit du chapitre 1 au dernier), ni vignette, ni lecteur intégré.
//
// Ici on regroupe par FLUX (un podcast, un livre audio = un dossier), on ordonne
// PAR TYPE — livre audio pubdate ASC (chapitre 1→N), podcast/série DESC (récent
// d'abord), au miroir du podcaster lui-même — et chaque épisode est jouable en
// ligne. On LIT la base du podcaster en lecture seule (comme DepuisPodcaster) ;
// l'audio passe par le relais existant /media/ep/<id>, la vignette par
// /media-cover/<fid> (cover.jpg extraite par le podcaster sous sa racine media).
package web

import (
	"database/sql"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	_ "modernc.org/sqlite"
)

// PodEpisode : un épisode téléchargé, jouable.
type PodEpisode struct {
	ID     int64
	Titre  string
	Media  string // /media/ep/<id>
	Duree  string // mm:ss, vide si inconnu
	Numero int    // rang d'affichage (1..N)
}

// PodFeed : un flux = un sous-dossier de la médiathèque.
type PodFeed struct {
	ID       int64
	Titre    string
	Type     string // "audiobook" | "podcast" | "serie"
	Glyphe   string // 📖 / 🎧 / 🎬
	Vignette string // /media-cover/<id>
	Date     int64  // pubdate du plus récent épisode — pour classer le flux dans la rédaction
	Episodes []PodEpisode
}

// mediatheque lit la base du podcaster et rend les flux qui ont AU MOINS un
// épisode téléchargé (donc jouable), chacun avec ses épisodes ordonnés par type.
func (s *Server) mediatheque(limite int) ([]PodFeed, error) {
	if s.opt.PodcastDB == "" {
		return nil, nil
	}
	if limite <= 0 {
		limite = 2000
	}
	db, err := sql.Open("sqlite", "file:"+s.opt.PodcastDB+"?mode=ro&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, err
	}
	defer db.Close()

	// JOINTURE + ORDRE PAR TYPE dans la requête : d'abord par flux (titre stable),
	// puis à l'intérieur d'un flux — livre audio du 1er au dernier chapitre
	// (pubdate ASC), sinon le plus récent d'abord (pubdate DESC via -pubdate ASC).
	rows, err := db.Query(`SELECT f.id, f.title, COALESCE(f.url,''),
		e.id, COALESCE(e.title,''), COALESCE(e.duration,0), COALESCE(e.pubdate,0)
		FROM feeds f JOIN episodes e ON e.feed_id = f.id
		WHERE e.state='done' AND e.local_path IS NOT NULL AND e.local_path <> ''
		ORDER BY f.title COLLATE NOCASE,
		         CASE WHEN f.url LIKE 'audiobook:%' THEN e.pubdate ELSE -e.pubdate END ASC
		LIMIT ?`, limite)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []PodFeed
	index := map[int64]int{} // feed id -> position dans out
	for rows.Next() {
		var fid, eid, pub int64
		// `duration` est une CHAÎNE dans le podcaster (« 00:36:15 »), parfois un
		// entier de secondes : on la scanne en texte et on normalise.
		var ftitre, furl, etitre, dur string
		if err := rows.Scan(&fid, &ftitre, &furl, &eid, &etitre, &dur, &pub); err != nil {
			return nil, err
		}
		pos, ok := index[fid]
		if !ok {
			typ, gly := classerFlux(furl)
			out = append(out, PodFeed{
				ID: fid, Titre: ftitre, Type: typ, Glyphe: gly,
				Vignette: "/media-cover/" + strconv.FormatInt(fid, 10),
			})
			pos = len(out) - 1
			index[fid] = pos
		}
		ep := PodEpisode{
			ID: eid, Titre: etitre,
			Media:  "/media/ep/" + strconv.FormatInt(eid, 10),
			Duree:  normaliserDuree(dur),
			Numero: len(out[pos].Episodes) + 1,
		}
		out[pos].Episodes = append(out[pos].Episodes, ep)
		if pub > out[pos].Date {
			out[pos].Date = pub // le flux se classe par son épisode le plus récent
		}
	}
	return out, rows.Err()
}

// classerFlux déduit le type d'un flux de son préfixe d'URL (convention du
// podcaster : `audiobook:` / `youtube:` / une vraie URL RSS pour un podcast).
func classerFlux(url string) (typ, glyphe string) {
	switch {
	case strings.HasPrefix(url, "audiobook:"):
		return "audiobook", "📖"
	case strings.HasPrefix(url, "youtube:"):
		return "serie", "🎬"
	default:
		return "podcast", "🎧"
	}
}

// normaliserDuree rend une durée lisible depuis ce que porte le podcaster :
// une chaîne « HH:MM:SS » (on masque « 00: » de tête), ou un entier de secondes.
func normaliserDuree(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if n, err := strconv.ParseInt(s, 10, 64); err == nil {
		return dureeMMSS(n)
	}
	if strings.HasPrefix(s, "00:") && strings.Count(s, ":") == 2 {
		return s[3:]
	}
	return s
}

func dureeMMSS(sec int64) string {
	if sec <= 0 {
		return ""
	}
	if sec >= 3600 {
		return strconv.FormatInt(sec/3600, 10) + ":" +
			pad2((sec%3600)/60) + ":" + pad2(sec%60)
	}
	return strconv.FormatInt(sec/60, 10) + ":" + pad2(sec%60)
}
func pad2(n int64) string {
	s := strconv.FormatInt(n, 10)
	if len(s) < 2 {
		return "0" + s
	}
	return s
}

// servirCover sert la vignette d'un flux : cover.jpg extraite par le podcaster
// sous sa racine media (<racine>/<fid>/cover.jpg). LECTURE SEULE et CONFINÉE aux
// racines déclarées — l'id de flux est validé numérique, aucun chemin ne peut
// remonter l'arborescence. 404 discret si absente (beaucoup de podcasts n'ont
// qu'une image RSS distante, pas de cover locale).
func (s *Server) servirCover(w http.ResponseWriter, r *http.Request) {
	fid := strings.TrimPrefix(r.URL.Path, "/media-cover/")
	if fid == "" || strings.ContainsAny(fid, "/.\\") {
		http.NotFound(w, r)
		return
	}
	if _, err := strconv.ParseInt(fid, 10, 64); err != nil {
		http.NotFound(w, r)
		return
	}
	for _, racine := range strings.Split(s.opt.PodcastRacine, ",") {
		racine = strings.TrimSpace(racine)
		if racine == "" {
			continue
		}
		p := filepath.Join(racine, fid, "cover.jpg")
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			w.Header().Set("Cache-Control", "public, max-age=86400")
			http.ServeFile(w, r, p)
			return
		}
	}
	http.NotFound(w, r)
}
