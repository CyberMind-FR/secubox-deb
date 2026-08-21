// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// Lecture des fils deposes par les passerelles media (#1020).
//
// La page Media annoncait « aucune passerelle media raccordee » alors que 222
// fils y etaient deja : 122 emissions du podcaster et 100 videos PeerTube. Elle
// n'interrogeait pas la base — meme defaut que la Bibliotheque et les Billets.
package store

// Sources media reconnues. Le podcaster et PeerTube deposent leurs fils par
// `bbsctl ingest`, sous l'auteur `passerelle` et dans leur salon dedie.
//
// La liste est explicite plutot que deduite : `billets` est aussi une
// passerelle, mais ce qu'elle depose est du TEXTE — l'afficher sous « Media »
// noierait ce qu'on vient y chercher.
var SourcesMedia = []string{"podcaster", "peertube"}

// FilMedia : un fil depose par une passerelle media.
type FilMedia struct {
	Thread
	Salon string
}

// MediasParSource rend les fils des passerelles media, les plus recents
// d'abord, toutes sources confondues.
//
// `borne` s'applique a l'ENSEMBLE et non par source : la page montre ce qui est
// recent, pas un quota par passerelle. Un podcast tres actif doit pouvoir
// occuper la page — c'est ce que l'on veut voir.
func (s *Store) MediasParSource(borne int) ([]FilMedia, error) {
	if borne <= 0 || borne > 500 {
		borne = 60
	}
	rows, err := s.db.Query(`
		SELECT t.id, t.category_id, t.slug, t.title, t.visibility,
		       COALESCE(t.source,''), t.last_post_at,
		       COALESCE(t.media_url,''), COALESCE(t.media_kind,''),
		       COALESCE(c.title,'')
		  FROM threads t
		  LEFT JOIN categories c ON c.id = t.category_id
		 WHERE t.source IN (?, ?)
		 ORDER BY t.last_post_at DESC, t.id DESC
		 LIMIT ?`, SourcesMedia[0], SourcesMedia[1], borne)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []FilMedia
	for rows.Next() {
		var f FilMedia
		if err := rows.Scan(&f.ID, &f.CategoryID, &f.Slug, &f.Title,
			&f.Visibility, &f.Source, &f.LastPostAt,
			&f.MediaURL, &f.MediaKind, &f.Salon); err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// CompteMedias rend le nombre de fils par source, pour dire ce qui est
// raccorde meme quand la page ne montre qu'un extrait.
func (s *Store) CompteMedias() (map[string]int, error) {
	rows, err := s.db.Query(`
		SELECT source, count(*) FROM threads
		 WHERE source IS NOT NULL AND source <> ''
		 GROUP BY source`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	m := map[string]int{}
	for rows.Next() {
		var s0 string
		var n int
		if err := rows.Scan(&s0, &n); err != nil {
			return nil, err
		}
		m[s0] = n
	}
	return m, rows.Err()
}

// MediasDuFil rend les pièces jointes (par ordre d'apparition) des messages
// d'un fil, pour la vignette média de sa carte de rédaction (#1092). Une seule
// requête, bornée. `pub` n'expose QUE les messages publics — une carte publique
// ne doit jamais révéler un média d'un message local. Ne renvoie que l'id et le
// type MIME : la carte sert la miniature par /f/<id>, elle n'a pas besoin du reste.
func (s *Store) MediasDuFil(threadID int64, pub bool, borne int) ([]Fichier, error) {
	q := `SELECT f.id, f.mime
	        FROM pieces_jointes pj
	        JOIN posts p ON p.id = pj.post_id
	        JOIN files f ON f.id = pj.file_id
	       WHERE p.thread_id = ? AND pj.post_id IS NOT NULL
	         AND p.deleted_at IS NULL AND f.deleted_at IS NULL`
	if pub {
		q += ` AND p.visibility = 'public'`
	}
	q += ` GROUP BY f.id ORDER BY min(p.created_at), min(pj.rang) LIMIT ?`
	rows, err := s.db.Query(q, threadID, borne)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Fichier
	for rows.Next() {
		var f Fichier
		if err := rows.Scan(&f.ID, &f.Mime); err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}
