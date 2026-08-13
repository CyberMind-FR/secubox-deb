// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// Lecture des fils publies en billet (#1020).
//
// La table `billets` etait ecrite mais jamais relue : la page annoncait
// « aucun fil publie » alors que deux l'etaient, et le compteur du menu — qui
// lit bien la base — affichait « 2 ». Un compteur juste a cote d'une liste
// vide est pire qu'une page absente : il prouve que la donnee existe et que la
// page ment.
package store

// BilletPublie : un fil sorti vers la vitrine.
type BilletPublie struct {
	ThreadID  int64
	Titre     string
	Slug      string
	BilletID  string
	URL       string
	Publie    int64
	Repris    int  // messages effectivement emportes
	Retenus   int  // messages restes locaux
}

// Billets rend les fils publies, le plus recent d'abord.
//
// Le titre vient de `threads` : la table `billets` ne le duplique pas, et c'est
// voulu — renommer un fil ne doit pas laisser un titre perime dans la vitrine.
func (s *Store) Billets(borne int) ([]BilletPublie, error) {
	if borne <= 0 || borne > 500 {
		borne = 100
	}
	rows, err := s.db.Query(`
		SELECT b.thread_id, COALESCE(t.title,''), COALESCE(t.slug,''),
		       b.billet_id, b.url, b.published_at, b.taken, b.held
		  FROM billets b
		  LEFT JOIN threads t ON t.id = b.thread_id
		 ORDER BY b.published_at DESC
		 LIMIT ?`, borne)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []BilletPublie
	for rows.Next() {
		var b BilletPublie
		if err := rows.Scan(&b.ThreadID, &b.Titre, &b.Slug, &b.BilletID,
			&b.URL, &b.Publie, &b.Repris, &b.Retenus); err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}
