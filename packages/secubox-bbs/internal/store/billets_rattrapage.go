// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
package store

import "database/sql"

// BilletSansAdresse : un billet publie dont l'adresse manque.
type BilletSansAdresse struct {
	ThreadID int64
	BilletID string
	Titre    string
}

// BilletsSansAdresse liste ce que le defaut #1024 a laisse derriere lui.
//
// POURQUOI UN INVENTAIRE PLUTOT QU'UN `UPDATE` A LA MAIN. Le defaut a dure des
// mois : deux billets sont concernes sur gk2 aujourd'hui, on ne sait pas
// combien ailleurs. Une commande qui LISTE d'abord permet de voir l'ampleur
// avant d'ecrire, et de repasser plus tard sans se souvenir de quoi que ce
// soit.
func (s *Store) BilletsSansAdresse() ([]BilletSansAdresse, error) {
	rows, err := s.db.Query(`
		SELECT b.thread_id, b.billet_id, COALESCE(t.title,'')
		  FROM billets b
		  LEFT JOIN threads t ON t.id = b.thread_id
		 WHERE COALESCE(b.url,'') = ''
		 ORDER BY b.published_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []BilletSansAdresse
	for rows.Next() {
		var b BilletSansAdresse
		if err := rows.Scan(&b.ThreadID, &b.BilletID, &b.Titre); err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

// PoseAdresseBillet renseigne l'adresse d'un billet deja publie.
//
// ON N'ECRASE JAMAIS UNE ADRESSE EXISTANTE. Le rattrapage comble un vide ; s'il
// pouvait remplacer, une passe malencontreuse repointerait des billets corrects
// vers ce que le rattrapage croit savoir — et un lien casse par une reparation
// est plus difficile a comprendre qu'un lien jamais pose.
func (s *Store) PoseAdresseBillet(threadID int64, url string) error {
	res, err := s.db.Exec(`
		UPDATE billets SET url = ?
		 WHERE thread_id = ? AND COALESCE(url,'') = ''`, url, threadID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return sql.ErrNoRows
	}
	return nil
}
