// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>

package store

// SujetsADiffuser : les sujets à publier comme billets éphémères (#2268) — mis à jour depuis `depuis`, d'au moins `minSources` sources, et PAS déjà publiés
// depuis `grace`. Les plus importants d'abord, puis les plus récents.
func (s *Store) SujetsADiffuser(depuis int64, minSources int, grace int64, limite int) ([]Topic, error) {
	return s.scanTopics(
		`WHERE updated_at >= ? AND sources_count >= ?
		   AND NOT EXISTS(SELECT 1 FROM billet_ephemere b WHERE b.topic_id = topic.id AND b.publie_a >= ?)
		 ORDER BY importance DESC, updated_at DESC LIMIT ?`, depuis, minSources, grace, limite)
}

// MarquerDiffuse retient qu'un sujet a été publié (remplace la ligne précédente : un seul état par sujet).
func (s *Store) MarquerDiffuse(topicID, billetID, slug string, at int64) error {
	_, err := s.db.Exec(`INSERT OR REPLACE INTO billet_ephemere(topic_id, billet_id, slug, publie_a) VALUES(?,?,?,?)`, topicID, billetID, slug, at)
	return err
}

// DiffusesDepuis : combien de sujets ont été publiés depuis `depuis` — le plafond horaire se tient là-dessus.
func (s *Store) DiffusesDepuis(depuis int64) (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM billet_ephemere WHERE publie_a >= ?`, depuis).Scan(&n)
	return n, err
}
