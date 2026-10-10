-- SPDX-License-Identifier: LicenseRef-CMSD-1.0
-- #2266 — LE FIL EST VIVANT : un billet publié, ou COMMENTÉ, remonte en tête.
--
-- `bumped_at` = l'instant de la dernière chose qui doit faire remonter le billet : sa publication, ou son dernier commentaire APPROUVÉ (un commentaire
-- en attente, rejeté ou signalé comme spam ne remonte rien). Le fil HTML se trie par cette colonne ; les flux RSS/JSON et la vignette « micro » restent
-- en ordre de publication. `published_at` n'est jamais modifié.
ALTER TABLE billet ADD COLUMN bumped_at TEXT;

UPDATE billet SET bumped_at = published_at WHERE published_at IS NOT NULL;

UPDATE billet
   SET bumped_at = (SELECT MAX(c.created_at) FROM comment c WHERE c.billet_id = billet.id AND c.status = 'approved')
 WHERE published_at IS NOT NULL
   AND (SELECT MAX(c.created_at) FROM comment c WHERE c.billet_id = billet.id AND c.status = 'approved') > published_at;

CREATE INDEX IF NOT EXISTS idx_billet_bumped ON billet(bumped_at DESC, id DESC) WHERE status = 'published';
