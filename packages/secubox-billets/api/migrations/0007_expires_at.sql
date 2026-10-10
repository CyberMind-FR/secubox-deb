-- SPDX-License-Identifier: LicenseRef-CMSD-1.0
-- #2268 — BILLETS ÉPHÉMÈRES : une durée de vie limitée (MetaNews publie des billets de 5 minutes).
--
-- `expires_at` = l'instant où le billet quitte le fil (publication + ttl_s). NULL = billet durable. Le fil et les flux l'excluent DÈS l'échéance (filtre à
-- la lecture) ; un balayage l'archive ensuite (status 'archived', conservé 24 h pour l'audit) puis le supprime.
ALTER TABLE billet ADD COLUMN expires_at TEXT;
CREATE INDEX IF NOT EXISTS idx_billet_expires ON billet(expires_at) WHERE expires_at IS NOT NULL;
