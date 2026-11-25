-- SPDX-License-Identifier: LicenseRef-CMSD-1.0
-- Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
-- Source-Disclosed License — All rights reserved except as expressly granted.
-- See LICENCE-CMSD-1.0.md for terms.
--
-- Instantanés du paysage (#3921) : graphe compressé (zlib(JSON)) par génération. Aucune hypothèse sur
-- l'espacement des instantanés. Table propre : n'écrit rien dans entities/relationships.

CREATE TABLE IF NOT EXISTS paysage_instantanes (
  ts TEXT PRIMARY KEY,
  epoch REAL NOT NULL,
  partiel INTEGER NOT NULL,
  graphe BLOB NOT NULL,
  compteurs_json TEXT NOT NULL,
  difference_json TEXT NOT NULL DEFAULT '{}',
  octets INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS paysage_instantanes_epoch ON paysage_instantanes(epoch);
