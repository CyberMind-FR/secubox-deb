-- SPDX-License-Identifier: LicenseRef-CMSD-1.0
-- Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
-- Source-Disclosed License — All rights reserved except as expressly granted.
-- See LICENCE-CMSD-1.0.md for terms.
--
-- Socle de l'index DataScope V0.1 (#3853). Horodatages UTC RFC 3339. Aucune relation « inferred » :
-- la provenance (evidence_type, justification) est obligatoire. schema_migrations est inscrite par store.ouvrir
-- dans la même transaction que ce script.

CREATE TABLE IF NOT EXISTS entities (
  id TEXT PRIMARY KEY,
  type TEXT NOT NULL CHECK (type IN ('node','network','interface','device','ip','service')),
  label TEXT NOT NULL DEFAULT '',
  attributes_json TEXT NOT NULL DEFAULT '{}',
  source_module TEXT NOT NULL,
  first_seen TEXT NOT NULL,
  last_seen TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS entities_type ON entities(type);

CREATE TABLE IF NOT EXISTS relationships (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  src TEXT NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
  dst TEXT NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
  type TEXT NOT NULL CHECK (type IN ('BELONGS_TO','CONNECTS_TO','HOSTED_ON','OBSERVED_BY')),
  source_module TEXT NOT NULL,
  first_seen TEXT NOT NULL,
  last_seen TEXT NOT NULL,
  evidence_type TEXT NOT NULL CHECK (evidence_type IN ('observed','reported')),
  confidence REAL NOT NULL CHECK (confidence >= 0 AND confidence <= 1),
  justification TEXT NOT NULL CHECK (length(trim(justification)) > 0),
  UNIQUE (src, dst, type, source_module)
);
CREATE INDEX IF NOT EXISTS relationships_src ON relationships(src);
CREATE INDEX IF NOT EXISTS relationships_dst ON relationships(dst);

CREATE TABLE IF NOT EXISTS observations (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  entity_id TEXT NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
  source_module TEXT NOT NULL,
  observed_at TEXT NOT NULL,
  attributes_json TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS observations_at ON observations(observed_at);

CREATE TABLE IF NOT EXISTS curseurs (
  source TEXT PRIMARY KEY,
  empreinte TEXT NOT NULL,
  etat TEXT NOT NULL CHECK (etat IN ('ok','inaccessible','unknown')),
  motif TEXT,
  vu_le TEXT NOT NULL
);
