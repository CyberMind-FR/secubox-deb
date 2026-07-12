-- SPDX-License-Identifier: LicenseRef-CMSD-1.0
-- Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
-- billets :: media attachments. Images are re-encoded (EXIF/polyglot stripped)
-- and stored on disk under BILLETS_MEDIA_DIR as <id>.<ext> (+ <id>_t.<ext>
-- thumbnail); this table holds the metadata. Ordering is (position, created_at).

CREATE TABLE IF NOT EXISTS media (
  id          TEXT PRIMARY KEY,     -- ULID
  billet_id   TEXT NOT NULL REFERENCES billet(id) ON DELETE CASCADE,
  filename    TEXT NOT NULL,        -- <id>.<ext> under BILLETS_MEDIA_DIR
  thumb       TEXT NOT NULL,        -- <id>_t.<ext> (vignette)
  mime        TEXT NOT NULL,
  width       INTEGER NOT NULL,
  height      INTEGER NOT NULL,
  alt         TEXT NOT NULL DEFAULT '',
  position    INTEGER NOT NULL DEFAULT 0,
  created_at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_media_billet ON media(billet_id, position, created_at);
