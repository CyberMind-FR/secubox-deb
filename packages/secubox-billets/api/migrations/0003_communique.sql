-- SPDX-License-Identifier: LicenseRef-CMSD-1.0
-- Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
-- billets :: per-billet presentation style + embed snapshot vignette.
--   style          : 'default' (feed look) or 'communique' (poster/affiche look).
--   embed_snapshot : filename of a captured vignette of the embed (headless
--                    screenshot, or og:image fallback), stored under
--                    BILLETS_MEDIA_DIR like any media file. Nullable — no snapshot
--                    yet (or capture failed) => render the live embed instead.
-- SQLite ALTER ADD COLUMN with a constant default is a metadata-only operation.

ALTER TABLE billet ADD COLUMN style TEXT NOT NULL DEFAULT 'default'
  CHECK (style IN ('default','communique'));
ALTER TABLE billet ADD COLUMN embed_snapshot TEXT;
