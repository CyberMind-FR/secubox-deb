-- SPDX-License-Identifier: LicenseRef-CMSD-1.0
-- Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
-- billets :: emoji hashtags for quick-view categorisation.
--   Authors just type `#secu #waf` in the body — no extra editor step, and it
--   works retroactively on billets written before this migration (backfilled by
--   `python -m api.manage backfill-tags`). Tags are EXTRACTED into real rows
--   rather than re-parsed per request so the feed can filter on an index
--   instead of scanning every body with LIKE.
--
--   tag.slug  : normalised (lowercase, accents folded) — #Réseau and #reseau are
--               the same tag. This is the identity, so it is the PK.
--   tag.emoji : curated in services/tags.py; unknown tags fall back to a default
--               badge emoji. Stored (not derived at read time) so a later map
--               change never silently rewrites what a published billet displayed.
--
-- billet_tag rows die with their billet (ON DELETE CASCADE); orphan tag rows are
-- harmless (they simply stop appearing in counts) and get reused on the next use.

CREATE TABLE IF NOT EXISTS tag (
  slug   TEXT PRIMARY KEY,
  emoji  TEXT NOT NULL,
  label  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS billet_tag (
  billet_id TEXT NOT NULL REFERENCES billet(id) ON DELETE CASCADE,
  tag_slug  TEXT NOT NULL REFERENCES tag(slug) ON DELETE CASCADE,
  PRIMARY KEY (billet_id, tag_slug)
);

-- The feed's filter direction is tag -> billets, so index that side.
CREATE INDEX IF NOT EXISTS idx_billet_tag_slug ON billet_tag(tag_slug);
