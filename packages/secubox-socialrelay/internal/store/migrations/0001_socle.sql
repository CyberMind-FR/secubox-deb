-- SPDX-License-Identifier: LicenseRef-CMSD-1.0
-- Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
-- SocialRelay — socle : sources sociales, posts relayés, médias cachés.

CREATE TABLE IF NOT EXISTS source (
  id          INTEGER PRIMARY KEY,
  slug        TEXT NOT NULL UNIQUE,
  name        TEXT NOT NULL,
  kind        TEXT NOT NULL DEFAULT 'mastodon',  -- mastodon | bluesky | peertube | youtube | bridge
  handle      TEXT NOT NULL DEFAULT '',          -- @user@instance ou #tag@instance
  url         TEXT NOT NULL DEFAULT '',
  enabled     INTEGER NOT NULL DEFAULT 1,
  mode        TEXT NOT NULL DEFAULT 'open',       -- open | bridge | consent
  salon       TEXT NOT NULL DEFAULT 'reseaux',    -- salon BBS cible
  refresh_sec INTEGER NOT NULL DEFAULT 600,
  last_sync   INTEGER NOT NULL DEFAULT 0,
  last_error  TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS post (
  id            INTEGER PRIMARY KEY,
  source_id     INTEGER NOT NULL REFERENCES source(id) ON DELETE CASCADE,
  ref           TEXT NOT NULL,                    -- id natif du post
  author        TEXT NOT NULL DEFAULT '',
  url           TEXT NOT NULL DEFAULT '',
  text          TEXT NOT NULL DEFAULT '',
  published_at  INTEGER NOT NULL DEFAULT 0,
  fetched_at    INTEGER NOT NULL DEFAULT 0,
  bbs_thread_id INTEGER NOT NULL DEFAULT 0,
  media         TEXT NOT NULL DEFAULT '[]',       -- JSON [{hash,kind,orig}]
  UNIQUE(source_id, ref)
);
CREATE INDEX IF NOT EXISTS idx_post_pub ON post(published_at DESC);

CREATE TABLE IF NOT EXISTS media (
  hash       TEXT PRIMARY KEY,
  kind       TEXT NOT NULL DEFAULT '',            -- image | video | gifv
  bytes      INTEGER NOT NULL DEFAULT 0,
  ext        TEXT NOT NULL DEFAULT '',
  fetched_at INTEGER NOT NULL DEFAULT 0,
  orig_url   TEXT NOT NULL DEFAULT ''
);
