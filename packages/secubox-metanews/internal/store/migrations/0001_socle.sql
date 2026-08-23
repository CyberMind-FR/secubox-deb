-- SPDX-License-Identifier: LicenseRef-CMSD-1.0
-- Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
-- MetaNews — socle : sources, articles, sujets (événements), timeline.

CREATE TABLE IF NOT EXISTS source (
  id          INTEGER PRIMARY KEY,
  slug        TEXT NOT NULL UNIQUE,
  name        TEXT NOT NULL,
  type        TEXT NOT NULL DEFAULT 'rss',      -- 'rss' | 'atom' (auto-détecté)
  url         TEXT NOT NULL,
  enabled     INTEGER NOT NULL DEFAULT 1,
  category    TEXT NOT NULL DEFAULT 'general',
  refresh_sec INTEGER NOT NULL DEFAULT 900,
  last_sync   INTEGER NOT NULL DEFAULT 0,
  last_error  TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS article (
  id           INTEGER PRIMARY KEY,
  source_id    INTEGER NOT NULL REFERENCES source(id) ON DELETE CASCADE,
  ref          TEXT NOT NULL,                    -- guid/link : identité stable
  title        TEXT NOT NULL,
  url          TEXT NOT NULL,
  summary      TEXT NOT NULL DEFAULT '',
  author       TEXT NOT NULL DEFAULT '',
  lang         TEXT NOT NULL DEFAULT '',
  published_at INTEGER NOT NULL DEFAULT 0,
  fetched_at   INTEGER NOT NULL DEFAULT 0,
  fingerprint  TEXT NOT NULL DEFAULT '',         -- hash titre+résumé normalisés (anti-clone)
  entities     TEXT NOT NULL DEFAULT '[]',       -- JSON
  tags         TEXT NOT NULL DEFAULT '[]',       -- JSON
  topic_id     TEXT NOT NULL DEFAULT '',         -- '' tant que non regroupé
  UNIQUE(source_id, ref)
);
CREATE INDEX IF NOT EXISTS idx_article_topic ON article(topic_id);
CREATE INDEX IF NOT EXISTS idx_article_pub   ON article(published_at DESC);

CREATE TABLE IF NOT EXISTS topic (
  id            TEXT PRIMARY KEY,                -- mn_YYYYMMDD_xxxx
  title         TEXT NOT NULL,
  summary       TEXT NOT NULL DEFAULT '',
  lang          TEXT NOT NULL DEFAULT '',
  created_at    INTEGER NOT NULL,
  updated_at    INTEGER NOT NULL,
  tags          TEXT NOT NULL DEFAULT '[]',      -- JSON
  entities      TEXT NOT NULL DEFAULT '[]',      -- JSON
  sources_count INTEGER NOT NULL DEFAULT 0,      -- ORIGINES distinctes (clones fondus)
  confidence    REAL NOT NULL DEFAULT 0,
  importance    REAL NOT NULL DEFAULT 0,
  bbs_thread_id INTEGER NOT NULL DEFAULT 0,      -- 0 tant que pas de discussion
  bbs_slug      TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_topic_updated ON topic(updated_at DESC);

CREATE TABLE IF NOT EXISTS topic_event (
  id       INTEGER PRIMARY KEY,
  topic_id TEXT NOT NULL REFERENCES topic(id) ON DELETE CASCADE,
  at       INTEGER NOT NULL,
  kind     TEXT NOT NULL,                        -- 'detected' | 'source' | 'resume'
  detail   TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_event_topic ON topic_event(topic_id, at);
