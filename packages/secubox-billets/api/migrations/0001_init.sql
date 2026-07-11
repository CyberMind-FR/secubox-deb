-- SPDX-License-Identifier: LicenseRef-CMSD-1.0
-- Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
-- billets :: initial schema. Timestamps are RFC3339 UTC TEXT ('...Z'), which
-- sorts lexicographically for cursor pagination. IDs are ULIDs (also sortable).

CREATE TABLE IF NOT EXISTS author (
  id            TEXT PRIMARY KEY,
  username      TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,          -- argon2id
  totp_secret   TEXT,                   -- nullable (2FA optional)
  created_at    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS billet (
  id              TEXT PRIMARY KEY,     -- ULID
  created_at      TEXT NOT NULL,
  updated_at      TEXT NOT NULL,
  published_at    TEXT,                 -- nullable => never published
  body            TEXT NOT NULL,        -- restricted markdown source
  ref_url         TEXT,
  embed_url       TEXT,
  embed_html      TEXT,                 -- sanitized oEmbed/linkcard render cache
  embed_provider  TEXT,
  embed_fetched_at TEXT,
  slug            TEXT NOT NULL UNIQUE,
  status          TEXT NOT NULL DEFAULT 'draft'
                    CHECK (status IN ('draft','published','archived')),
  view_count      INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_billet_feed
  ON billet(published_at DESC, id DESC) WHERE status = 'published';
CREATE INDEX IF NOT EXISTS idx_billet_status ON billet(status);

CREATE TABLE IF NOT EXISTS comment (
  id              TEXT PRIMARY KEY,     -- ULID
  billet_id       TEXT NOT NULL REFERENCES billet(id) ON DELETE CASCADE,
  created_at      TEXT NOT NULL,
  author_name     TEXT NOT NULL,
  author_email    TEXT,                 -- encrypted at rest; never displayed
  body            TEXT NOT NULL,
  status          TEXT NOT NULL DEFAULT 'pending'
                    CHECK (status IN ('pending','approved','rejected')),
  ip_hash         TEXT NOT NULL,        -- BLAKE2b(salt||ip); never the raw IP
  honeypot_tripped INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_comment_billet ON comment(billet_id, created_at);
CREATE INDEX IF NOT EXISTS idx_comment_status ON comment(status);

CREATE TABLE IF NOT EXISTS reaction (
  id                 TEXT PRIMARY KEY,  -- ULID
  billet_id          TEXT NOT NULL REFERENCES billet(id) ON DELETE CASCADE,
  emoji              TEXT NOT NULL
                       CHECK (emoji IN ('👍','❤️','😂','😮','😢','🔥')),
  visitor_token_hash TEXT NOT NULL,
  created_at         TEXT NOT NULL,
  UNIQUE (billet_id, emoji, visitor_token_hash)
);
CREATE INDEX IF NOT EXISTS idx_reaction_billet ON reaction(billet_id, emoji);

-- Append-only, hash-chained (BLAKE2b) audit log. Never UPDATE/DELETE.
CREATE TABLE IF NOT EXISTS event_log (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  ts         TEXT NOT NULL,
  event_type TEXT NOT NULL,
  payload    TEXT NOT NULL,             -- canonical JSON
  prev_hash  TEXT NOT NULL,
  hash       TEXT NOT NULL UNIQUE
);
