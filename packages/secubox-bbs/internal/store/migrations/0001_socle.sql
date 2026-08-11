-- Socle : comptes, sessions, salons, fils, messages, recherche.
--
-- Rappel de la regle d'or du projet : LE DISQUE FAIT FOI. Cette base n'est
-- qu'un INDEX. Tout ce qu'elle contient doit pouvoir etre reconstruit depuis
-- content/ et files/ par `bbsctl reindex`. On n'y stocke donc jamais le seul
-- exemplaire d'un contenu — d'ou `body_path` plutot qu'une colonne texte.

CREATE TABLE users (
  id            INTEGER PRIMARY KEY,
  handle        TEXT NOT NULL UNIQUE COLLATE NOCASE,
  display_name  TEXT NOT NULL,
  role          TEXT NOT NULL CHECK (role IN ('sysop','member','guest')),
  created_at    INTEGER NOT NULL,
  disabled_at   INTEGER,
  quota_bytes   INTEGER NOT NULL DEFAULT 0
);
-- Le hash du mot de passe n'est PAS ici : il vit dans secrets/, hors de
-- l'arborescence de contenu. Un index qui fuite ne doit pas livrer les
-- identifiants, et un rsync vers un support externe ne doit pas les emporter.

CREATE TABLE sessions (
  token_sha256  BLOB PRIMARY KEY,
  user_id       INTEGER NOT NULL REFERENCES users(id),
  created_at    INTEGER NOT NULL,
  expires_at    INTEGER NOT NULL,
  ip            TEXT,
  user_agent    TEXT
);
CREATE INDEX idx_sessions_expiry ON sessions(expires_at);

CREATE TABLE categories (
  id             INTEGER PRIMARY KEY,
  slug           TEXT NOT NULL UNIQUE,
  title          TEXT NOT NULL,
  description    TEXT,
  color          TEXT,
  position       INTEGER NOT NULL DEFAULT 0,
  min_role_read  TEXT NOT NULL DEFAULT 'guest'  CHECK (min_role_read  IN ('sysop','member','guest')),
  min_role_write TEXT NOT NULL DEFAULT 'member' CHECK (min_role_write IN ('sysop','member','guest')),
  -- `feed` marque le salon Flux : ce que les AUTRES modules annoncent.
  -- Un humain n'y ecrit pas de fil, il ne fait qu'y repondre.
  feed           INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE threads (
  id           INTEGER PRIMARY KEY,
  category_id  INTEGER NOT NULL REFERENCES categories(id),
  author_id    INTEGER NOT NULL REFERENCES users(id),
  slug         TEXT NOT NULL,
  title        TEXT NOT NULL,
  visibility   TEXT NOT NULL DEFAULT 'local' CHECK (visibility IN ('local','public')),
  -- `source` distingue ce qu'un humain a ecrit de ce qu'un module a annonce.
  -- NULL = humain. Sinon : 'podcaster', 'peertube', 'torrent'...
  source       TEXT,
  source_ref   TEXT,
  pinned       INTEGER NOT NULL DEFAULT 0,
  locked       INTEGER NOT NULL DEFAULT 0,
  created_at   INTEGER NOT NULL,
  last_post_at INTEGER NOT NULL,
  UNIQUE (category_id, slug)
);
CREATE INDEX idx_threads_recent ON threads(category_id, last_post_at DESC);

CREATE TABLE posts (
  id          INTEGER PRIMARY KEY,
  thread_id   INTEGER NOT NULL REFERENCES threads(id),
  author_id   INTEGER NOT NULL REFERENCES users(id),
  body_path   TEXT NOT NULL,   -- relatif a content/ — le corps vit sur le DISQUE
  body_sha256 BLOB NOT NULL,   -- detecte une divergence entre disque et index
  -- La visibilite est portee par le fil ET par le message : un fil public peut
  -- contenir une reponse locale. C'est le cas difficile de tout le systeme.
  visibility  TEXT NOT NULL DEFAULT 'local' CHECK (visibility IN ('local','public')),
  created_at  INTEGER NOT NULL,
  edited_at   INTEGER,
  deleted_at  INTEGER
);
CREATE INDEX idx_posts_thread ON posts(thread_id, created_at);

CREATE TABLE audit (
  id       INTEGER PRIMARY KEY,
  at       INTEGER NOT NULL,
  actor_id INTEGER REFERENCES users(id),
  action   TEXT NOT NULL,
  target   TEXT NOT NULL,
  detail   TEXT
);

CREATE VIRTUAL TABLE search USING fts5(
  title, body,
  kind UNINDEXED, ref_id UNINDEXED, visibility UNINDEXED,
  tokenize = "unicode61 remove_diacritics 2"
);
