CREATE TABLE content_object (
  id TEXT PRIMARY KEY, type TEXT NOT NULL, title TEXT NOT NULL,
  metadata TEXT NOT NULL DEFAULT '{}', bbs_topic_id INTEGER NOT NULL DEFAULT 0,
  status TEXT NOT NULL DEFAULT 'proposed', visibility TEXT NOT NULL DEFAULT 'community',
  created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL);
CREATE TABLE content_provenance (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  content_id TEXT NOT NULL REFERENCES content_object(id) ON DELETE CASCADE,
  source_url TEXT NOT NULL, source_type TEXT NOT NULL,
  is_original INTEGER NOT NULL DEFAULT 0, noted_at INTEGER NOT NULL,
  UNIQUE(content_id, source_url));
CREATE TABLE content_representation (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  content_id TEXT NOT NULL REFERENCES content_object(id) ON DELETE CASCADE,
  kind TEXT NOT NULL, module TEXT NOT NULL, ref TEXT NOT NULL,
  is_cache INTEGER NOT NULL DEFAULT 0, url TEXT NOT NULL DEFAULT '', created_at INTEGER NOT NULL,
  UNIQUE(content_id, kind, module, ref));
CREATE INDEX idx_repr_ref ON content_representation(module, ref);
CREATE TABLE content_event (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  content_id TEXT NOT NULL REFERENCES content_object(id) ON DELETE CASCADE,
  kind TEXT NOT NULL, actor TEXT NOT NULL DEFAULT '', payload TEXT NOT NULL DEFAULT '{}', at INTEGER NOT NULL);
CREATE TABLE content_timeline (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  content_id TEXT NOT NULL REFERENCES content_object(id) ON DELETE CASCADE,
  author TEXT NOT NULL, author_id INTEGER NOT NULL CHECK(author_id > 0),
  offset_ms INTEGER NOT NULL DEFAULT 0, body TEXT NOT NULL,
  broadcast_at INTEGER NOT NULL DEFAULT 0, created_at INTEGER NOT NULL);
CREATE INDEX idx_timeline_off ON content_timeline(content_id, offset_ms);
