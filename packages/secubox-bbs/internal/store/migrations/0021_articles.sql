-- Article collaboratif (#1056 stage 3) : un document écrit à PLUSIEURS MAINS.
--
-- Un article naît d'un dossier (ou vierge), s'écrit par CONTRIBUTIONS
-- attribuées et ordonnées — chaque main ajoute la sienne, l'attribution ne se
-- perd pas — puis se PUBLIE vers billets, la face publique. Tant qu'il est en
-- brouillon il reste sur le BBS (privé) : le local ne sort qu'à la publication.
--
-- Deux tables plutôt qu'un champ texte : garder QUI a écrit QUOI est le cœur du
-- collaboratif. Un corps unique perdrait l'attribution à la première fusion.
CREATE TABLE IF NOT EXISTS articles (
  id            INTEGER PRIMARY KEY,
  title         TEXT    NOT NULL,
  thread_id     INTEGER,                         -- dossier d'origine (optionnel)
  status        TEXT    NOT NULL DEFAULT 'draft', -- draft | published
  created_by    INTEGER NOT NULL REFERENCES users(id),
  created_at    INTEGER NOT NULL,
  updated_at    INTEGER NOT NULL,
  published_url TEXT    NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS article_parts (
  id         INTEGER PRIMARY KEY,
  article_id INTEGER NOT NULL REFERENCES articles(id) ON DELETE CASCADE,
  author_id  INTEGER NOT NULL REFERENCES users(id),
  body       TEXT    NOT NULL,
  position   INTEGER NOT NULL,
  created_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_article_parts ON article_parts(article_id, position);
CREATE INDEX IF NOT EXISTS idx_articles_status ON articles(status, updated_at);
