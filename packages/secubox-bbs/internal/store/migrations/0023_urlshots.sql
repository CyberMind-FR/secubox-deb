-- 0023_urlshots.sql — file d'attente + état des vignettes-snapshot d'URL (#1120).
-- La CLÉ est calculée côté Go (sha256 de l'URL normalisée) ; le worker Python la
-- réutilise telle quelle. `visibility` recopie la plus haute visibilité d'un post
-- CITANT l'URL (public si au moins un post public la cite) — miroir du gating /f/.
CREATE TABLE IF NOT EXISTS urlshots (
  cle        TEXT PRIMARY KEY,
  url        TEXT NOT NULL,
  visibility TEXT NOT NULL DEFAULT 'local',
  statut     TEXT NOT NULL DEFAULT 'pending',
  maj        INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS urlshots_pending ON urlshots(statut) WHERE statut = 'pending';
