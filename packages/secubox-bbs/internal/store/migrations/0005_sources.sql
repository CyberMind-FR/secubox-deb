-- IDENTITE DES FILS IMPORTES.
--
-- Un fil venu d'un module est identifie par le couple (source, source_ref) —
-- jamais par son titre. Deux episodes peuvent porter le meme titre ; le meme
-- episode peut etre renomme. Se fier au titre produit soit des doublons, soit
-- des fusions silencieuses.
--
-- L'index est UNIQUE et pose au niveau de la BASE, pas dans le code d'import.
-- Une garde applicative ne tient que tant que tous les appelants pensent a la
-- respecter ; celle-ci tient meme si un import est lance deux fois en parallele.
--
-- (Un import de podcast avait deja produit 34 flux en double et 2,3 Go inutiles
-- sur cette board, faute d'identite stable. Cet index existe pour cela.)
CREATE UNIQUE INDEX idx_threads_source ON threads(source, source_ref)
  WHERE source IS NOT NULL AND source_ref IS NOT NULL;

-- Journal des imports : quand, combien vus, combien crees.
-- Sert a repondre « pourquoi ce fil n'est-il pas la ? » sans relancer l'import.
CREATE TABLE ingest_runs (
  id        INTEGER PRIMARY KEY,
  source    TEXT NOT NULL,
  ran_at    INTEGER NOT NULL,
  seen      INTEGER NOT NULL DEFAULT 0,
  created   INTEGER NOT NULL DEFAULT 0,
  skipped   INTEGER NOT NULL DEFAULT 0,
  error     TEXT
);
