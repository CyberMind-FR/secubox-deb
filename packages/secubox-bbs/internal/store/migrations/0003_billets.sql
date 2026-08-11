-- Le lien entre un fil et le billet qui en est tire.
--
-- Il vit ICI, dans le BBS, et non seulement chez billets : c'est le BBS qui
-- doit savoir si un fil a deja ete publie, pour ne pas proposer deux fois de le
-- publier et pour afficher le lien retour. La reference existe donc des DEUX
-- cotes — chacun reste consultable si l'autre est arrete.
CREATE TABLE billets (
  thread_id    INTEGER PRIMARY KEY REFERENCES threads(id),
  billet_id    TEXT NOT NULL,
  url          TEXT NOT NULL,
  published_at INTEGER NOT NULL,
  -- Nombre de messages effectivement repris, et nombre retenus en local. Les
  -- deux sont affiches : « 6 repris, 2 retenus » dit a l'auteur que la
  -- publication n'a pas tout emporte, avant qu'il ne s'en apercoive autrement.
  taken        INTEGER NOT NULL DEFAULT 0,
  held         INTEGER NOT NULL DEFAULT 0
);
