-- AVATAR : une piece jointe dont on retient l'identifiant (#1008).
--
-- Pas de chemin, pas de copie : une REFERENCE vers `files`. Stocker un chemin
-- creerait une seconde verite a maintenir — et un avatar supprime de la
-- bibliotheque laisserait un chemin mort dans `users`.
--
-- ON DELETE SET NULL : effacer l'image rend l'icone d'initiales, elle ne casse
-- pas le compte.
ALTER TABLE users ADD COLUMN avatar_file INTEGER REFERENCES files(id) ON DELETE SET NULL;
