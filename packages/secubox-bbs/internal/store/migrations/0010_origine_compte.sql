-- D'OU VIENT L'AUTHENTIFICATION D'UN COMPTE.
--
--   'local'   : mot de passe verifie par le BBS (fichier de hashes)
--   'secubox' : mot de passe verifie par secubox-auth, jamais stocke ici
--
-- LE BBS NE COPIE AUCUN MOT DE PASSE. Recopier une empreinte creerait une
-- seconde copie a maintenir : un changement cote SecuBox ne s'y refleterait
-- pas, une revocation non plus, et le compte resterait ouvert ici apres avoir
-- ete ferme la-bas. On delegue, ou on ne synchronise pas du tout.
ALTER TABLE users ADD COLUMN auth_source TEXT NOT NULL DEFAULT 'local';
