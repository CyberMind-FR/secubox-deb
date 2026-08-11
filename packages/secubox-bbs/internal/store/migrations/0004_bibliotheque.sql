-- Bibliotheque de fichiers.
--
-- Comme pour les messages, LE FICHIER FAIT FOI : `path` designe un fichier reel
-- sous files/, et cette table n'en est que l'index. Un fichier depose puis
-- retrouve par un `find` reste exploitable sans cette base.
CREATE TABLE files (
  id          INTEGER PRIMARY KEY,
  category_id INTEGER REFERENCES categories(id),
  owner_id    INTEGER NOT NULL REFERENCES users(id),
  path        TEXT NOT NULL UNIQUE,   -- relatif a files/
  name        TEXT NOT NULL,          -- nom affiche, tel que depose
  size        INTEGER NOT NULL,
  sha256      BLOB NOT NULL,
  mime        TEXT NOT NULL DEFAULT 'application/octet-stream',
  visibility  TEXT NOT NULL DEFAULT 'local' CHECK (visibility IN ('local','public')),
  created_at  INTEGER NOT NULL,
  deleted_at  INTEGER
);
CREATE INDEX idx_files_cat ON files(category_id, created_at);

-- LE QUOTA EST PAR PERSONNE, PAS GLOBAL.
--
-- Un quota global se remplit d'un seul depot et bloque tout le monde ; personne
-- ne sait alors a qui demander de faire le menage. `users.quota_bytes` existe
-- deja ; cette vue donne la consommation en regard.
CREATE VIEW quota_usage AS
  SELECT u.id AS user_id, u.handle, u.quota_bytes,
         COALESCE(SUM(f.size), 0) AS used_bytes
    FROM users u LEFT JOIN files f
      ON f.owner_id = u.id AND f.deleted_at IS NULL
   GROUP BY u.id;
