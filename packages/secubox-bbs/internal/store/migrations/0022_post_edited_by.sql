-- #1091 — QUI a edite un message.
--
-- `edited_at` existe depuis le socle (0001) mais ne dit pas par qui. On ajoute
-- l'auteur de l'edition pour distinguer, en clair et dans le journal, une
-- CORRECTION DE MODERATION (editeur != auteur) d'une retouche de l'auteur sur
-- son propre texte. NULL = jamais edite.
ALTER TABLE posts ADD COLUMN edited_by INTEGER REFERENCES users(id);
