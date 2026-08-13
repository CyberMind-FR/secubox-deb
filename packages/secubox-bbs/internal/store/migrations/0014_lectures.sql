-- LU / NON-LU (#1020 suite).
--
-- POURQUOI UNE DATE ET NON UN COMPTEUR DE MESSAGES.
--
-- On pourrait retenir « le dernier message lu » par son identifiant. C'est
-- tentant et c'est un piege : un message efface, deplace ou modere ferait
-- disparaitre le repere, et le fil redeviendrait non-lu en entier sans que
-- personne ne comprenne pourquoi. Une DATE ne depend d'aucune ligne : elle
-- survit a la moderation, qui est justement ce qu'on ajoute ensuite.
--
-- COMPARER A last_post_at, PAS COMPTER. Un fil est non-lu si son dernier
-- message est posterieur a la derniere visite. Cela repond a la seule question
-- que se pose le lecteur — « y a-t-il du nouveau depuis ma derniere visite ? »
-- — sans tenir de compteur qui se desynchroniserait a la premiere suppression.
--
-- AUCUNE LIGNE = JAMAIS OUVERT. On n'ecrit rien tant que le fil n'a pas ete
-- ouvert : un BBS de cent fils ne cree pas cent lignes par membre inscrit. Le
-- cout suit l'usage reel, pas le catalogue.
CREATE TABLE lectures (
  user_id   INTEGER NOT NULL REFERENCES users(id)   ON DELETE CASCADE,
  thread_id INTEGER NOT NULL REFERENCES threads(id) ON DELETE CASCADE,
  -- Date de la derniere ouverture du fil par ce membre.
  lu_at     INTEGER NOT NULL,
  PRIMARY KEY (user_id, thread_id)
) WITHOUT ROWID;

-- La question posee a chaque affichage de liste est « quels fils ce membre
-- a-t-il lus ? ». La cle primaire (user_id, thread_id) la sert deja ; cet index
-- sert l'autre sens, le balayage par fil lors d'une suppression.
CREATE INDEX idx_lectures_thread ON lectures(thread_id);
