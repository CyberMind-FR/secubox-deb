-- MESSAGERIE INTERNE ET REGLAGES (#1008).
--
-- POURQUOI LES MESSAGES SONT EN BASE ET NON SUR DISQUE.
--
-- Le forum vit sur disque parce qu'il est publiable et reindexable : `Reindex`
-- reconstruit l'index a partir des .md, qui font autorite. Un message prive
-- n'est ni publiable ni reindexable. L'y mettre creerait une seconde categorie
-- de fichiers dans content/, que la sauvegarde emporte et que le rsync vers un
-- support externe recopie — exactement ce que la page /mp annonce ne pas faire.
--
-- `users`, `sessions` et `invites` vivent deja en base seule, pour la meme
-- raison : ce sont des donnees d'exploitation, pas du contenu.
--
-- CONSEQUENCE ASSUMEE : les messages ne sont PAS repris dans la sauvegarde
-- (`Backup` n'emporte que content/ et files/). L'interface doit le dire, sans
-- quoi la propriete devient une perte silencieuse.
CREATE TABLE messages (
  id          INTEGER PRIMARY KEY,
  -- L'expediteur peut disparaitre (compte supprime) sans emporter le message
  -- recu : ON DELETE SET NULL plutot que CASCADE. Un fil de conversation
  -- ampute a moitie est plus deroutant qu'un message signe « compte supprime ».
  sender_id   INTEGER REFERENCES users(id) ON DELETE SET NULL,
  recipient_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  body        TEXT NOT NULL,
  sent_at     INTEGER NOT NULL,
  read_at     INTEGER
);

-- Les deux acces reels : « mes non-lus » (compteur de navigation, evalue a
-- chaque page) et « ma conversation avec X » (les deux sens).
CREATE INDEX idx_messages_non_lus ON messages(recipient_id) WHERE read_at IS NULL;
CREATE INDEX idx_messages_fil ON messages(recipient_id, sender_id, sent_at);
CREATE INDEX idx_messages_envoyes ON messages(sender_id, recipient_id, sent_at);

-- REGLAGES CLE/VALEUR.
--
-- Le lien d'invitation Mastodon est declare par le sysop depuis l'interface,
-- pas dans le TOML : c'est une donnee d'exploitation qui change au gre des
-- invitations creees dans Mastodon, et un conffile la ferait ressortir a
-- chaque mise a jour du paquet comme une modification locale a arbitrer.
CREATE TABLE reglages (
  cle     TEXT PRIMARY KEY,
  valeur  TEXT NOT NULL,
  maj_at  INTEGER NOT NULL
);
