-- PASSERELLE MASTODON : un lien PERSONNEL, jamais un jeton partage (#1044).
--
-- CE QUE CETTE MIGRATION REFUSE D'EMBLEE, ET QUI DICTE SA FORME.
--
-- La solution economique aurait ete un seul jeton d'administration, range dans
-- les reglages a cote de `mastodon.invitation`, avec lequel le BBS publie pour
-- tout le monde. Elle est fausse sur trois plans a la fois : ce qui sort porte
-- l'identite de l'instance et non celle de l'auteur ; un membre ne peut rien
-- revoquer sans qu'on le lui retire a tous ; et un vol de ce jeton donne la
-- parole publique au nom de la communaute entiere.
--
-- Ici chaque membre lie SON compte, avec SON jeton, revocable par lui seul —
-- des deux cotes, puisque Mastodon liste les applications autorisees.
--
-- ET SURTOUT : LE LIEN NE SE DEDUIT JAMAIS DU NOM. Un membre local « alice »
-- n'est PAS @alice sur l'instance tant qu'elle ne l'a pas prouve par l'aller-
-- retour OAuth. Rapprocher deux comptes sur l'egalite des pseudonymes ferait
-- publier au nom de quelqu'un d'autre — sur une instance ouverte, il suffirait
-- d'y prendre le pseudonyme d'un membre du BBS pour recevoir sa parole.

-- ── applications OAuth, une par instance ────────────────────────────────────
--
-- Mastodon exige qu'une application soit enregistree AUPRES DE CHAQUE INSTANCE
-- avant tout OAuth. L'enregistrement est fait une fois puis relu : le refaire a
-- chaque lien creerait une application morte par membre dans l'instance d'en
-- face, ce qui est impoli autant qu'illisible.
CREATE TABLE mastodon_apps (
  instance      TEXT PRIMARY KEY,   -- hote normalise, sans schema ni barre finale
  client_id     TEXT NOT NULL,
  client_secret TEXT NOT NULL,
  cree_le       INTEGER NOT NULL
);

-- ── le lien personnel ───────────────────────────────────────────────────────
--
-- UN COMPTE PAR MEMBRE : la cle primaire porte `user_id`. Relier un second
-- compte ne serait pas refuse par la base mais remplacerait le premier, ce qui
-- est le geste attendu (« je change de compte »).
CREATE TABLE mastodon_comptes (
  user_id   INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  instance  TEXT NOT NULL,
  acct      TEXT NOT NULL,   -- tel que l'instance le dit, jamais tel qu'on le devine
  compte_id TEXT NOT NULL,   -- identifiant chez l'instance
  -- LE JETON NE SORT JAMAIS VERS LE NAVIGATEUR. Aucun gabarit ne le rend ; il
  -- ne quitte le serveur que vers l'instance, en en-tete Authorization.
  jeton     TEXT NOT NULL,
  portee    TEXT NOT NULL,   -- ce qui a ete accorde, pour pouvoir le relire
  lie_le    INTEGER NOT NULL
);

-- DEUX MEMBRES NE PARLENT PAS SOUS LA MEME IDENTITE FEDIVERSE. Techniquement
-- les deux auraient prouve leur controle du compte ; mais l'attribution
-- deviendrait ambigue — deux pseudonymes du BBS pour une seule voix dehors.
CREATE UNIQUE INDEX idx_mastodon_comptes_identite
  ON mastodon_comptes(instance, compte_id);

-- ── etats OAuth ─────────────────────────────────────────────────────────────
--
-- L'ETAT LIE L'ALLER AU RETOUR. Sans lui, n'importe qui pourrait faire aboutir
-- un retour d'autorisation dans la session d'un autre et lui attacher SON
-- compte Mastodon — la personne publierait ensuite, de bonne foi, chez
-- l'attaquant.
--
-- Stocke HACHE et a USAGE UNIQUE, pour les memes raisons qu'une invitation : il
-- circule dans une adresse, donc dans des journaux et des historiques.
CREATE TABLE mastodon_etats (
  etat_sha256 BLOB PRIMARY KEY,
  user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  instance    TEXT NOT NULL,
  cree_le     INTEGER NOT NULL,
  servi_le    INTEGER
);

-- Le menage porte sur les etats jamais servis : un aller-retour abandonne ne
-- doit pas rester une porte ouverte.
CREATE INDEX idx_mastodon_etats_ouverts
  ON mastodon_etats(cree_le) WHERE servi_le IS NULL;
