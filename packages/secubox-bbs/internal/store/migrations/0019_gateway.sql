-- Passerelle média : un objet unique pour tout ce qui entre, d'où qu'il vienne.
--
-- La clé est l'EMPREINTE, pas un identifiant local : c'est elle qui rend le
-- ré-import inoffensif. Un collecteur qui repasse toutes les demi-heures sur un
-- flux doit retrouver le contenu déjà connu, pas en créer une copie.

CREATE TABLE gateway_contenu (
  empreinte     TEXT PRIMARY KEY,      -- BLAKE2b de la forme canonique
  id            TEXT NOT NULL,         -- identifiant local, stable, pour les liens
  genre         TEXT NOT NULL,
  titre         TEXT NOT NULL DEFAULT '',
  corps         TEXT NOT NULL DEFAULT '',
  auteur        TEXT NOT NULL DEFAULT '',
  publie_le     INTEGER NOT NULL DEFAULT 0,
  source_url    TEXT NOT NULL,         -- jamais effacée : seule façon de retrouver l'œuvre
  connecteur    TEXT NOT NULL,
  ref_native    TEXT NOT NULL DEFAULT '',
  metadonnees   TEXT NOT NULL DEFAULT '{}',
  expire_le     INTEGER NOT NULL DEFAULT 0,   -- 0 = pas d'expiration
  retention     TEXT NOT NULL DEFAULT 'cache',
  propriete     TEXT NOT NULL,         -- pas de défaut : commande le droit de republier
  noeud_origine TEXT NOT NULL,
  cree_le       INTEGER NOT NULL,
  maj_le        INTEGER NOT NULL
);

CREATE UNIQUE INDEX gateway_contenu_id ON gateway_contenu(id);
CREATE INDEX gateway_contenu_connecteur ON gateway_contenu(connecteur);
CREATE INDEX gateway_contenu_retention ON gateway_contenu(retention);
-- Le ramasse-miettes balaie par date d'expiration : sans cet index il relirait
-- toute la table à chaque passage.
CREATE INDEX gateway_contenu_expire ON gateway_contenu(expire_le)
  WHERE expire_le > 0;

CREATE TABLE gateway_media (
  empreinte TEXT NOT NULL REFERENCES gateway_contenu(empreinte) ON DELETE CASCADE,
  chemin    TEXT NOT NULL,
  mime      TEXT NOT NULL DEFAULT '',
  taille    INTEGER NOT NULL DEFAULT 0,
  somme     TEXT NOT NULL DEFAULT '',
  PRIMARY KEY (empreinte, chemin)
);

CREATE TABLE gateway_replique (
  empreinte TEXT NOT NULL REFERENCES gateway_contenu(empreinte) ON DELETE CASCADE,
  cible     TEXT NOT NULL,
  cible_url TEXT NOT NULL DEFAULT '',
  ref_cible TEXT NOT NULL DEFAULT '',
  pousse_le INTEGER NOT NULL DEFAULT 0,
  mode      TEXT NOT NULL,
  PRIMARY KEY (empreinte, cible)
);
