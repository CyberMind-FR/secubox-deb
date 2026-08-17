-- SALONS PRIVES : ouverts a des PERSONNES, pas a un rang (#1044).
--
-- CE QUI EXISTAIT DEJA, ET QU'ON NE TOUCHE PAS. `categories` porte
-- `min_role_read` et `min_role_write` : un salon peut deja etre ferme aux
-- invites, ou reserve aux sysops. C'est une barriere par RANG, et elle repond
-- tres bien a « reserve aux membres ».
--
-- CE QU'ELLE NE SAIT PAS DIRE : « ce forum est ouvert a Alice et Bob ». Aucune
-- table ne reliait un membre a un salon. C'est le seul manque, et cette
-- migration ne comble que celui-la.
--
-- DEUX AXES ORTHOGONAUX PLUTOT QU'UN RANG DE PLUS. On aurait pu ajouter
-- `'prive'` a la contrainte de `min_role_read`. C'est un piege : le rang dit
-- « a partir de quel niveau », l'appartenance dit « qui nommement ». Les
-- confondre dans une seule colonne rend impossible un salon a la fois reserve
-- aux membres ET limite a trois d'entre eux — et surtout, cela ferait dependre
-- une regle de confidentialite d'un ordre entre valeurs textuelles.
ALTER TABLE categories ADD COLUMN prive INTEGER NOT NULL DEFAULT 0;

-- UN SALON PRIVE NE DOIT PAS APPARAITRE A QUI N'Y EST PAS. L'index sert le rail :
-- il est reconstruit a chaque page, et la liste des salons visibles se calcule
-- alors par appartenance.
CREATE INDEX idx_categories_prive ON categories(prive);

-- ── appartenance ────────────────────────────────────────────────────────────
--
-- LA CLE PRIMAIRE EST LE COUPLE : une personne appartient a un salon, ou n'y
-- appartient pas. Il n'y a pas de « deux fois membre », et la base l'interdit
-- plutot que de compter sur le code appelant.
CREATE TABLE salon_membres (
  category_id INTEGER NOT NULL REFERENCES categories(id) ON DELETE CASCADE,
  user_id     INTEGER NOT NULL REFERENCES users(id)      ON DELETE CASCADE,

  -- QUI A OUVERT LA PORTE. Sur un salon prive, la question « comment cette
  -- personne est-elle entree » se pose un jour ; sans cette colonne, elle reste
  -- sans reponse. `ON DELETE SET NULL` : le depart du parrain ne chasse pas
  -- l'invite.
  ajoute_par  INTEGER REFERENCES users(id) ON DELETE SET NULL,
  ajoute_le   INTEGER NOT NULL,

  PRIMARY KEY (category_id, user_id)
);

-- « Quels salons pour cette personne ? » est LA question du rail, posee a chaque
-- page. Sans cet index, elle balaie la table entiere.
CREATE INDEX idx_salon_membres_user ON salon_membres(user_id);

-- ── invitations a un salon ──────────────────────────────────────────────────
--
-- UNE TABLE SEPAREE DE `invites`, ET C'EST LE POINT LE PLUS IMPORTANT ICI.
--
-- `invites` ouvre un COMPTE : `RedeemInvite` cree l'utilisateur. Ajouter une
-- colonne `category_id` a cette table-la aurait paru economique et aurait cree
-- exactement le defaut qu'on veut eviter : un lien destine a ouvrir une section
-- serait devenu, par heritage, une porte d'entree sur la board. Un partage
-- maladroit dans un salon public aurait suffi.
--
-- Ici, l'invitation ne fait qu'UNE chose : rattacher un compte DEJA EXISTANT ET
-- AUTHENTIFIE a un salon. Elle ne cree rien.
CREATE TABLE invites_salon (
  code_sha256 BLOB PRIMARY KEY,   -- jamais le code en clair : il circule
  category_id INTEGER NOT NULL REFERENCES categories(id) ON DELETE CASCADE,
  issued_by   INTEGER NOT NULL REFERENCES users(id)      ON DELETE CASCADE,
  issued_at   INTEGER NOT NULL,
  expires_at  INTEGER NOT NULL,
  used_at     INTEGER,
  used_by     INTEGER REFERENCES users(id) ON DELETE SET NULL
);

-- Les invitations encore ouvertes sont la seule chose qu'on relise souvent —
-- pour les afficher au sysop, et pour les revoquer.
CREATE INDEX idx_invites_salon_ouvertes
  ON invites_salon(category_id) WHERE used_at IS NULL;
