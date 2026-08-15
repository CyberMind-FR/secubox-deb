-- SOCLE DE LA RADIO COLLABORATIVE (#1047).

-- ── pistes ──────────────────────────────────────────────────────────────────
CREATE TABLE pistes (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,

  -- `source` est l'adresse d'origine NORMALISEE (voir store.CleSource) et non
  -- ce qui a ete colle : `youtu.be/X`, `youtube.com/watch?v=X&t=42` et
  -- `youtube.com/watch?v=X` designent la meme piste. Sans normalisation, la
  -- meme chanson entre trois fois et la playlist se remplit de doublons que
  -- personne ne comprend.
  source      TEXT NOT NULL UNIQUE,
  titre       TEXT NOT NULL DEFAULT '',
  auteur      TEXT NOT NULL DEFAULT '',
  duree_ms    INTEGER NOT NULL DEFAULT 0,

  -- QUI L'A AJOUTEE. La question « qui a mis ca » se pose des le premier
  -- soir ; sans cette colonne elle reste sans reponse. `ON DELETE SET NULL` :
  -- le depart d'un membre ne retire pas sa musique de l'antenne.
  ajoute_par  INTEGER,
  ajoute_le   INTEGER NOT NULL,

  -- ── cache local ─────────────────────────────────────────────────────────
  -- `fichier` vide = pas encore recupere. Une piste reste dans la file pendant
  -- sa recuperation : la retirer puis la remettre ferait clignoter la file.
  fichier     TEXT NOT NULL DEFAULT '',
  mime        TEXT NOT NULL DEFAULT '',
  octets      INTEGER NOT NULL DEFAULT 0,

  -- ECARTEE, PAS SUPPRIMEE. Une piste indisponible (retiree, geo-bloquee)
  -- reste visible avec sa raison : un titre qui disparait en silence fait
  -- chercher la panne ailleurs. Elle peut redevenir disponible.
  indisponible INTEGER NOT NULL DEFAULT 0,
  raison       TEXT NOT NULL DEFAULT ''
);

CREATE INDEX idx_pistes_jouables ON pistes(indisponible, ajoute_le);

-- ── coeurs ──────────────────────────────────────────────────────────────────
--
-- UNE TABLE, PAS UN COMPTEUR. Un entier `coeurs` sur `pistes` aurait tenu en
-- une colonne, et rendu impossibles deux choses qu'on veut : retirer son
-- coeur sans pouvoir le retirer deux fois, et savoir QUI a aime — le panneau
-- le montre, et le tirage doit pouvoir etre explique.
CREATE TABLE coeurs (
  piste_id INTEGER NOT NULL REFERENCES pistes(id) ON DELETE CASCADE,
  user_id  INTEGER NOT NULL,
  mis_le   INTEGER NOT NULL,
  PRIMARY KEY (piste_id, user_id)
);
CREATE INDEX idx_coeurs_piste ON coeurs(piste_id);

-- ── lectures ────────────────────────────────────────────────────────────────
--
-- JOURNAL APPEND-ONLY, et c'est ce qui rend le tirage EXPLICABLE. La graine y
-- est retenue : on peut rejouer le tirage et montrer pourquoi tel titre est
-- passe. Sans cela, « pourquoi cette chanson trois fois ce soir ? » n'a pas de
-- reponse verifiable.
--
-- C'est aussi d'ici que sort la derniere lecture d'une piste, donc son repos —
-- une colonne `jouee_le` sur `pistes` aurait suffi au tirage mais perdu
-- l'historique.
CREATE TABLE lectures (
  id       INTEGER PRIMARY KEY AUTOINCREMENT,
  piste_id INTEGER NOT NULL REFERENCES pistes(id) ON DELETE CASCADE,
  debut_le INTEGER NOT NULL,
  graine   INTEGER NOT NULL DEFAULT 0
);
-- « quand cette piste a-t-elle joue pour la derniere fois » est LA question du
-- tirage, posee pour chaque piste a chaque choix.
CREATE INDEX idx_lectures_piste ON lectures(piste_id, debut_le DESC);

-- ── reglages ────────────────────────────────────────────────────────────────
CREATE TABLE reglages (
  cle    TEXT PRIMARY KEY,
  valeur TEXT NOT NULL
);
