-- L'emetteur d'une invitation devient FACULTATIF.
--
-- `bbsctl invite` tourne en ligne de commande, sans session : il n'a personne
-- a qui attribuer l'invitation. Deux mauvaises reponses ont ete ecartees :
--
--   - passer 0 — l'identifiant de personne. C'est ce que faisait le premier
--     jet : clef etrangere violee, invitation jamais creee, message d'erreur
--     muet sur la cause.
--
--   - l'attribuer d'office au premier sysop. La console afficherait alors un
--     emetteur qui n'a rien emis. Une trace fausse est pire qu'une trace
--     absente : on lui fait confiance.
--
-- NULL dit ce qui est vrai : emise depuis la machine, sans session.
--
-- SQLite ne sait pas relacher une contrainte NOT NULL : la table est
-- reconstruite. Les invitations existantes sont conservees.
CREATE TABLE invites_nouveau (
  code_sha256 BLOB PRIMARY KEY,
  issued_by   INTEGER REFERENCES users(id),
  issued_at   INTEGER NOT NULL,
  expires_at  INTEGER NOT NULL,
  used_at     INTEGER,
  used_by     INTEGER REFERENCES users(id),
  label       TEXT
);
INSERT INTO invites_nouveau(code_sha256, issued_by, issued_at, expires_at, used_at, used_by, label)
  SELECT code_sha256, issued_by, issued_at, expires_at, used_at, used_by, label FROM invites;
DROP TABLE invites;
ALTER TABLE invites_nouveau RENAME TO invites;
-- L'index disparait avec l'ancienne table : DROP TABLE emporte ses index.
-- L'oublier ici ferait qu'il n'existerait plus, sans que rien ne le signale —
-- juste des lectures un peu plus lentes, de plus en plus, sans cause visible.
CREATE INDEX idx_invites_unused ON invites(used_at) WHERE used_at IS NULL;
