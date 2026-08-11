-- Inscription SUR INVITATION uniquement.
--
-- Un BBS auto-heberge finit exposé sur internet ; une inscription ouverte, c'est
-- une file de comptes jetables a moderer chaque matin. Le sysop emet un code,
-- il sert UNE fois.
CREATE TABLE invites (
  code_sha256 BLOB PRIMARY KEY,   -- jamais le code en clair : il circule par mail
  issued_by   INTEGER NOT NULL REFERENCES users(id),
  issued_at   INTEGER NOT NULL,
  expires_at  INTEGER NOT NULL,
  used_at     INTEGER,
  used_by     INTEGER REFERENCES users(id)
);
CREATE INDEX idx_invites_unused ON invites(used_at) WHERE used_at IS NULL;
