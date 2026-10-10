-- SPDX-License-Identifier: LicenseRef-CMSD-1.0
-- Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
-- MetaNews — billets éphémères (#2268).
--
-- Un sujet est publié dans le fil des billets pour QUELQUES MINUTES (billet à durée de vie limitée). Cette table retient ce qui l'a été, pour ne pas
-- republier le même sujet à chaque tour (délai de grâce) et pour tenir le plafond horaire.
CREATE TABLE IF NOT EXISTS billet_ephemere(
  topic_id  TEXT PRIMARY KEY,
  billet_id TEXT NOT NULL,
  slug      TEXT NOT NULL DEFAULT '',
  publie_a  INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_billet_eph_pub ON billet_ephemere(publie_a);
