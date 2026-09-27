-- SPDX-License-Identifier: LicenseRef-CMSD-1.0
-- Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
-- Source-Disclosed License — All rights reserved except as expressly granted.
-- See LICENCE-CMSD-1.0.md for terms.
--
-- SALONS PRIVES ADOSSES AUX COMMUNAUTES SBX OS (#1519, decision D4).
--
-- Un salon prive peut etre ouvert a une communaute : ses membres y entrent
-- sans etre conviees un par un. Les ajouts nominatifs (salon_membres) restent.
-- La communaute vit dans l'identite SBX OS (sbx.db), pas ici : on ne garde que
-- son identifiant et son NOM AU MOMENT DU RATTACHEMENT, pour que la console
-- du sysop reste lisible meme si sbx.db ne l'est plus.
CREATE TABLE salon_communautes (
  category_id    INTEGER NOT NULL REFERENCES categories(id) ON DELETE CASCADE,
  community_uuid TEXT NOT NULL,
  nom            TEXT NOT NULL,
  ajoute_par     INTEGER REFERENCES users(id),
  ajoute_le      INTEGER NOT NULL,
  PRIMARY KEY (category_id, community_uuid)
);
