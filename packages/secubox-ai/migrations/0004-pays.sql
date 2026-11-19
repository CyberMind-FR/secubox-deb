-- SPDX-License-Identifier: LicenseRef-CMSD-1.0
-- Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
-- Source-Disclosed License — All rights reserved except as expressly granted.
-- See LICENCE-CMSD-1.0.md for terms.
--
-- Tendances par pays du Radar (#3811), portées du POC gk0 (2026-11-18) : un échantillon par créneau de 15 min, écrit
-- par la veille (seul écrivain), gardé 8 jours. quand = époque (UTC). Les colonnes *_json sont les comptes par pays
-- tels que gk2 les rend (top 5) ; NULL = source illisible à ce créneau (jamais 0 inventé).
CREATE TABLE pays_echantillons (
  creneau INTEGER PRIMARY KEY,           -- quand // 900
  quand INTEGER NOT NULL,
  alertes_json TEXT, tot_alertes INTEGER,
  bans_json TEXT, tot_bans INTEGER
);
CREATE INDEX idx_pays_quand ON pays_echantillons(quand);
