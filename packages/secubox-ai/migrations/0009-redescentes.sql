-- SPDX-License-Identifier: LicenseRef-CMSD-1.0
-- Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
-- Source-Disclosed License — All rights reserved except as expressly granted.
-- See LICENCE-CMSD-1.0.md for terms.
--
-- Redescente du niveau d'un dossier décidée par un administrateur (#3724, onglet Dossier). L'API n'écrit que la
-- décision (une ligne en attente par dossier au plus, avec sa ligne `audit_chaine` relayée) ; la VEILLE l'applique à
-- sa passe suivante (veille/riposte.py, `appliquer_redescentes`) : niveau `observer`, preuves antérieures à la
-- décision soldées (plancher), audit `riposte_niveau` de cible « humain ». Aucun geste n'est défait.
CREATE TABLE redescentes (
  id TEXT PRIMARY KEY,
  dossier_id TEXT NOT NULL REFERENCES dossiers(id) ON DELETE CASCADE,
  acteur TEXT NOT NULL,                         -- `sub` du jeton require_jwt
  demandee_le TEXT NOT NULL,
  appliquee_le TEXT,
  resultat TEXT CHECK (resultat IN ('appliquee', 'deja_observer'))
);
CREATE UNIQUE INDEX idx_redescente_attente ON redescentes(dossier_id) WHERE appliquee_le IS NULL;
