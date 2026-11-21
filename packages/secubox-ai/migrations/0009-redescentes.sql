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

-- Défaire (#3724) : une levée (`unban`) est unique par geste visé (`reference`), non plus par cible : lever le ban
-- d'une adresse ET retirer l'indicateur partagé de la même adresse sont deux levées vivantes distinctes. Les autres
-- gestes gardent une seule proposition vivante par (geste, cible).
DROP INDEX idx_prop_vivante;
CREATE UNIQUE INDEX idx_prop_vivante ON propositions(geste, cible, COALESCE(CASE WHEN geste = 'unban' THEN reference END, ''))
  WHERE etat IN ('proposee', 'approuvee', 'envoyee');
