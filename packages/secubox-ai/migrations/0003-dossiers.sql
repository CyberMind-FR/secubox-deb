-- SPDX-License-Identifier: LicenseRef-CMSD-1.0
-- Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
-- Source-Disclosed License — All rights reserved except as expressly granted.
-- See LICENCE-CMSD-1.0.md for terms.
--
-- Dossiers d'attaquant et de campagne (complément § 2, #3795). Clé = acteur d'actord (ACT-nnnn) ou adresse ;
-- campagne = acteurs regroupés par règle écrite. etapes_json : étapes atteintes, chacune avec sa règle, ses preuves
-- et ses heures. outils_json : rempli par l'identification d'outils (tâche 8). Les liens partent avec l'événement
-- ou l'incident purgé (cascade).

CREATE TABLE dossiers (
  id TEXT PRIMARY KEY,
  cle TEXT NOT NULL UNIQUE,
  type TEXT NOT NULL CHECK (type IN ('acteur', 'campagne')),
  gravite TEXT NOT NULL,
  etapes_json TEXT NOT NULL DEFAULT '[]',
  outils_json TEXT NOT NULL DEFAULT '[]',
  premiere_vue TEXT NOT NULL, derniere_vue TEXT NOT NULL, maj_le TEXT NOT NULL,
  a_recalculer INTEGER NOT NULL DEFAULT 1     -- passe bornée : le reste attend la suivante
);
CREATE INDEX idx_dossiers_recalcul ON dossiers(a_recalculer);
CREATE INDEX idx_dossiers_vue ON dossiers(derniere_vue);
CREATE TABLE dossier_incidents (
  dossier_id TEXT NOT NULL REFERENCES dossiers(id) ON DELETE CASCADE,
  incident_id TEXT NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
  PRIMARY KEY(dossier_id, incident_id)
);
CREATE TABLE dossier_evenements (
  dossier_id TEXT NOT NULL REFERENCES dossiers(id) ON DELETE CASCADE,
  evenement_id TEXT NOT NULL REFERENCES evenements(id) ON DELETE CASCADE,
  PRIMARY KEY(dossier_id, evenement_id)
);
CREATE INDEX idx_dossier_evt ON dossier_evenements(evenement_id);
-- Membres d'une campagne (dossiers d'acteur) et la règle qui les a réunis.
CREATE TABLE dossier_membres (
  campagne_id TEXT NOT NULL REFERENCES dossiers(id) ON DELETE CASCADE,
  membre_id TEXT NOT NULL REFERENCES dossiers(id) ON DELETE CASCADE,
  regle TEXT NOT NULL,
  PRIMARY KEY(campagne_id, membre_id)
);
