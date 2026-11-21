-- SPDX-License-Identifier: LicenseRef-CMSD-1.0
-- Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
-- Source-Disclosed License — All rights reserved except as expressly granted.
-- See LICENCE-CMSD-1.0.md for terms.
-- Index de la rétention bornée (#3725) : chaque purge par âge ou par plafond parcourt un index, jamais la table.
CREATE INDEX IF NOT EXISTS idx_prop_reference ON propositions(reference);
CREATE INDEX IF NOT EXISTS idx_prop_maj ON propositions(maj_le);
CREATE INDEX IF NOT EXISTS idx_analyses_cree ON analyses(cree_le);
CREATE INDEX IF NOT EXISTS idx_adresses_horodatage ON acteurs_adresses(horodatage);
CREATE INDEX IF NOT EXISTS idx_filtres_maj ON filtres(maj_le);
CREATE INDEX IF NOT EXISTS idx_audit_horodatage ON audit_chaine(horodatage);
CREATE INDEX IF NOT EXISTS idx_dossier_incidents_incident ON dossier_incidents(incident_id);
CREATE INDEX IF NOT EXISTS idx_redescentes_dossier ON redescentes(dossier_id);
