-- SPDX-License-Identifier: LicenseRef-CMSD-1.0
-- Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
-- Source-Disclosed License — All rights reserved except as expressly granted.
-- See LICENCE-CMSD-1.0.md for terms.
--
-- Tour de filtres WAF Nuclei (#3862), porté du POC gk0. `filtres.origine` : `outil` (catalogue d'empreintes, #3723)
-- ou `nuclei` (candidats.json du collecteur) ; `filtres.version` : version du filtre envoyée à gk2 (gk2 tient pour
-- « inchangé » le même id dans la même version) ; `filtres.adopte` : 1 pour un filtre Nuclei déjà en vigueur sur gk2
-- (posé par gk0) dans la même version, inscrit SANS envoi pour être surveillé (retrait d'office sur adresse
-- protégée) ; il ne compte pas aux plafonds. `outil` vaut `nuclei` pour ces lignes.
ALTER TABLE filtres ADD COLUMN origine TEXT NOT NULL DEFAULT 'outil';
ALTER TABLE filtres ADD COLUMN version INTEGER NOT NULL DEFAULT 1;
ALTER TABLE filtres ADD COLUMN adopte INTEGER NOT NULL DEFAULT 0;
CREATE INDEX IF NOT EXISTS idx_filtres_origine ON filtres(origine, etat);
