-- SPDX-License-Identifier: LicenseRef-CMSD-1.0
-- Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
-- Source-Disclosed License — All rights reserved except as expressly granted.
-- See LICENCE-CMSD-1.0.md for terms.
--
-- Riposte graduée et propositions (#3723 ; spec riposte 2026-11-19 § 1, V2 § 6 et § 10.3). Niveau du dossier calculé
-- par le code (veille/riposte.py) : observer | contenir | usager ; niveau_depuis = dernier changement ; signaux_json =
-- signaux chiffrés qui l'ont fixé (tentatives, couches, fenetre_s, campagne, recidive, critique, derniere_preuve…).
-- Propositions : nées du code (règle + politique), motif produit par le code, une seule VIVANTE par (geste, cible).
-- Elles survivent à leur dossier, à l'incident et à l'analyse purgés (SET NULL : rétention 730 j). Aucun déclencheur.

ALTER TABLE dossiers ADD COLUMN niveau TEXT NOT NULL DEFAULT 'observer'
  CHECK (niveau IN ('observer', 'contenir', 'usager'));
ALTER TABLE dossiers ADD COLUMN niveau_depuis TEXT;
ALTER TABLE dossiers ADD COLUMN signaux_json TEXT NOT NULL DEFAULT '{}';
CREATE INDEX idx_dossiers_niveau ON dossiers(niveau);

CREATE TABLE propositions (
  id TEXT PRIMARY KEY,
  version INTEGER NOT NULL DEFAULT 1,           -- l'approbation porte sur (id, version)
  dossier_id TEXT REFERENCES dossiers(id) ON DELETE SET NULL,
  incident_id TEXT REFERENCES incidents(id) ON DELETE SET NULL,
  analyse_id TEXT REFERENCES analyses(id) ON DELETE SET NULL,
  geste TEXT NOT NULL CHECK (geste IN ('ban', 'ban_bloc', 'prolonger', 'limiter', 'leurre', 'partager', 'unban')),
  cible TEXT NOT NULL,
  duree_s INTEGER,
  mode TEXT NOT NULL CHECK (mode IN ('clic', 'auto')),
  niveau TEXT CHECK (niveau IN ('observer', 'contenir', 'usager')),
  politique TEXT NOT NULL,                      -- clé de politiques.toml qui l'a admise
  motif TEXT NOT NULL,                          -- produit par le code, jamais par le modèle
  etat TEXT NOT NULL CHECK (etat IN ('proposee', 'approuvee', 'refusee', 'expiree', 'envoyee', 'faite',
                                     'refusee_gk2', 'echec')),
  expire_le TEXT NOT NULL,
  cree_le TEXT NOT NULL,
  maj_le TEXT NOT NULL
);
-- Une seule proposition vivante par geste et cible.
CREATE UNIQUE INDEX idx_prop_vivante ON propositions(geste, cible) WHERE etat IN ('proposee', 'approuvee', 'envoyee');
CREATE INDEX idx_prop_etat ON propositions(etat, expire_le);
CREATE INDEX idx_prop_geste ON propositions(geste, cree_le);
CREATE INDEX idx_prop_dossier ON propositions(dossier_id);

CREATE TABLE approbations (
  id TEXT PRIMARY KEY,
  proposition_id TEXT NOT NULL REFERENCES propositions(id) ON DELETE CASCADE,
  version INTEGER NOT NULL,
  acteur TEXT NOT NULL,                         -- `sub` du jeton require_jwt
  decision TEXT NOT NULL CHECK (decision IN ('approuver', 'refuser')),
  motif TEXT,
  cree_le TEXT NOT NULL,
  UNIQUE(proposition_id, version)               -- pas de double décision
);
