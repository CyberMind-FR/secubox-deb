-- SPDX-License-Identifier: LicenseRef-CMSD-1.0
-- Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
-- Source-Disclosed License — All rights reserved except as expressly granted.
-- See LICENCE-CMSD-1.0.md for terms.
--
-- Analyste IA à preuves vérifiées (V2 § 9, #3722). Une analyse par passage de l'analyste sur un dossier :
-- etat = valide | rejete | quarantaine | sans_ia ; seule une analyse « valide » porte le texte du modèle (resume,
-- lecture) ; les autres portent le résumé produit par le code. motif = raison de l'état, produite par le code.
-- recommandations_json : gestes du catalogue retenus (motif du code) ; retirees_json : retirées, avec leur motif.
-- Les analyses partent avec leur dossier (cascade : fusion d'un dossier par adresse, rétention).
CREATE TABLE analyses (
  id TEXT PRIMARY KEY,
  dossier_id TEXT NOT NULL REFERENCES dossiers(id) ON DELETE CASCADE,
  etat TEXT NOT NULL CHECK (etat IN ('valide', 'rejete', 'quarantaine', 'sans_ia')),
  version_prompt TEXT,
  moteur TEXT,
  resume TEXT NOT NULL,
  lecture TEXT,
  preuves_json TEXT NOT NULL DEFAULT '[]',
  manques_json TEXT NOT NULL DEFAULT '[]',
  recommandations_json TEXT NOT NULL DEFAULT '[]',
  retirees_json TEXT NOT NULL DEFAULT '[]',
  motif TEXT,
  cree_le TEXT NOT NULL,
  duree_ms INTEGER
);
CREATE INDEX idx_analyses_dossier ON analyses(dossier_id, cree_le);

-- File de travaux de la veille (genre « analyser » : objet = dossier). disponible_le : époque (UTC) avant laquelle le
-- travail n'est pas pris. repere : « rang de gravité|étapes » du dossier au dépôt (nouveau ou aggravé, V2 § 9.4).
-- Une seule ligne en attente par (genre, objet) : index unique partiel.
CREATE TABLE travaux (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  genre TEXT NOT NULL,
  objet_id TEXT NOT NULL,
  etat TEXT NOT NULL DEFAULT 'attente' CHECK (etat IN ('attente', 'en_cours', 'fait', 'abandon')),
  essais INTEGER NOT NULL DEFAULT 0,
  disponible_le REAL NOT NULL,
  cree_le TEXT NOT NULL,
  repere TEXT
);
CREATE UNIQUE INDEX idx_travaux_attente ON travaux(genre, objet_id) WHERE etat = 'attente';
CREATE INDEX idx_travaux_file ON travaux(etat, disponible_le);
CREATE INDEX idx_travaux_objet ON travaux(genre, objet_id, id);
