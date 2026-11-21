-- SPDX-License-Identifier: LicenseRef-CMSD-1.0
-- Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
-- Source-Disclosed License — All rights reserved except as expressly granted.
-- See LICENCE-CMSD-1.0.md for terms.
--
-- Exécuteur des réponses (#3723, V2 § 6 et § 10.3) : une ligne `actions` par proposition envoyée à gk2, créée en
-- état `envoi` AVANT l'appel (UNIQUE(proposition_id) : jamais deux envois, même après redémarrage), puis la réponse de
-- gk2 telle quelle (code, motif, corps borné : données NON FIABLES). Une ligne restée en `envoi` (processus arrêté en
-- plein envoi, délai, réponse illisible) est rapprochée par GET /ai/etat avant toute nouvelle tentative, jamais
-- renvoyée. `jti` : celui du jeton envoyé, jamais le jeton ; `cle` : empreinte (kid) de la clé ai-ban, jamais la clé.
-- `id_cible_gk2` : identifiant gk2 visé par `prolonger` / `unban` (repris de l'action du ban de la proposition de
-- `reference`) ; `id_gk2` : identifiant rendu par gk2 pour le geste fait.
--
-- `executeur_etat` : état durable de l'exécuteur, lu par l'API (/veille/etat) : suspension de l'automatique (manuelle
-- ou d'elle-même, survit au redémarrage), état de la clé ai-ban, dernier relevé de /ai/etat, curseur du relais d'audit.

CREATE TABLE actions (
  id TEXT PRIMARY KEY,
  proposition_id TEXT NOT NULL UNIQUE REFERENCES propositions(id),
  geste TEXT NOT NULL,
  cible TEXT NOT NULL,
  mode TEXT NOT NULL CHECK (mode IN ('auto', 'clic')),
  id_cible_gk2 TEXT,
  etat TEXT NOT NULL CHECK (etat IN ('envoi', 'faite', 'refusee_gk2', 'echec')),
  jti TEXT NOT NULL,
  cle TEXT NOT NULL,
  code_http INTEGER,
  motif TEXT,
  reponse_json TEXT,
  id_gk2 TEXT,
  fin_gk2 INTEGER,
  envoyee_le TEXT NOT NULL,
  repondue_le TEXT,
  rapprochee_le TEXT,
  constatee_le TEXT,
  effet TEXT
);
CREATE INDEX idx_actions_etat ON actions(etat);
CREATE INDEX idx_actions_geste ON actions(geste, envoyee_le);
CREATE INDEX idx_actions_envoi ON actions(envoyee_le);
CREATE INDEX idx_actions_gk2 ON actions(id_gk2);
CREATE INDEX idx_actions_refus ON actions(code_http, repondue_le);

CREATE TABLE executeur_etat (
  cle TEXT PRIMARY KEY,
  valeur TEXT NOT NULL,
  maj_le TEXT NOT NULL
);
