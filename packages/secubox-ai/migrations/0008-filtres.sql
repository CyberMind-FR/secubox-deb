-- SPDX-License-Identifier: LicenseRef-CMSD-1.0
-- Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
-- Source-Disclosed License — All rights reserved except as expressly granted.
-- See LICENCE-CMSD-1.0.md for terms.
--
-- Filtres WAF d'office (#3723, carte 4 ; complément § 4) : un filtre par id `ia-…`, construit par le CODE depuis le
-- catalogue d'empreintes (`[[outil.filtre]]` sourcé, CVE compris), jamais du texte du modèle. Cycle :
-- envoi (ligne créée AVANT POST /ai/filtres) → essai (gk2 l'a appliqué ; `essai_depuis`) → a_confirmer (24 h sans
-- toucher d'adresse protégée : confirmation en UN CLIC d'un administrateur, jamais d'office, le critère « vhost routé
-- à réponse légitime » n'étant pas mesurable depuis gk3) → confirme ; à tout moment une touche protégée → retrait
-- (DELETE /ai/filtres/{id}) et alerte → retire. rejete : refusé par le vérificateur de gk2 ; echec : refus ou panne.
-- Un id retiré ou rejeté n'est jamais renvoyé.

CREATE TABLE filtres (
  id TEXT PRIMARY KEY,
  outil TEXT NOT NULL,
  cve TEXT NOT NULL,
  dossier_id TEXT,
  corps_json TEXT NOT NULL,
  etat TEXT NOT NULL CHECK (etat IN ('envoi', 'essai', 'a_confirmer', 'confirme', 'retire', 'rejete', 'echec')),
  jti TEXT,
  cle TEXT,
  code_http INTEGER,
  motif TEXT,
  touches_protegees INTEGER,
  envoye_le TEXT NOT NULL,
  essai_depuis TEXT,
  confirme_par TEXT,
  maj_le TEXT NOT NULL
);
CREATE INDEX idx_filtres_etat ON filtres(etat);
CREATE INDEX idx_filtres_envoi ON filtres(envoye_le);
