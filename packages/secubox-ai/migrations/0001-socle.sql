-- SPDX-License-Identifier: LicenseRef-CMSD-1.0
-- Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
-- Source-Disclosed License — All rights reserved except as expressly granted.
-- See LICENCE-CMSD-1.0.md for terms.
--
-- Socle de veille.db (V2 § 6, #3719). Horodatages UTC RFC 3339. Les champs venant de gk2 sont des données non
-- fiables. schema_migrations est créée et remplie par veille.base.migrer (la version est inscrite dans la même
-- transaction que le script).

CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, appliquee_le TEXT NOT NULL);

CREATE TABLE curseurs (
  source TEXT PRIMARY KEY,
  position TEXT,
  etat TEXT NOT NULL,
  derniere_lecture TEXT, derniere_erreur TEXT, lus_total INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE evenements (
  id TEXT PRIMARY KEY,
  source TEXT NOT NULL,
  id_source TEXT,
  noeud TEXT NOT NULL,
  horodatage TEXT NOT NULL,
  famille TEXT NOT NULL,
  sous_famille TEXT,
  gravite TEXT NOT NULL,
  ip_src TEXT, bloc24 TEXT,
  pays TEXT, service TEXT, vhost TEXT,
  message TEXT,
  attributs_json TEXT NOT NULL DEFAULT '{}',
  empreinte TEXT NOT NULL,
  cree_le TEXT NOT NULL,
  UNIQUE(empreinte)
);
CREATE INDEX idx_evt_temps ON evenements(horodatage);
CREATE INDEX idx_evt_ip ON evenements(ip_src, horodatage);
CREATE INDEX idx_evt_bloc ON evenements(bloc24, horodatage);
CREATE INDEX idx_evt_famille ON evenements(famille, horodatage);

CREATE TABLE campagnes (
  id TEXT PRIMARY KEY,
  outil TEXT, attaquants INTEGER, sondes INTEGER, haute_valeur INTEGER,
  premiere_vue TEXT NOT NULL, derniere_vue TEXT NOT NULL, attributs_json TEXT NOT NULL DEFAULT '{}'
);
CREATE TABLE blocs (
  bloc24 TEXT PRIMARY KEY, adresses INTEGER, familles_json TEXT, banni_jusqua TEXT, origine TEXT, vu_le TEXT NOT NULL
);

CREATE TABLE incidents (
  id TEXT PRIMARY KEY,
  regle TEXT NOT NULL,
  cle TEXT NOT NULL,
  titre TEXT NOT NULL,
  etat TEXT NOT NULL,
  gravite TEXT NOT NULL,
  sources_json TEXT NOT NULL,
  campagne_id TEXT REFERENCES campagnes(id),
  premiere_vue TEXT NOT NULL, derniere_vue TEXT NOT NULL, cree_le TEXT NOT NULL, maj_le TEXT NOT NULL,
  UNIQUE(regle, cle, premiere_vue)
);
CREATE TABLE incident_preuves (
  incident_id TEXT NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
  evenement_id TEXT NOT NULL REFERENCES evenements(id),
  PRIMARY KEY(incident_id, evenement_id)
);

CREATE TABLE audit_chaine (
  id INTEGER PRIMARY KEY AUTOINCREMENT, horodatage TEXT NOT NULL, acteur TEXT NOT NULL,
  operation TEXT NOT NULL, objet TEXT, objet_id TEXT, resultat TEXT NOT NULL, details_json TEXT,
  empreinte_prec TEXT, empreinte TEXT NOT NULL
);

CREATE TABLE mesures (
  horodatage TEXT PRIMARY KEY, retard_collecte_s INTEGER, retard_correlation_s INTEGER,
  file_travaux INTEGER, memoire_dispo_mo INTEGER, moteur TEXT, latence_moteur_ms INTEGER, erreurs INTEGER
);
