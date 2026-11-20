# Task 4 - mode et politique
Fichiers: api/defense_etat.py, api/migrations/0001-defense.sql, api/defense.py (GET /policies, POST /mode, status.mode), tests/test_defense_mode.py.
Choix: DB via SECUBOX_SOC_DEFENSE_DB, audit via SECUBOX_AUDIT_LOG (aucune API publique d'audit dans secubox_core; ecriture append). Migrations copiees du patron secubox-ai (schema_migrations). Packaging: rules fait deja cp -r api, migrations incluses.
Notes: /defense/status renvoie le mode en MAJUSCULES (test existant), /policies en minuscules (brief). Dossier /var/lib/secubox/soc doit exister/etre inscriptible par l'utilisateur du service (mkdir tente a l'ouverture).
