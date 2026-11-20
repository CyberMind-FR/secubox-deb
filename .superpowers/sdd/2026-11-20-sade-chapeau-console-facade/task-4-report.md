# Task 4 - mode et politique
Fichiers: api/defense_etat.py, api/migrations/0001-defense.sql, api/defense.py (GET /policies, POST /mode, status.mode), tests/test_defense_mode.py.
Choix: DB via SECUBOX_SOC_DEFENSE_DB, audit via SECUBOX_AUDIT_LOG (aucune API publique d'audit dans secubox_core; ecriture append). Migrations copiees du patron secubox-ai (schema_migrations). Packaging: rules fait deja cp -r api, migrations incluses.
Notes: /defense/status renvoie le mode en MAJUSCULES (test existant), /policies en minuscules (brief). Dossier /var/lib/secubox/soc doit exister/etre inscriptible par l'utilisateur du service (mkdir tente a l'ouverture).

## Fix round 1
C1: changer_mode en une transaction BEGIN IMMEDIATE, audit ecrit+flush+fsync avant COMMIT, ROLLBACK + 503 audit_indisponible si echec ; inchange = no-op. I1: triggers BEFORE DELETE/UPDATE sur amorcee=1. I2: mode relu en direct apres le cache, minuscules partout. I3: pyc retires de l'index (.gitignore les couvrait deja). M1: operateur assaini (64 car., sans controle/espaces). M2: base indisponible -> observe + etat_base indisponible, POST 503, postinst cree /var/lib/secubox/soc (secubox, 0750). M3: executescript, amorcage en SQL (INSERT OR IGNORE).
