<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Design — PeerTube WebUI admin ops: reset-password + version check/upgrade

- **Issue** : [#798](https://github.com/CyberMind-FR/secubox-deb/issues/798)
- **Date** : 2026-07-04
- **Licence** : LicenseRef-CMSD-1.0
- **Module** : `packages/secubox-peertube/`

## 1. Problème

Le WebUI PeerTube n'offre aucune action admin pour (a) réinitialiser le mot de passe admin, (b) voir si une nouvelle version existe, (c) faire l'upgrade. Ces opérations doivent s'exécuter **dans la LXC `peertube`** (lxc-attach, npm CLI PeerTube), mais l'API `secubox-peertube` tourne **non-privilégiée** : `User=secubox`, `NoNewPrivileges=true`, **aucun sudoers**. Elle ne peut donc pas `lxc-attach` ni `sudo`.

Le module a déjà résolu ce genre de besoin (#407) via un **spool + unité root** : l'API dépose un fichier dans `/run/secubox/`, une unité systemd `.path` (root) le détecte et lance un `.service` (root) qui exécute `peertubectl` (qui fait le lxc-attach). On généralise ce pattern.

## 2. Objectif

Trois actions admin dans le WebUI PeerTube, toutes via le mécanisme spool→root :
- **A. Reset admin password** — lockout-safe (CLI PeerTube), réécrit le secret admin.
- **B. Check version** — installée vs dernière release (non privilégié).
- **C. Upgrade** — download release + migration DB + restart, avec backup pré-upgrade obligatoire et rollback.

## 3. Architecture — mécanisme d'ops privilégiées partagé

### 3.1 Spool + unité root (généralisation de #407)

- **Répertoire de spool** : `/run/secubox/peertube/ops/` (créé 0750 `secubox:secubox` par postinst + tmpfiles). L'API (secubox) y écrit ; root lit/supprime.
- **Requête** : l'API écrit `ops/<uuid>.request.json` = `{ "op": "reset-password"|"upgrade", "id": "<uuid>", ...args }`, chmod **0600** (peut contenir un mot de passe).
- **Watcher** : `peertube-ops.path` (root) — `DirectoryNotEmpty=/run/secubox/peertube/ops` → `Unit=peertube-ops.service`.
- **Exécuteur** : `peertube-ops.service` (root, `Type=oneshot`) — `ExecStart=/usr/sbin/peertubectl process-ops`.
- **`peertubectl process-ops`** : pour chaque `ops/*.request.json` : parse `op`, dispatch (`cmd_reset_admin_password` / `cmd_upgrade`), écrit `ops/<id>.result.json` = `{ "status": "done"|"error"|"running", "detail": "...", ...extra }` (0640 `root:secubox`), puis supprime le `.request.json` (évite le re-trigger + sensible).
- **Polling** : l'API lit `ops/<id>.result.json`. Tant qu'il n'existe pas → `pending`. L'upgrade (long) écrit d'abord `status:"running"` (progress), puis `done`/`error`.

Ce mécanisme **préserve NoNewPrivileges** sur l'API (aucun sudo) et concentre le privilège dans une unité root auditée, exactement comme #407.

### 3.2 peertubectl — constantes existantes

`peertubectl` utilise déjà `lxc-attach -n "$LXC_NAME" -P "$LXC_PATH" -- …` (LXC sous `/data/lxc`). PeerTube dans la LXC : `/var/www/peertube`, user OS `peertube`, service `peertube.service`, release `peertube-latest → versions/peertube-v8.2.0`, `NODE_ENV=production`, `NODE_CONFIG_DIR=/var/www/peertube/config`.

## 4. Les trois actions

### 4.1 A — Reset admin password

**peertubectl `reset-admin-password`** (appelé par process-ops avec la requête) :
```
pw="$(jq -r .password <request>)"      # fourni par l'API (aléatoire si l'utilisateur n'en donne pas)
lxc-attach -n peertube -P /data/lxc -- sudo -u peertube \
  env NODE_ENV=production NODE_CONFIG_DIR=/var/www/peertube/config \
  bash -lc 'cd /var/www/peertube/peertube-latest && printf "%s\n" "'"$pw"'" | npm run reset-password -- -u root'
```
- Le CLI `reset-password` est **interactif** (prompt masqué) → on lui pipe le mot de passe (une ligne).
- **Puis réécrit `/etc/secubox/secrets/peertube-admin`** avec le nouveau mot de passe (0600 `secubox-peertube`), sinon `get_admin_token()` (api/main.py:262) casse pour toutes les write-ops du dashboard.
- Résultat : `{status:"done", password:"<pw>"}` (le mdp n'est renvoyé qu'ici, une fois, pour que l'UI l'affiche si généré).

**API `POST /admin/reset-password`** (`require_jwt` + gate rôle admin) : body `{"password": "<optional>"}`. Si absent → génère un mdp fort (secrets). Écrit la requête spool. Renvoie `{"id": "<uuid>"}`.
**API `GET /admin/op/{id}`** (`require_jwt`) : lit le result file → `{status, detail, password?}`. `password` purgé du result après première lecture (ou result 0640 + suppression best-effort).

**WebUI** (onglet Users, action admin — mirroir de `deleteUser`) : bouton **🔑 Reset password** → petit modal (« saisir un mot de passe » ou « générer ») → `POST` → poll `GET /admin/op/{id}` → toast + si généré, affiche le mdp (copiable).

### 4.2 B — Check version (non privilégié, côté API)

**API `GET /version`** (`require_jwt`) :
- **installée** : via `pt_api("/api/v1/config")` → champ `serverVersion` (l'API a déjà `pt_api`). Fallback : lire la cible du symlink si accessible.
- **latest** : `GET https://api.github.com/repos/Chocobozzz/PeerTube/releases/latest` → `tag_name` (ex. `v8.2.0`), **caché ~1 h** (fichier `/run/secubox/peertube/latest-version.json`, best-effort ; hors-ligne → `latest=null`).
- Compare **semver** → `{"installed": "8.2.0", "latest": "8.x.y", "upgrade_available": bool}`.

**WebUI** (carte Maintenance) : badge `v8.2.0 · ✅ à jour` ou `v8.2.0 · ⬆️ v8.x dispo`.

### 4.3 C — Upgrade (gated, spool→root)

**peertubectl `upgrade`** (via process-ops) — étapes, chacune vérifiée, écrit `status:"running"` + progression :
1. **Backup DB obligatoire** : `pg_dump` de `peertube_prod` → `/var/lib/secubox/peertube/backups/pre-upgrade-<ts>.sql.gz` (dans la LXC ou via le postgres de la LXC). Si échec backup → **abort** (pas d'upgrade).
2. Résoudre la version cible (release GitHub `target|latest`), télécharger le zip release dans `versions/`.
3. Extraire → `versions/peertube-vX` ; `npm install --production` (dans la LXC, user peertube).
4. **Migrations** : arrêter `peertube.service`, swap symlink `peertube-latest → versions/peertube-vX`, lancer les migrations (PeerTube les exécute au démarrage, ou `npm run … migrate`).
5. `systemctl start peertube` + **health-check** (HTTP 200 sur `/api/v1/config` via `pt_api` boucle courte).
6. **En cas d'échec (npm/migration/health)** : re-swap le symlink vers l'ancienne version + restart → **l'ancienne version reste live** ; result `{status:"error", detail, backup:"<path>"}`.
7. Succès : result `{status:"done", from, to, backup}`.

**API `POST /upgrade`** (`require_jwt` + admin) : body `{"target": "latest"|"vX"}`. Écrit la requête spool. Renvoie `{"id"}`. Poll `GET /admin/op/{id}` → `running`/`done`/`error` (+ `detail`/progression). La route root a un `TimeoutStartSec` généreux (upgrade = plusieurs minutes).

**WebUI** (carte Maintenance) : bouton **⬆️ Upgrade to vX** (visible seulement si `upgrade_available`) → `confirm()` **avertissant downtime + backup** → `POST /upgrade` → polling avec état (« Upgrade en cours… » / « Terminé v8.2.0→vX » / « Échec — ancienne version restaurée, backup: … »).

## 5. Gestion d'erreurs / sécurité

- **Fail-safe** : chaque op écrit un result `{status, detail}` ; l'API mappe en toast. Requête illisible → result `error`.
- **Reset** : si `npm run reset-password` échoue, **ne pas** réécrire le secret ; result `error`.
- **Upgrade** : backup obligatoire (abort si échec) ; échec post-download → **pas de swap** (ou re-swap) → ancienne version live ; le backup path est toujours rapporté. Rollback restore = documenté (manuel), hors périmètre auto.
- **Auth** : toutes les routes mutantes `require_jwt`. **Nouveau** : gate rôle admin (le module accepte aujourd'hui tout JWT valide ; `require_jwt` expose un claim `role` via `/auth/verify`). On ajoute une dépendance `require_admin` locale (vérifie `role in {admin}`), appliquée à `/admin/reset-password` et `/upgrade`.
- **Secrets** : le mdp transite en clair dans le fichier spool (0600 secubox) et le result (0640, purgé après lecture) — dans `/run` (tmpfs), TTL court. Acceptable (même surface que le secret admin déjà stocké 0600).
- **Concurrence** : `process-ops` traite les fichiers séquentiellement ; l'API refuse un 2e upgrade si un result `running` existe.
- **Pas de régression** `/run/secubox` 1777 ni `/etc/secubox` 0755 (on crée seulement `/run/secubox/peertube/ops` sous le parent).

## 6. Tests

- **peertubectl** (`bats`/shell) : `--dry-run` sur `reset-admin-password` et `upgrade` (n'exécute pas lxc-attach, imprime la commande) ; `process-ops` lit une requête fixture, écrit un result attendu (lxc-attach mocké via un stub PATH) ; `shellcheck` propre.
- **API** (`pytest`) : `POST /admin/reset-password` écrit bien une requête spool (dir monkeypatché) ; `GET /admin/op/{id}` lit un result fixture → mapping statut ; `GET /version` compare-semver (installed<latest → upgrade_available true ; égal → false ; latest null → false) avec `pt_api`/GitHub mockés ; `require_admin` refuse un JWT non-admin (403).
- **WebUI** : manuel (boutons + polling + toasts).

## 7. Packaging

- `sbin/peertubectl` : verbes `reset-admin-password`, `upgrade`, `process-ops` (+ `--dry-run`).
- `debian/` : `peertube-ops.path` + `peertube-ops.service` (root, oneshot) ; `rules` les installe (mirroir des unités cookie) ; `postinst` crée `/run/secubox/peertube/ops` (ou tmpfiles.d) + le dir backups ; enable la `.path`.
- `api/main.py` : `POST /admin/reset-password`, `GET /admin/op/{id}`, `GET /version`, `POST /upgrade`, dépendance `require_admin`.
- `www/peertube/index.html` : bouton reset (Users) + carte version/upgrade (Maintenance) + polling.
- `tests/` : peertubectl + API.

## 8. Séquencement (pour le plan)

Ordre par risque croissant, chaque étape livrable/testable seule :
1. **Mécanisme spool→root partagé** (peertubectl `process-ops` + `.path`/`.service` + postinst dir + `require_admin`).
2. **Reset password** (peertubectl verbe + API + WebUI + secret rewrite).
3. **Check version** (API `/version` + badge WebUI).
4. **Upgrade** (peertubectl `upgrade` + API + WebUI) — **le plus risqué, en dernier** ; live-test = downtime accepté.

## 9. Risques

- **Upgrade DB migration** : irréversible sans restore du dump. Mitigation : backup obligatoire + abort-if-backup-fails + pas de swap si migration/health échoue.
- **reset-password interactif** : le pipe stdin doit matcher le prompt du CLI v8.2.0 (une ligne). À valider live (le CLI peut redemander confirmation — dans ce cas, piper deux lignes).
- **GitHub rate-limit / hors-ligne** : `latest` best-effort caché ; jamais bloquant pour le check.
- **Live-test upgrade** : ne pas tester l'upgrade sur l'instance de prod sans accepter le downtime + avoir le backup ; idéalement tester le chemin sur une release identique (no-op) d'abord.
