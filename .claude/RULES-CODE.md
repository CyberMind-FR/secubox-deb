<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# RULES-CODE — règles permanentes de code

S'appliquent à **tout code nouveau ou modifié**, dès la ligne touchée. **Aucune correction de masse** :
on ne réécrit pas l'existant pour s'y conformer ; on ne l'aggrave pas, et on corrige ce qu'on modifie.
Complète `MODULE-COMPLIANCE.md` (conformité d'un module) et `PATTERNS.md` (patterns). Le
sous-agent `relecteur-securite` relit un diff contre ce fichier. Un écart voulu s'écrit en
**exception**, dans ce fichier, avec sa raison et son test (voir § Exceptions).

## 1. Archives : extraction par helper validé

- Jamais `tarfile.extractall` / `zipfile.extractall` nu. Extraire par un helper qui **résout chaque
  entrée** et refuse tout ce qui sort du répertoire cible (`..`, chemin absolu, lien symbolique
  sortant, périphérique), puis plafonne le nombre d'entrées et la taille décompressée.
- Modèle : `_extract_archive` de `packages/secubox-publish/api/main.py` et son test
  `packages/secubox-publish/tests/test_publication_1823.py` (#1823, « archive tar confinée »).
- Un nouvel appelant **réutilise** ce helper ; il n'en écrit pas un second.

## 2. Permissions

- Pas de `0o666`, pas de `0o777`, pas de `chmod 666|777|a+w|o+w`, pas de `os.umask(0)`.
  Fichiers de config `0640`, secrets `0600`, répertoires `0750` ; un répertoire partagé reste `0755`
  (ne jamais resserrer un parent traversé par d'autres modules).
- Unités systemd : `UMask=0027` (au pire `0002`), jamais `0000` (#1416).
- Sockets Unix : sous `/run/secubox/<module>.sock`, propriétaire le service, groupe `secubox`,
  mode `0660`. L'unité porte `ExecStartPre=+/bin/rm -f /run/secubox/<module>.sock` ; **jamais**
  `RuntimeDirectory=secubox` ni `chown` du parent `/run/secubox` (voir `MODULE-COMPLIANCE.md`, § Socket).

## 3. API : toute route mutante porte une garde

- `POST|PUT|PATCH|DELETE` : `Depends(require_jwt)` (administrateur réel). `require_session` ou
  `require_personne` seulement sur une route d'**usager**, posés explicitement. Lecture :
  `require_lecture`. Jamais une route mutante sans garde « parce qu'elle est en LAN ».
- Le rôle vient du jeton vérifié côté serveur, jamais d'un en-tête, d'un paramètre ou du corps.
- Routes sous `sudo`/`ctl` : arguments validés par liste blanche ou motif entier avant l'appel.

## 4. TLS

- Pas de `verify=False`, pas de `ssl._create_unverified_context`, pas de `CERT_NONE`, pas de
  `curl -k` dans du code livré. Un service interne se vérifie avec la **CA interne** de la box
  (`verify="<chemin de la CA>"`, ex. `/usr/share/secubox/egress-ca.pem`) ; TLS 1.3 minimum côté frontal.

## 5. XML externe

- Tout XML qui ne vient pas de nous (flux, uploads, réponses distantes) se lit avec `defusedxml`
  (`defusedxml.ElementTree`), jamais `xml.etree` / `xml.dom` / `lxml` sans désactiver entités et DTD.

## 6. Async

- Dans un `async def` : ni `subprocess.*`, ni `time.sleep`, ni `requests`, ni lecture/écriture
  de fichier volumineuse, ni appel `sudo`. Utiliser `asyncio.create_subprocess_exec`, `httpx.AsyncClient`,
  `await asyncio.to_thread(...)` ou une route `def` simple (exécutée dans le pool).
- Un module servi par l'agrégateur partage **une seule boucle** : un appel bloquant la gèle pour tout le parc.

## 7. Erreurs et sous-processus

- Pas d'`except:` nu ; pas d'`except Exception: pass` — attraper l'exception précise, journaliser
  (`logger.exception` / `logger.warning` avec le motif), ou propager. Un échec silencieux est un bug.
- `subprocess.run([...], check=True, timeout=N, capture_output=True, text=True)` : liste d'arguments,
  `check` et `timeout` toujours présents. **Jamais `shell=True`**, jamais d'argument assemblé par f-string
  dans une commande shell.

## 8. Dates

- UTC avec fuseau : `datetime.now(timezone.utc)` ; sérialisation RFC 3339. Plus de `datetime.utcnow()`
  ni de `datetime.now()` sans fuseau pour un horodatage persistant.

## 9. Shell

- `#!/usr/bin/env bash` + `set -euo pipefail` ; variables entre guillemets ; `[[ ]]` ; `mktemp`.
- `trap` correctement quoté : `trap 'rm -f -- "$tmp"' EXIT` (apostrophes : l'expansion a lieu au
  déclenchement). Scripts `debian/*` en `#!/bin/sh` POSIX : `sh -n` doit passer.
- JSON par `jq`, jamais `grep`/`sed` ; `ss -tlnp`, `journalctl`, `systemctl` (pas de commandes OpenWrt).

## 10. systemd : socle de durcissement commun

Toute unité de service porte au minimum : `User=secubox-<module>` (jamais root, sauf exception),
`NoNewPrivileges=yes`, `ProtectSystem=strict` (ou `full` avec raison) + `ReadWritePaths=` explicite,
`ProtectHome=yes`, `PrivateTmp=yes`, `ProtectKernelTunables=yes`, `ProtectControlGroups=yes`,
`RestrictSUIDSGID=yes`, `LockPersonality=yes`, `UMask=0027`. Modèle : `packages/secubox-vault/debian/secubox-vault.service`.
Un `ReadWritePaths` n'est pas un lien symbolique vers un autre disque (le bac à sable le bloque en silence).

## Exceptions (explicites, listées)

Une exception n'existe que si elle est écrite ici avec sa raison et un test qui la fige.

| Règle | Exception | Raison | Test |
|---|---|---|---|
| § 3 garde | `POST /login`, `/login/mfa`, `/totp/confirm`, `/set-password` (secubox-auth) | portent leur propre preuve (mot de passe, défi, jeton à portée) | `packages/secubox-auth/tests/` |
| § 3 garde | `POST /compte/*`, `/personne/*` (secubox-vault, socket interne) | servent secubox-auth par la socket, refusent la marque du relais web | `packages/secubox-vault/tests/test_compte_1855.py`, `test_personne_connexion_1855.py` |
| § 10 durcissement | unités qui pilotent LXC ou nftables (`User=root` ou capacités) | accès conteneurs / pare-feu ; confinées par `ReadWritePaths`, sudoers exacts, AppArmor | revue au cas par cas |
| § 10 durcissement | unités d'API qui appellent un sudoers à argv EXACT (`secubox-voicestudio-api` : `NoNewPrivileges=no`, `User=secubox` partagé) | sudo est neutralisé par `NoNewPrivileges=yes` ; la seule surface privilégiée est `voicestudioctl api` (JSON sur stdin, actions en liste blanche, audit). Dette nommée : utilisateur dédié `secubox-voicestudio` + sudoers à son nom | `packages/secubox-voicestudio/tests/test_paquet_1917.py`, `test_api_1917.py::test_sudoers_et_argv_sont_identiques` |
