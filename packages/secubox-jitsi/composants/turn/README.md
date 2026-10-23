<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# 🔄 TURN / STUN (composant de `secubox-jitsi`)

Relais TURN/STUN (coturn) pour WebRTC : état, relais en cours, identifiants temporaires, utilisateurs long terme.
Page `/turn/` (profil Aurora), API `/api/v1/turn/`.

## Qui fait quoi (#3060)

- **`secubox-turn.service`** — l'API FastAPI, utilisateur `secubox`, socket `/run/secubox/turn.sock`. Elle ne touche
  **ni** coturn, **ni** systemd, **ni** `/etc/turnserver.conf` (root:turnserver 0640) : elle valide les entrées et
  délègue par `sudo -n /usr/sbin/secubox-turnctl <verbe exact>` (sudoers `secubox-turn`, mot de passe d'un utilisateur
  par stdin, jamais en argument).
- **`secubox-turnctl`** — l'actionneur root, la seule surface privilégiée. Verbes (JSON sur stdout) : `status`,
  `start|stop|restart|enable`, `generer [realm]`, `secret-renouveler`, `credentials <nom> <ttl>`, `users`,
  `user-add <nom>` (stdin), `user-del <nom>`, `sessions`, `journal [n]`, `config` (secret masqué). Chaque décision est
  écrite dans `/var/log/secubox/audit.log`.
- **coturn** — `coturn.service` (Debian), configuration **générée** par le ctl : `/etc/turnserver.conf` commence par
  `# SecuBox` ; le realm vient de `/etc/secubox/turn.toml` (`realm = "turn.<domaine de la box>"` par défaut,
  `secubox-domaine turn`), le secret partagé de `/etc/secubox/secrets/turn/static-auth-secret` (root 0600, généré au
  premier besoin). Écriture en double tampon : ombre `.sbx-nouveau` → bascule atomique (l'ancienne en `.avant`) → coturn
  relancé → `is-active` → sinon retour arrière sur la précédente.

## Configuration générée

`listening-port=3478`, `lt-cred-mech` + `use-auth-secret` (identifiants temporaires TURN REST **et** utilisateurs long
terme de la base `/var/lib/turn/turndb`), `fingerprint`, `no-cli`, `no-multicast-peers`, `no-rfc5780`, relais refusé vers
la boucle locale et le lien local, journal `/var/log/turnserver/turnserver.log` (`simple-log`), ports relais 49152-65535.
**TLS** (`tls-listening-port=5349`) seulement si un certificat du realm existe (`/etc/haproxy/certs/<realm>.pem` ou
`/etc/secubox/certs/<realm>/fullchain.pem`) ; sinon `no-tls`/`no-dtls` plutôt qu'un écouteur en échec. Pas de
`listening-ip` : toutes les adresses, l'exposition reste la décision de nftables (DEFAULT DROP).

Le postinst génère cette configuration si celle en place n'est pas SecuBox (Debian par défaut, ou éditée à la main) ;
une configuration SecuBox existante n'est pas réécrite (« Régénérer » dans le panneau, ou `secubox-turnctl generer`).

## API

| Route | Garde | Fait |
|---|---|---|
| `GET /status`, `/stats`, `/sessions`, `/users`, `/realm`, `/access`, `/components`, `/logs`, `/config` | `require_jwt` | lecture par le ctl ; `/config` renvoie le texte avec le secret masqué |
| `POST /start`, `/stop`, `/restart` | `require_jwt` | `systemctl … coturn` par le ctl |
| `POST /generer` | `require_jwt` | configuration régénérée (double tampon, retour arrière) |
| `POST /realm {realm}` | `require_jwt` | realm appliqué = régénération ; `secret` ignoré (généré côté serveur) |
| `POST /generate_secret` | `require_jwt` | nouveau secret partagé, appliqué aussitôt ; jamais renvoyé |
| `POST /credentials {username, ttl}`, `GET /credentials` | `require_jwt` | identifiants TURN REST (HMAC-SHA1 imposé par le protocole) |
| `POST /users {username, password}`, `DELETE /users/{nom}` | `require_jwt` | base de coturn (`turnadmin`) |
| `POST /config` | `require_jwt` | **409** : configuration générée, pas d'édition à la main |
| `GET /health` | public | `{status: ok}` |

## Tests

`packages/secubox-jitsi/tests/test_turn_ctl_3060.py` : ctl (`bash -n`, shellcheck, verbes, double tampon, secret hors
argv, HMAC), sudoers exacts, unité sans `NoNewPrivileges` ni accès à `turnserver.conf`, API sans `systemctl`/`turnadmin`
directs et répondant par le ctl (TestClient), paquet (rules, control, postinst), panneau (lecture seule + régénération).

## Licence

LicenseRef-CMSD-1.0 (Source-Disclosed License) — CyberMind © 2024-2026.
