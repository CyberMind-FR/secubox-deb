<!-- SPDX-License-Identifier: LicenseRef-CMSD-1.0 -->
# secubox-smb (composant de secubox-media)

SecuBox — partage SMB servi par le noyau (ksmbd).

Expose les supports USB montés (/media/secubox-media) et /data en SMB3, cantonné au réseau local par nftables, sans accès invité.

ksmbd sert les fichiers depuis l'espace noyau : pas d'aller-retour vers un processus utilisateur à chaque lecture, contrairement à smbd.

Composant absorbé par `secubox-media` (#2050) ; panneau de gestion depuis 1.9.0 (#3000).

## Contenu

- `avahi/` : annonce `_smb._tcp` sur le LAN
- `etc/ksmbd.conf` : configuration (SMB3 seul, signature obligatoire, aucun invité, écoute LAN) + bloc AUTO-SHARES
- `nft/zz-secubox-smb.nft` : port 445 ouvert depuis le LAN seulement
- `sbin/smbctl` : seule surface privilégiée (JSON), appelée par l'API en `sudo -n`

## LAN du mode routeur (1.9.4, #3206)

ksmbd écoute `eth2 br-lan` (une interface absente est ignorée par le noyau jusqu'à son apparition) et la table
`secubox_smb` accepte le 445 depuis `br-lan` avant le refus ; les ports isolés restent refusés. `ksmbd.conf` étant
modifié en place par smbctl, le postinst ne migre que l'ancien défaut exact `interfaces = eth2`. Le `.nft` se recharge
de façon idempotente (création puis suppression de la table).

## smbctl

| Commande | Effet |
|---|---|
| `status` | module noyau, service, écoute 445, comptes, `usable`, section `global` (`netbios`, `interfaces`, `min_protocol`), racines partageables, partages (`auto` = généré, `users` = `valid users`) |
| `users` | comptes SMB déclarés |
| `user-add <nom>` | crée ou remplace le mot de passe, **lu sur stdin** (jamais en argument) |
| `user-del <nom>` | retire un compte |
| `share-add <nom> <chemin> [--ro\|--rw] [--users a,b] [--comment t]` | partage manuel : nom `[A-Za-z0-9][A-Za-z0-9._-]{0,39}`, chemin réel (liens résolus) sous `SECUBOX_SMB_ROOTS` (`/data:/media:/srv:/mnt:/home`), comptes existants ; `ksmbd.addshare` écrit hors du bloc généré |
| `share-del <nom>` | retire un partage manuel ; un partage généré se retire en démontant le support puis `sync-shares` |
| `sync-shares` | un partage par support réellement monté (ksmbd ne traverse pas les points de montage) |
| `reload` | recharge ksmbd |

Chaque décision (partage créé/modifié/retiré, compte créé/modifié/retiré) écrit une ligne JSON dans `/var/log/secubox/audit.log`, sans secret.

## API (secubox-media, `/api/v1/media/smb/*`, jeton d'administrateur requis)

- `GET /smb/status`, `GET /smb/users`
- `POST /smb/users` `{user, password}` (mot de passe transmis sur l'entrée standard du ctl), `POST /smb/users/delete` `{user}`
- `POST /smb/shares` `{name, path, readonly=true, users=[], comment=""}`, `POST /smb/shares/delete` `{name}`
- `POST /smb/sync-shares`, `POST /smb/reload`

Un refus du ctl renvoie 400 avec le motif. Panneau : `/media/smb.html` (`?demo=1`, `?embed=1`).
