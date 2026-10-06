<!-- SPDX-License-Identifier: LicenseRef-CMSD-1.0 -->
# secubox-smb

SecuBox — partage SMB servi par le noyau (ksmbd).

Expose les supports USB montes (/media/secubox-media) et /data en SMB3, cantonne au reseau local par nftables, sans acces invite.

ksmbd sert les fichiers depuis l'espace noyau : pas d'aller-retour vers un processus utilisateur a chaque lecture, contrairement a smbd.

Paquet Debian : version `1.1.0-1~bookworm1`, architecture `all`.

## Contenu

- `avahi/` : fichiers du module
- `etc/` : fichiers du module
- `nft/` : fichiers du module
- `sbin/` : exécutables

## Exécution

- `secubox-smb.service`
