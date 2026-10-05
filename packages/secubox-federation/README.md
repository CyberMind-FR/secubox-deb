<!-- SPDX-License-Identifier: LicenseRef-CMSD-1.0 -->
# secubox-federation

SecuBox — fédération SBX (GK2) : certificats et adhésion.

Phase 1 de la fédération SBX v2 : autorité de certification GK2, certificat SBX v2 signé Ed25519 (sujet = identité annuaire de la box, canonicalisation identique à secubox-annuaire), demandes d'adhésion signées, renouvellement avec preuve de clé, liste de révocation signée, niveaux d'abonnement configurables (/etc/secubox/federation.yaml).

La box reste autonome : sans fichier de configuration elle est hors fédération, et toute synchronisation est initiée par elle.

Fournit sbx-certd (API sur /run/secubox/federation.sock) et sbxctl.

Paquet Debian : version `0.3.2-1~bookworm1`, architecture `any`.

## Contenu

- `cmd/` : sources Go
- `conf/` : configuration livrée
- `internal/` : fichiers du module
- `nginx/` : route nginx
- `systemd/` : unités systemd
- `vendor/` : fichiers du module

## Exécution

Socket Unix : `/run/secubox/auth.sock`, `/run/secubox/federation.sock`.
- `secubox-federation.service` : SecuBox — fédération SBX (sbx-certd : certificats, adhésion) (utilisateur `secubox`), lance `sbx-certd`

## Dépendances SecuBox

`secubox-core`.
