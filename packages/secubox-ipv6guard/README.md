<!-- SPDX-License-Identifier: LicenseRef-CMSD-1.0 -->
# secubox-ipv6guard

Phase 1 de l'IPv6 Guardian (conception : `docs/dossiers/ipv6-guardian.md`).

API lecture seule sur `/run/secubox/ipv6guard.sock` : `GET /status` (verdict, quatre étapes, appareils), `GET /appareils`, `GET /health`.
Sources passives : `ip -6/-4 neigh` et `avahi-browse` ; aucune émission vers les appareils, aucune adresse MAC complète dans les réponses.

Phase 2 : lecture du pare-feu IPv6 de la Freebox (API v16, autorisation unique).
