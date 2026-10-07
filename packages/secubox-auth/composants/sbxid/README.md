<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# 🪪 secubox-sbxid — SBX Identity Manager

L'identité **SBX OS** : une personne (`user_uuid`), prouvée par ses appareils
(clé P-256 non exportable), des rôles qui sont des profils de capacités —
**jamais** SSH, sudo ni root. Les comptes système (root, admin, gk2, operator)
n'y apparaissent jamais ; l'exploitant y est **gandalf**.

Absorbe `secubox-acces` (admission des appareils, défi signé, sessions).

## Où

| Quoi | Adresse |
|---|---|
| Gestionnaire (utilisateur + Administration) | `https://hall.<nœud>/identite/` — servi par le Hall, l'origine où vivent les clés d'appareil |
| Entrée du menu admin | `https://admin.<nœud>/sbxid/` → redirige vers `/identite/#admin` |
| API | `/api/v1/sbxid/` (agrégateur) ; `/api/v1/sbxid/admin/` réservé au LAN sur le Hall |

## Ce qu'on y fait

- **Mon identité**, **Mes appareils** (renommer, révoquer, certificat à double
  signature appareil + nœud), navigateur et système de la dernière session.
- **Administration SBX OS** : demandes d'accès (accepter, rattacher à une
  personne existante, refuser), personnes (rôles, statut), journal, matrice
  rôles → capacités.
- **Personnes sans appareil** : créées par l'administration ; leur premier
  appareil leur est rattaché à l'admission.
- **Comptes de services** d'une personne (courriel, Nextcloud, PeerTube) :
  - *ouvrir* — créés par le helper root de secubox-users, **un seul mot de
    passe de services**, rendu une fois, réinitialisable d'un geste partout ;
  - *relier un compte existant* — vérifié, jamais recréé, il garde **son**
    mot de passe ; un nom système ne se relie qu'à l'exploitant.
  - Un module endormi (on-demand) est réveillé et tenu le temps de l'action ;
    l'écran relit le résultat (la requête peut dépasser les 30 s d'HAProxy).
- **BBS lié** : connexion passive — `/auth/verify` rend `Remote-Sbx-Bbs`, le
  BBS ouvre ce compte avec la session du Hall.

## API (extraits)

| Méthode | Chemin | Rôle |
|---|---|---|
| GET | `/moi` | identité, appareils (agent, IP), connexions liées |
| GET | `/admin/personnes` · POST idem | lister (avec comptes liés) · créer |
| GET | `/admin/appareils` | `sbx-<empreinte>` → personne, appareil, agent |
| GET/POST | `/admin/demandes` · `/{did}/accepter` (`personne`) · `/refuser` | file unique d'admission |
| GET/POST | `/admin/personnes/{uuid}/comptes` · `/comptes/reinitialiser` · `/comptes/travail` | comptes de services (travail en arrière-plan) |
| POST | `/admin/personnes/{uuid}/lier` (`app`, `ident`) · `/bbs` | relier un compte existant |
| DELETE | `/admin/personnes/{uuid}/liens/{app}/{ident}` | délier |

Documentation : `docs/AUTH_V2.md`, `docs/AUTH_V3.md`, wiki [[Identite-SBX-OS]].
