<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# 💬 secubox-messagerie — la messagerie de la box

Un **mur public** et des **messages privés**, servis par le Hall
(`https://hall.<nœud>/messagerie/`, carte « Messagerie »).

- **Qui écrit** : la personne SBX OS de la session (pseudo), sinon un visiteur
  avec un pseudo — publié d'emblée, modéré ensuite (`bbs.moderate`), plafond
  de 10 messages/heure par adresse, pseudos de la box réservés.
- **À qui** : à tous, ou à une personne ; on répond en privé ou publiquement.
- **Centralisée** : le chat de la radio et les commentaires des Billets
  apparaissent dans le mur ; y répondre publie **à la source** (un message vit
  à un seul endroit). Les messages privés du BBS sont repris dans « Privés »
  (lecture seule de sa base) ; un compte BBS lié s'affiche sous le pseudo de sa
  personne (gk2 → gandalf).
- **Garde** : en-tête d'intention `X-Sbx-Messagerie` sur toute écriture ;
  référence visiteur = empreinte du cookie ; noms système jamais affichés.

## API — `/api/v1/messagerie/`

| Méthode | Chemin | Rôle |
|---|---|---|
| GET | `/fil` | mur (local + radio + Billets) |
| GET | `/prives` | messages privés de la session (+ reprise BBS) |
| GET | `/annuaire` | personnes SBX OS à qui écrire |
| POST | `/messages` | écrire (`corps`, `destinataire`, `parent`, `public`, `pseudo`) |
| DELETE | `/messages/{id}` | retirer (auteur ou modération) |

Base : `/var/lib/secubox/messagerie/messages.db` (SQLite WAL).
