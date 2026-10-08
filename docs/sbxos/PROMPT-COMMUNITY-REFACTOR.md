<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Prompt Claude Code · SBXOS Community Refactor

> Source : Gérald Kerma (Gandalf), 2026-09-27 — versionné tel que fourni (#1509).
> Cadrage de l'auteur : « la bonne base, c'est d'analyser le code d'abord,
> ensuite de l'écrire. Donc une identité portable avec les états utilisateur
> clairs, des communautés nommées et gérables, des permissions par module et une
> aura représentée mais pas recalculée, entre les boxes. »
>
> Suivi : audit [AUDIT-COMMUNITY-REFACTOR.md](AUDIT-COMMUNITY-REFACTOR.md).

---

> Mission : faire évoluer `secubox-deb` en conservant l'architecture existante.
> Réaliser une rétro-ingénierie du code avant toute modification. Ne jamais
> réécrire une fonctionnalité déjà présente, l'étendre uniquement.
> Dépôt de référence : CyberMind.FR · GitHub.

## Principe fondateur

SBXOS repose sur 5 notions distinctes qui ne doivent jamais être mélangées :

| Entité | Nature |
| --- | --- |
| Node | Box physique / matériel |
| User | Identité SBXOS |
| Community | Groupe logique de membres |
| Shared Space | Espace de stockage du Node |
| Activity | Événements système et sociaux |

Le Shared Space appartient au Node, jamais à un utilisateur.
Une Community appartient aux utilisateurs, jamais au matériel.

## Architecture cible

```
                 NODE (SecuBox)
          ┌────────────┴────────────┐
   Shared Space                   Users
  (Nextcloud Node)              (Identités)
          │                         │
     Communities               Mood → Aura
   (Groupes & rôles)        (État émotionnel)
          └──────────┬──────────────┘
                 Hall SBXOS
                     │
              Mesh inter-boxes
```

## 1. Identité portable

Un utilisateur SBXOS doit pouvoir voyager entre plusieurs boxes.

### États d'un utilisateur

- `guest`
- `invitation_requested`
- `invited`
- `member`
- `community_assigned`
- `node_admin`

Les clés, préférences, avatar, historique et permissions personnelles restent
attachés à sa box d'origine et sont transportés via le Mesh.

## 2. Communities

Créer une véritable entité `Community`.

```
Community
 ├── UUID
 ├── Name
 ├── Avatar
 ├── Members[]
 ├── Roles[]
 ├── Permissions
 └── Visibility
```

Une communauté peut être : privée, invitée, publique.

Les groupes existants deviennent des communautés de premier niveau.

## 3. Permissions

Toutes les pages d'administration doivent accepter : User, Community.

Au lieu de `Allow User`, devenir `Allow User` + `Allow Community`.

Modules concernés : BBS, Hall, Nextcloud partagé, Radio, tous les modules SBXOS
disposant déjà d'une ACL.

## 4. Shared Space

Le stockage est séparé en deux couches.

| Stockage | Propriétaire |
| --- | --- |
| Personnel | User |
| Partagé | Node |

Le Shared Space du Node apparaît automatiquement chez tous les membres du Node.
Aucune confusion visuelle avec le stockage privé.

## 5. Activity Engine

Créer un moteur d'activités unifié.

Événements :

```
user_joined
community_joined
file_shared
bbs_post
radio_live
mood_changed
avatar_changed
permission_granted
```

Chaque activité possède : auteur, contexte, visibilité, timestamp, node d'origine.

## 6. Mood devient la source

Le module Mood reste inchangé. Il fournit 6 états émotionnels et 1 état
`indeterminate`.

Créer une nouvelle couche Aura.

```
Mood
   │
   ▼
Aura Engine
   │
   ├── Avatar glow
   ├── Hall
   ├── BBS
   ├── Radio
   └── Activity Feed
```

Aura ne calcule rien. Elle ne fait que représenter l'état fourni par Mood.

## 7. Avatar onboarding

Lors de l'invitation :

1. validation du code existant
2. choix d'un avatar parmi les 32 Zanimalos
3. création de l'identité SBXOS
4. rattachement automatique au Node
5. apparition dans le Hall

Aucun upload obligatoire.

## 8. Livrables attendus

- Audit du code existant
- Diagrammes UML des entités
- Migration SQL si nécessaire
- Refactor ACL User → User + Community
- Intégration Aura avec Mood
- Maquettes Hall mises à jour
- Documentation développeur

## Règle absolue

Analyser le code avant d'écrire du code.

Ne jamais simuler un comportement lorsqu'il existe déjà dans `secubox-deb`.
Toute proposition doit être justifiée par la rétro-ingénierie des sources.

## Contraintes de sécurité permanentes (rappel du projet)

- Ne jamais modifier directement root ou les comptes Linux ; tout passe par
  `user_uuid` et certificats.
- Aucun rôle SBX ne possède de capacité SSH, sudo ou root.
- Ne jamais migrer root, gk2 ou operator dans `sbx_users` ; les comptes système
  (root, admin, gk2, operator) restent invisibles dans SBX OS.
