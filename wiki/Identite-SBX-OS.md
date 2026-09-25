<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# 🪪 Identité SBX OS

SecuBox distingue deux mondes :

- **SecuBox System** — les comptes techniques (root, admin, gk2, operator,
  services). Ils administrent la box ; ils n'apparaissent jamais dans SBX OS.
- **SBX OS** — les **personnes** : un `user_uuid`, un pseudo, des rôles
  (invité, membre, abonné, bêta-testeur, modérateur, opérateur SBX) qui sont des
  profils de capacités. **Aucun rôle SBX ne donne SSH, sudo ni root.**

L'exploitant de la box y est **gandalf** (opérateur SBX + modérateur).

## Une personne, ses appareils

Une personne se prouve par ses **appareils** : chacun porte une clé P-256 non
exportable, gardée par le navigateur *par origine* — d'où le gestionnaire servi
par le Hall (`https://hall.<nœud>/identite/`). Un appareil qui se présente fait
une **demande d'accès** ; l'administration l'accepte (nouvelle personne, ou
**rattaché** à une personne existante) ou la refuse. Chaque appareil affiche le
navigateur et le système de sa dernière session ; le révoquer coupe ses
sessions.

Une session ouverte **par mot de passe** (sans appareil) désigne la personne
unique propriétaire des appareils acceptés pour ce compte — la session gk2 est
gandalf.

## Ses comptes de services

Depuis l'Administration SBX OS (ou le menu admin « Identité SBX OS ») :

| Geste | Effet |
|---|---|
| **Ouvrir** courriel / Nextcloud / PeerTube | comptes créés au nom de la personne, **un seul mot de passe de services**, affiché une fois |
| **Relier** un compte existant | vérifié dans le service, jamais recréé ; il garde **son** mot de passe |
| **Réinitialiser** | nouveau mot de passe dans tous les services ouverts d'ici — une seule réinitialisation rend l'accès à tout |
| **Lier le BBS** | son compte BBS s'ouvre **sans mot de passe** depuis le Hall (connexion passive) |

Nextcloud et PeerTube dorment quand on ne s'en sert pas : l'ouverture d'un
compte les réveille et les tient éveillés le temps du travail.

La personne retrouve ses comptes dans la carte **🗝️ Mes comptes** du Hall.

## Où administrer

| Écran | Contenu |
|---|---|
| Hall → `/identite/#admin` | demandes, personnes (rôles, statut, comptes), journal, rôles → capacités |
| Admin → Utilisateurs | comptes système · **Personnes SBX OS** · **Demandes** (la même file) · sessions nommées « personne · appareil » |

Voir aussi : `docs/AUTH_V2.md`, `docs/AUTH_V3.md`, [[Messagerie]].
