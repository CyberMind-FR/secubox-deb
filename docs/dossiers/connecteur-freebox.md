<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
-->
# Connecteur Freebox — conception

**But.** Étendre ce que SecuBox sait faire en mode « esclave, non routeur » (un simple appareil du réseau, derrière la Freebox) aux
possibilités de l'**API Freebox OS**. Un seul module, `secubox-freebox`, tient la connexion, son panneau d'administration et un petit
service local que les autres modules interrogent (IPv6 Guardian, NAC, exposition…).

## Décisions du propriétaire (2026-10-08)
Tout, dans cet ordre de prudence : appareils du réseau (lecture) · pare-feu IPv6 et redirections (lecture) · état de la connexion
(lecture) · redirections de ports (écriture).

## Autorisation (une fois)
1. Le panneau envoie une demande d'autorisation (`login/authorize`) ; la Freebox rend un **jeton d'application** et un numéro de suivi.
2. **Le propriétaire valide sur la Freebox** (touche ✓ de l'afficheur). Sans cela, rien n'est accordé.
3. Les **droits** de l'application se règlent sur la Freebox (Paramètres → Gestion des accès → Applications) : lecture des appareils par
   défaut ; « modification des réglages » nécessaire pour les redirections. Le panneau affiche les droits obtenus et dit lesquels manquent.
4. Session : défi HMAC-SHA1 (jeton + défi) → jeton de session, renouvelé automatiquement.

## Sécurité
- Le **jeton d'application ne quitte jamais la box** : `/var/lib/secubox/freebox/app.json`, 0600, utilisateur du module ; aucune route ne
  le rend, aucun journal ne le contient.
- Lecture : `require_lecture`. Autorisation, révocation et **toute écriture** : `require_jwt` (administrateur).
- Écriture (redirections) : confirmation explicite, simulation (`dry_run`) par défaut, **chaque décision journalisée** dans
  `/var/log/secubox/audit.log` (append-only). Jamais d'ouverture « tous ports » ; le panneau avertit des ports sensibles.
- Rien n'est envoyé hors de la box ; la Freebox est jointe en HTTP sur le réseau local (`mafreebox.freebox.fr`).

## API locale (socket `/run/secubox/freebox.sock`)
`GET /status` · `POST /autoriser` · `GET /autoriser/etat` · `POST /revoquer` · `GET /appareils` · `GET /connexion` ·
`GET /pare-feu` · `GET /redirections` · `POST /redirections` · `DELETE /redirections/{id}`.

## Phases
- **v0.1** : autorisation, droits, appareils, connexion, pare-feu (lecture), panneau.
- **v0.2** : redirections (lecture puis écriture confirmée et journalisée).
- **Intégrations** : IPv6 Guardian (étapes « bloquées » / « exceptions », noms réels), NAC (noms), exposition (ouvrir 80/443 pour un site).
