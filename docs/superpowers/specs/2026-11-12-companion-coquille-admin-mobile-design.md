<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Companion 2.0 — coquille Android de l'admin mobile, associée à sa box — conception

**Date :** 2026-11-12 · **Issue :** #3683 · **Statut :** à valider par le propriétaire
**Remplace en partie :** `2026-07-30-companion-qr-and-wireguard-design.md` (l'appairage par QR y reste une piste, cf. § 7).

## 1. Intention

Le propriétaire veut que **le même APK**, servi par n'importe quelle box (exemple : gk12), **retrouve la box qui l'a servi**
et permette de **la piloter**. Aujourd'hui la Companion (Capacitor 6, `in.secubox.companion` 1.4, servie à la main sur gk2
seulement) a ses propres écrans : modules absents de gk12 (PhotoPrism, Torrent, Jellyfin, YouTube), liens `*.gk2` en dur,
adresse de la box à taper au premier lancement.

Décision du propriétaire : l'appli devient **une coquille de l'admin de la box, dans le rendu du profil mobile**, parce que
c'est l'interface la plus testée (bêta 1, menu tactile, pages à 420 px sans débordement, menu limité aux modules installés et
actifs). Des **comportements embarqués** (natifs) viendront ensuite, **choisis selon le profil** de la box.

## 2. Buts, non-buts, anti-buts

**Buts**
- Un seul APK pour toutes les box ; chaque box le sert elle-même avec sa page de téléchargement.
- Depuis la page de la box, l'appli s'ouvre **déjà réglée sur cette box** : rien à taper.
- L'appli affiche l'admin de la box tel que la box le sert (menu, pages, gardes) ; tout pilotage passe par l'API de la box
  (gardes `require_*`, journal d'audit), exactement comme depuis un navigateur.
- Changer de box associée reste possible (box remplacée, plusieurs box).

**Non-buts (v1)**
- Pas d'écrans propres à l'appli (les vues `www/modules/*` de la Companion 1.x disparaissent).
- Pas de Play Store, pas d'app iOS native (iPhone : l'admin reste utilisable en appli web installable).
- Pas de tunnel WireGuard ni de nouvelle exposition : l'appli joint la box là où son adresse est déjà joignable
  (gk2 : partout, derrière HAProxy → sbxwaf ; gk12 sans nom public : depuis son réseau seulement).
- Pas de jeton d'appareil longue durée ni de nouveau mode d'authentification.

**Anti-buts (échec même si « ça marche »)**
- Une interface parallèle qui diverge de l'admin (double maintenance, écarts de garde).
- Un contournement du WAF, de l'authentification ou de la 2FA de la box.
- Une découverte automatique « de la box du réseau » : sur un réseau hostile, l'appli s'associerait à une fausse box.
- Un pont natif (plugins Capacitor) offert à une page distante en v1.

## 3. Parcours

1. Sur le téléphone, la personne ouvre `https://admin.<box>/companion/` (page de la box, en HTTPS, authentifiée par le
   certificat de la box ; page accessible sans connexion, elle ne contient rien de secret).
2. « Télécharger l'appli » → APK servi par la box → installation (sources inconnues autorisées une fois).
3. Retour sur la page → « Ouvrir dans l'appli » → lien `secubox://associer?box=https%3A%2F%2Fadmin.<box>` →
   l'appli demande « Associer cette appli à admin.<box> ? » → oui → l'adresse est enregistrée.
4. L'appli charge `https://admin.<box>/` : la personne se connecte avec **la page de connexion habituelle de la box**
   (mot de passe, 2FA) ; la session vit dans le stockage du WebView comme dans un navigateur (`sbx_token`, cookie SSO).
5. Lancements suivants : l'appli rouvre directement l'admin de la box associée.
6. La même page affiche un **QR code** du lien de l'étape 3 (lisible par l'appareil photo d'un autre téléphone).

Premier lancement sans lien (APK reçu autrement) : écran local « Associer une box » → champ d'adresse (https seulement) +
explication « ouvrez la page /companion/ de votre box ».

## 4. Ce qui est décidé

**Côté box — paquet `secubox-companion` (arch all, nouveau)**
- Installe l'APK (fichier construit hors box, cf. § 5) et la page `/companion/` (profil Aurora, `?embed=1`, 420 px) :
  version de l'APK, empreinte SHA-256, bouton « Télécharger », bouton « Ouvrir dans l'appli », QR du lien d'association.
  Le lien porte l'adresse canonique de l'admin de la box (`secubox-domaine admin` ou équivalent du dépôt), jamais une
  valeur en dur.
- `/companion/version.json` (version, empreinte, taille) lu par l'appli pour proposer les mises à jour.
- Servi par le vhost admin existant (aucun nouveau vhost, aucune nouvelle route WAF) ; entrée de menu et place dans les
  profils (au moins `mobile` et `full`).
- Le déploiement manuel actuel de gk2 (`/data/companion/www`, vhost `companion.gk2`) est retiré au profit du paquet ;
  l'ancienne URL de l'APK redirige vers `/companion/` pendant une période de transition.

**Côté appli — Companion 2.0 (`in.secubox.companion`, versionName 2.0)**
- Reste Capacitor 6 (la recette de construction de cette machine fonctionne, cf. mémoire projet).
- Coquille : écran local d'association, écran local « box injoignable » (réessayer, changer de box), puis chargement de
  l'admin distant dans le WebView.
- Navigation limitée à l'origine associée ; tout autre lien (sous-domaines de services, sites tiers) s'ouvre dans le
  navigateur du téléphone.
- Lien profond `secubox://associer?box=<url>` : https obligatoire, pas d'identifiant ni de chemin hors `/`, confirmation
  explicite affichant le nom d'hôte ; le lien ne transporte **aucun secret**.
- Le WebView ajoute `SecuBoxCompanion/2.0` à son User-Agent : la box peut forcer le rendu tactile mobile (même sur
  tablette) et, plus tard, adapter les comportements embarqués.
- Les vues `www/modules/*`, le coffre à PIN et la file hors ligne de la 1.x sont retirés (la session est celle de la box).
- Pas de pont natif exposé à l'origine distante en v1.

## 5. Construction et signature

- L'APK actuel est signé avec la clé de **débogage** de ce poste. La 2.0 passe à une **clé de publication dédiée**, générée
  une fois, conservée hors du dépôt (secrets du propriétaire, sauvegardée) ; les installations 1.x devront être
  désinstallées une fois (changement de clé). *(Choix de Claude, à confirmer.)*
- L'APK est construit sur le poste de développement (recette existante), puis déposé dans le paquet `secubox-companion`
  à la construction de celui-ci ; le paquet ne compile rien.

## 5 bis. Réponses établies à la relecture « constructeur » (2026-11-12)

- **Certificats** : chaque box a un certificat Let's Encrypt valide (`*.gk6.secubox.in`, `*.gk7.secubox.in` — joker par
  box ; `admin.gk2.secubox.in` nominatif). Aucune autorité privée ni épinglage à prévoir. Sur le réseau d'une box, le
  téléphone résout `admin.<box>` par la box, qui est le seul DNS du réseau (à vérifier au banc pour chaque box).
- **Page sans connexion** : les pages de l'admin sont statiques et servies sans garde nginx ; la garde est dans l'API
  (JWT). `/companion/` ne demande donc ni exemption ni nouvelle route WAF. Type MIME de l'APK à déclarer
  (`application/vnd.android.package-archive`) ; taille ≈ 4 Mo.
- **Rendu mobile** : `sidebar.js` passe déjà en mode tactile sur `(hover: none) and (pointer: coarse)`, ce qu'un
  WebView de téléphone vérifie : rien à forcer en v1. Le marqueur `SecuBoxCompanion/2.0` du User-Agent reste un simple
  identifiant pour le profilage futur, sans effet en v1.
- **Origine de l'APK au build du paquet** *(choix de Claude)* : APK jamais commité (`dist/` est ignoré) ; le build du
  paquet attend `secubox-companion/dist/secubox-companion-<version>.apk` et échoue s'il manque ; l'empreinte de
  `version.json` est calculée au build depuis ce fichier.
- **Mises à jour** *(choix de Claude)* : l'écran local lit `https://<box associée>/companion/version.json` au lancement ;
  si la version est plus récente, il propose d'ouvrir `/companion/` dans le navigateur du téléphone. Pas
  d'installation par l'appli (ni `REQUEST_INSTALL_PACKAGES` ni pont natif).
- Version de l'appli : `versionName` 2.0, `versionCode` > 6 (le source est en 1.5/6, la version publiée en 1.4).

## 6. Laissé au constructeur

Mécanisme exact de restriction de navigation et de non-exposition du pont Capacitor ; écrans locaux (charte Aurora) ;
génération du QR (JS embarqué, sans CDN) ; emplacement de l'APK dans l'arbre du paquet ; tests (Playwright pour la page,
tests unitaires de l'analyse du lien profond, essai réel sur un téléphone).

## 7. Après la v1 (hors périmètre, pour mémoire)

- **Comportements embarqués profilés** : selon le profil de la box (`mobile`, `full`…) — lecture de QR à la caméra,
  notifications, télécommande du kiosque (#1004), tunnel WireGuard intégré (#2351 niveau 2).
- **Association en un geste avec code à usage unique** émis par la box pour une personne déjà connectée (évite de
  ressaisir le mot de passe) : nouvelle surface d'authentification, à concevoir à part.
- Joindre gk12 hors de chez elle : nom public derrière son WAF, ou tunnel.

## 8. Essais

Banc : gk6 (maître de test), puis gk12 à son retour en ligne ; gk2 en dernier. Vérifier : la page `/companion/` sert le bon
lien et la bonne empreinte ; l'appli s'ouvre réglée sur la box ; connexion avec 2FA ; menu = modules de la box ; un lien vers
un service ou un site tiers sort vers le navigateur ; box éteinte → écran « injoignable » ; mise à jour proposée quand
`version.json` change.
