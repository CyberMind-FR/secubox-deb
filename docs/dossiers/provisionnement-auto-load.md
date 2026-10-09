<!-- SPDX-License-Identifier: LicenseRef-CMSD-1.0 -->
<!-- Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr> -->
# Provisionnement réseau « Auto-Load » : cadrage (#2183, parent #2182)

Ce document ne code rien. Il fixe les décisions qui débloquent les volets #2184 à #2193, le modèle de menace, et les points qui demandent l'avis du propriétaire.

## 1. But et principes

Une box neuve, branchée chez un client sans intervention technique, récupère son profil, installe ses paquets depuis le dépôt signé `apt.secubox.in`, ouvre un tunnel WireGuard **sortant** vers `admin.gk2.secubox.in`, se déclare, puis produit un rapport.

- La certification CSPN est une **précaution, pas une contrainte** : aucune fonction n'est restreinte pour elle. Restent les pratiques du dépôt : aucun secret versionné (`/etc/secubox/secrets/`), journal d'audit append-only, un utilisateur dédié par service, jamais de port entrant côté client.
- Auto-Load n'est **pas un méta-paquet de plus** (il existe `lite`, `isp`, `full` et le profil « provision »). C'est un mécanisme qui choisit un de ces profils et l'applique.
- Deux modes : **one-shot** (atelier, déclenché à la main) et **automatique** (zero-touch).
- Le jeton client porte un **statut d'abonnement** (actif, suspendu, révoqué). La facturation est hors périmètre.

## 2. Ce qui existe et qu'on réutilise

| Besoin | Brique existante | Ce qu'elle fait déjà |
|---|---|---|
| Fichier de réponses | `secubox-premier-pas` (`profil.toml`, `premier-pasctl examiner`, face « silencieuse ») | Profil TOML complet = la box s'applique seule, incomplet = l'assistant s'ouvre à l'étape qui manque. Sections `[box]`, `[admin]`, `[reseau]`, `[services]` (profil), `[maillage]` (jeton `sbx-mesh-invite`), `[apt]` |
| Choix et application d'un profil | `secubox-profiles` (`profilectl export --format pkglist`, `apply`, `rollback`) | Liste de paquets, application avec snapshots 4R et audit |
| Démarrage réseau | `secubox-netboot` (B0 local, B1 TFTP, B2 HTTP `boot.fit` signé, B3 installateur) | Signature FIT vérifiée par `bootm`, garde-fou anti-brique (`bootcount`/`altbootcmd`) |
| Tunnel et maillage | `secubox-p2p` (`sbx-mesh-invite/join/up`, `wg-mesh` 10.10.0.0/24 udp/51822, `wg-ephemeral` 10.11.0.0/24 udp/51825), annuaire (Gondwana) | Invitation à durée courte, rejoindre une box maîtresse, déclaration d'un nœud |
| Dépôt | `apt.secubox.in` sur gk2, clé de signature gérée par `secubox-depot-deverrouille.service` | Index signé, `secubox-majauto` (mises à jour nocturnes des seuls paquets SecuBox) |
| Courrier | relais mail de la box | Envoi du rapport |

**Conséquence :** le fichier de réponses n'est pas un nouveau format. C'est le `profil.toml` de premier-pas, étendu d'une section `[provision]`.

## 3. Décisions proposées

**D1 — Fichier de réponses = `profil.toml` étendu (TOML).** Une section `[provision]` porte le jeton (par référence), l'identifiant du lot et le mode. La validation stricte (champs inconnus refusés) et l'examen pas à pas de premier-pas sont réutilisés. Les mots de passe restent des empreintes argon2 ou `"demander"`, jamais en clair. Les clés et jetons générés vont dans `/etc/secubox/secrets/` et le fichier ne contient qu'une référence.

**D2 — Signature du fichier de réponses.** Signature détachée OpenPGP par une clé « SecuBox Provisioning » **distincte** de la clé du dépôt apt, dont la partie publique est embarquée dans l'image minimale (et vérifiée par la signature FIT en netboot). Une box refuse un fichier non signé ou dont la signature ne correspond pas. Le détail de l'outil est tranché dans #2184.

**D3 — Deux étapes d'amorçage, pas une.** Constat : l'U-Boot d'usine du MOCHAbin (2020.10) n'a pas `wget`, et le netboot HTTP exige donc le chargement en mémoire d'un overlay Tow-Boot signé (déjà conçu dans `secubox-netboot`), et l'essai sur ESPRESSObin est actuellement KO (#2177). Un « netboot pur, sans aucune préparation » n'est donc pas livrable aujourd'hui.
- **Phase A (livrable d'abord)** : la box part d'une **image préinstallée** en atelier ou chez le fabricant (image `lite` actuelle + agent `secubox-autoload-agent`). Au premier démarrage l'agent appelle l'infrastructure. C'est du plug-and-play pour le client.
- **Phase B (ensuite)** : netboot HTTP signé (niveaux B2/B3) pour les cartes qui ont l'overlay. Dépend du banc matériel (#2186, #2177).

**D4 — Jeton : un par box.** 128 bits aléatoires, stocké **haché** côté infrastructure, à usage unique pour l'enrôlement. Un « lot » est un groupe de jetons, pas un jeton partagé. États : `émis` → `réclamé` (jeton consommé) → `révoqué`. Durée de vie avant réclamation : 90 jours, configurable. À la réclamation, la box reçoit son identité durable : une **clé WireGuard propre** enregistrée dans l'annuaire. Le jeton ne sert plus ensuite. Le **statut d'abonnement** est porté par le compte client et lu à chaque (ré)enrôlement et à chaque livraison de profil.

**D5 — Que fait la box sans jeton ?** Elle ne contacte pas l'infrastructure et reste en parcours local (assistant de premier-pas). Un client « déjà pré-évalué » est un client dont le **numéro de série ou la MAC** a été préenregistré avec un profil : la box s'identifie alors par son numéro de série et reçoit un jeton à la volée.

**D6 — Zero-touch : pré-rapport et délai de grâce.** Avant d'appliquer, l'agent produit un **pré-rapport** (paquets à installer, paramètres réseau, comptes créés par nom, références de secrets générés, jamais leur valeur), le signe avec la clé de la box et l'envoie à l'infrastructure. En l'absence d'utilisateur, il s'applique après un **délai de grâce** configurable (par défaut 15 minutes), pendant lequel l'opérateur peut refuser. Le profil appliqué est celui que le jeton désigne : on ne restreint pas la fonction pour une raison de certification.

**D7 — Canal.** Inscription par HTTPS sur `admin.gk2.secubox.in` (HAProxy → `sbxwaf`, route déclarée par le paquet avec `secubox-waf-route`), puis tunnel WireGuard sortant. Première version : **étoile** (les clients se connectent à l'infrastructure), plage dédiée distincte de `wg-mesh`, `wg-ephemeral` et des autres. L'intégration progressive au maillage MirrorNet vient ensuite. Aucune règle nftables entrante côté client ; l'infrastructure ouvre un seul port UDP.

**D8 — Deux paquets, pour ne pas confondre avec le profil « provision ».**
- `secubox-autoload` : le côté infrastructure (jetons, registre des box, panel, WebUI des load profiles). Tourne sur gk2 derrière `admin.gk2.secubox.in`.
- `secubox-autoload-agent` : le côté box (enrôlement, pré-rapport, application, rapport). **Verrouillé** comme `core`, `auth` et `aggregator` : non désinstallable depuis le panneau, car sans lui la box perd son canal d'administration.

**D9 — Cibles matérielles.** Phase A : toutes les cartes qui démarrent l'image SecuBox (MOCHAbin, ESPRESSObin, gk3 amd64, c3box, etc.). Phase B (netboot) : cartes Marvell Armada (MOCHAbin, ESPRESSObin v7/Ultra) d'abord.

## 4. Modèle de menace

| Menace | Effet | Parade |
|---|---|---|
| Jeton volé avant l'usage | Un tiers enrôle sa propre box à la place du client | Usage unique, durée de vie courte avant réclamation, alerte à la réclamation, révocation immédiate |
| Rejeu d'un jeton réclamé | Enrôlement d'une copie | Jeton consommé à la première réclamation ; clé WireGuard propre à la box ensuite |
| Énumération et force brute du point d'enrôlement | Découverte de jetons valides | 128 bits, limitation de débit, `sbxwaf` en frontal, aucune différence de réponse entre « inconnu » et « expiré » |
| Fichier de réponses falsifié | Comptes ou profil imposés | Signature détachée obligatoire (D2), validateur strict (D1) |
| Dépôt apt détourné | Paquets malveillants | Index signé, clé de signature protégée (niveau 0, #1366) |
| Box clonée (image copiée) | Deux box, une identité | Clé WireGuard générée sur la box à la réclamation, jamais dans l'image |
| Infrastructure compromise | Prise en main de toute la flotte | Cloisonnement du module `secubox-autoload` (utilisateur dédié, AppArmor enforce), clés de signature hors de la machine d'exposition, journal d'audit append-only, révocation de masse |
| Délai de grâce abusé ou ignoré | Application non voulue | Pré-rapport signé et conservé, refus possible avant application, rollback 4R après |
| Secrets exposés dans le rapport | Fuite par email | Le rapport ne contient que des références, jamais de valeur |

## 5. Ordre de réalisation

1. #2183 (ce dossier) — débloque tout.
2. #2184 (fichier de réponses) et #2185 (jetons) en parallèle.
3. #2187 (moteur) et #2188 (validation) ; #2189 (tunnel) en parallèle.
4. #2190 (panel infra) et #2191 (WebUI) puis #2192 (rapport).
5. #2193 (banc de bout en bout) clôt la **phase A**.
6. #2186 (netboot) est la **phase B**, dépend du matériel (#2177).

## 6. Points à trancher par le propriétaire

1. **Phase A d'abord** (image préinstallée + agent) puis netboot, comme en D3 : accord ?
2. **Suspension d'abonnement** : arrête-t-elle seulement les nouvelles livraisons et l'admission au maillage (proposé), ou aussi des fonctions locales de la box ? Je recommande de ne **jamais** couper une fonction locale à distance.
3. **Délai de grâce** zero-touch de 15 minutes : valeur acceptable ?
4. **Plage du tunnel** des clients et **port UDP** sur `admin.gk2.secubox.in` : à choisir parmi les plages libres (celles de `wg-mesh` 10.10.0.0/24 et `wg-ephemeral` 10.11.0.0/24 sont prises).
5. **Clé « SecuBox Provisioning »** : où elle est tenue (hors ligne, ou sur gk2 avec la même protection de niveau 0 que la clé apt).
