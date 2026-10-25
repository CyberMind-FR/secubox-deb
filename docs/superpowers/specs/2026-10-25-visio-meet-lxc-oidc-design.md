<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Visio : La Suite Meet en LXC, connectée à l'identité SecuBox

Issues #3154 (le paquet) et #3155 (écarts du fournisseur OIDC). Demande du propriétaire (2026-10-25) : une visio libre de l'État
(La Suite Meet, DINUM) dans la Boutique, installable en LXC ; **brancher l'identité de SecuBox** (pas de Keycloak) ; ouvrir des
issues et **documenter pour un partage ultérieur** (voir `docs/OIDC-FOURNISSEUR.md`). Ce document est une conception : aucun code
n'est écrit.

## Constat (2026-10-25)

- **Le fournisseur OIDC existe déjà et tourne sur gk2.** Composant `oidc` du paquet `secubox-auth` : code + PKCE S256, id_token
  RS256, `userinfo`, JWKS, découverte, clients enregistrés par `secubox-oidcctl`. Émetteur : `https://hall.gk2.secubox.in/oidc`.
  La découverte répond. L'audit d'authentification (`docs/AUDIT_AUTHENTICATION.md`) notait que le README de `secubox-identity`
  annonçait SAML/OIDC « absents » : ce paquet n'est pas celui du fournisseur, qui vit dans `secubox-auth`. Détail :
  `docs/OIDC-FOURNISSEUR.md`.
- **Jitsi tourne déjà en LXC** (`secubox-jitsi`) : modèle de paquet, de vhost `jitsi.*`, de route WAF et de décision d'exposition
  (le drop-in nftables du flux média est **livré en exemple, jamais appliqué par `apt install`**).
- **La Suite Meet** (`suitenumerique/meet`, MIT) : backend Django + DRF, front React (Vite), flux WebRTC par **LiveKit**, PostgreSQL,
  Redis, et un fournisseur OIDC obligatoire. Installation officielle : Docker Compose ou Kubernetes ; Nix et YunoHost en
  communautaire. Aucune installation native Debian n'existe. Documentation encore en beta. Sources :
  <https://documentation-meet.beta.numerique.gouv.fr/self-hosting/> et <https://github.com/suitenumerique/meet>.
  *Non vérifié :* la liste exacte des variables d'environnement et l'adresse de rappel (`redirect_uri`) de Meet ; à lire dans
  `docs/installation/` du dépôt avant d'écrire le paquet.

## Objectifs

1. Une personne connectée au Hall ouvre une visio sur `visio.<domaine>` **sans second mot de passe** : son identité SecuBox est
   transmise par OIDC.
2. Le paquet `secubox-meet` s'installe depuis la Boutique et se retire proprement, dans **un seul conteneur LXC** (jamais Docker ni
   Podman), géré comme `secubox-jitsi`.
3. Rien ne s'ouvre à l'insu de l'administrateur : le flux média n'est exposé que sur décision explicite.

## Hors champ

- Enregistrement, transcription et résumés (LiveKit Egress, stockage S3, tâches Celery) : plus tard.
- Téléphonie (SIP) ; passerelle vers Jitsi.
- **Fédération d'identité entre boxes** (une personne de gk1 dans la visio de gk2) : l'émetteur reste « un par box ».
- Keycloak, Authentik, Dex : on n'embarque aucun second fournisseur d'identité.

## Conception

### Le conteneur

Un LXC Debian trixie non privilégié, nom `meet`, contenant :

| Brique | Mise en œuvre |
|---|---|
| Backend | Django de Meet dans un environnement virtuel, servi par gunicorn derrière le nginx du conteneur |
| Front | fichiers statiques de la version publiée (construction Node à la fabrication du paquet, pas dans le conteneur) |
| Base | PostgreSQL du conteneur (jamais exposé) |
| Cache | Redis du conteneur (jamais exposé) |
| Média | `livekit-server` (binaire Go ; disponibilité d'un build arm64 à confirmer) ; signalisation sous le même nom en HTTPS, médias en UDP/TCP directs |

Gestion par `meetctl` (modèle `jitsictl`) : création du conteneur, secrets dans `/etc/secubox/secrets/meet/` (jamais dans un TOML
versionné), état, mise à jour (migrations Django, reconstruction du front). Mise à jour sans Docker : **à la charge du paquet**.

### Exposition

- Nom `visio.<domaine>` : vhost nginx `server_name visio.*` sur 9080, route sbxwaf (`secubox-waf-route`), vhost HAProxy vers
  `sbxwaf_inspector`, **comme la Boutique** (#3150). Aucun contournement du WAF pour la signalisation.
- **Flux média hors WAF, décision explicite.** LiveKit exige **7881/TCP** et **7882/UDP** entrants (plage UDP selon la
  configuration retenue). Un WAF HTTP ne voit pas du WebRTC : même situation que l'UDP/10000 de Jitsi. Le drop-in nftables est
  livré en exemple (`/usr/share/doc/secubox-meet/examples/meet.nft`), jamais appliqué à l'installation ; la Boutique ou l'écran
  Exposition l'applique après confirmation de l'administrateur.
- **TURN** conseillé (LiveKit sait en servir un) : sans lui, des participants derrière un pare-feu d'entreprise se connectent sans
  son ni image. À décider avec l'ouverture des ports.

### Identité : Meet client du fournisseur OIDC de la box

1. À l'installation, `meetctl` enregistre le client : `secubox-oidcctl client-add meet --name "Visio" --redirect <adresse de rappel
   de Meet>`, récupère le secret imprimé **une fois** et l'écrit aussitôt dans `/etc/secubox/secrets/meet/` (0640 root:secubox),
   puis dans l'environnement du conteneur.
2. Meet est configuré avec l'émetteur `https://hall.<domaine>/oidc`, ses quatre points d'accès, `RS256`, les portées
   `openid email`, PKCE.
3. **Le conteneur doit joindre l'émetteur sous son nom public** : l'`iss` des jetons est comparé tel quel, donc pas d'adresse
   interne. Résolution du nom public vers la box depuis le conteneur (entrée d'hôtes vers l'adresse du pont LXC, ou DNS de la
   box) ; le certificat présenté est celui du Hall.
4. Le cookie de session SecuBox couvre `.<domaine>` : le navigateur qui arrive de `visio.<domaine>` porte déjà la session du Hall.
   Si elle manque, **voir l'écart 1** ci-dessous.

### Écarts du fournisseur à combler (#3155)

Tous sont additifs et ne changent pas le comportement des clients existants (PhotoPrism, Mastodon).

| # | Écart | Pourquoi Meet en a besoin | Proposition |
|---|---|---|---|
| 1 | Sans session, `/authorize` affiche une impasse (« connectez-vous au Hall puis réessayez ») | Un usager qui clique « Se connecter » sur la visio doit arriver sur la connexion et revenir seul | Rediriger vers la connexion du Hall avec retour sur l'adresse `/authorize` d'origine ; refuser tout retour hors du domaine de la box |
| 2 | Aucune politique d'accès par client | La visio ne devrait pas s'ouvrir à toute personne de la box sans choix de l'administrateur | Clé facultative `acces` par client (rôle ou capacité SBX ID requis) ; absente = comportement actuel. Refus : `access_denied` avec une page claire |
| 3 | Pas de `end_session_endpoint`, pas de `refresh_token` | Meet peut demander la déconnexion et le renouvellement | `end_session_endpoint` qui ne ferme que la session du client (la session SecuBox reste) ; pas de jeton de rafraîchissement tant que Meet n'en exige pas |
| 4 | Adresse synthétique non vérifiée (`email_verified=false`) | Meet identifie souvent la personne par son courriel | Garder le `sub` comme clé stable ; documenter le réglage de Meet qui accepte une adresse non vérifiée |
| 5 | L'émetteur doit être joignable sous son nom public depuis le LXC | Voir plus haut | Test de bout en bout au démarrage de `meetctl` (découverte + JWKS depuis le conteneur) |

L'ordre de livraison : écarts 1 et 5 avant tout essai de Meet (sans eux, pas de connexion utilisable), puis 2, puis 3 et 4 si
l'essai le demande.

### Boutique

- Fiche « Visio » dans `boutique-fiches.json` : nom, résumé, détail, catégorie Communication.
- La fiche pourra proposer **plusieurs solutions** pour le besoin « Visio » : Jitsi (installable), La Suite Meet (installable une
  fois le paquet publié), ce qui prolonge l'idée des solutions publiques par besoin.

## Sécurité

- **Surface :** deux ports média entrants à ouvrir sur décision ; tout le reste passe par HAProxy puis sbxwaf.
- **Secrets :** secret client OIDC, secrets Django, clés LiveKit : `/etc/secubox/secrets/meet/`, jamais dans un fichier versionné ni
  dans les journaux ; `meetctl` ne les affiche jamais.
- **Identité :** seule une session désignant une **personne** ouvre un compte ; la politique par client (écart 2) restreint qui.
- **Conteneur non privilégié**, sans accès aux sockets des autres modules, ressources plafonnées (CPU et mémoire) : une visio
  peut saturer une petite carte. Réglage d'un nombre maximal de participants à prévoir avant de l'offrir aux boxes à 4 Go.
- **AppArmor :** profil du service en `enforce` avec son utilisateur dédié (règle du projet).

## Tests et preuves

- Fournisseur : tests unitaires de chaque écart (redirection de connexion avec retour borné au domaine, refus par politique, fin
  de session) ; non-régression des clients existants.
- Paquet : test de bout en bout dans un vrai navigateur sur une box d'essai : connexion par OIDC, création d'une salle, deux
  participants, aucun journal ne contient un secret.
- Exposition : `nft list ruleset` avant et après l'application du drop-in ; retrait propre.

## Laissé au constructeur

- Version de Meet à figer et mode de fabrication du front.
- Plage UDP de LiveKit et choix TURN intégré ou externe.
- Mémoire cible du conteneur et plafond de participants.

## Décisions du propriétaire (2026-10-25)

1. **Qui peut utiliser la visio :** toute personne de la box, **invités compris** (rôle `guest` : une invitation crée une personne, donc
   le fournisseur l'authentifie déjà). Pas de restriction par défaut ; la politique par client (écart 2) reste une option.
   *Précision de mon fait :* Meet lui-même laisse un participant sans compte rejoindre une salle par son lien ; l'OIDC ne sert qu'à
   créer et gérer des salles.
2. **Ports média :** ouverts **après confirmation dans la Boutique** (jamais par `apt install`, comme Jitsi).
3. **Fédération d'identité entre boxes :** voulue ; projet à part, issue #3157. Les écarts du fournisseur sont conçus pour ne pas
   l'empêcher : l'émetteur reste lu en configuration et le `sub` reste l'identifiant stable de la personne.

## Avancement

- Écart 1 (#3155) : fait, avec les tests (renvoi vers la connexion avec retour, pas de boucle pour une session sans personne).
- Écart 5 : à traiter avec `meetctl` (test de découverte et de JWKS depuis le conteneur).
- Écarts 2, 3 et 4 : à faire quand Meet demande ce qu'il lui faut ; le 2 est facultatif d'après la décision 1.
