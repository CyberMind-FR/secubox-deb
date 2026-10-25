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
  La documentation d'installation et de configuration a été lue le 2026-10-25 : voir « Ce que dit la documentation de Meet ».

## Ce que dit la documentation de Meet (lue le 2026-10-25)

Sources : <https://documentation-meet.beta.numerique.gouv.fr/> (auto-hébergement, `reference/env-variables`, `configuration/sso`,
`configuration/livekit`, `configuration/upgrade`) et `docs/installation/` du dépôt.

**Méthodes officielles :** Kubernetes (celle de la production, seule à avoir un support avancé), Docker Compose, Scalingo. Nix et
YunoHost sont communautaires, « instables » ou « en construction ». **Aucune installation native Debian n'est documentée** : le
paquet `secubox-meet` sera une adaptation, sans support amont. Les images publiées sont `lasuite/meet-backend` et
`lasuite/meet-frontend` (Docker Hub) ; la documentation ne chiffre ni CPU ni mémoire.

**Briques obligatoires :** backend Django, front React, LiveKit, PostgreSQL, Redis (cache et courtier Celery), fournisseur OIDC.
Facultatives : Egress, S3, résumés, téléphonie.

**OIDC, la concordance avec notre fournisseur :**

| Meet demande | Notre fournisseur | Verdict |
|---|---|---|
| Adresse de rappel `https://visio.<domaine>/api/v1.0/callback/` (barre finale obligatoire) | égalité stricte de `redirect_uri` | enregistrer exactement cette adresse |
| `OIDC_OP_AUTHORIZATION/TOKEN/USER/JWKS_ENDPOINT` | les quatre existent | rien à faire |
| `OIDC_RP_SIGN_ALGO=RS256` (défaut) | RS256 | rien à faire |
| `OIDC_RP_SCOPES=openid email` | acceptés | rien à faire |
| `OIDC_USE_PKCE=True`, méthode `S256` (recommandé) | S256 | activer |
| `OIDC_USE_NONCE=True` (défaut) | nonce repris dans l'id_token | rien à faire |
| `OIDC_OP_USER_ENDPOINT_FORMAT=AUTO` | `userinfo` répond en JSON | rien à faire |
| Nom complet : `given_name`, `usual_name` (défaut) | nous publions `name`, `nickname`, `preferred_username` | **régler** `OIDC_USERINFO_FULLNAME_FIELDS=name` et `OIDC_USERINFO_SHORTNAME_FIELD=nickname` |
| `FRONTEND_IS_SILENT_LOGIN_ENABLED=True` (défaut) : exige `prompt=none` | `prompt=none` renvoie `login_required` quand il faut | compatible |
| `OIDC_OP_LOGOUT_ENDPOINT` : facultatif | absent chez nous (écart 3) | **laisser vide** : la déconnexion de Meet ne ferme que la session de Meet |
| `OIDC_FALLBACK_TO_EMAIL_FOR_IDENTIFICATION=False` (défaut) | le `sub` est stable ; le courriel synthétique n'est pas fiable | garder `False` |
| `email_verified` : non mentionné par la documentation | faux pour l'adresse synthétique | à essayer ; écart 4 seulement si Meet le refuse |

La documentation ne dit pas si les revendications viennent de l'id_token ou de `userinfo` : les deux portent les mêmes champs chez nous.

**LiveKit :**
- Signalisation (WebSocket) : en WSS sur 443 par un proxy inverse, vers LiveKit sur **7880** (non exposé).
- Médias, option A recommandée : `tcp_port: 7881` et `udp_port: 7882` ; ouvrir **7881/TCP et 7882/UDP**. Option B (plage 50000–60000/UDP) :
  plus large, déconseillée ici. Ne jamais régler `udp_port` et la plage ensemble.
- **`LIVEKIT_API_URL` est l'adresse publique en HTTPS**, sur un **sous-domaine dédié** (`livekit.<domaine>`), utilisée par les
  navigateurs *et* par le backend. Le backend doit donc résoudre ce nom depuis le conteneur.
- `use_external_ip: true` sur un serveur derrière un NAT (LiveKit trouve son adresse publique par STUN) ; à ne pas mettre si l'adresse
  publique est sur l'interface même. Clé et secret : `keys:` du serveur, `LIVEKIT_API_KEY` et `LIVEKIT_API_SECRET` (32 caractères et plus).
- TURN : bloc `turn:` (UDP 443, domaine) pour les réseaux d'entreprise.

**Variables de base :** `DJANGO_SETTINGS_MODULE=meet.settings`, `DJANGO_CONFIGURATION=Production`, `DJANGO_SECRET_KEY` (50 caractères et
plus), `DJANGO_ALLOWED_HOSTS`, `DJANGO_CSRF_TRUSTED_ORIGINS`, `DJANGO_DATA_DIR` (préfixe `DJANGO_` imposé par django-configurations : `DATA_DIR`
seul est ignoré et collectstatic écrit dans `/data`), `DB_HOST/PORT/NAME/USER/PASSWORD`, `REDIS_URL`.
**À régler pour nous :** `ALLOW_UNREGISTERED_ROOMS=False` (par défaut, `True` laisse **n'importe qui créer des salles sans compte** sur un
nom public) ; `RESOURCE_DEFAULT_ACCESS_LEVEL` : `public` (lien suffisant) ou `trusted` selon la décision sur les invités externes.

**Mise à jour :** lire `CHANGELOG.md` et `UPGRADE.md`, sauvegarder la base, puis `python manage.py migrate` **après chaque mise à
jour**, puis `collectstatic`. LiveKit se met à jour séparément de Meet (vérifier la compatibilité). Épingler les versions.

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
| Média | `livekit-server` (binaire Go ; build arm64 confirmé le 2026-10-25, 53 Mo) ; signalisation sous le même nom en HTTPS, médias en UDP/TCP directs |

Gestion par `meetctl` (modèle `jitsictl`) : création du conteneur, secrets dans `/etc/secubox/secrets/meet/` (jamais dans un TOML
versionné), état, mise à jour (migrations Django, reconstruction du front). Mise à jour sans Docker : **à la charge du paquet**.

### Exposition

- **Deux noms** : `visio.<domaine>` (Meet) et `livekit.<domaine>` (signalisation WSS de LiveKit, imposée par la documentation).
  Pour chacun : vhost nginx `server_name … .*` sur 9080, route sbxwaf (`secubox-waf-route`), vhost HAProxy vers `sbxwaf_inspector`,
  **comme la Boutique** (#3150). Aucun contournement du WAF pour la signalisation.
- **Éprouvé le 2026-10-25 : le WebSocket de LiveKit traverse la chaîne complète.** Essai jetable sur gk1 (`livekit-server` 1.13.10 arm64,
  nginx local, jeton signé HS256) : depuis Internet, `wss://livekit.gk1.secubox.in/rtc` répond **101 Switching Protocols** avec
  `x-secubox-waf: inspected`, puis les premières trames protobuf de LiveKit. Chemin : HAProxy de gk2, sbxwaf, nginx de gk2, relais du
  maillage, nginx de gk1, LiveKit. Le relais a posé seul la route sbxwaf et le vhost HAProxy après l'apparition du nom dans le
  catalogue de gk1 (environ trois minutes). Aucun contournement du WAF n'est donc nécessaire pour la signalisation. Non éprouvé :
  les médias (7881/TCP, 7882/UDP), qui demandent de vrais pairs.
- **Un serveur sur gk1 et un nom `livekit.*` :** une box derrière le relais n'a pas son propre HAProxy ; ses noms passent par gk2.
  Piège relevé : un nom en `x.*` est vu par le relais seulement s'il figure dans les `server_name` nginx de la box.
- **NAT et Freebox :** gk2 est la **cible de la DMZ** de la Freebox (autoconfig conforme, 0 écart) : 7881/TCP et 7882/UDP lui arrivent sans
  redirection. gk1 et les autres boxes derrière la même Freebox exigent des **redirections de ports explicites**. `secubox-freebox` sait
  les lire mais pas les créer (« à venir ») : décision du 2026-10-25, l'autoconfig créera et retirera ces redirections (issue #3160),
  avec la même garde que le reste (administrateur, droit « Modification des réglages », confirmation, audit). La décision « ouvrir les
  ports média » de la Boutique posera donc deux choses : le drop-in nftables local et, si la box n'est pas la cible de la DMZ, la
  redirection. Réglage `use_external_ip` selon que l'adresse publique est sur l'interface ou non (ici non).
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
3. **Réglage des noms** : `OIDC_USERINFO_FULLNAME_FIELDS=name`, `OIDC_USERINFO_SHORTNAME_FIELD=nickname`, `OIDC_USE_PKCE=True`, pas de
   `OIDC_OP_LOGOUT_ENDPOINT`, `ALLOW_UNREGISTERED_ROOMS=False`.
4. **Le conteneur doit joindre l'émetteur sous son nom public** : l'`iss` des jetons est comparé tel quel, donc pas d'adresse
   interne. Résolution du nom public vers la box depuis le conteneur (entrée d'hôtes vers l'adresse du pont LXC, ou DNS de la
   box) ; le certificat présenté est celui du Hall.
5. Le cookie de session SecuBox couvre `.<domaine>` : le navigateur qui arrive de `visio.<domaine>` porte déjà la session du Hall.
   Si elle manque, l'écart 1 (fait) le renvoie vers la connexion et il revient seul.

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

- Version de Meet à figer et mode de fabrication du front : construction Node à partir des sources, ou extraction des fichiers du paquet
  d'images `lasuite/meet-frontend` à la fabrication (sans jamais lancer Docker sur la box).
- Plage UDP de LiveKit et choix TURN intégré ou externe.
- Mémoire cible du conteneur et plafond de participants.

## Décisions du propriétaire (2026-10-25)

1. **Qui peut utiliser la visio :** toute personne de la box, **invités compris** (rôle `guest` : une invitation crée une personne, donc
   le fournisseur l'authentifie déjà). Pas de restriction par défaut ; la politique par client (écart 2) reste une option.
   *Précision de mon fait :* Meet lui-même laisse un participant sans compte rejoindre une salle par son lien ; l'OIDC ne sert qu'à
   créer et gérer des salles.
2. **Ports média :** ouverts **après confirmation** (jamais par `apt install`, comme Jitsi) ; la confirmation vit dans la page
   d'administration `/meet/`, que la Boutique ouvre par ⚙️. **Redirection via gk2** (décision du 2026-10-25) : une box derrière le
   relais publie ses ports média (`/public/ports`) et le maître, cible de la DMZ, les DNAT vers elle par `wg-mesh` avec masquerade
   (retour par le maître). Aucune redirection Freebox pour ces boxes ; #3160 reste utile pour une box exposée en direct.
3. **Fédération d'identité entre boxes :** voulue ; projet à part, issue #3157. Les écarts du fournisseur sont conçus pour ne pas
   l'empêcher : l'émetteur reste lu en configuration et le `sub` reste l'identifiant stable de la personne.

## Avancement

- Écart 1 (#3155) : fait, avec les tests (renvoi vers la connexion avec retour, pas de boucle pour une session sans personne).
- Documentation d'installation lue : la concordance OIDC est complète sans autre changement du fournisseur (voir le tableau).
- Essai du WebSocket LiveKit réussi (voir Exposition) ; redirections Freebox : #3160.
- Écart 5 : à traiter avec `meetctl` (test de découverte et de JWKS depuis le conteneur, et du nom `livekit.<domaine>`).
- Écarts 2, 3 et 4 : à faire quand Meet demande ce qu'il lui faut ; le 2 est facultatif d'après la décision 1.
