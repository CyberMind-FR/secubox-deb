<!-- SPDX-License-Identifier: LicenseRef-CMSD-1.0 -->
<!-- Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr> -->
# SBXOS Admin — audit de l'interface d'administration (#2212)

Audit en lecture seule du 2026-10-10, avant la refonte « conserver le moteur, simplifier le cockpit ». La matrice page par page est dans `docs/SBXOS_ADMIN_UI_MAP.md` (générée).
Limite : tout vient de la lecture du dépôt ; l'état d'exécution (gk2, gk3) n'a pas été revérifié, et les recherches « API sans page » sont des greps qui ratent les appels construits dynamiquement.

## 1. Ce que le cahier des charges suppose, et ce qui est vrai
- **Pas de Jinja ni de HTMX dans l'administration.** 182 pages HTML statiques en JavaScript vanilla appellent l'API par `fetch()`. Seul `secubox-billets` utilise Jinja (son blog public). Aucun framework JS, hors le Hall PWA (`secubox-sbxos`).
- **Le menu est piloté par les données** : 125 fichiers `menu.d/*.json` (84 de paquets, 41 de composants) → `GET /api/v1/hub/public/menu` (double tampon) → `/shared/sidebar.js` (2 611 lignes, 123 pages), cache navigateur `sbx_menu_cache` d'une heure.
- **Les pages portées ne sont pas modifiables** (règle de #2050) : la refonte regroupe par navigation et par données, jamais en réécrivant les pages.
- **Des façades existent déjà** : le Hall WebOS (`secubox-webos`, cartes et iframes, avec recherche des cartes) et Aurora (`secubox-sbxos`, pré-alpha, palette Ctrl K), destinés à se remplacer. Une quatrième navigation en parallèle est exclue : la nouvelle s'aligne sur eux par un champ commun `espace`.

## 2. Ressources partagées (`packages/secubox-hub/www/shared/`)
`sidebar.js` (menu, LED de santé, statut, utilisateur, déconnexion, injection du skin) · `hybrid-skin.css`, `hybrid-dark.css`, `design-tokens.css` · `api-utils.js` (fetch JSON, redirection sur 401) · `health-banner.js` · `crt-*` (style téléscripteur) · pages d'erreur nginx.
**Manques côté admin** : aucune recherche, aucun panneau de notifications (l'API `GET /api/v1/hub/notifications` existe, `require_jwt`), pas de page de profil (le rôle affiché est écrit en dur « OPERATOR »), pas d'aide hors Hall. Le thème est forcé sombre.

## 3. Authentification et rôles
Connexion par `packages/secubox-portal/www/login.html` (`/api/v1/auth/login`, TOTP), jeton dans `localStorage.sbx_token`, 24 h, sans rafraîchissement. Gardes (`common/secubox_core/auth.py`) : `require_jwt` (administrateur réel, ~124 modules), `require_personne`, `require_session`, `require_lecture` (jeton, ou « mode tableau de bord » LAN s'il est armé), `require_capability`. Le relais de l'agrégateur réserve `actor`, `radio` et `vault` à l'administrateur. Les pages traitent le 401 par une redirection ou un toast, et rien n'affiche un 403 « administrateur requis ».
**Séparation inviolable** : comptes Linux (`root`, `admin`, `gk2`, `operator`) hors identités SBXOS (`docs/AUTH_V3.md`, `common/secubox_core/capacites.py`).

## 4. Objets centraux : l'état réel
- **APPAREIL** : huit objets, huit clés. `nac` (MAC, zones, politique, parental), `ad-guard` (appareils vus au DNS), `dpi` (clients WireGuard, `sha256(clé)`), `mediaflow`/`ndpid` (IP), `webfilter` (MAC), `qos` (IP/MAC), `sbxid` (`device_uuid`, certificat), pairs (`wireguard`, `p2p`, `annuaire`, `eye-remote`). Pas de fiche commune. La consolidation de `nac` comme source canonique est décidée (`docs/superpowers/specs/2026-07-05-device-guardian-consolidation-design.md`) mais pas terminée. DPI et ad-guard ne voient presque pas les mêmes appareils (`docs/superpowers/specs/2026-10-04-dpi-enrichi-adguard-design.md`).
- **IDENTITÉ** : trois registres (`users.json`, `sbx.db`, comptes par application) et cinq écrans voisins (`/users/`, `/identite/`, `/acces/`, `/auth/`, `/avatar/`) ; deux clés de nœud (`docs/AUDIT_SBX_IDENTITY.md`).
- **SERVICE** : quatre mécanismes d'installation et d'état (`appstore`, `profiles`/`profilectl`, pages par module, `premier-pas`).

## 5. Les dix doublons les plus coûteux
1. Contrôle par appareil : `nac`, `webfilter`, `qos`, `toolbox`, `ad-guard`, sans fiche commune.
2. Blocage d'IP à neuf endroits : `ipblock`, `vortex-firewall`, `cyberfeed`, `waf-ng`, `nac`, `toolbox`, `threatmesh`, `p2p`, `threats`.
3. Blocage de domaine à six endroits (`ad-guard`, `dns-guard`, `webfilter`, `dns`, `toolbox`, `dns-lan`), trois listes blanches distinctes.
4. Identité : trois registres, cinq écrans.
5. WireGuard géré par `wireguard`, `p2p`, `toolbox`, `netmodes`.
6. Tableaux de bord concurrents : `hub`, `metrics`, `soc`, `security-posture`, `threats`, `system`.
7. Mises à jour, redémarrage, journaux : `system`, `admin`, `hub`, `repo` ; sauvegardes : `backup`, `cloner`, `system`.
8. Installation des services : `appstore`, `profiles`, pages par module.
9. Alertes, webhooks et `/logs` recopiés dans une dizaine de modules.
10. Le mot « profil » a sept sens ; trois racines « système » (`system`, `admin`, `hub`).

## 6. Orphelins
- **Pages hors menu** : `/coffre/`, `/pgp/`, `/identite/` (joignable par la redirection de `/sbxid/`), `/premier-pas/`, `/master-link/`, `/messagerie/`, `/podcaster/portal/`, `micro.html` et `maquette.html` de `acces` et `waf`.
- **API sans page** : `oidc`, `ipv6guard` (`/appareils`), `dns-lan` (CLI seul), `ephemeride`, `rbs-sensor`, `soc-agent`, `soc-gateway`.
- **Menu sans page** : `reality`, `socialrelay`, `metanews`, `sbxos-audio-mood` (écartées par le hub), `console` (TUI).
- **Fonctions enterrées** : `toolbox` (`/admin/filter-control`, `/admin/splice-whitelist`, quarantaine), `nac` (`/mesh/peers`, `/presence*`), `qos` (VLANs), `netmodes` (MTU, BBR), `hub` (`/network_mode`, doublon de `netmodes`). Aucune route dédiée au stockage (`/disk` du hub seulement) ni au recovery/firmware.
- **Données du menu** : `order` non uniques (par exemple 10, 570, 590, 613, 706), `console` sans `path`, catégories (`root`, `auth`, `boot`, `wall`, `mind`, `mesh`) sans rapport avec les thèmes.

## 7. Sources de la vue d'ensemble (routes existantes)
`/api/v1/hub/dashboard`, `/security_summary`, `/network_summary`, `/system_health`, `/board_summary`, `/notifications`, `/module-health/summary` (`require_jwt`) ; `/api/v1/security-posture/overview`, `/defcon`, `/cspn` ; `/api/v1/metrics/overview` ; `/api/v1/backup/status` ; `/api/v1/repo/status` ; `/api/v1/health/summary` ; `/api/v1/soc/summary`, `/alerts`. **À ne pas appeler** : `hub/check_updates` (lance `apt update`). `scripts/check-dashboard-cache.py` (CI) refuse les endpoints chauds sans cache : la vue d'ensemble agrège des caches.

## 8. Tests et déploiement à respecter
- Menu : `scripts/tests/test_menu_theme_2050.py`, `packages/secubox-hub/tests/test_menu_*`, `test_menud_schema.py` (webos). Hall : `scripts/verifie-relais-hall.py`, `test_js_syntaxe.py`. JWT : `tests/test_conformite_jwt.py` (cliquet). Pas de suite navigateur en CI (Playwright optionnel, `importorskip`).
- pytest se lance par répertoire (collision de noms `api/`).
- Pages installées sous `/usr/share/secubox/www/<module>/` ; l'agrégateur relaie `/api/v1/<module>/` en retirant le préfixe ; tout paquet figure dans `arbre.yaml` ou `hors-arbre`.
- Le registre des unités root ne s'allonge pas : aucune API de synthèse ne tourne en root.

## 9. Risques
`sidebar.js` partagé par 123 pages (régression visible partout : nouvelle navigation derrière un drapeau, ancien menu intact) · cache du menu d'une heure (clé versionnée) · cohabitation Hall/Aurora (champ `espace` commun) · peu de tests navigateur (à ajouter) · vue d'ensemble lourde (caches seulement) · lecture en mode tableau de bord LAN (données d'identité et d'appareils sous `require_jwt`).

## 10. Décisions retenues
La façade est la sidebar d'administration pilotée par les données, alignée sur le Hall et Aurora par `espace` ; une seule facette responsive ; Auto-Load en Système avec lien depuis Identité & accès ; `nac` source de vérité de l'objet APPAREIL.
