<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# HISTORY — SecuBox-DEB : mois courant
Entrées datées, les plus récentes en haut. Seul le **mois courant** vit ici ; les mois
précédents sont dans `archive/HISTORY/AAAA-MM.md` (lus sur demande, voir `archive/INDEX.md`).

## 2026-10-02 — SESSIONS SOBRES, WAF SANS FAUX POSITIFS, COFFRE POUR TOUS (ref #1863, #1858, #1859, #1857, #1855, #1862)

- **Contexte (#1863)** : WIP.md 485 Ko, HISTORY.md 516 Ko et TODO.md 89 Ko lus « en premier » ;
  CLAUDE.md et AGENTS.md dupliqués. Découpe par mois dans `archive/`, **zéro perte prouvée**
  (SHA-256 identique à l'octet, `archive/reassembler.py`) ; instructions à source unique.
- **WAF** : `cred-004` prenait `requesttoken=` de Nextcloud pour un jeton (l'iPhone était
  compté, 2/3 avant bannissement) ; `api-001` bannissait l'administrateur légitime ;
  bruit `localhost` retiré de sbxwaf ; `waf-rules-sync` met à jour les règles livrées sans
  écraser celles de wafgen (secubox-waf 1.10.42, secubox-waf-ng 1.18.12). PR #1860, #1861.
- **Coffre** : la connexion ouvre le Coffre de l'admin ET le compartiment de toute personne,
  invités compris (vault 2.0.15, auth 1.1.18, aggregator 0.3.10 ; PR #1856 fusionnée) ;
  un pin `vault = off` périmé le tenait arrêté (le Coffre rejoint les modules protégés de
  `secubox-profiles`) ; 421 `undefined`/`vault.gk2` corrigés dans le Hall (webos 1.0.395).
- **Accès délégués retirés (#1857)** : l'identité SBX OS porte les liens ; sonde de session
  `GET /api/v1/webos/session` ; « Mes sites » en lien direct ; cadre embarqué par
  `/sbx/entrer`. Le coffre `webos-acces` est conservé (il sert l'Identity Manager).
- **RustDesk décommissionné (#1862)** : paquet, conteneur LXC (archive 190 Mo), flux
  HAProxy, références dépôt (54 métapaquets republiés).
- **gk3** vérifié en direct : frontal HAProxy → sbxwaf → nginx, 0 unité en échec (#1808, #1684).

## 2026-10-02 — Polices Google via le cache de la box (#1875)
- secubox-hub 1.9.31 : zone `sbx_fonts` + snippet `/cdn/fonts/css|s/` (proxy_cache, CSS réécrit). billets 0.8.70, podcaster 1.2.6 : liens `/cdn/fonts/css/…`, CSP sans hôte Google. Vérifié Chromium : 0 requête Google (podcaster, billets, Hall). Déployé gk2. Reste (phase 2) : ~30 autres pages www/ (ref #1875).
- Dette notée : `billets.conf` livré diverge du live (waking, X-SecuBox-LAN) ; sites-enabled/billets.conf était une copie, remplacée par un lien.

## 2026-10-02 — Backends fermés côté eth2 (ref #1306)
- secubox-hardening 1.3.0 : `/etc/nftables.d/secubox-wan-guard.nft` (table `inet secubox_wan_guard`, priorité filter-10) coupe 7331, 8088, 8404, 8880, 8900, 8910, 9080 en entrée eth2, sans toucher la règle de base `iif "eth2" accept` (fichier non géré par un paquet). Déployé gk2 : ces ports sont fermés depuis le LAN, 22/80/443/9443 ouverts, sites 200. Reste : 8780, 8099, 8000, 9000, 8888, 9050 (usage LAN non établi) et le propriétaire du pare-feu de base.

## 2026-10-02 — Garde des ports de backend intégrée à secubox-hardening (ref #1306)
- hardening 1.4.1 : `GET /wan-guard` (règle livrée, ports gardés, ports encore en écoute joignables par le LAN), carte dans le tableau de bord, `hardeningctl wan-guard` (table chargée, root), 4 tests. Déployé gk2 (aggregator redémarré, hall 200). Reste non gardé et à trancher : 2222, 8000, 8780, 8888, 9000, 9050 + les leurres (23, 445, 1433, 3306, 3389, 5432, 5900, 6379, 9200, 27017).

## 2026-10-02 — Leurres fermés côté eth2 (ref #1306)
- hardening 1.4.2 : la garde coupe aussi les écoutes de leurre de sbx-authwatch (23, 1433, 3306, 3389, 5432, 5900, 6379, 9200, 27017) ; 445 (SMB réel) reste ouvert. Déployé gk2, vérifié depuis le LAN. Effet : sbx-authwatch ne voit plus de sondes sur eth2. Reste non gardé : 2222, 8000, 8780, 8888, 9000, 9050.

## 2026-10-02 — Une seule base de pare-feu pour toutes les SecuBox (ref #1306)
- secubox-hardening 1.5.1 livre /etc/nftables.conf (table `inet filter`, superset gk2 + firstboot/gk3 : ICMPv6, DHCP, WireGuard 51820-51825, maillage, mDNS, masquerade LXC). Propre à la box : `/etc/secubox/hardening/nft-input-trust.d/` (interfaces de confiance) et `nft-site.d/` (tables NAT reprises de l'ancienne base). `image/firstboot.sh` n'écrit plus sa propre base : il installe celle du paquet (secubox-meta dépend de secubox-hardening). Essai sur gk2 en espace de noms isolé : ruleset = ancien + ajouts seulement, rien perdu ; non appliqué en direct (effet au prochain démarrage de nftables).
- À vérifier avant de propager à gk3 : ses règles de `secubox_filter` (bonjour, noms, relais) sont reprises par la base ; contrôler en espace de noms puis au prochain démarrage.

## 2026-10-02 — Test dynamique du WAF dans la page Santé (ref #1883)
- health-doctor 1.1.1 : contrôle `waf-selftest` (sbxwaf à l'écoute, témoin non bloqué, canaris XSS/SQLi/LFI/RCE en 403 depuis 198.51.100.77, vhost public hall.*), au plus toutes les 5 min, `POST /waf-selftest/run` pour le rejouer. hub 1.9.32 : section « WAF — test dynamique » dans /health/. Vérifié gk2 + Chromium. Constat : sbxwaf n'inspecte pas admin.* ni git.* (liste en dur du binaire).

## 2026-10-02 — Menu admin : entrées p2p/zkp ignorées sur une box neuve (ref #1888)
- Cause : secubox-p2p et secubox-zkp livraient leur entrée en /etc/secubox/menu.d, que le hub ne lisait pas ; gk2 les avait par copie manuelle (21/05), gk3 non. hub 1.9.33 lit aussi /etc/secubox/menu.d (locale prioritaire, dédoublonnée) ; p2p 1.11.18 et zkp 1.2.3 livrent en /usr/share/secubox/menu.d. 3 tests. gk2 : p2p inchangé (déjà présent), zkp non affiché faute de www/zkp. Écarts de gk3 restants : pas de dpi, mediaflow, sentinelle-gsm (jeu de paquets), hub/health-doctor/hardening en retard sur gk2.

## 2026-10-02 — Assistance : boutons de session non muets (ref #1894)
- secubox-assist 0.2.10 : sans session active, Kill session / Autoriser / Retirer sont désactivés avec l'explication ; le POST passe par postAction (succès et échec visibles). Avant : `if (!sid) return;` et réponse jamais lue. 3 tests.
## 2026-10-02 — Santé : veille pondérée (ref #1887)
- core 1.5.53 + hub 1.9.35 : unités au repos (oneshot ou TriggeredBy timer/path, dernier passage réussi) et modules endormis = ok + `veille`; unités not-found/masked écartées; échec = alerte. Page Santé : carte 💤 en veille, score pondéré (sain 1, veille 1, dégradé 0,5, panne 0). gk2 : dégradés 59 → 2 (premier-pas-console, zia-llm), 68 en veille, 121 sains, 0 panne. 14 tests core.

## 2026-10-02 — Assistance : demandes reçues visibles (ref #1895)
- secubox-assist 0.2.11 : la carte « Demandes en attente » liste aussi les demandes ouvertes reçues des autres box (bouton Répondre). La demande de gk3 (motif sbx, req 4e68e4cb…) était active dans le journal de gk2 mais ne s'affichait que dans l'onglet « Demandes ouvertes ». Déployé gk2 (page seule, sans redémarrage). 4 tests.

## 2026-10-02 — Accès : erreur « Votre nom est nécessaire » rattrapée (ref #1893)
- sbxid 0.4.18 : bouton() des pages d'accès exécute l'action dans la chaîne de promesses ; le throw synchrone n'est plus une erreur non rattrapée avec bouton figé. Non traité : iframes blob:https://admin.gk2… bloquées par la CSP du Hall (origine non identifiée, aucun createObjectURL d'iframe dans les sources) ; bruit Firefox Feature Policy autoplay/encrypted-media et Layout forced sans effet.

## 2026-10-03 — Reporter : téléchargement du PDF dans Firefox (ref #1895)
- Cause : le PDF était servi (200, 21014 o) mais Reporter, embarqué dans le Hall, téléchargeait par blob: ; Firefox traite la navigation vers le blob comme un chargement de cadre refusé par frame-src du Hall (les trois iframes blob bloquées de la console = les trois clics). Chromium télécharge dans tous les cas (reproduit). reporter 1.2.3 : lien direct (cookie de session) sinon blob en repli avec ancre dans le DOM et révocation différée ; guillemet final du nom de fichier retiré. Non vérifié dans Firefox (absent ici). Clôt aussi l'iframe blob: laissée « origine inconnue » dans #1893.

## 2026-10-03 — nginx real_ip : relais propres à la box seulement (closes #1754)
- hub 1.9.36 : `secubox-lan-geo.conf` ne trustait plus que 127.0.0.1 ; `secubox-realip` (service + minuteur 60 s) engendre `/etc/nginx/conf.d/secubox-real-ip-local.conf` avec les adresses locales (gk2 : 11 adresses). Avant : 192.168.1.0/24, 10.100.0.0/24, 192.168.255.0/24 crues. Mesuré gk2 avant/après : `X-Forwarded-For: 8.8.8.8` depuis un poste du LAN → journalisé 8.8.8.8 (avant), 192.168.1.3 réel (après) ; clients réels (192.168.1.254, IP externes) toujours résolus via HAProxy ; sites 200 ; verdict $lan_client inchangé. 6 tests, dont un bug du script trouvé par les tests (set -e).
- closes #1306 : pare-feu — backends fermés côté eth2 (hardening 1.4.x), base unique livrée par le paquet (1.5.1, gk2 et gk3 à jour, images via firstboot) ; les services LAN-only (Lyrion 3483/9000/8888, 2222, 8000, 8099, 9050) restent ouverts par décision de l'exploitant.

## 2026-10-03 — NAC : blocage, quarantaine et zones ont un effet réseau (ref #1766)
- nac 3.1.7 : l'API écrit l'état voulu (nft-desired.json), `secubox-nac-apply` (root, CAP_NET_ADMIN seul, unité .path) valide et charge en une transaction règles + éléments ; `/etc/nftables.d/secubox-nac.nft` enfin référencé par des règles (blocked, quarantine, iot/guest isolés du LAN). Preuve de bout en bout gk2 (netns jetables) : bloqué → ping KO, retiré → OK, quarantaine KO, IoT internet OK / LAN KO. Chaîne réelle API→.path→nft vérifiée (ajout/retrait d'une MAC factice, 3 s). 8 tests. Non déployé gk3 (apt). 2 tests test_discovery échouent déjà sur master.

## 2026-10-03 — Dossiers photo partagés : fin des 0777 (closes #1516)
- UID mesurés sur gk2 : Nextcloud www-data=100033 (seul écrivain 30 j), PhotoPrism = utilisateur `photoprism` uid 995 → 100995 (pas root ; arrêté sur gk2). nextcloud 1.8.10 + photoprism 1.3.10 : racine 0755 100000:100000, dossiers d'usagers 2750 100033:100995 ; `nextcloudctl fix-photos-perms` (racine + sous-dossiers directs, jamais récursif) appelé par la postinst. Trois points de création corrigés (nextcloudctl, photoprismctl, postinst + install-lxc.sh de photoprism qui remettaient 0777). Vérifié gk2 : www-data écrit gk2/ et admin/, uid 100995 lit, un autre uid refusé, contenu intact (1001:1001 conservé), nc.gk2 200. Le premier jet avait le groupe 100000 : PhotoPrism n'aurait pas lu — trouvé en mesurant avant de déployer le reste. Hors périmètre vu en passant : /data/droplet/*_html en 0777 (107:114), un tar de sauvegarde mail en 0666.
