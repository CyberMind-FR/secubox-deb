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
