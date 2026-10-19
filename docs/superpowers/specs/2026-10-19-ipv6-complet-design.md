<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# IPv6 complet — conception (ref #2938)

Statut : **à valider par le propriétaire.** Les points marqués **(mon choix)** sont des décisions de l'auteur.
Demande du 2026-10-19 : « full IPv6 avec guardian et firewall, zonning et guarders, metrics et autocheck, all full specs »,
précisée le même jour : phase 1 = ouvrir gk2 (HAProxy et UDP) en IPv6, phase 2 = observabilité (métriques IPv4/IPv6 comparées).

## Intention

Faire d'IPv6 un citoyen de première classe de SecuBox, sans jamais élargir la surface exposée par accident : ce qui est
joignable en IPv4 l'est en IPv6 **parce qu'on l'a décidé**, mesuré, et réversible en une commande.

## État mesuré (gk2, 2026-10-19)

| Couche | État | Source |
|---|---|---|
| Freebox | Pare-feu IPv6 actif (`ipv6_prefix_firewall = true`), un interrupteur **global**, pas de règle par port ni par machine ; préfixe délégué `2a01:e0a:dec:c4e0::/64` et suivants | sonde de l'API, #2930 |
| gk2, réseau | Adresse publique stable `2a01:e0a:dec:c4e0::200` sur `eth2` ; routes IPv6 présentes | `ip -6` |
| HAProxy | n'écoute qu'en IPv4 (`*:80`, `*:443`) ; option `ipv6 = true` prête, désactivée (#2934) | `ss`, haproxyctl |
| sbxwaf | gère les adresses IPv6 (set `waf_ban6`, `blacklist_v6`), adresse cliente normalisée (#2932) | tests Go |
| nftables | table `inet`, politique d'entrée `drop` ; règles TCP 80/443 valables pour les deux familles ; règles `ip saddr` (SSH, DNS du mesh) **IPv4 seulement** | `nft list` |
| WireGuard | 51821, 51822 et 51825 écoutent en IPv4 **et** IPv6 ; 51823 et 51824 en IPv4 seulement | `ss -lun` |
| Relais UDP gk2 → cartes | table `ip secubox_relais_wg` : **IPv4 seulement** | `nft` |
| DNS (unbound) | écoute déjà en IPv6, y compris sur l'adresse publique `…::200:53` ; bloqué aujourd'hui par le pare-feu de la Freebox ET par nftables (aucune règle d'entrée 53 pour une source IPv6) | `ss`, `nft` |
| p2p/mesh | réseau interne `10.10.0.0/24` IPv4 ; point d'accès d'un pair IPv6 corrigé (`[adr]:port`, #2936) | tests |
| MTU | `wg-mesh` à 1420 ; **aucune règle de serrage du MSS active** ; ICMPv6 « paquet trop grand » accepté | `nft`, `sysctl` |

## Phase 1 — ouverture contrôlée de gk2 (TCP 80/443 puis UDP)

**Portée (mon choix)** : HAProxy 80/443 et WireGuard UDP en IPv6. **Pas** le DNS ni SSH : ils restent fermés à l'Internet IPv6.

Ordre, chaque étape avec son contrôle et son retour arrière :

1. **Préparer sans ouvrir.** Déployer les paquets préparés (freebox 0.5.1, sbxwaf, haproxy, p2p) ; `haproxyctl generate` avec
   `ipv6 = true` sur un fichier de **test**, `haproxy -c`, ne pas recharger. Contrôle : configuration valide.
2. **Fermer ce qui ne doit pas sortir (avant d'ouvrir).** nftables : règle d'entrée explicite
   `ip6 saddr != { <préfixe LAN>, fe80::/10 } tcp/udp dport { 22, 53, 8404, 9443, 9080 } drop` placée avant les règles
   permissives, avec un compteur. Contrôle : `nft -c`, compteur à zéro avant ouverture.
3. **HAProxy en IPv6.** `ipv6 = true` dans `haproxy.toml`, `haproxyctl generate`, rechargement (jamais de redémarrage en
   rafale). Contrôle : `ss -ltn` montre `[::]:80` et `[::]:443`. Retour : `ipv6 = false` + regénération.
4. **UDP/WireGuard.** Doubler le relais en `inet` (ou ajouter `ip6`) pour les ports retenus ; faire écouter en IPv6
   51823/51824 seulement si leur usage l'exige. Contrôle : un pair joint gk2 par son adresse IPv6.
5. **Freebox : désactiver le pare-feu IPv6.** **Seule étape qui expose le réseau**. Elle rend joignable en IPv6 **toutes** les
   machines du réseau, pas seulement gk2 (leur propre pare-feu les protège). Confirmation explicite du propriétaire, comptage
   préalable des machines à adresse publique (liste des appareils de la Freebox), journal d'audit, **minuterie de retour
   automatique** (réactivation du pare-feu sous 10 min sans confirmation, comme pour le pare-feu par zones). **(mon choix)**
6. **DNS public.** Rétablir l'enregistrement `AAAA` de `secubox.in` et des vhosts retenus vers `2a01:e0a:dec:c4e0::200`
   (la sauvegarde de l'ancien est sur gk2, `/root/secubox.in-AAAA-sauvegarde.json`). TTL court (300 s) pendant l'essai.
7. **Essai depuis l'extérieur** (un hôte réellement externe, pas le LAN) : `curl -6` sur chaque vhost, vérification d'une
   requête bloquée par le WAF (et du bannissement dans `waf_ban6`), SSH et DNS **fermés**. Retour arrière de tout en une
   commande (script `ipv6-retour`) : pare-feu Freebox réactivé, `AAAA` supprimé, `ipv6 = false`.

## Phase 2 — observabilité IPv4 / IPv6 comparée

Objectif : voir en direct, **par couche et par famille**, ce que fait chaque pile.

- **Couches et sources** : nftables (compteurs nommés par famille : paquets, écartés, scans — des ensembles `sbx_scan_seen4/6`
  existent déjà), HAProxy (statistiques par frontal, ajouter l'écouteur IPv6 en frontal distinct pour séparer les
  compteurs), sbxwaf (requêtes, bloquées, bannies par famille), nginx (journal : famille déduite de l'adresse).
- **Métriques** : débit, connexions, taux d'erreurs, latence de première réponse, paquets écartés, bannissements — pour
  IPv4 et IPv6 côte à côte, rapport IPv6/IPv4.
- **Interface** : l'onglet « Temps réel » de `/netdiag/` gagne une vue « IPv4 / IPv6 » (mêmes cartes, deux colonnes). Aucune
  fausse valeur : une famille sans mesure affiche « — ».
- **Auto-contrôle** : sondes périodiques, sortantes (`ping -6`, résolution AAAA, connexion à un service tiers en IPv6) et
  entrantes (depuis un hôte tiers, si disponible), résultat « IPv4 ok / IPv6 ok / dégradé » écrit pour le hub et alimentant les
  alertes. Un IPv6 qui **disparaît** (changement de préfixe de l'opérateur) est une alerte, pas un silence.

## Phase 3 — zones, gardes, MTU (hors de la première livraison)

- **Pare-feu par zones** (#2891, suspendu) : le modèle de zones est écrit pour les deux familles dès le départ ; une règle
  `ip saddr` sans pendant `ip6 saddr` est un défaut de conception (test dédié).
- **Gardes** : `ipv6guard` (déjà dans le profil minimal) et `dns-guard` auditent les règles écrites en IPv4 seulement.
- **MTU / PMTU** : serrage du MSS actif sur gk2 ; mesures de MTU de chemin par famille (sondes avec bit DF ; en IPv6 les
  routeurs ne fragmentent pas) ; alertes de trou noir ; MTU par interface réglable avec retour arrière, **conseillé avant
  d'être imposé** (un MTU faux sur le WAN coupe tout). Voir la réponse du 2026-10-19.

## Non-objectifs

NAT64/DNS64, IPv6 du réseau interne du mesh (`10.10.0.0/24` reste IPv4), exposition automatique de nouveaux services,
suppression de l'IPv4.

## Anti-objectifs

Ouvrir SSH, DNS ou les ports d'administration à l'Internet IPv6 ; exposer une machine du LAN sans que le propriétaire l'ait
vu dans la liste ; perdre l'accès d'administration à gk2 (retour arrière automatique à l'étape 5) ; une fausse « santé »
IPv6 affichée sans mesure.

## À trancher par le propriétaire

1. **Étape 5** : acceptez-vous que le pare-feu IPv6 de la Freebox soit désactivé (avec la minuterie de retour) ? Alternative :
   rester en IPv4 pour le public et ne tester l'IPv6 que depuis le LAN.
2. **Portée des vhosts** en IPv6 : tous, ou une liste courte pour l'essai (`secubox.in`, `admin.gk2` exclu) ?
3. **Hôte d'essai externe** : disposez-vous d'une machine hors du réseau (ex. VPS) d'où lancer `curl -6` ?
