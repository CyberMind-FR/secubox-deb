<!-- SPDX-License-Identifier: LicenseRef-CMSD-1.0 -->
<!-- Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr> -->

# Profils SecuBox : tableau comparatif et prompt de vulgarisation

Deux notions se croisent et se confondent facilement :

- **Niveau (tier)** : ce que la machine peut porter, selon sa mémoire. Fichiers `profiles/tier-*.yaml`, appliqués par `secubox-profiles`.
- **Méta-paquet** : ce qu'on installe. `secubox-lite`, `secubox-isp`, `secubox-full` ne contiennent rien eux-mêmes, ils tirent d'autres paquets par leurs dépendances.

## 1. Niveaux (selon la mémoire de la machine)

| | **lite** | **standard** | **pro** |
|---|---|---|---|
| Mémoire visée | 1 à 2 Go | 4 à 8 Go | 8 Go et plus |
| Machine type | ESPRESSObin | Raspberry Pi 400, boîtes 4 Go | MOCHAbin |
| Analyse du trafic (DPI) | en miroir (léger) | en miroir (observe) | en ligne (inline) |
| Conteneurs LXC | non | oui | oui |
| Swap | 512 Mo | aucun | aucun |
| Obligatoire | WireGuard, modes réseau, contrôle d'accès | + DPI, QoS, WAF, HAProxy, vhosts | `secubox-full` |
| Exclus | Ollama, Jellyfin, Matrix, Nextcloud, Gitea | — | — |

## 2. Méta-paquets (ce qui est installé)

Les profils s'emboîtent : **isp = lite + hébergement simple**, **full = isp + tout le parc gk2**.

| | **secubox-lite** 1.3.0 | **secubox-isp** 1.2.0 | **secubox-full** 1.4.0 |
|---|---|---|---|
| Rôle | Protections uniquement | Couche protégée, hébergement simple et limité | Totalité du parc actuel (comme gk2) |
| Protections | Pare-feu nftables, WAF (`sbxwaf`, HAProxy), DPI, MITM (`sbxmitm`), ad-guard, webfilter, menaces, anti-rootkit, mac-guard, contrôle d'accès (NAC), WireGuard, durcissement | Celles de lite | Celles de lite |
| Réseau / FAI | DNS | + routage, QoS, certificats, exposition, Tor, maillage, supervision | idem isp |
| Hébergement | aucun | simple : metablogizer, publish | complet : Nextcloud, Gitea, Jellyfin, PeerTube, courrier, radio, BBS, billets, Zigbee, IA, voix… |
| Niveau adapté | lite (2 Go) | standard (4 Go) | pro (8 Go) |

## 3. Coût mémoire des deux modules DNS (mesures du 2026-10-04)

| Élément | Coût |
|---|---|
| Unbound avec le puits ad-guard complet (656 704 zones) | ~295 Mo, démarrage 6,9 s |
| Webfilter, observation seule | négligeable, aucune zone écrite dans Unbound |
| Webfilter, une vue qui bloque (≈ 312 000 zones) | ~+100 Mo, démarrage 9,4 s |
| Chaque configuration de blocage distincte | +1 vue, donc ~+100 Mo |

Conséquence pour **lite (2 Go)** : avec le WAF, le DPI et le MITM en plus, ad-guard et webfilter ne tiennent qu'avec les listes par défaut réduites et un seul profil de blocage. À mesurer sur une machine 2 Go.

## 4. Prompt pour ChatGPT (vulgarisation et définitions)

```text
Tu es rédacteur technique et vulgarisateur. Tu t'adresses à un lecteur non
spécialiste (commerçant, élu, particulier curieux) qui doit comprendre quel
produit SecuBox choisir. Réponds en français, sans jargon non défini.

Contexte : SecuBox est un boîtier de sécurité réseau libre qui protège un
réseau local (maison, petite structure). Il existe en trois niveaux selon la
mémoire de la machine (lite 1 à 2 Go, standard 4 à 8 Go, pro 8 Go et plus) et
en trois ensembles installables qui s'emboîtent : "lite" (les protections
uniquement : pare-feu, WAF, analyse du trafic, filtrage), "isp" (lite plus un
hébergement simple et limité, par exemple un blog) et "full" (tout le parc :
Nextcloud, Jellyfin, courrier, radio, etc.).
Deux modules touchent au DNS : "ad-guard" (retire publicités et traceurs sur
les téléviseurs et appareils) et "webfilter" (contrôle parental et blocage de
sites dangereux ou pour adultes, par appareil).

Tâches :
1. Écris un glossaire de 15 à 20 termes, une phrase simple chacun, avec une
   analogie du quotidien : DNS, résolveur, WAF, pare-feu, DPI, VPN/WireGuard,
   NAC, QoS, HAProxy, TLS, LXC/conteneur, métapaquet, Tor, maillage (mesh),
   liste de blocage, puits DNS (sinkhole), observation vs blocage.
2. Explique en 10 lignes maximum la différence entre "niveau" et "ensemble".
3. Pour chaque ensemble (lite, isp, full), donne : à qui il s'adresse, ce
   qu'il protège, ce qu'il ne fait pas, la machine conseillée.
4. Termine par un arbre de décision de 5 questions ("Avez-vous des enfants à
   protéger ?", "Hébergez-vous vos propres services ?"...) menant au bon choix.

Contraintes : aucun nom de marque de concurrent, pas de promesse de sécurité
absolue, ton clair et rassurant, pas plus de 900 mots hors glossaire.
```
