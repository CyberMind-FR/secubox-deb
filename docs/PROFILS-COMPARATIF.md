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

## 4. Modules liés à chaque profil

Chaque profil contient celui du dessous : **full ⊃ isp ⊃ lite**.

| Profil | Fonction | Modules |
|---|---|---|
| **lite** (28) | Pare-feu et accès | `vortex-firewall`, `ipblock`, `nac`, `mac-guard`, `wireguard`, `netmodes`, `hardening` |
| | Protection web | `waf`, `waf-ng` (sbxwaf), `haproxy` |
| | Analyse et interception | `dpi`, `ndpid-engine`, `toolbox`, `toolbox-ng` (sbxmitm) |
| | Filtrage DNS | `dns`, `ad-guard`, `webfilter` |
| | Détection | `threats`, `antirootkit`, `security-posture` |
| | Base et supervision | `core`, `hub`, `portal`, `system`, `auth`, `profiles`, `watchdog`, `health-doctor` |
| **isp** (+19) | Réseau d'opérateur | `routes`, `modem`, `qos`, `traffic`, `netdiag`, `mediaflow`, `vortex-dns`, `dns-provider` |
| | Accès et exposition | `certs`, `exposure`, `vhost`, `users`, `defaults`, `tor` |
| | Maillage | `mesh`, `meshname`, `p2p` |
| | Hébergement simple | `metablogizer`, `publish` |
| **full** (+44) | Cloud et collaboration | `nextcloud`, `gitea`, `webmail`, `mail`, `jitsi`, `jabber`, `matrix` |
| | Médias | `jellyfin`, `lyrion`, `photoprism`, `peertube`, `podcaster`, `radio`, `torrent`, `ytsas`, `media` |
| | Édition et réseaux sociaux | `bbs`, `billets`, `streamforge`, `streamlit`, `saas-relay` |
| | Domotique et terrain | `zigbee`, `mqtt`, `picobrew`, `sentinelle-gsm` |
| | Sécurité avancée | `soc`, `threatmesh`, `network-anomaly`, `interceptor`, `reality`, `reporter` |
| | Exploitation | `admin`, `aggregator`, `console`, `metacatalog`, `mirror`, `nettweak`, `assist`, `droplet`, `localrecall`, `turn`, `yacy`, `ndpid` |

## 5. Prompt pour ChatGPT image (infographie à partager)

Version corrigée : seuls figurent des modules qui existent dans le dépôt, sans promesse de sauvegarde ni de conformité.

```text
Crée une infographie claire, format paysage 16:9, style illustration moderne et
chaleureuse, fond clair, quatre couleurs de profil (vert LITE, bleu ISP, orange
FULL, violet CUSTOM), police sans empattement très lisible. Aucun logo de marque
tierce. Texte en français, peu de mots par bulle.

BANDEAU DU HAUT : "SecuBox / SBXOS — couche de sécurité intelligente". Trois ou
quatre mots par fonction : ad-guard (blocage pubs et traceurs), DPI (analyse du
trafic), WAF (protection des services), MITM (analyse HTTPS avec consentement
explicite), filtrage par catégories, journalisation et rapports.

DEUX MODES DE DÉPLOIEMENT (deux schémas côte à côte) :
1. "Derrière une box existante" : Internet → box/routeur (Freebox, Livebox…) →
   SecuBox → vos appareils (TV, ordinateur, mobile, console, objets connectés).
   Légende : "Parfait pour la maison — profil LITE".
2. "SecuBox comme passerelle" : Internet → SecuBox → vos appareils. Légende :
   "La SecuBox remplace la box (DHCP, NAT, Wi-Fi) — profils ISP, FULL, CUSTOM".

QUATRE CARTES DE PROFIL, côte à côte, chacune avec la mémoire conseillée :
- LITE (2 Go) — "Couche de protections complète". ad-guard, DPI, WAF, MITM avec
  consentement, filtrage par catégories, contrôle parental par profils,
  journalisation et alertes, tableau de bord DNS Guard (compteurs par appareil).
  Usage : maison, derrière une box.
- ISP (4 Go) — "Protégé, avec hébergement simple et limité". Toutes les
  protections de LITE + routeur/passerelle, VPN WireGuard, hébergement web simple
  (blog, site vitrine, publication de sites), gestion des domaines et
  certificats, supervision. Usage : association, petite structure.
- FULL (8 Go et plus) — "Protections + services hébergés". Toutes les protections
  + Nextcloud (fichiers, agenda), courrier et webmail, médias (PhotoPrism,
  PeerTube, Jellyfin, radio), domotique Zigbee, Gitea, messagerie et blog.
  Usage : domicile avancé, PME, communauté — son cloud privé.
- CUSTOM — "À la carte". Modules choisis dans l'App Store SecuBox, configuration
  sur mesure. Usage : experts, projets spécifiques.

BANDEAU DU BAS : une rangée de petites icônes "Vie privée préservée", "Réseau plus
sûr", "Contrôle par l'utilisateur", "Moins de pubs", "Modulaire et évolutif".
Phrase finale : "SecuBox ajoute une couche de protection à votre réseau."

À NE PAS REPRÉSENTER : Home Assistant, Kbin, "Forge", sauvegardes, mention du
RGPD ou de toute conformité, promesse de sécurité absolue.
```

## 6. Prompt pour ChatGPT (vulgarisation et définitions)

```text
Tu es rédacteur technique et vulgarisateur. Tu t'adresses à un lecteur non
spécialiste (commerçant, élu, particulier curieux) qui doit comprendre quel
produit SecuBox choisir. Réponds en français, sans jargon non défini.

Contexte : SecuBox est un boîtier de sécurité réseau libre qui protège un
réseau local (maison, petite structure). Il existe en trois niveaux selon la
mémoire de la machine (lite 2 Go, standard 4 à 8 Go, pro 8 Go et plus) et
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
