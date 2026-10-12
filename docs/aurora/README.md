<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
-->
# Galerie du profil projet référence Aurora

Une capture « bureau » (1400 px) et une capture « mobile » (420 px, `?embed=1`) de chaque page, **en mode démonstration** : les données sont
fictives et le bandeau orange le dit. On ne publie volontairement **aucune capture authentifiée** d'une box (adresses, noms d'appareils,
empreintes). Les règles qui produisent ces pages sont dans [`.claude/AURORA-REFERENCE.md`](../../.claude/AURORA-REFERENCE.md).

Régénérer : `python3 scripts/snapshots-aurora.py [préfixe…]` (playwright + Pillow).

**Captures de données réelles, identifiants masqués** (wiki) : `SBX_TOKEN=<jeton de session> SBX_BASE=https://admin.<domaine> python3 scripts/snapshots-live.py [dossier] [préfixe…]`.
Le jeton vient de l'environnement, jamais du dépôt (copié depuis `localStorage.sbx_token` d'une session ouverte). Le navigateur masque avant la capture les adresses IP et MAC, les clés
et empreintes, les courriels et les noms de domaine, et floute les noms d'appareils des pages qui en montrent. Un masque est un filet : **relire chaque capture avant de la publier**.

## Anatomie d'une page (voir `waf-vue`)

| Zone | Rôle |
|---|---|
| `.cadre` | conteneur de requêtes (`container-name:a`), sans `min-height` ; c'est lui qu'on mesure pour annoncer la hauteur |
| `.app` | carte principale : bordure `--trait2`, dégradé sombre, halo cyan |
| `.tete` | marque, pastille d'état, heure, bouton Rafraîchir |
| bandeaux | orange = démonstration ; cyan = « session requise » |
| `.tuiles` | synthèse chiffrée, chaque tuile avec sa définition en infobulle ; « — » sans mesure |
| `.pan` | panneaux : courbes, barres, donuts, tableaux, cartes — SVG écrits à la main |

## Les pages

### WAF — Vue d'ensemble (le modèle)

`packages/secubox-waf-ng/composants/waf/www/waf/vue.html` — Le modèle. Bandeau d'état, 6 tuiles, carte du monde (grille 60×120), évolution, répartition (donut), derniers événements, campagnes, leurres.

| Bureau | Mobile |
|---|---|
| ![WAF — Vue d'ensemble (le modèle) — bureau](waf-vue-bureau.webp) | ![WAF — Vue d'ensemble (le modèle) — mobile](waf-vue-mobile.webp) |

### WAF — Menaces

`packages/secubox-waf-ng/composants/waf/www/waf/menaces.html` — Tuiles de menaces, tableau d'événements à pastilles de gravité, deux anneaux (gravité, catégorie), origine des attaques, sites visés, détections comportementales.

| Bureau | Mobile |
|---|---|
| ![WAF — Menaces — bureau](waf-menaces-bureau.webp) | ![WAF — Menaces — mobile](waf-menaces-mobile.webp) |

### WAF — Attaquants suivis

`packages/secubox-waf-ng/composants/waf/www/waf/attaquants.html` — Classement en cartes avec nature de l'IP, jauge de sondes, catégories en pastilles, filtre/tri/recherche, frise des 10 plus actifs.

| Bureau | Mobile |
|---|---|
| ![WAF — Attaquants suivis — bureau](waf-attaquants-bureau.webp) | ![WAF — Attaquants suivis — mobile](waf-attaquants-mobile.webp) |

### WAF — Campagnes

`packages/secubox-waf-ng/composants/waf/www/waf/campagnes.html` — Une carte par campagne (empreinte, adresses, cible, catégories, état), frise chronologique SVG, répartitions.

| Bureau | Mobile |
|---|---|
| ![WAF — Campagnes — bureau](waf-campagnes-bureau.webp) | ![WAF — Campagnes — mobile](waf-campagnes-mobile.webp) |

### WAF — Surfaces

`packages/secubox-waf-ng/composants/waf/www/waf/surfaces.html` — Barres des surfaces sondées, carte des pays, comptes visés, leurres touchés, noms non servis.

| Bureau | Mobile |
|---|---|
| ![WAF — Surfaces — bureau](waf-surfaces-bureau.webp) | ![WAF — Surfaces — mobile](waf-surfaces-mobile.webp) |

### WAF — Visites

`packages/secubox-waf-ng/composants/waf/www/waf/visites.html` — Donuts types de client et systèmes, statuts HTTP par classe, vhosts, carte des pays.

| Bureau | Mobile |
|---|---|
| ![WAF — Visites — bureau](waf-visites-bureau.webp) | ![WAF — Visites — mobile](waf-visites-mobile.webp) |

### WAF — Historique

`packages/secubox-waf-ng/composants/waf/www/waf/historique.html` — Aires empilées par gravité, histogramme journalier avec pic et moyenne, sélecteur de période, meilleurs attaquants.

| Bureau | Mobile |
|---|---|
| ![WAF — Historique — bureau](waf-historique-bureau.webp) | ![WAF — Historique — mobile](waf-historique-mobile.webp) |

### DPI — Vue d'ensemble

`packages/secubox-dpi/www/dpi/vue.html` — Tuiles de trafic, flux appareils → usages, applications, appareils principaux.

| Bureau | Mobile |
|---|---|
| ![DPI — Vue d'ensemble — bureau](dpi-vue-bureau.webp) | ![DPI — Vue d'ensemble — mobile](dpi-vue-mobile.webp) |

### ndpid — Flux

`packages/secubox-dpi/composants/ndpid/www/ndpid/flux.html` — Tableau de flux filtrable et triable, risque en pastille, donut des protocoles, hôtes les plus actifs.

| Bureau | Mobile |
|---|---|
| ![ndpid — Flux — bureau](ndpid-flux-bureau.webp) | ![ndpid — Flux — mobile](ndpid-flux-mobile.webp) |

### ndpid — Protocoles

`packages/secubox-dpi/composants/ndpid/www/ndpid/protocoles.html` — Donut des protocoles, classement des applications (octets/flux), catégories, part chiffrée.

| Bureau | Mobile |
|---|---|
| ![ndpid — Protocoles — bureau](ndpid-protocoles-bureau.webp) | ![ndpid — Protocoles — mobile](ndpid-protocoles-mobile.webp) |

### ndpid — Empreintes

`packages/secubox-dpi/composants/ndpid/www/ndpid/empreintes.html` — Classement des empreintes TLS (hash court + copier), familles, SNI, confiance.

| Bureau | Mobile |
|---|---|
| ![ndpid — Empreintes — bureau](ndpid-empreintes-bureau.webp) | ![ndpid — Empreintes — mobile](ndpid-empreintes-mobile.webp) |

### ndpid — Risques

`packages/secubox-dpi/composants/ndpid/www/ndpid/risques.html` — Risques nDPI en français avec définition en infobulle, hôtes exposés, anneaux de gravité.

| Bureau | Mobile |
|---|---|
| ![ndpid — Risques — bureau](ndpid-risques-bureau.webp) | ![ndpid — Risques — mobile](ndpid-risques-mobile.webp) |

### ndpid — Réglages

`packages/secubox-dpi/composants/ndpid/www/ndpid/reglages.html` — Réglages affichés, actions démarrer/arrêter/redémarrer/mirred avec confirmation intégrée.

| Bureau | Mobile |
|---|---|
| ![ndpid — Réglages — bureau](ndpid-reglages-bureau.webp) | ![ndpid — Réglages — mobile](ndpid-reglages-mobile.webp) |

### SOC — Guardian

`packages/secubox-soc/www/soc/guardian.html` — Guardian (maquette « Mode Canari ») encadré dans le SOC : carte des attaques, catégories, canaris, état du mode.

| Bureau | Mobile |
|---|---|
| ![SOC — Guardian — bureau](soc-guardian-bureau.webp) | ![SOC — Guardian — mobile](soc-guardian-mobile.webp) |

### SOC — Réseau en direct

`packages/secubox-soc/www/soc/reseau.html` — Débit par interface sur 24 h (échelle commune, groupes Interfaces/Tunnels/Conteneurs), paquets écartés par catégorie.

| Bureau | Mobile |
|---|---|
| ![SOC — Réseau en direct — bureau](soc-reseau-bureau.webp) | ![SOC — Réseau en direct — mobile](soc-reseau-mobile.webp) |

### Threats

`packages/secubox-threats/www/threats/index.html` — Chronologie 24 h empilée, jauge et classement du score, alertes, IOC, incidents, flux de renseignement.

| Bureau | Mobile |
|---|---|
| ![Threats — bureau](threats-bureau.webp) | ![Threats — mobile](threats-mobile.webp) |

### Metrics — Vue d'ensemble

`packages/secubox-metrics/www/metrics/index.html` — Santé globale, jauges CPU/mémoire/disque, courbes 24 h, services, connexions, trafic WAF, certificats.

| Bureau | Mobile |
|---|---|
| ![Metrics — Vue d'ensemble — bureau](metrics-index-bureau.webp) | ![Metrics — Vue d'ensemble — mobile](metrics-index-mobile.webp) |

### Metrics — Sites

`packages/secubox-metrics/www/metrics/vhosts.html` — Classement des sites trié/filtré, donut des statuts, histogramme par jour, détail d'un site, certificats.

| Bureau | Mobile |
|---|---|
| ![Metrics — Sites — bureau](metrics-vhosts-bureau.webp) | ![Metrics — Sites — mobile](metrics-vhosts-mobile.webp) |

### Toolbox — Vue d'ensemble

`packages/secubox-toolbox/www/toolbox/apercu.html` — Niveau R actif, clients, flux interceptés, pubs bloquées, débit réseau, détections de la sentinelle.

| Bureau | Mobile |
|---|---|
| ![Toolbox — Vue d'ensemble — bureau](toolbox-apercu-bureau.webp) | ![Toolbox — Vue d'ensemble — mobile](toolbox-apercu-mobile.webp) |

### Toolbox — Clients

`packages/secubox-toolbox/www/toolbox/clients.html` — Cartes clients avec niveau R, donut par niveau, filtres ; remise à zéro avec confirmation intégrée.

| Bureau | Mobile |
|---|---|
| ![Toolbox — Clients — bureau](toolbox-clients-bureau.webp) | ![Toolbox — Clients — mobile](toolbox-clients-mobile.webp) |

### Toolbox — Filtres MITM

`packages/secubox-toolbox/www/toolbox/filtres.html` — Règles de filtrage (activer/supprimer), splice whitelist, propositions auto-apprises.

| Bureau | Mobile |
|---|---|
| ![Toolbox — Filtres MITM — bureau](toolbox-filtres-bureau.webp) | ![Toolbox — Filtres MITM — mobile](toolbox-filtres-mobile.webp) |

### Toolbox — Cartographie sociale

`packages/secubox-toolbox/www/toolbox/social.html` — Graphe SVG réseau → fournisseurs, classement des trackers, appareils exposés, quarantaine.

| Bureau | Mobile |
|---|---|
| ![Toolbox — Cartographie sociale — bureau](toolbox-social-bureau.webp) | ![Toolbox — Cartographie sociale — mobile](toolbox-social-mobile.webp) |

### Toolbox — Pubs

`packages/secubox-toolbox/www/toolbox/pubs.html` — Blocage publicitaire : taux, régies, domaines appris, candidats, interrupteur Ad-Guard.

| Bureau | Mobile |
|---|---|
| ![Toolbox — Pubs — bureau](toolbox-pubs-bureau.webp) | ![Toolbox — Pubs — mobile](toolbox-pubs-mobile.webp) |

### Toolbox — Tor

`packages/secubox-toolbox/www/toolbox/tor.html` — Circuit (schéma indicatif), pays de sortie, clients VPN, ponts, vérification de fuite, émancipation.

| Bureau | Mobile |
|---|---|
| ![Toolbox — Tor — bureau](toolbox-tor-bureau.webp) | ![Toolbox — Tor — mobile](toolbox-tor-mobile.webp) |

### Toolbox — Sentinelle

`packages/secubox-toolbox/www/toolbox/sentinelle.html` — Capteur, verdicts, répartition par type, chronologie, C2 appris (action « ignorer »).

| Bureau | Mobile |
|---|---|
| ![Toolbox — Sentinelle — bureau](toolbox-sentinelle-bureau.webp) | ![Toolbox — Sentinelle — mobile](toolbox-sentinelle-mobile.webp) |

### Toolbox — Config

`packages/secubox-toolbox/www/toolbox/config.html` — Configuration affichée (jamais de clé privée), certificats, politiques, exports.

| Bureau | Mobile |
|---|---|
| ![Toolbox — Config — bureau](toolbox-config-bureau.webp) | ![Toolbox — Config — mobile](toolbox-config-mobile.webp) |

### Actor Intelligence — Renseignement

`packages/secubox-webos/www/actor-intelligence/index.html` — Renseignement : acteurs, scores, modes, carte et tuiles sur les mêmes jetons.

| Bureau | Mobile |
|---|---|
| ![Actor Intelligence — Renseignement — bureau](actor-bureau.webp) | ![Actor Intelligence — Renseignement — mobile](actor-mobile.webp) |

### Guardian (filtrage DNS)

`packages/secubox-ad-guard/www/guardian/index.html` — Tableau de bord du filtrage DNS : tuiles, requêtes 24 h, types bloqués, appareils.

| Bureau | Mobile |
|---|---|
| ![Guardian (filtrage DNS) — bureau](guardian-bureau.webp) | ![Guardian (filtrage DNS) — mobile](guardian-mobile.webp) |

### NAC — Appareils et zones

`packages/secubox-nac/www/nac/index.html` — Tuiles filtres (état, zone, connexion), appareils réels agrégés (NAC, DPI, DNS, Toolbox), comportement des zones, noms et services Bonjour.

| Bureau | Mobile |
|---|---|
| ![NAC — Appareils et zones — bureau](nac-bureau.webp) | ![NAC — Appareils et zones — mobile](nac-mobile.webp) |

### Filtre web

`packages/secubox-webfilter/www/webfilter/index.html` — Observation par catégorie, profils, exceptions par appareil, domaines toujours bloqués, application différée.

| Bureau | Mobile |
|---|---|
| ![Filtre web — bureau](webfilter-bureau.webp) | ![Filtre web — mobile](webfilter-mobile.webp) |

### Ad Guard

`packages/secubox-ad-guard/www/ad-guard/index.html` — Filtrage DNS : tuiles, requêtes, familles de domaines, blocage différé, confirmations intégrées.

| Bureau | Mobile |
|---|---|
| ![Ad Guard — bureau](ad-guard-bureau.webp) | ![Ad Guard — mobile](ad-guard-mobile.webp) |

### DNS Guard

`packages/secubox-dns-guard/www/dns-guard/index.html` — Garde DNS : anomalies, résolveur, état et actions.

| Bureau | Mobile |
|---|---|
| ![DNS Guard — bureau](dns-guard-bureau.webp) | ![DNS Guard — mobile](dns-guard-mobile.webp) |

### Anomalies réseau

`packages/secubox-dns-guard/composants/network-anomaly/www/network-anomaly/index.html` — Débits mesurés, lignes de base automatiques, classement des anomalies et détail.

| Bureau | Mobile |
|---|---|
| ![Anomalies réseau — bureau](network-anomaly-bureau.webp) | ![Anomalies réseau — mobile](network-anomaly-mobile.webp) |

### WireGuard

`packages/secubox-wireguard/www/wireguard/index.html` — Tunnels dépliables, pairs, trafic par tunnel, ajout de pair, confirmation avant de descendre un tunnel d'administration.

| Bureau | Mobile |
|---|---|
| ![WireGuard — bureau](wireguard-bureau.webp) | ![WireGuard — mobile](wireguard-mobile.webp) |

### Interceptor

`packages/secubox-interceptor/www/interceptor/index.html` — Supervision de l'inspection : moteurs sbxmitm et sbxwaf, activité, classes nDPI, cartes des entrées et sorties, exclusions.

| Bureau | Mobile |
|---|---|
| ![Interceptor — bureau](interceptor-bureau.webp) | ![Interceptor — mobile](interceptor-mobile.webp) |

### Modes réseau

`packages/secubox-netmodes/www/netmodes/index.html` — Mode jamais inventé (« inconnu »), interfaces, sortie Internet lue dans la route par défaut, détection matérielle, application confirmée.

| Bureau | Mobile |
|---|---|
| ![Modes réseau — bureau](netmodes-bureau.webp) | ![Modes réseau — mobile](netmodes-mobile.webp) |

### Caches de la box

`packages/secubox-cdn/www/cdn/index.html` — Taille, fichiers et activité de chaque cache réel de /var/cache/secubox ; dossier fermé = tiret ; politiques non appliquées signalées.

| Bureau | Mobile |
|---|---|
| ![Caches de la box — bureau](cdn-bureau.webp) | ![Caches de la box — mobile](cdn-mobile.webp) |
