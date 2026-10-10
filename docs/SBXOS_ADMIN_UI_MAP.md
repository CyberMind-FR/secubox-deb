<!-- SPDX-License-Identifier: LicenseRef-CMSD-1.0 -->
<!-- Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr> -->
<!-- GÉNÉRÉ par scripts/generate-admin-ui-map.py — ne pas éditer à la main ; la source est packages/secubox-hub/espaces.json -->
# SBXOS Admin — matrice de migration vers les six espaces (#2212)

127 entrées de menu, rattachées chacune à un espace et à un objet central. **Aucune route n'est supprimée ni déplacée** : toutes les pages gardent leur chemin ; seule la navigation les regroupe. Colonnes : ancienne page · nouvelle section · objet · route conservée · composant réutilisé · réécriture nécessaire ? · risque.

## 🏠 1 — Vue d'ensemble (3)

| Ancienne page | Chemin conservé | Objet | Composant réutilisé | Réécriture ? | Risque | Remarque |
|---|---|---|---|---|---|---|
| Dashboard (`hub`) | `/` oui | BOX | `packages/secubox-hub/www` + sidebar.js | non (page conservée) ; la VUE D'ENSEMBLE est une page nouvelle qui agrège ses caches | moyen | tableau de bord lourd : ne pas en faire une seconde page de configuration |
| Health Monitor (`health`) | `/health/` oui | BOX | `packages/secubox-hub/www` + sidebar.js | non | faible | source de la santé des services |
| Vue d'ensemble (`apercu`) | `/apercu/` oui | BOX | `packages/secubox-hub/www` + sidebar.js | non | faible |  |

## 🛡️ 2 — Protection (21)

| Ancienne page | Chemin conservé | Objet | Composant réutilisé | Réécriture ? | Risque | Remarque |
|---|---|---|---|---|---|---|
| Ad Guard (`ad-guard`) | `/ad-guard/` oui | DEVICE | `packages/secubox-ad-guard/www` + sidebar.js | non | faible | porte déjà une vue par appareil (DNS) : à relier à la fiche appareil |
| Anti-Rootkit (`antirootkit`) | `/antirootkit/` oui | ALERT | `packages/secubox-security-posture/www` + sidebar.js | non | faible |  |
| Cookie Tracker (`cookies`) | `/cookies/` oui | — | `packages/secubox-cookies/www` + sidebar.js | non | faible |  |
| Cve-triage (`cve-triage`) | `/cve-triage/` oui | UPDATE | `packages/secubox-security-posture/www` + sidebar.js | non | faible |  |
| CyberFeed (`cyberfeed`) | `/cyberfeed/` oui | — | `packages/secubox-ipblock/www` + sidebar.js | non | faible |  |
| Interceptor (`interceptor`) | `/interceptor/` oui | — | `packages/secubox-interceptor/www` + sidebar.js | non | faible |  |
| IP Blocklist (`ipblock`) | `/ipblock/` oui | — | `packages/secubox-ipblock/www` + sidebar.js | non | faible |  |
| R-Level (`rlevel`) | `/rlevel/` oui | DEVICE | `packages/secubox-toolbox/www` + sidebar.js | non | faible |  |
| ThreatMesh (`threatmesh`) | `/threatmesh/` oui | ACTOR | `packages/secubox-threatmesh/www` + sidebar.js | non | faible |  |
| ToolBoX (`toolbox`) | `/toolbox/` oui | DEVICE | `packages/secubox-toolbox/www` + sidebar.js | non | faible |  |
| Vortex Firewall (`vortex-firewall`) | `/vortex-firewall/` oui | — | `packages/secubox-ipblock/www` + sidebar.js | non | faible |  |
| WAF (`waf`) | `/waf/` oui | — | `packages/secubox-waf-ng/www` + sidebar.js | non | moyen | cinq pages (waf, tableau, micro, racine, actor) : regrouper par navigation seulement |
| DNS Guard (`dns-guard`) | `/dns-guard/` oui | — | `packages/secubox-dns-guard/www` + sidebar.js | non | faible |  |
| Exposure (`exposure`) | `/exposure/` oui | SERVICE | `packages/secubox-haproxy/www` + sidebar.js | non | faible |  |
| Filtrage de contenus (`webfilter`) | `/webfilter/` oui | DEVICE | `packages/secubox-webfilter/www` + sidebar.js | non | faible |  |
| HAProxy (`haproxy`) | `/haproxy/` oui | — | `packages/secubox-haproxy/www` + sidebar.js | non | faible |  |
| ProxyPAC (`proxypac`) | `/proxypac/` oui | — | `packages/secubox-tor/www` + sidebar.js | non | faible |  |
| Reality (`reality`) | `/reality/` oui | — | `packages/secubox-reality/www` + sidebar.js | non | faible | entrée de menu sans page : écartée par le hub |
| Tor (`tor`) | `/tor/` oui | — | `packages/secubox-tor/www` + sidebar.js | non | faible |  |
| WireGuard VPN (`wireguard`) | `/wireguard/` oui | DEVICE | `packages/secubox-wireguard/www` + sidebar.js | non | faible | quatre modules gèrent WireGuard (wireguard, p2p, toolbox, netmodes) : un seul rattachement visible, les autres par lien |
| Hardening (`hardening`) | `/hardening/` oui | BOX | `packages/secubox-hardening/www` + sidebar.js | non | faible |  |

## 👁️ 3 — Surveillance (18)

| Ancienne page | Chemin conservé | Objet | Composant réutilisé | Réécriture ? | Risque | Remarque |
|---|---|---|---|---|---|---|
| AI Insights (`ai-insights`) | `/ai-insights/` oui | ALERT | `packages/secubox-threats/www` + sidebar.js | non | faible |  |
| DPI (`dpi`) | `/dpi/` oui | DEVICE | `packages/secubox-dpi/www` + sidebar.js | non | faible | ne voit que les clients WireGuard : pas de jointure avec ad-guard |
| Media Flow (`mediaflow`) | `/mediaflow/` oui | DEVICE | `packages/secubox-dpi/www` + sidebar.js | non | faible | rangé en « boot » dans le menu actuel : reclassé en Surveillance |
| nDPId (`ndpid`) | `/ndpid/` oui | DEVICE | `packages/secubox-dpi/www` + sidebar.js | non | faible |  |
| Renseignement (`actor`) | `/actor/` oui | ACTOR | `packages/secubox-waf-ng/www` + sidebar.js | non | moyen | relais réservé à l'administrateur (_SOCKETS_ADMIN) : garder la garde |
| Security Posture (`security-posture`) | `/security-posture/` oui | BOX | `packages/secubox-security-posture/www` + sidebar.js | non | faible |  |
| SENTINELLE-GSM (`sentinelle-gsm`) | `/sentinelle/` oui | ALERT | `packages/secubox-sentinelle-gsm/www` + sidebar.js | non | faible |  |
| Soc (`soc`) | `/soc/` oui | ALERT | `packages/secubox-soc/www` + sidebar.js | non | faible |  |
| Threats (`threats`) | `/threats/` oui | ALERT | `packages/secubox-threats/www` + sidebar.js | non | faible |  |
| DevWatch (`devwatch`) | `/devwatch/` oui | SERVICE | `packages/secubox-metanews/www` + sidebar.js | non | faible |  |
| Client Guardian (`nac`) | `/nac/` oui | DEVICE | `packages/secubox-nac/www` + sidebar.js | API d'agrégation à ajouter (fiche appareil), page conservée | moyen | source canonique des appareils (MAC) ; jointure DNS (ad-guard) et trafic (dpi, clients WireGuard seulement) |
| Network-anomaly (`network-anomaly`) | `/network-anomaly/` oui | ALERT | `packages/secubox-dns-guard/www` + sidebar.js | non | faible |  |
| Watchdog (`watchdog`) | `/watchdog/` oui | SERVICE | `packages/secubox-health/www` + sidebar.js | non | faible |  |
| C3box (`c3box`) | `/c3box/` oui | BOX | `packages/secubox-c3box/www` + sidebar.js | non | faible |  |
| Glances (`glances`) | `/glances/` oui | BOX | `packages/secubox-metrics/www` + sidebar.js | non | faible |  |
| Grafana (`grafana`) | `/grafana/` oui | BOX | `packages/secubox-metrics/www` + sidebar.js | non | faible |  |
| Metrics (`metrics`) | `/metrics/` oui | BOX | `packages/secubox-metrics/www` + sidebar.js | non | faible |  |
| Reporter (`reporter`) | `/reporter/` oui | BOX | `packages/secubox-metrics/www` + sidebar.js | non | faible |  |

## 📦 4 — Services (45)

| Ancienne page | Chemin conservé | Objet | Composant réutilisé | Réécriture ? | Risque | Remarque |
|---|---|---|---|---|---|---|
| VoiceStudio (`voicestudio`) | `/voicestudio/` oui | SERVICE | `packages/secubox-voicestudio/www` + sidebar.js | non | faible |  |
| Voix (`voicestudio-usager`) | `/voicestudio/usager.html` oui | SERVICE | `packages/secubox-voicestudio/www` + sidebar.js | non | faible |  |
| ZIA (`zia`) | `/zia/` oui | SERVICE | `packages/secubox-zia/www` + sidebar.js | non | faible |  |
| Billets (`billets`) | `/billets/` oui | SERVICE | `packages/secubox-billets/www` + sidebar.js | non | faible |  |
| Jabber (`jabber`) | `/jabber/` oui | SERVICE | `packages/secubox-matrix/www` + sidebar.js | non | faible |  |
| Jitsi Meet (`jitsi`) | `/jitsi/` oui | SERVICE | `packages/secubox-jitsi/www` + sidebar.js | non | faible |  |
| Mail (`mail`) | `/mail/` oui | SERVICE | `packages/secubox-mail/www` + sidebar.js | non | faible |  |
| Matrix Chat (`matrix`) | `/matrix/` oui | SERVICE | `packages/secubox-matrix/www` + sidebar.js | non | faible |  |
| SMTP Relay (`smtp-relay`) | `/smtp-relay/` oui | SERVICE | `packages/secubox-mail/www` + sidebar.js | non | faible |  |
| SocialRelay (`socialrelay`) | `/social/` oui | SERVICE | `packages/secubox-socialrelay/www` + sidebar.js | non | faible | entrée de menu sans page à son nom : écartée par le hub |
| TURN/STUN Server (`turn`) | `/turn/` oui | SERVICE | `packages/secubox-jitsi/www` + sidebar.js | non | faible |  |
| Audio Mood (`sbxos-audio-mood`) | `/sbxos-audio-mood/` oui | SERVICE | `packages/sbxos-audio-mood/www` + sidebar.js | non | faible | entrée de menu sans page à son nom : écartée par le hub |
| AI Gateway (`ai-gateway`) | `/ai-gateway/` oui | SERVICE | `packages/secubox-ai-gateway/www` + sidebar.js | non | faible |  |
| Localrecall (`localrecall`) | `/localrecall/` oui | SERVICE | `packages/secubox-ai-gateway/www` + sidebar.js | non | faible |  |
| MCP Server (`mcp-server`) | `/mcp-server/` oui | SERVICE | `packages/secubox-ai-gateway/www` + sidebar.js | non | faible |  |
| StreamForge (`streamforge`) | `/streamforge/` oui | SERVICE | `packages/secubox-streamlit/www` + sidebar.js | non | faible |  |
| Streamlit (`streamlit`) | `/streamlit/` oui | SERVICE | `packages/secubox-streamlit/www` + sidebar.js | non | faible |  |
| MQTT (`mqtt`) | `/mqtt/` oui | SERVICE | `packages/secubox-mqtt/www` + sidebar.js | non | faible |  |
| PicoBrew (`picobrew`) | `/picobrew/` oui | SERVICE | `packages/secubox-picobrew/www` + sidebar.js | non | faible |  |
| Zigbee (`zigbee`) | `/zigbee/` oui | SERVICE | `packages/secubox-mqtt/www` + sidebar.js | non | faible |  |
| Jellyfin (`jellyfin`) | `/jellyfin/` oui | SERVICE | `packages/secubox-jellyfin/www` + sidebar.js | non | faible |  |
| Lyrion (`lyrion`) | `/lyrion/` oui | SERVICE | `packages/secubox-lyrion/www` + sidebar.js | non | faible |  |
| Médias externes (`media`) | `/media/` oui | SERVICE | `packages/secubox-media/www` + sidebar.js | non | faible |  |
| PeerTube (`peertube`) | `/peertube/` oui | SERVICE | `packages/secubox-peertube/www` + sidebar.js | non | faible |  |
| Podcaster (`podcaster`) | `/podcaster/` oui | SERVICE | `packages/secubox-podcaster/www` + sidebar.js | non | faible |  |
| Radio (`radio`) | `/radio/` oui | SERVICE | `packages/secubox-radio/www` + sidebar.js | non | faible |  |
| Torrent (`torrent`) | `/torrent/` oui | SERVICE | `packages/secubox-ytsas/www` + sidebar.js | non | faible |  |
| YouTube SAS (`ytsas`) | `/ytsas/` oui | SERVICE | `packages/secubox-ytsas/www` + sidebar.js | non | faible |  |
| Meshtastic (`meshtastic`) | `/meshtastic/` oui | SERVICE | `packages/secubox-meshtastic/www` + sidebar.js | non | faible |  |
| Droplet (`droplet`) | `/droplet/` oui | SERVICE | `packages/secubox-metablogizer/www` + sidebar.js | non | faible |  |
| Gitea (`gitea`) | `/gitea/` oui | SERVICE | `packages/secubox-gitea/www` + sidebar.js | non | faible |  |
| Nextcloud (`nextcloud`) | `/nextcloud/` oui | SERVICE | `packages/secubox-nextcloud/www` + sidebar.js | non | faible |  |
| PhotoPrism (`photoprism`) | `/photoprism/` oui | SERVICE | `packages/secubox-photoprism/www` + sidebar.js | non | faible |  |
| BBS (`bbs`) | `/bbs/` oui | SERVICE | `packages/secubox-bbs/www` + sidebar.js | non | faible |  |
| MetaBlogizer (`metablogizer`) | `/metablogizer/` oui | SERVICE | `packages/secubox-metablogizer/www` + sidebar.js | non | faible |  |
| Publish (`publish`) | `/publish/` oui | SERVICE | `packages/secubox-metablogizer/www` + sidebar.js | non | faible |  |
| Service Catalog (`metacatalog`) | `/metacatalog/` oui | SERVICE | `packages/secubox-appstore/www` + sidebar.js | non | faible |  |
| CDN Cache (`cdn`) | `/cdn/` oui | SERVICE | `packages/secubox-cdn/www` + sidebar.js | non | faible |  |
| Mirror/CDN (`mirror`) | `/mirror/` oui | SERVICE | `packages/secubox-cdn/www` + sidebar.js | non | faible |  |
| SaaS Relay (`saas-relay`) | `/saas-relay/` oui | SERVICE | `packages/secubox-saas-relay/www` + sidebar.js | non | faible |  |
| Virtual Hosts (`vhost`) | `/vhost/` oui | SERVICE | `packages/secubox-haproxy/www` + sidebar.js | non | faible |  |
| App Store (`appstore`) | `/appstore/` oui | SERVICE | `packages/secubox-appstore/www` + sidebar.js | non | faible |  |
| Profiles (`profiles`) | `/profiles/` oui | SERVICE | `packages/secubox-profiles/www` + sidebar.js | non | faible |  |
| MetaNews (`metanews`) | `/metanews/` oui | SERVICE | `packages/secubox-metanews/www` + sidebar.js | non | faible | entrée de menu sans page à son nom : écartée par le hub |
| YaCy (`yacy`) | `/yacy/` oui | SERVICE | `packages/secubox-metanews/www` + sidebar.js | non | faible |  |

## 👤 5 — Identité & accès (11)

| Ancienne page | Chemin conservé | Objet | Composant réutilisé | Réécriture ? | Risque | Remarque |
|---|---|---|---|---|---|---|
| Accès (`acces`) | `/acces/` oui | USER | `packages/secubox-auth/www` + sidebar.js | non | faible |  |
| Identité SBX OS (`sbxid`) | `/sbxid/` oui | USER | `packages/secubox-auth/www` + sidebar.js | non | moyen | le menu redirige vers /identite/ : garder la redirection |
| Portal (`portal`) | `/portal/` oui | USER | `packages/secubox-portal/www` + sidebar.js | non | élevé | page de connexion : hors périmètre de la façade |
| Annuaire (`annuaire`) | `/annuaire/` oui | USER | `packages/secubox-annuaire/www` + sidebar.js | non | faible |  |
| Assistance (`assist`) | `/assist/` oui | USER | `packages/secubox-assist/www` + sidebar.js | non | faible |  |
| Auth Guardian (`auth`) | `/auth/` oui | USER | `packages/secubox-auth/www` + sidebar.js | non | élevé | login, TOTP et portail captif sous un seul nom : ne rien toucher à la logique |
| Certificates (`certs`) | `/certs/` oui | CERTIFICATE | `packages/secubox-certs/www` + sidebar.js | non | faible | certificats de service ; les certificats système restent aussi sous Système |
| Coffre (`vault`) | `/vault/` oui | CERTIFICATE | `packages/secubox-vault/www` + sidebar.js | non | moyen | trois pages (/vault/, /coffre/, /pgp/) dont deux hors menu : raccorder sans les modifier ; ne jamais re-sceller |
| Identity Manager (`avatar`) | `/avatar/` oui | USER | `packages/secubox-avatar/www` + sidebar.js | non | faible | « Identity Manager » dans le menu mesh : entrée à renommer plus tard |
| Users (`users`) | `/users/` oui | USER | `packages/secubox-auth/www` + sidebar.js | non | élevé | comptes SecuBox ; la séparation comptes Linux / identités SBXOS (capacites.py) est inviolable |
| Zero-Knowledge Proof (`zkp`) | `/zkp/` oui | USER | `packages/secubox-zkp/www` + sidebar.js | non | faible |  |

## ⚙️ 6 — Système (29)

| Ancienne page | Chemin conservé | Objet | Composant réutilisé | Réécriture ? | Risque | Remarque |
|---|---|---|---|---|---|---|
| Centres (`centers`) | `/centers/` oui | BOX | `packages/secubox-annuaire/www` + sidebar.js | non | faible |  |
| Flotte (`fleet`) | `/fleet/` oui | BOX | `packages/secubox-annuaire/www` + sidebar.js | non | faible |  |
| MESH 802.11s (`mesh`) | `/mesh/` oui | BOX | `packages/secubox-mesh/www` + sidebar.js | non | faible |  |
| Mesh DNS (`meshname`) | `/meshname/` oui | BOX | `packages/secubox-p2p/www` + sidebar.js | non | faible |  |
| P2P Hub (`p2p`) | `/p2p/` oui | BOX | `packages/secubox-p2p/www` + sidebar.js | non | faible |  |
| Auto-Load (`autoload`) | `/autoload/` oui | BOX | `packages/secubox-autoload/www` + sidebar.js | non | faible | nouveau (#2190) ; lien depuis Identité & accès pour les abonnements |
| Cloner (`cloner`) | `/cloner/` oui | BACKUP | `packages/secubox-backup/www` + sidebar.js | non | faible |  |
| NetBoot (`netboot`) | `/netboot/` oui | BOX | `packages/secubox-netboot/www` + sidebar.js | non | faible |  |
| Releases (`releases`) | `/releases/` oui | UPDATE | `packages/secubox-repo/www` + sidebar.js | non | faible |  |
| VM Manager (`vm`) | `/vm/` oui | SERVICE | `packages/secubox-vm/www` + sidebar.js | non | faible |  |
| Bandwidth Manager (`qos`) | `/qos/` oui | DEVICE | `packages/secubox-qos/www` + sidebar.js | non | faible |  |
| Dns (`dns`) | `/dns/` oui | BOX | `packages/secubox-dns/www` + sidebar.js | non | faible | zones DNS ; le filtrage DNS est sous Protection (dns-guard, ad-guard, webfilter) |
| DNS Provider (`dns-provider`) | `/dns-provider/` oui | CERTIFICATE | `packages/secubox-dns/www` + sidebar.js | non | faible |  |
| Freebox (`freebox`) | `/freebox/` oui | BOX | `packages/secubox-freebox/www` + sidebar.js | non | faible |  |
| Modem (`modem`) | `/modem/` oui | BOX | `packages/secubox-modem/www` + sidebar.js | non | faible |  |
| Network Diagnostics (`netdiag`) | `/netdiag/` oui | BOX | `packages/secubox-routes/www` + sidebar.js | non | faible |  |
| Network Modes (`netmodes`) | `/netmodes/` oui | BOX | `packages/secubox-netmodes/www` + sidebar.js | non | faible |  |
| Network Tuning (`nettweak`) | `/nettweak/` oui | BOX | `packages/secubox-qos/www` + sidebar.js | non | faible |  |
| Routes (`routes`) | `/routes/` oui | BOX | `packages/secubox-routes/www` + sidebar.js | non | faible |  |
| Traffic Shaping (`traffic`) | `/traffic/` oui | BOX | `packages/secubox-qos/www` + sidebar.js | non | faible |  |
| Administration (`admin`) | `/admin/` oui | BOX | `packages/secubox-system/www` + sidebar.js | non | moyen | composant de system : mêmes actions que system et hub |
| APT Repo (`repo`) | `/repo/` oui | UPDATE | `packages/secubox-repo/www` + sidebar.js | non | faible | dépôt APT local : mises à jour |
| Backup (`backup`) | `/backup/` oui | BACKUP | `packages/secubox-backup/www` + sidebar.js | non | moyen | avec cloner et system : restauration à ne pas faire diverger |
| Boxes à préparer (`premier-pas-maitre`) | `/premier-pas-maitre/` oui | BOX | `packages/secubox-premier-pas/www` + sidebar.js | non | faible |  |
| Config Advisor (`config-advisor`) | `/config-advisor/` oui | BOX | `packages/secubox-config-advisor/www` + sidebar.js | non | faible |  |
| Console TUI (`console`) | `(sans page web)` oui | BOX | — | non (TUI sans page web) | faible | sans chemin : le hub l'écarte déjà |
| KSM Memory (`ksm`) | `/ksm/` oui | BOX | `packages/secubox-system/www` + sidebar.js | non | faible |  |
| System Hub (`system`) | `/system/` oui | BOX | `packages/secubox-system/www` + sidebar.js | non | moyen | trois racines « système » (system, admin, hub) avec reboot et mises à jour en double : dédoublonner plus tard |
| Eye Remote (`eye-remote`) | `/eye-remote/` oui | DEVICE | `packages/secubox-eye-remote/www` + sidebar.js | non | faible |  |

## Ce qui est réellement nouveau (aucune page existante à réutiliser)

| Élément | Pourquoi | S'appuie sur |
|---|---|---|
| Page « Vue d'ensemble » | aucune page ne synthétise l'état de la box | caches de `/hub/dashboard`, `/security-posture/overview`, `/metrics/overview`, `/backup/status`, `/repo/summary`, `/health/summary` |
| Recherche globale | aucune recherche côté admin | index des menus (`espaces`), puis objets |
| Panneau de notifications | l'API existe, aucun écran | `GET /api/v1/hub/notifications` (`require_jwt`) |
| Fiche appareil | huit « appareils » avec huit clés, aucune fiche commune | `nac` (source), `ad-guard` (DNS), `dpi` (clients WireGuard) |
| Fiche service | l'état est dispersé entre appstore, profiles et les pages | `appstore`, `health`, `/services/{s}/logs` de metrics |

