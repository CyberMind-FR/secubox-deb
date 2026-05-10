# Modules SecuBox

*Documentation complète des modules*

**Total des modules:** 105

[🇬🇧 English](MODULES-EN.md) | [🇫🇷 Français](MODULES-FR.md) | [🇩🇪 Deutsch](MODULES-DE.md) | [🇨🇳 中文](MODULES-ZH.md)

---

## Aperçu

| Modules | Catégorie | Description |
|--------|----------|-------------|
| 🏠 **SecuBox Hub** | Dashboard | Tableau de bord central et centre de contrôle |
| 🛡️ **Security Operations Center** | Dashboard | SOC avec horloge mondiale, carte menaces, tickets |
| 📋 **Migration Roadmap** | Dashboard | Suivi migration OpenWRT vers Debian |
| 📈 **System Metrics** | Dashboard | Tableau de bord métriques système temps réel |
| ⚙️ **Admin Panel** | Dashboard | Panneau d'administration système |
| 🛡️ **CrowdSec** | Security | Moteur de sécurité collaboratif avec analyse comportementale |
| 🔥 **Web Application Firewall** | Security | WAF avec 300+ règles de sécurité OWASP |
| 🔥 **Vortex Firewall** | Security | Pare-feu d'application des menaces basé sur nftables |
| 🔒 **System Hardening** | Security | Durcissement système et noyau pour conformité ANSSI CSPN |
| 🔍 **MITM Proxy** | Security | Inspection trafic et proxy WAF avec auto-ban |
| 🔐 **Auth Guardian** | Security | Gestion unifiée de l'authentification |
| 🛡️ **Network Access Control** | Security | Guardian client et NAC avec quarantaine |
| 🚫 **IP Block Manager** | Security | Gestion du blocage IP et réseau |
| 🔐 **MAC Guard** | Security | Contrôle d'accès par adresse MAC |
| 📡 **Traffic Interceptor** | Security | Interception et analyse du trafic réseau |
| 🍪 **Cookie Manager** | Security | Gestion de la sécurité des cookies et sessions |
| ⚠️ **Threat Dashboard** | Security | Visualisation unifiée des menaces |
| 🔬 **Threat Analyst** | Security | Analyse des menaces assistée par IA |
| 🔴 **CVE Triage** | Security | Suivi et triage des vulnérabilités CVE |
| 🛡️ **Wazuh SIEM** | Security | Intégration SIEM Wazuh |
| 🔒 **OSSEC HIDS** | Security | Détection d'intrusion basée hôte OSSEC |
| 🦞 **OpenClaw Scanner** | Security | Scanner de vulnérabilités réseau |
| 🔌 **IoT Guard** | Security | Surveillance sécurité appareils IoT |
| 🌐 **Network Modes** | Network | Configuration topologie réseau |
| 📊 **QoS Manager** | Network | QoS avec HTB/VLAN |
| 📈 **Traffic Shaping** | Network | Mise en forme trafic TC/CAKE |
| ⚡ **HAProxy** | Network | Load balancer avec TLS 1.3 |
| 🚀 **CDN Cache** | Network | Cache de diffusion de contenu |
| 🏗️ **Virtual Hosts** | Network | Gestion hôtes virtuels Nginx |
| 🛤️ **Routing Manager** | Network | Routage statique et basé sur politiques |
| 🔧 **Network Tweaks** | Network | Réglage des paramètres réseau du noyau |
| 🔍 **Network Diagnostics** | Network | Outils de diagnostic réseau |
| 📉 **Network Anomaly** | Network | Détection d'anomalies réseau |
| 📶 **Modem Manager** | Network | Gestion modem 3G/4G/5G |
| 🌍 **DNS Server** | DNS | Gestion zones DNS BIND |
| 🛡️ **Vortex DNS** | DNS | Pare-feu DNS avec listes de blocage RPZ |
| 📡 **Mesh DNS** | DNS | Résolution domaines réseau mesh |
| 🛡️ **DNS Guard** | DNS | Protection basée sur DNS contre les menaces |
| 🌐 **DNS Provider** | DNS | Intégration fournisseur DNS externe |
| 🚫 **AdGuard** | DNS | Blocage DNS AdGuard Home |
| 🔗 **WireGuard VPN** | VPN | VPN moderne avec intégration noyau |
| 🕸️ **Mesh Network** | VPN | Réseau mesh avec Yggdrasil |
| 🔗 **P2P Network** | VPN | Réseau pair-à-pair |
| 🔗 **MasterLink** | VPN | Fédération mesh SecuBox |
| 🧅 **Tor Network** | Privacy | Anonymat Tor et services cachés |
| 🌐 **Exposure Settings** | Privacy | Gestion unifiée de l'exposition |
| 🔐 **Zero-Knowledge Proofs** | Privacy | Authentification ZKP Hamiltonien |
| 💬 **SimpleX Chat** | Privacy | Messagerie axée sur la vie privée |
| 🔐 **Secret Vault** | Privacy | Gestion des secrets et identifiants |
| 📊 **Netdata** | Monitoring | Surveillance système temps réel |
| 🔬 **Deep Packet Inspection** | Monitoring | DPI avec netifyd/nDPId |
| 🔬 **Netifyd DPI** | Monitoring | Inspection paquets profonde Netifyd |
| 🔬 **nDPId** | Monitoring | Démon nDPI pour analyse trafic |
| 📱 **Device Intelligence** | Monitoring | Découverte actifs et empreintes |
| 👁️ **Watchdog** | Monitoring | Surveillance services et conteneurs |
| 🎬 **Media Flow** | Monitoring | Analyse trafic média |
| 👀 **Glances** | Monitoring | Tableau de bord surveillance système |
| 🔐 **Login Portal** | Access | Portail authentification avec JWT |
| 👥 **User Management** | Access | Gestion identité unifiée |
| 🪪 **Identity Provider** | Access | Fournisseur d'identité SAML/OIDC |
| 📦 **Services Portal** | Services | Portail services C3Box |
| 🦊 **Gitea** | Services | Serveur Git (LXC) |
| ☁️ **Nextcloud** | Services | Synchronisation fichiers (LXC) |
| 🦙 **Ollama** | AI | Serveur LLM local |
| 🤖 **LocalAI** | AI | API locale compatible OpenAI |
| 🚪 **AI Gateway** | AI | Passerelle API modèles IA |
| 💡 **AI Insights** | AI | Aperçus sécurité assistés par IA |
| 🧠 **LocalRecall** | AI | Système mémoire RAG local |
| 🔌 **MCP Server** | AI | Serveur Model Context Protocol |
| 📧 **Mail Server** | Email | Serveur mail Postfix/Dovecot |
| 💌 **Webmail** | Email | Webmail Roundcube/SOGo |
| 📤 **SMTP Relay** | Email | Relais SMTP et smarthost |
| 💬 **Jabber/XMPP** | Email | Serveur messagerie XMPP |
| 🎬 **Jellyfin** | Media | Serveur média |
| 🎵 **Lyrion Music** | Media | Serveur streaming musique |
| 📻 **Web Radio** | Media | Streaming radio Internet |
| 📸 **PhotoPrism** | Media | Gestion photos assistée par IA |
| 📺 **PeerTube** | Media | Plateforme vidéo fédérée |
| 🌊 **Torrent** | Media | Client BitTorrent |
| 📰 **Newsbin** | Media | Client Usenet/NNTP |
| 📰 **Publishing Platform** | Publishing | Tableau de bord publication unifié |
| 💧 **Droplet** | Publishing | Upload et publication fichiers |
| 📝 **Metablogizer** | Publishing | Éditeur site statique avec Tor |
| ✏️ **Hexo Blog** | Publishing | Générateur blog statique |
| 🐘 **GoToSocial** | Publishing | Serveur social ActivityPub |
| 📡 **CyberFeed** | Publishing | Agrégateur flux RSS/Atom |
| 🎨 **Streamlit** | Apps | Plateforme apps Streamlit |
| ⚡ **StreamForge** | Apps | Développement apps Streamlit |
| 📦 **APT Repository** | Apps | Gestion dépôt APT |
| 🏠 **Domoticz** | IoT | Domotique |
| 🏡 **Home Assistant** | IoT | Hub domotique |
| 📡 **Zigbee Gateway** | IoT | Passerelle Zigbee2MQTT |
| 📡 **MQTT Broker** | IoT | Broker MQTT Mosquitto |
| 💬 **Matrix Server** | Communication | Serveur chat Matrix/Synapse |
| 📹 **Jitsi Meet** | Communication | Visioconférence |
| 📞 **VoIP Server** | Communication | VoIP Asterisk/FreePBX |
| 🔄 **TURN Server** | Communication | Serveur relais TURN/STUN |
| ⚙️ **System Hub** | System | Configuration et gestion système |
| 💾 **Backup Manager** | System | Sauvegarde système et LXC |
| 📋 **Config Advisor** | System | Recommandations de configuration |
| 📊 **Reporter** | System | Rapports et analytiques système |
| 🪞 **Mirror Manager** | System | Gestion miroir APT |
| 📀 **System Cloner** | System | Clonage image système |
| 👁️ **Eye Remote** | System | Interface de gestion à distance |
| 🖥️ **RTTY Console** | System | Accès terminal distant |

---

## Modules

### AI

#### 🦙 Ollama

Serveur LLM local

**Fonctionnalités:** Gestion modèles, API, Chat, Support GPU

![Ollama](screenshots/vm/ollama.png)

#### 🤖 LocalAI

API locale compatible OpenAI

**Fonctionnalités:** API OpenAI, Modèles multiples, Embeddings, Génération images

![LocalAI](screenshots/vm/localai.png)

#### 🚪 AI Gateway

Passerelle API modèles IA

**Fonctionnalités:** Limitation débit, Équilibrage charge, Cache, Logs

![AI Gateway](screenshots/vm/ai-gateway.png)

#### 💡 AI Insights

Aperçus sécurité assistés par IA

**Fonctionnalités:** Détection anomalies, Recommandations, Prédictions, Rapports

![AI Insights](screenshots/vm/ai-insights.png)

#### 🧠 LocalRecall

Système mémoire RAG local

**Fonctionnalités:** Stockage vecteurs, Recherche sémantique, Indexation documents, API

![LocalRecall](screenshots/vm/localrecall.png)

#### 🔌 MCP Server

Serveur Model Context Protocol

**Fonctionnalités:** Intégration outils, Gestion contexte, Multi-modèle, API

![MCP Server](screenshots/vm/mcp-server.png)

---

### Access

#### 🔐 Login Portal

Portail authentification avec JWT

**Fonctionnalités:** Auth JWT, Sessions, Récupération mot de passe, Portail captif

![Login Portal](screenshots/vm/portal.png)

#### 👥 User Management

Gestion identité unifiée

**Fonctionnalités:** CRUD utilisateurs, Groupes, Provisioning services, RBAC

![User Management](screenshots/vm/users.png)

#### 🪪 Identity Provider

Fournisseur d'identité SAML/OIDC

**Fonctionnalités:** SAML 2.0, OpenID Connect, Fédération, SSO

![Identity Provider](screenshots/vm/identity.png)

---

### Apps

#### 🎨 Streamlit

Plateforme apps Streamlit

**Fonctionnalités:** Hébergement apps, Déploiement, Gestion, Logs

![Streamlit](screenshots/vm/streamlit.png)

#### ⚡ StreamForge

Développement apps Streamlit

**Fonctionnalités:** Templates, Éditeur code, Aperçu, Déploiement

![StreamForge](screenshots/vm/streamforge.png)

#### 📦 APT Repository

Gestion dépôt APT

**Fonctionnalités:** Gestion paquets, Signature GPG, Multi-distro, Uploads

![APT Repository](screenshots/vm/repo.png)

---

### Communication

#### 💬 Matrix Server

Serveur chat Matrix/Synapse

**Fonctionnalités:** Chiffrement E2E, Fédération, Bridges, Appels

![Matrix Server](screenshots/vm/matrix.png)

#### 📹 Jitsi Meet

Visioconférence

**Fonctionnalités:** Appels vidéo, Partage écran, Enregistrement, Lobby

![Jitsi Meet](screenshots/vm/jitsi.png)

#### 📞 VoIP Server

VoIP Asterisk/FreePBX

**Fonctionnalités:** Extensions, Trunks, IVR, Messagerie vocale

![VoIP Server](screenshots/vm/voip.png)

#### 🔄 TURN Server

Serveur relais TURN/STUN

**Fonctionnalités:** Traversée NAT, WebRTC, TLS, Statistiques

![TURN Server](screenshots/vm/turn.png)

---

### DNS

#### 🌍 DNS Server

Gestion zones DNS BIND

**Fonctionnalités:** Gestion zones, Enregistrements, DNSSEC, DNS inverse

![DNS Server](screenshots/vm/dns.png)

#### 🛡️ Vortex DNS

Pare-feu DNS avec listes de blocage RPZ

**Fonctionnalités:** Listes blocage, RPZ, Flux menaces, DoH/DoT

![Vortex DNS](screenshots/vm/vortex-dns.png)

#### 📡 Mesh DNS

Résolution domaines réseau mesh

**Fonctionnalités:** mDNS/Avahi, DNS local, Découverte services, Intégration mesh

![Mesh DNS](screenshots/vm/meshname.png)

#### 🛡️ DNS Guard

Protection basée sur DNS contre les menaces

**Fonctionnalités:** Blocage malware, Protection phishing, Analytiques, Liste blanche

![DNS Guard](screenshots/vm/dns-guard.png)

#### 🌐 DNS Provider

Intégration fournisseur DNS externe

**Fonctionnalités:** Cloudflare, Route53, DigitalOcean, DNS dynamique

![DNS Provider](screenshots/vm/dns-provider.png)

#### 🚫 AdGuard

Blocage DNS AdGuard Home

**Fonctionnalités:** Blocage pubs, Protection tracking, Contrôle parental, Statistiques

![AdGuard](screenshots/vm/ad-guard.png)

---

### Dashboard

#### 🏠 SecuBox Hub

Tableau de bord central et centre de contrôle

**Fonctionnalités:** Vue système, Surveillance services, Actions rapides, Métriques

![SecuBox Hub](screenshots/vm/hub.png)

#### 🛡️ Security Operations Center

SOC avec horloge mondiale, carte menaces, tickets

**Fonctionnalités:** Horloge mondiale, Carte menaces, Tickets, Intel P2P, Alertes

![Security Operations Center](screenshots/vm/soc.png)

#### 📋 Migration Roadmap

Suivi migration OpenWRT vers Debian

**Fonctionnalités:** Suivi progression, État modules, Vue catégories

![Migration Roadmap](screenshots/vm/roadmap.png)

#### 📈 System Metrics

Tableau de bord métriques système temps réel

**Fonctionnalités:** CPU/Mémoire, Stats réseau, I/O disque, Historique

![System Metrics](screenshots/vm/metrics.png)

#### ⚙️ Admin Panel

Panneau d'administration système

**Fonctionnalités:** Gestion utilisateurs, Config système, Logs, Diagnostics

![Admin Panel](screenshots/vm/admin.png)

---

### Email

#### 📧 Mail Server

Serveur mail Postfix/Dovecot

**Fonctionnalités:** Domaines, Boîtes mail, DKIM, SpamAssassin, ClamAV

![Mail Server](screenshots/vm/mail.png)

#### 💌 Webmail

Webmail Roundcube/SOGo

**Fonctionnalités:** Interface web, Carnet adresses, Calendrier, Mobile

![Webmail](screenshots/vm/webmail.png)

#### 📤 SMTP Relay

Relais SMTP et smarthost

**Fonctionnalités:** Relais, Authentification, Limitation débit, Logs

![SMTP Relay](screenshots/vm/smtp-relay.png)

#### 💬 Jabber/XMPP

Serveur messagerie XMPP

**Fonctionnalités:** Chat, Groupes, Transfert fichiers, Fédération

![Jabber/XMPP](screenshots/vm/jabber.png)

---

### IoT

#### 🏠 Domoticz

Domotique

**Fonctionnalités:** Appareils, Scènes, Scripts, Historique

![Domoticz](screenshots/vm/domoticz.png)

#### 🏡 Home Assistant

Hub domotique

**Fonctionnalités:** Intégrations, Automatisations, Tableau de bord, Voix

![Home Assistant](screenshots/vm/homeassistant.png)

#### 📡 Zigbee Gateway

Passerelle Zigbee2MQTT

**Fonctionnalités:** Appairage appareils, MQTT, Groupes, Mises à jour OTA

![Zigbee Gateway](screenshots/vm/zigbee.png)

#### 📡 MQTT Broker

Broker MQTT Mosquitto

**Fonctionnalités:** Topics, ACL, TLS, WebSocket

![MQTT Broker](screenshots/vm/mqtt.png)

---

### Media

#### 🎬 Jellyfin

Serveur média

**Fonctionnalités:** Streaming vidéo, TV en direct, Transcodage, Apps mobiles

![Jellyfin](screenshots/vm/jellyfin.png)

#### 🎵 Lyrion Music

Serveur streaming musique

**Fonctionnalités:** Bibliothèque musique, Playlists, Radio, Multi-pièces

![Lyrion Music](screenshots/vm/lyrion.png)

#### 📻 Web Radio

Streaming radio Internet

**Fonctionnalités:** Stations radio, Enregistrement, Programmation, Favoris

![Web Radio](screenshots/vm/webradio.png)

#### 📸 PhotoPrism

Gestion photos assistée par IA

**Fonctionnalités:** Reconnaissance faciale, Auto-tagging, Recherche, Albums

![PhotoPrism](screenshots/vm/photoprism.png)

#### 📺 PeerTube

Plateforme vidéo fédérée

**Fonctionnalités:** Hébergement vidéo, Fédération, Live streaming, Commentaires

![PeerTube](screenshots/vm/peertube.png)

#### 🌊 Torrent

Client BitTorrent

**Fonctionnalités:** Téléchargements, RSS, Contrôle distant, Limites bande passante

![Torrent](screenshots/vm/torrent.png)

#### 📰 Newsbin

Client Usenet/NNTP

**Fonctionnalités:** Téléchargements NZB, Traitement auto, Recherche, Catégories

![Newsbin](screenshots/vm/newsbin.png)

---

### Monitoring

#### 📊 Netdata

Surveillance système temps réel

**Fonctionnalités:** Métriques, Alertes, Graphiques, Plugins

![Netdata](screenshots/vm/netdata.png)

#### 🔬 Deep Packet Inspection

DPI avec netifyd/nDPId

**Fonctionnalités:** Détection protocoles, Identification apps, Analyse flux, Statistiques

![Deep Packet Inspection](screenshots/vm/dpi.png)

#### 🔬 Netifyd DPI

Inspection paquets profonde Netifyd

**Fonctionnalités:** Détection applications, Analyse protocoles, Stats flux, API

![Netifyd DPI](screenshots/vm/netifyd.png)

#### 🔬 nDPId

Démon nDPI pour analyse trafic

**Fonctionnalités:** Détection protocoles, Suivi flux, API JSON, Temps réel

![nDPId](screenshots/vm/ndpid.png)

#### 📱 Device Intelligence

Découverte actifs et empreintes

**Fonctionnalités:** Scan ARP, Recherche vendeur MAC, Détection OS, Services

![Device Intelligence](screenshots/vm/device-intel.png)

#### 👁️ Watchdog

Surveillance services et conteneurs

**Fonctionnalités:** Vérifications santé, Auto-redémarrage, Alertes, Logs

![Watchdog](screenshots/vm/watchdog.png)

#### 🎬 Media Flow

Analyse trafic média

**Fonctionnalités:** Détection flux, Utilisation bande passante, Analyse protocoles, QoE

![Media Flow](screenshots/vm/mediaflow.png)

#### 👀 Glances

Tableau de bord surveillance système

**Fonctionnalités:** CPU/Mémoire, Disque/Réseau, Docker, Interface web

![Glances](screenshots/vm/glances.png)

---

### Network

#### 🌐 Network Modes

Configuration topologie réseau

**Fonctionnalités:** Mode routeur, Mode pont, Mode AP, VLAN

![Network Modes](screenshots/vm/netmodes.png)

#### 📊 QoS Manager

QoS avec HTB/VLAN

**Fonctionnalités:** Contrôle bande passante, Politiques VLAN, 802.1p PCP, Limites utilisateur

![QoS Manager](screenshots/vm/qos.png)

#### 📈 Traffic Shaping

Mise en forme trafic TC/CAKE

**Fonctionnalités:** QoS par interface, Algorithme CAKE, Statistiques, Graphes temps réel

![Traffic Shaping](screenshots/vm/traffic.png)

#### ⚡ HAProxy

Load balancer avec TLS 1.3

**Fonctionnalités:** Gestion backends, Stats, ACLs, Terminaison SSL, Health checks

![HAProxy](screenshots/vm/haproxy.png)

#### 🚀 CDN Cache

Cache de diffusion de contenu

**Fonctionnalités:** Gestion cache, Purge, Statistiques, Règles edge

![CDN Cache](screenshots/vm/cdn.png)

#### 🏗️ Virtual Hosts

Gestion hôtes virtuels Nginx

**Fonctionnalités:** Gestion sites, Certificats SSL, Reverse proxy, Let's Encrypt

![Virtual Hosts](screenshots/vm/vhost.png)

#### 🛤️ Routing Manager

Routage statique et basé sur politiques

**Fonctionnalités:** Routes statiques, Routage politique, Multi-WAN, Failover

![Routing Manager](screenshots/vm/routes.png)

#### 🔧 Network Tweaks

Réglage des paramètres réseau du noyau

**Fonctionnalités:** Réglage TCP, Tailles buffer, Contrôle congestion, Profils

![Network Tweaks](screenshots/vm/nettweak.png)

#### 🔍 Network Diagnostics

Outils de diagnostic réseau

**Fonctionnalités:** Ping/Traceroute, Recherche DNS, Scan ports, Test vitesse

![Network Diagnostics](screenshots/vm/netdiag.png)

#### 📉 Network Anomaly

Détection d'anomalies réseau

**Fonctionnalités:** Baselines trafic, Alertes anomalies, Détection ML, Visualisation

![Network Anomaly](screenshots/vm/network-anomaly.png)

#### 📶 Modem Manager

Gestion modem 3G/4G/5G

**Fonctionnalités:** État connexion, Force signal, SMS, Failover

![Modem Manager](screenshots/vm/modem.png)

---

### Privacy

#### 🧅 Tor Network

Anonymat Tor et services cachés

**Fonctionnalités:** Circuits, Services cachés, Bridges, Proxy transparent

![Tor Network](screenshots/vm/tor.png)

#### 🌐 Exposure Settings

Gestion unifiée de l'exposition

**Fonctionnalités:** Exposition Tor, Certificats SSL, Enregistrements DNS, Accès mesh

![Exposure Settings](screenshots/vm/exposure.png)

#### 🔐 Zero-Knowledge Proofs

Authentification ZKP Hamiltonien

**Fonctionnalités:** Génération preuves, Vérification, Gestion clés, MirrorNet

![Zero-Knowledge Proofs](screenshots/vm/zkp.png)

#### 💬 SimpleX Chat

Messagerie axée sur la vie privée

**Fonctionnalités:** Chiffrement E2E, Sans identifiants, Auto-hébergé, Groupes

![SimpleX Chat](screenshots/vm/simplex.png)

#### 🔐 Secret Vault

Gestion des secrets et identifiants

**Fonctionnalités:** Stockage chiffré, Contrôle d'accès, Rotation, Audit

![Secret Vault](screenshots/vm/vault.png)

---

### Publishing

#### 📰 Publishing Platform

Tableau de bord publication unifié

**Fonctionnalités:** Multi-plateforme, Planification, Analytiques, Templates

![Publishing Platform](screenshots/vm/publish.png)

#### 💧 Droplet

Upload et publication fichiers

**Fonctionnalités:** Upload fichiers, Liens partage, Expiration, Protection mot de passe

![Droplet](screenshots/vm/droplet.png)

#### 📝 Metablogizer

Éditeur site statique avec Tor

**Fonctionnalités:** Sites statiques, Publication Tor, Templates, Markdown

![Metablogizer](screenshots/vm/metablogizer.png)

#### ✏️ Hexo Blog

Générateur blog statique

**Fonctionnalités:** Markdown, Thèmes, Plugins, Déploiement

![Hexo Blog](screenshots/vm/hexo.png)

#### 🐘 GoToSocial

Serveur social ActivityPub

**Fonctionnalités:** Compatible Mastodon, Fédération, Média, Vie privée

![GoToSocial](screenshots/vm/gotosocial.png)

#### 📡 CyberFeed

Agrégateur flux RSS/Atom

**Fonctionnalités:** Gestion flux, Catégories, Recherche, Export

![CyberFeed](screenshots/vm/cyberfeed.png)

---

### Security

#### 🛡️ CrowdSec

Moteur de sécurité collaboratif avec analyse comportementale

**Fonctionnalités:** Gestion décisions, Alertes, Bouncers, Collections, Listes communautaires

![CrowdSec](screenshots/vm/crowdsec.png)

#### 🔥 Web Application Firewall

WAF avec 300+ règles de sécurité OWASP

**Fonctionnalités:** Règles OWASP, Règles custom, Intégration CrowdSec, Logs requêtes

![Web Application Firewall](screenshots/vm/waf.png)

#### 🔥 Vortex Firewall

Pare-feu d'application des menaces basé sur nftables

**Fonctionnalités:** Listes IP, Sets nftables, Flux menaces, Géo-blocage

![Vortex Firewall](screenshots/vm/vortex-firewall.png)

#### 🔒 System Hardening

Durcissement système et noyau pour conformité ANSSI CSPN

**Fonctionnalités:** Durcissement sysctl, Blacklist modules, Score sécurité, AppArmor

![System Hardening](screenshots/vm/hardening.png)

#### 🔍 MITM Proxy

Inspection trafic et proxy WAF avec auto-ban

**Fonctionnalités:** Inspection trafic, Logs requêtes, Auto-ban, Interception SSL

![MITM Proxy](screenshots/vm/mitmproxy.png)

#### 🔐 Auth Guardian

Gestion unifiée de l'authentification

**Fonctionnalités:** OAuth2, LDAP, 2FA/TOTP, Sessions

![Auth Guardian](screenshots/vm/auth.png)

#### 🛡️ Network Access Control

Guardian client et NAC avec quarantaine

**Fonctionnalités:** Contrôle appareils, Filtrage MAC, Quarantaine, Assignation VLAN

![Network Access Control](screenshots/vm/nac.png)

#### 🚫 IP Block Manager

Gestion du blocage IP et réseau

**Fonctionnalités:** Listes IP, Plages réseau, Bans temporaires, Import/Export

![IP Block Manager](screenshots/vm/ipblock.png)

#### 🔐 MAC Guard

Contrôle d'accès par adresse MAC

**Fonctionnalités:** Liste MAC blanche/noire, Auto-découverte, Alertes, Liaison VLAN

![MAC Guard](screenshots/vm/mac-guard.png)

#### 📡 Traffic Interceptor

Interception et analyse du trafic réseau

**Fonctionnalités:** Capture paquets, Analyse protocoles, Suivi sessions, Forensique

![Traffic Interceptor](screenshots/vm/interceptor.png)

#### 🍪 Cookie Manager

Gestion de la sécurité des cookies et sessions

**Fonctionnalités:** Politiques cookies, Sécurité sessions, Enforcement SameSite, Audit

![Cookie Manager](screenshots/vm/cookies.png)

#### ⚠️ Threat Dashboard

Visualisation unifiée des menaces

**Fonctionnalités:** Flux menaces, Timeline attaques, Niveaux gravité, Corrélation

![Threat Dashboard](screenshots/vm/threats.png)

#### 🔬 Threat Analyst

Analyse des menaces assistée par IA

**Fonctionnalités:** Détection ML, Analyse comportementale, Extraction IOC, Rapports

![Threat Analyst](screenshots/vm/threat-analyst.png)

#### 🔴 CVE Triage

Suivi et triage des vulnérabilités CVE

**Fonctionnalités:** Base CVE, Paquets affectés, Score risque, Remédiation

![CVE Triage](screenshots/vm/cve-triage.png)

#### 🛡️ Wazuh SIEM

Intégration SIEM Wazuh

**Fonctionnalités:** Analyse logs, Intégrité fichiers, Détection vulnérabilités, Conformité

![Wazuh SIEM](screenshots/vm/wazuh.png)

#### 🔒 OSSEC HIDS

Détection d'intrusion basée hôte OSSEC

**Fonctionnalités:** Analyse logs, Détection rootkits, Intégrité fichiers, Réponse active

![OSSEC HIDS](screenshots/vm/ossec.png)

#### 🦞 OpenClaw Scanner

Scanner de vulnérabilités réseau

**Fonctionnalités:** Scan ports, Détection services, Vérifications vulnérabilités, Rapports

![OpenClaw Scanner](screenshots/vm/openclaw.png)

#### 🔌 IoT Guard

Surveillance sécurité appareils IoT

**Fonctionnalités:** Empreinte appareils, Détection anomalies, Isolation, Vérif firmware

![IoT Guard](screenshots/vm/iot-guard.png)

---

### Services

#### 📦 Services Portal

Portail services C3Box

**Fonctionnalités:** Liens services, Vue état, Accès rapide, Catégories

![Services Portal](screenshots/vm/c3box.png)

#### 🦊 Gitea

Serveur Git (LXC)

**Fonctionnalités:** Dépôts, Utilisateurs, SSH/HTTP, LFS, Actions

![Gitea](screenshots/vm/gitea.png)

#### ☁️ Nextcloud

Synchronisation fichiers (LXC)

**Fonctionnalités:** Sync fichiers, WebDAV, CalDAV, CardDAV, Talk

![Nextcloud](screenshots/vm/nextcloud.png)

---

### System

#### ⚙️ System Hub

Configuration et gestion système

**Fonctionnalités:** Paramètres, Logs, Services, Mises à jour

![System Hub](screenshots/vm/system.png)

#### 💾 Backup Manager

Sauvegarde système et LXC

**Fonctionnalités:** Sauvegarde config, Snapshots LXC, Restauration, Planification

![Backup Manager](screenshots/vm/backup.png)

#### 📋 Config Advisor

Recommandations de configuration

**Fonctionnalités:** Audit sécurité, Bonnes pratiques, Optimisation, Rapports

![Config Advisor](screenshots/vm/config-advisor.png)

#### 📊 Reporter

Rapports et analytiques système

**Fonctionnalités:** Rapports, Planification, Export, Email

![Reporter](screenshots/vm/reporter.png)

#### 🪞 Mirror Manager

Gestion miroir APT

**Fonctionnalités:** Sync miroir, Bande passante, Planification, Cache

![Mirror Manager](screenshots/vm/mirror.png)

#### 📀 System Cloner

Clonage image système

**Fonctionnalités:** Image disque, Clone USB, Restauration, Compression

![System Cloner](screenshots/vm/cloner.png)

#### 👁️ Eye Remote

Interface de gestion à distance

**Fonctionnalités:** Gadget USB, Console série, Média boot, Récupération

![Eye Remote](screenshots/vm/eye-remote.png)

#### 🖥️ RTTY Console

Accès terminal distant

**Fonctionnalités:** Terminal web, SSH, Transfert fichiers, Enregistrement

![RTTY Console](screenshots/vm/rtty.png)

---

### VPN

#### 🔗 WireGuard VPN

VPN moderne avec intégration noyau

**Fonctionnalités:** Gestion pairs, QR codes, Stats trafic, Multi-tunnel

![WireGuard VPN](screenshots/vm/wireguard.png)

#### 🕸️ Mesh Network

Réseau mesh avec Yggdrasil

**Fonctionnalités:** Découverte pairs, Routage, Chiffrement, Overlay IPv6

![Mesh Network](screenshots/vm/mesh.png)

#### 🔗 P2P Network

Réseau pair-à-pair

**Fonctionnalités:** Connexions directes, Traversée NAT, Chiffrement, DHT

![P2P Network](screenshots/vm/p2p.png)

#### 🔗 MasterLink

Fédération mesh SecuBox

**Fonctionnalités:** Découverte box, Fédération, Politiques partagées, Sync

![MasterLink](screenshots/vm/master-link.png)

---

