# Modules SecuBox

*Documentation complète des modules*

**Total des modules:** 128

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
| 🔐 **Authelia SSO** | Access | Fournisseur d'identité SSO (couche AUTH-BRIDGE) |
| 🧑 **Avatar Manager** | Apps | Gestionnaire d'identité et d'avatar |
| 📜 **Certificate Manager** | Security | Gestionnaire de certificats ACME / TLS |
| 📻 **FM Relay** | Media | rtl_fm vers mount MP3 Icecast avec métadonnées RDS live |
| 📊 **Grafana** | Monitoring | Tableaux de bord métriques de sécurité |
| ❤️ **Hub Health** | Dashboard | Tableau santé et état des services |
| 🧠 **KSM Optimizer** | System | Tableau d'optimisation mémoire KSM (kernel same-page) |
| 🪞 **MagicMirror** | Apps | Gestion de l'affichage intelligent MagicMirror |
| 🧪 **Metabolizer** | Monitoring | Processeur et analyseur de logs |
| 🗄️ **Metoblizer** | Monitoring | Agrégateur de logs centralisé |
| 📇 **Metacatalog** | Services | Catalogue et registre de services |
| 🍺 **PicoBrew** | IoT | Contrôleur de brassage / fermentation |
| 🎙️ **Podcaster** | Media | Gestionnaire de podcasts moderne |
| 🤖 **ReDroid** | Apps | Runtime Android en conteneur |
| 📦 **RezApp** | Services | Déploiement et gestion d'applications |
| 🖥️ **RustDesk** | Access | Relais de bureau distant auto-hébergé |
| 🔌 **SaaS Relay** | Network | Relais proxy SaaS / API |
| 🎯 **Security Posture** | Security | Carte de score de sécurité honnête (vérité board) |
| 📡 **SENTINELLE-GSM** | Security | Capteur passif de fausse BTS (couche MIND) |
| 🕸️ **ThreatMesh** | Security | Mesh de threat-intel souverain (remplace CrowdSec CAPI) |
| 🧰 **ToolBoX (Cabine)** | Security | AP captif + analyseur MITM de vie privée consenti |
| 💻 **VM Manager** | System | Gestion de la virtualisation |
| 🔎 **YaCy** | Network | Moteur de recherche pair-à-pair |

---

## Modules

### AI

#### 🦙 Ollama

Serveur LLM local

**Fonctionnalités:** Gestion modèles, API, Chat, Support GPU

![Ollama](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/ollama.png)

#### 🤖 LocalAI

API locale compatible OpenAI

**Fonctionnalités:** API OpenAI, Modèles multiples, Embeddings, Génération images

![LocalAI](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/localai.png)

#### 🚪 AI Gateway

Passerelle API modèles IA

**Fonctionnalités:** Limitation débit, Équilibrage charge, Cache, Logs

![AI Gateway](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/ai-gateway.png)

#### 💡 AI Insights

Aperçus sécurité assistés par IA

**Fonctionnalités:** Détection anomalies, Recommandations, Prédictions, Rapports

![AI Insights](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/ai-insights.png)

#### 🧠 LocalRecall

Système mémoire RAG local

**Fonctionnalités:** Stockage vecteurs, Recherche sémantique, Indexation documents, API

![LocalRecall](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/localrecall.png)

#### 🔌 MCP Server

Serveur Model Context Protocol

**Fonctionnalités:** Intégration outils, Gestion contexte, Multi-modèle, API

![MCP Server](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/mcp-server.png)

---

### Access

#### 🔐 Login Portal

Portail authentification avec JWT

**Fonctionnalités:** Auth JWT, Sessions, Récupération mot de passe, Portail captif

![Login Portal](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/portal.png)

#### 👥 User Management

Gestion identité unifiée

**Fonctionnalités:** CRUD utilisateurs, Groupes, Provisioning services, RBAC

![User Management](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/users.png)

#### 🪪 Identity Provider

Fournisseur d'identité SAML/OIDC

**Fonctionnalités:** SAML 2.0, OpenID Connect, Fédération, SSO

![Identity Provider](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/identity.png)

#### 🔐 Authelia SSO

Fournisseur d'identité SSO (couche AUTH-BRIDGE)

**Fonctionnalités:** SSO, 2FA / TOTP, Politiques d'accès, Backend LDAP / fichier

![Authelia SSO](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/authelia.png)

#### 🖥️ RustDesk

Relais de bureau distant auto-hébergé

**Fonctionnalités:** Serveur relais, Serveur d'ID, Sessions, Auto-hébergé

![RustDesk](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/rustdesk.png)

---

### Apps

#### 🎨 Streamlit

Plateforme apps Streamlit

**Fonctionnalités:** Hébergement apps, Déploiement, Gestion, Logs

![Streamlit](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/streamlit.png)

#### ⚡ StreamForge

Développement apps Streamlit

**Fonctionnalités:** Templates, Éditeur code, Aperçu, Déploiement

![StreamForge](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/streamforge.png)

#### 📦 APT Repository

Gestion dépôt APT

**Fonctionnalités:** Gestion paquets, Signature GPG, Multi-distro, Uploads

![APT Repository](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/repo.png)

#### 🧑 Avatar Manager

Gestionnaire d'identité et d'avatar

**Fonctionnalités:** Profils d'identité, Génération d'avatar, Ressources par utilisateur

![Avatar Manager](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/avatar.png)

#### 🪞 MagicMirror

Gestion de l'affichage intelligent MagicMirror

**Fonctionnalités:** Disposition modules, Widgets, Thèmes, Contrôle distant

![MagicMirror](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/magicmirror.png)

#### 🤖 ReDroid

Runtime Android en conteneur

**Fonctionnalités:** Conteneur Android, ADB, Installation d'apps, Vue écran

![ReDroid](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/redroid.png)

---

### Communication

#### 💬 Matrix Server

Serveur chat Matrix/Synapse

**Fonctionnalités:** Chiffrement E2E, Fédération, Bridges, Appels

![Matrix Server](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/matrix.png)

#### 📹 Jitsi Meet

Visioconférence

**Fonctionnalités:** Appels vidéo, Partage écran, Enregistrement, Lobby

![Jitsi Meet](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/jitsi.png)

#### 📞 VoIP Server

VoIP Asterisk/FreePBX

**Fonctionnalités:** Extensions, Trunks, IVR, Messagerie vocale

![VoIP Server](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/voip.png)

#### 🔄 TURN Server

Serveur relais TURN/STUN

**Fonctionnalités:** Traversée NAT, WebRTC, TLS, Statistiques

![TURN Server](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/turn.png)

---

### DNS

#### 🌍 DNS Server

Gestion zones DNS BIND

**Fonctionnalités:** Gestion zones, Enregistrements, DNSSEC, DNS inverse

![DNS Server](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/dns.png)

#### 🛡️ Vortex DNS

Pare-feu DNS avec listes de blocage RPZ

**Fonctionnalités:** Listes blocage, RPZ, Flux menaces, DoH/DoT

![Vortex DNS](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/vortex-dns.png)

#### 📡 Mesh DNS

Résolution domaines réseau mesh

**Fonctionnalités:** mDNS/Avahi, DNS local, Découverte services, Intégration mesh

![Mesh DNS](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/meshname.png)

#### 🛡️ DNS Guard

Protection basée sur DNS contre les menaces

**Fonctionnalités:** Blocage malware, Protection phishing, Analytiques, Liste blanche

![DNS Guard](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/dns-guard.png)

#### 🌐 DNS Provider

Intégration fournisseur DNS externe

**Fonctionnalités:** Cloudflare, Route53, DigitalOcean, DNS dynamique

![DNS Provider](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/dns-provider.png)

#### 🚫 AdGuard

Blocage DNS AdGuard Home

**Fonctionnalités:** Blocage pubs, Protection tracking, Contrôle parental, Statistiques

![AdGuard](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/ad-guard.png)

---

### Dashboard

#### 🏠 SecuBox Hub

Tableau de bord central et centre de contrôle

**Fonctionnalités:** Vue système, Surveillance services, Actions rapides, Métriques

![SecuBox Hub](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/hub.png)

#### 🛡️ Security Operations Center

SOC avec horloge mondiale, carte menaces, tickets

**Fonctionnalités:** Horloge mondiale, Carte menaces, Tickets, Intel P2P, Alertes

![Security Operations Center](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/soc.png)

#### 📋 Migration Roadmap

Suivi migration OpenWRT vers Debian

**Fonctionnalités:** Suivi progression, État modules, Vue catégories

![Migration Roadmap](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/roadmap.png)

#### 📈 System Metrics

Tableau de bord métriques système temps réel

**Fonctionnalités:** CPU/Mémoire, Stats réseau, I/O disque, Historique

![System Metrics](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/metrics.png)

#### ⚙️ Admin Panel

Panneau d'administration système

**Fonctionnalités:** Gestion utilisateurs, Config système, Logs, Diagnostics

![Admin Panel](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/admin.png)

#### ❤️ Hub Health

Tableau santé et état des services

**Fonctionnalités:** Santé services, Vérifs socket, Uptime, Alertes dégradation

![Hub Health](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/health.png)

---

### Email

#### 📧 Mail Server

Serveur mail Postfix/Dovecot

**Fonctionnalités:** Domaines, Boîtes mail, DKIM, SpamAssassin, ClamAV

![Mail Server](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/mail.png)

#### 💌 Webmail

Webmail Roundcube/SOGo

**Fonctionnalités:** Interface web, Carnet adresses, Calendrier, Mobile

![Webmail](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/webmail.png)

#### 📤 SMTP Relay

Relais SMTP et smarthost

**Fonctionnalités:** Relais, Authentification, Limitation débit, Logs

![SMTP Relay](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/smtp-relay.png)

#### 💬 Jabber/XMPP

Serveur messagerie XMPP

**Fonctionnalités:** Chat, Groupes, Transfert fichiers, Fédération

![Jabber/XMPP](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/jabber.png)

---

### IoT

#### 🏠 Domoticz

Domotique

**Fonctionnalités:** Appareils, Scènes, Scripts, Historique

![Domoticz](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/domoticz.png)

#### 🏡 Home Assistant

Hub domotique

**Fonctionnalités:** Intégrations, Automatisations, Tableau de bord, Voix

![Home Assistant](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/homeassistant.png)

#### 📡 Zigbee Gateway

Passerelle Zigbee2MQTT

**Fonctionnalités:** Appairage appareils, MQTT, Groupes, Mises à jour OTA

![Zigbee Gateway](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/zigbee.png)

#### 📡 MQTT Broker

Broker MQTT Mosquitto

**Fonctionnalités:** Topics, ACL, TLS, WebSocket

![MQTT Broker](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/mqtt.png)

#### 🍺 PicoBrew

Contrôleur de brassage / fermentation

**Fonctionnalités:** Contrôle température, Recettes, Journal fermentation, Capteurs

![PicoBrew](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/picobrew.png)

---

### Media

#### 🎬 Jellyfin

Serveur média

**Fonctionnalités:** Streaming vidéo, TV en direct, Transcodage, Apps mobiles

![Jellyfin](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/jellyfin.png)

#### 🎵 Lyrion Music

Serveur streaming musique

**Fonctionnalités:** Bibliothèque musique, Playlists, Radio, Multi-pièces

![Lyrion Music](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/lyrion.png)

#### 📻 Web Radio

Streaming radio Internet

**Fonctionnalités:** Stations radio, Enregistrement, Programmation, Favoris

![Web Radio](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/webradio.png)

#### 📸 PhotoPrism

Gestion photos assistée par IA

**Fonctionnalités:** Reconnaissance faciale, Auto-tagging, Recherche, Albums

![PhotoPrism](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/photoprism.png)

#### 📺 PeerTube

Plateforme vidéo fédérée

**Fonctionnalités:** Hébergement vidéo, Fédération, Live streaming, Commentaires

![PeerTube](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/peertube.png)

#### 🌊 Torrent

Client BitTorrent

**Fonctionnalités:** Téléchargements, RSS, Contrôle distant, Limites bande passante

![Torrent](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/torrent.png)

#### 📰 Newsbin

Client Usenet/NNTP

**Fonctionnalités:** Téléchargements NZB, Traitement auto, Recherche, Catégories

![Newsbin](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/newsbin.png)

#### 📻 FM Relay

rtl_fm vers mount MP3 Icecast avec métadonnées RDS live

**Fonctionnalités:** Capture FM SDR, Flux Icecast, Métadonnées RDS, Préréglages stations

![FM Relay](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/fmrelay.png)

#### 🎙️ Podcaster

Gestionnaire de podcasts moderne

**Fonctionnalités:** Gestion des flux, Épisodes, Transcodage, Publication RSS

![Podcaster](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/podcaster.png)

---

### Monitoring

#### 📊 Netdata

Surveillance système temps réel

**Fonctionnalités:** Métriques, Alertes, Graphiques, Plugins

![Netdata](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/netdata.png)

#### 🔬 Deep Packet Inspection

DPI avec netifyd/nDPId

**Fonctionnalités:** Détection protocoles, Identification apps, Analyse flux, Statistiques

![Deep Packet Inspection](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/dpi.png)

#### 🔬 Netifyd DPI

Inspection paquets profonde Netifyd

**Fonctionnalités:** Détection applications, Analyse protocoles, Stats flux, API

![Netifyd DPI](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/netifyd.png)

#### 🔬 nDPId

Démon nDPI pour analyse trafic

**Fonctionnalités:** Détection protocoles, Suivi flux, API JSON, Temps réel

![nDPId](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/ndpid.png)

#### 📱 Device Intelligence

Découverte actifs et empreintes

**Fonctionnalités:** Scan ARP, Recherche vendeur MAC, Détection OS, Services

![Device Intelligence](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/device-intel.png)

#### 👁️ Watchdog

Surveillance services et conteneurs

**Fonctionnalités:** Vérifications santé, Auto-redémarrage, Alertes, Logs

![Watchdog](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/watchdog.png)

#### 🎬 Media Flow

Analyse trafic média

**Fonctionnalités:** Détection flux, Utilisation bande passante, Analyse protocoles, QoE

![Media Flow](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/mediaflow.png)

#### 👀 Glances

Tableau de bord surveillance système

**Fonctionnalités:** CPU/Mémoire, Disque/Réseau, Docker, Interface web

![Glances](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/glances.png)

#### 📊 Grafana

Tableaux de bord métriques de sécurité

**Fonctionnalités:** Tableaux time-series, Alertes, Sources de données, Panneaux

![Grafana](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/grafana.png)

#### 🧪 Metabolizer

Processeur et analyseur de logs

**Fonctionnalités:** Parsing de logs, Analyse de motifs, Pipelines, Enrichissement

![Metabolizer](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/metabolizer.png)

#### 🗄️ Metoblizer

Agrégateur de logs centralisé

**Fonctionnalités:** Collecte de logs, Stockage central, Recherche, Rétention

![Metoblizer](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/metoblizer.png)

---

### Network

#### 🌐 Network Modes

Configuration topologie réseau

**Fonctionnalités:** Mode routeur, Mode pont, Mode AP, VLAN

![Network Modes](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/netmodes.png)

#### 📊 QoS Manager

QoS avec HTB/VLAN

**Fonctionnalités:** Contrôle bande passante, Politiques VLAN, 802.1p PCP, Limites utilisateur

![QoS Manager](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/qos.png)

#### 📈 Traffic Shaping

Mise en forme trafic TC/CAKE

**Fonctionnalités:** QoS par interface, Algorithme CAKE, Statistiques, Graphes temps réel

![Traffic Shaping](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/traffic.png)

#### ⚡ HAProxy

Load balancer avec TLS 1.3

**Fonctionnalités:** Gestion backends, Stats, ACLs, Terminaison SSL, Health checks

![HAProxy](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/haproxy.png)

#### 🚀 CDN Cache

Cache de diffusion de contenu

**Fonctionnalités:** Gestion cache, Purge, Statistiques, Règles edge

![CDN Cache](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/cdn.png)

#### 🏗️ Virtual Hosts

Gestion hôtes virtuels Nginx

**Fonctionnalités:** Gestion sites, Certificats SSL, Reverse proxy, Let's Encrypt

![Virtual Hosts](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/vhost.png)

#### 🛤️ Routing Manager

Routage statique et basé sur politiques

**Fonctionnalités:** Routes statiques, Routage politique, Multi-WAN, Failover

![Routing Manager](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/routes.png)

#### 🔧 Network Tweaks

Réglage des paramètres réseau du noyau

**Fonctionnalités:** Réglage TCP, Tailles buffer, Contrôle congestion, Profils

![Network Tweaks](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/nettweak.png)

#### 🔍 Network Diagnostics

Outils de diagnostic réseau

**Fonctionnalités:** Ping/Traceroute, Recherche DNS, Scan ports, Test vitesse

![Network Diagnostics](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/netdiag.png)

#### 📉 Network Anomaly

Détection d'anomalies réseau

**Fonctionnalités:** Baselines trafic, Alertes anomalies, Détection ML, Visualisation

![Network Anomaly](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/network-anomaly.png)

#### 📶 Modem Manager

Gestion modem 3G/4G/5G

**Fonctionnalités:** État connexion, Force signal, SMS, Failover

![Modem Manager](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/modem.png)

#### 🔌 SaaS Relay

Relais proxy SaaS / API

**Fonctionnalités:** Proxy API, Limitation de débit, Routage, Coffre identifiants

![SaaS Relay](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/saas-relay.png)

#### 🔎 YaCy

Moteur de recherche pair-à-pair

**Fonctionnalités:** Index P2P, Crawler, Recherche privée, Fédération

![YaCy](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/yacy.png)

---

### Privacy

#### 🧅 Tor Network

Anonymat Tor et services cachés

**Fonctionnalités:** Circuits, Services cachés, Bridges, Proxy transparent

![Tor Network](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/tor.png)

#### 🌐 Exposure Settings

Gestion unifiée de l'exposition

**Fonctionnalités:** Exposition Tor, Certificats SSL, Enregistrements DNS, Accès mesh

![Exposure Settings](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/exposure.png)

#### 🔐 Zero-Knowledge Proofs

Authentification ZKP Hamiltonien

**Fonctionnalités:** Génération preuves, Vérification, Gestion clés, MirrorNet

![Zero-Knowledge Proofs](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/zkp.png)

#### 💬 SimpleX Chat

Messagerie axée sur la vie privée

**Fonctionnalités:** Chiffrement E2E, Sans identifiants, Auto-hébergé, Groupes

![SimpleX Chat](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/simplex.png)

#### 🔐 Secret Vault

Gestion des secrets et identifiants

**Fonctionnalités:** Stockage chiffré, Contrôle d'accès, Rotation, Audit

![Secret Vault](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/vault.png)

---

### Publishing

#### 📰 Publishing Platform

Tableau de bord publication unifié

**Fonctionnalités:** Multi-plateforme, Planification, Analytiques, Templates

![Publishing Platform](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/publish.png)

#### 💧 Droplet

Upload et publication fichiers

**Fonctionnalités:** Upload fichiers, Liens partage, Expiration, Protection mot de passe

![Droplet](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/droplet.png)

#### 📝 Metablogizer

Éditeur site statique avec Tor

**Fonctionnalités:** Sites statiques, Publication Tor, Templates, Markdown

![Metablogizer](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/metablogizer.png)

#### ✏️ Hexo Blog

Générateur blog statique

**Fonctionnalités:** Markdown, Thèmes, Plugins, Déploiement

![Hexo Blog](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/hexo.png)

#### 🐘 GoToSocial

Serveur social ActivityPub

**Fonctionnalités:** Compatible Mastodon, Fédération, Média, Vie privée

![GoToSocial](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/gotosocial.png)

#### 📡 CyberFeed

Agrégateur flux RSS/Atom

**Fonctionnalités:** Gestion flux, Catégories, Recherche, Export

![CyberFeed](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/cyberfeed.png)

---

### Security

#### 🛡️ CrowdSec

Moteur de sécurité collaboratif avec analyse comportementale

**Fonctionnalités:** Gestion décisions, Alertes, Bouncers, Collections, Listes communautaires

![CrowdSec](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/crowdsec.png)

#### 🔥 Web Application Firewall

WAF avec 300+ règles de sécurité OWASP

**Fonctionnalités:** Règles OWASP, Règles custom, Intégration CrowdSec, Logs requêtes

![Web Application Firewall](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/waf.png)

#### 🔥 Vortex Firewall

Pare-feu d'application des menaces basé sur nftables

**Fonctionnalités:** Listes IP, Sets nftables, Flux menaces, Géo-blocage

![Vortex Firewall](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/vortex-firewall.png)

#### 🔒 System Hardening

Durcissement système et noyau pour conformité ANSSI CSPN

**Fonctionnalités:** Durcissement sysctl, Blacklist modules, Score sécurité, AppArmor

![System Hardening](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/hardening.png)

#### 🔍 MITM Proxy

Inspection trafic et proxy WAF avec auto-ban

**Fonctionnalités:** Inspection trafic, Logs requêtes, Auto-ban, Interception SSL

![MITM Proxy](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/mitmproxy.png)

#### 🔐 Auth Guardian

Gestion unifiée de l'authentification

**Fonctionnalités:** OAuth2, LDAP, 2FA/TOTP, Sessions

![Auth Guardian](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/auth.png)

#### 🛡️ Network Access Control

Guardian client et NAC avec quarantaine

**Fonctionnalités:** Contrôle appareils, Filtrage MAC, Quarantaine, Assignation VLAN

![Network Access Control](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/nac.png)

#### 🚫 IP Block Manager

Gestion du blocage IP et réseau

**Fonctionnalités:** Listes IP, Plages réseau, Bans temporaires, Import/Export

![IP Block Manager](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/ipblock.png)

#### 🔐 MAC Guard

Contrôle d'accès par adresse MAC

**Fonctionnalités:** Liste MAC blanche/noire, Auto-découverte, Alertes, Liaison VLAN

![MAC Guard](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/mac-guard.png)

#### 📡 Traffic Interceptor

Interception et analyse du trafic réseau

**Fonctionnalités:** Capture paquets, Analyse protocoles, Suivi sessions, Forensique

![Traffic Interceptor](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/interceptor.png)

#### 🍪 Cookie Manager

Gestion de la sécurité des cookies et sessions

**Fonctionnalités:** Politiques cookies, Sécurité sessions, Enforcement SameSite, Audit

![Cookie Manager](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/cookies.png)

#### ⚠️ Threat Dashboard

Visualisation unifiée des menaces

**Fonctionnalités:** Flux menaces, Timeline attaques, Niveaux gravité, Corrélation

![Threat Dashboard](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/threats.png)

#### 🔬 Threat Analyst

Analyse des menaces assistée par IA

**Fonctionnalités:** Détection ML, Analyse comportementale, Extraction IOC, Rapports

![Threat Analyst](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/threat-analyst.png)

#### 🔴 CVE Triage

Suivi et triage des vulnérabilités CVE

**Fonctionnalités:** Base CVE, Paquets affectés, Score risque, Remédiation

![CVE Triage](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/cve-triage.png)

#### 🛡️ Wazuh SIEM

Intégration SIEM Wazuh

**Fonctionnalités:** Analyse logs, Intégrité fichiers, Détection vulnérabilités, Conformité

![Wazuh SIEM](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/wazuh.png)

#### 🔒 OSSEC HIDS

Détection d'intrusion basée hôte OSSEC

**Fonctionnalités:** Analyse logs, Détection rootkits, Intégrité fichiers, Réponse active

![OSSEC HIDS](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/ossec.png)

#### 🦞 OpenClaw Scanner

Scanner de vulnérabilités réseau

**Fonctionnalités:** Scan ports, Détection services, Vérifications vulnérabilités, Rapports

![OpenClaw Scanner](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/openclaw.png)

#### 🔌 IoT Guard

Surveillance sécurité appareils IoT

**Fonctionnalités:** Empreinte appareils, Détection anomalies, Isolation, Vérif firmware

![IoT Guard](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/iot-guard.png)

#### 📜 Certificate Manager

Gestionnaire de certificats ACME / TLS

**Fonctionnalités:** Émission ACME, Renouvellement, SAN / wildcard, Inventaire

![Certificate Manager](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/certs.png)

#### 🎯 Security Posture

Carte de score de sécurité honnête (vérité board)

**Fonctionnalités:** Scorecard, Vérifs de contrôles, Écarts, Tendance

![Security Posture](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/security-posture.png)

#### 📡 SENTINELLE-GSM

Capteur passif de fausse BTS (couche MIND)

**Fonctionnalités:** Détection IMSI-catcher, Relevé cellules, Alertes anomalies, RF passif

![SENTINELLE-GSM](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/sentinelle.png)

#### 🕸️ ThreatMesh

Mesh de threat-intel souverain (remplace CrowdSec CAPI)

**Fonctionnalités:** Partage intel P2P, Feed souverain, Filtrage par confiance, Sync blocklist

![ThreatMesh](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/threatmesh.png)

#### 🧰 ToolBoX (Cabine)

AP captif + analyseur MITM de vie privée consenti

**Fonctionnalités:** Portail captif, Niveaux R0-R4, Exposition trackers, Sortie Tor

![ToolBoX (Cabine)](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/toolbox.png)

---

### Services

#### 📦 Services Portal

Portail services C3Box

**Fonctionnalités:** Liens services, Vue état, Accès rapide, Catégories

![Services Portal](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/c3box.png)

#### 🦊 Gitea

Serveur Git (LXC)

**Fonctionnalités:** Dépôts, Utilisateurs, SSH/HTTP, LFS, Actions

![Gitea](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/gitea.png)

#### ☁️ Nextcloud

Synchronisation fichiers (LXC)

**Fonctionnalités:** Sync fichiers, WebDAV, CalDAV, CardDAV, Talk

![Nextcloud](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/nextcloud.png)

#### 📇 Metacatalog

Catalogue et registre de services

**Fonctionnalités:** Registre services, Découverte, Métadonnées, UI catalogue

![Metacatalog](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/metacatalog.png)

#### 📦 RezApp

Déploiement et gestion d'applications

**Fonctionnalités:** Déploiement d'apps, Cycle de vie, Config, État

![RezApp](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/rezapp.png)

---

### System

#### ⚙️ System Hub

Configuration et gestion système

**Fonctionnalités:** Paramètres, Logs, Services, Mises à jour

![System Hub](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/system.png)

#### 💾 Backup Manager

Sauvegarde système et LXC

**Fonctionnalités:** Sauvegarde config, Snapshots LXC, Restauration, Planification

![Backup Manager](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/backup.png)

#### 📋 Config Advisor

Recommandations de configuration

**Fonctionnalités:** Audit sécurité, Bonnes pratiques, Optimisation, Rapports

![Config Advisor](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/config-advisor.png)

#### 📊 Reporter

Rapports et analytiques système

**Fonctionnalités:** Rapports, Planification, Export, Email

![Reporter](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/reporter.png)

#### 🪞 Mirror Manager

Gestion miroir APT

**Fonctionnalités:** Sync miroir, Bande passante, Planification, Cache

![Mirror Manager](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/mirror.png)

#### 📀 System Cloner

Clonage image système

**Fonctionnalités:** Image disque, Clone USB, Restauration, Compression

![System Cloner](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/cloner.png)

#### 👁️ Eye Remote

Interface de gestion à distance

**Fonctionnalités:** Gadget USB, Console série, Média boot, Récupération

![Eye Remote](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/eye-remote.png)

#### 🖥️ RTTY Console

Accès terminal distant

**Fonctionnalités:** Terminal web, SSH, Transfert fichiers, Enregistrement

![RTTY Console](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/rtty.png)

#### 🧠 KSM Optimizer

Tableau d'optimisation mémoire KSM (kernel same-page)

**Fonctionnalités:** Stats partage de pages, Mémoire économisée, Réglage, Vue par VM

![KSM Optimizer](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/ksm.png)

#### 💻 VM Manager

Gestion de la virtualisation

**Fonctionnalités:** Cycle de vie VM, Console, Snapshots, Limites ressources

![VM Manager](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/vm.png)

---

### VPN

#### 🔗 WireGuard VPN

VPN moderne avec intégration noyau

**Fonctionnalités:** Gestion pairs, QR codes, Stats trafic, Multi-tunnel

![WireGuard VPN](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/wireguard.png)

#### 🕸️ Mesh Network

Réseau mesh avec Yggdrasil

**Fonctionnalités:** Découverte pairs, Routage, Chiffrement, Overlay IPv6

![Mesh Network](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/mesh.png)

#### 🔗 P2P Network

Réseau pair-à-pair

**Fonctionnalités:** Connexions directes, Traversée NAT, Chiffrement, DHT

![P2P Network](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/p2p.png)

#### 🔗 MasterLink

Fédération mesh SecuBox

**Fonctionnalités:** Découverte box, Fédération, Politiques partagées, Sync

![MasterLink](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/master-link.png)

---

