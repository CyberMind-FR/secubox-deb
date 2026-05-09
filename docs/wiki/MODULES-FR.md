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

#### 🤖 LocalAI

API locale compatible OpenAI

**Fonctionnalités:** API OpenAI, Modèles multiples, Embeddings, Génération images

#### 🚪 AI Gateway

Passerelle API modèles IA

**Fonctionnalités:** Limitation débit, Équilibrage charge, Cache, Logs

#### 💡 AI Insights

Aperçus sécurité assistés par IA

**Fonctionnalités:** Détection anomalies, Recommandations, Prédictions, Rapports

#### 🧠 LocalRecall

Système mémoire RAG local

**Fonctionnalités:** Stockage vecteurs, Recherche sémantique, Indexation documents, API

#### 🔌 MCP Server

Serveur Model Context Protocol

**Fonctionnalités:** Intégration outils, Gestion contexte, Multi-modèle, API

---

### Access

#### 🔐 Login Portal

Portail authentification avec JWT

**Fonctionnalités:** Auth JWT, Sessions, Récupération mot de passe, Portail captif

#### 👥 User Management

Gestion identité unifiée

**Fonctionnalités:** CRUD utilisateurs, Groupes, Provisioning services, RBAC

#### 🪪 Identity Provider

Fournisseur d'identité SAML/OIDC

**Fonctionnalités:** SAML 2.0, OpenID Connect, Fédération, SSO

---

### Apps

#### 🎨 Streamlit

Plateforme apps Streamlit

**Fonctionnalités:** Hébergement apps, Déploiement, Gestion, Logs

#### ⚡ StreamForge

Développement apps Streamlit

**Fonctionnalités:** Templates, Éditeur code, Aperçu, Déploiement

#### 📦 APT Repository

Gestion dépôt APT

**Fonctionnalités:** Gestion paquets, Signature GPG, Multi-distro, Uploads

---

### Communication

#### 💬 Matrix Server

Serveur chat Matrix/Synapse

**Fonctionnalités:** Chiffrement E2E, Fédération, Bridges, Appels

#### 📹 Jitsi Meet

Visioconférence

**Fonctionnalités:** Appels vidéo, Partage écran, Enregistrement, Lobby

#### 📞 VoIP Server

VoIP Asterisk/FreePBX

**Fonctionnalités:** Extensions, Trunks, IVR, Messagerie vocale

#### 🔄 TURN Server

Serveur relais TURN/STUN

**Fonctionnalités:** Traversée NAT, WebRTC, TLS, Statistiques

---

### DNS

#### 🌍 DNS Server

Gestion zones DNS BIND

**Fonctionnalités:** Gestion zones, Enregistrements, DNSSEC, DNS inverse

#### 🛡️ Vortex DNS

Pare-feu DNS avec listes de blocage RPZ

**Fonctionnalités:** Listes blocage, RPZ, Flux menaces, DoH/DoT

#### 📡 Mesh DNS

Résolution domaines réseau mesh

**Fonctionnalités:** mDNS/Avahi, DNS local, Découverte services, Intégration mesh

#### 🛡️ DNS Guard

Protection basée sur DNS contre les menaces

**Fonctionnalités:** Blocage malware, Protection phishing, Analytiques, Liste blanche

#### 🌐 DNS Provider

Intégration fournisseur DNS externe

**Fonctionnalités:** Cloudflare, Route53, DigitalOcean, DNS dynamique

#### 🚫 AdGuard

Blocage DNS AdGuard Home

**Fonctionnalités:** Blocage pubs, Protection tracking, Contrôle parental, Statistiques

---

### Dashboard

#### 🏠 SecuBox Hub

Tableau de bord central et centre de contrôle

**Fonctionnalités:** Vue système, Surveillance services, Actions rapides, Métriques

#### 🛡️ Security Operations Center

SOC avec horloge mondiale, carte menaces, tickets

**Fonctionnalités:** Horloge mondiale, Carte menaces, Tickets, Intel P2P, Alertes

#### 📋 Migration Roadmap

Suivi migration OpenWRT vers Debian

**Fonctionnalités:** Suivi progression, État modules, Vue catégories

#### 📈 System Metrics

Tableau de bord métriques système temps réel

**Fonctionnalités:** CPU/Mémoire, Stats réseau, I/O disque, Historique

#### ⚙️ Admin Panel

Panneau d'administration système

**Fonctionnalités:** Gestion utilisateurs, Config système, Logs, Diagnostics

---

### Email

#### 📧 Mail Server

Serveur mail Postfix/Dovecot

**Fonctionnalités:** Domaines, Boîtes mail, DKIM, SpamAssassin, ClamAV

#### 💌 Webmail

Webmail Roundcube/SOGo

**Fonctionnalités:** Interface web, Carnet adresses, Calendrier, Mobile

#### 📤 SMTP Relay

Relais SMTP et smarthost

**Fonctionnalités:** Relais, Authentification, Limitation débit, Logs

#### 💬 Jabber/XMPP

Serveur messagerie XMPP

**Fonctionnalités:** Chat, Groupes, Transfert fichiers, Fédération

---

### IoT

#### 🏠 Domoticz

Domotique

**Fonctionnalités:** Appareils, Scènes, Scripts, Historique

#### 🏡 Home Assistant

Hub domotique

**Fonctionnalités:** Intégrations, Automatisations, Tableau de bord, Voix

#### 📡 Zigbee Gateway

Passerelle Zigbee2MQTT

**Fonctionnalités:** Appairage appareils, MQTT, Groupes, Mises à jour OTA

#### 📡 MQTT Broker

Broker MQTT Mosquitto

**Fonctionnalités:** Topics, ACL, TLS, WebSocket

---

### Media

#### 🎬 Jellyfin

Serveur média

**Fonctionnalités:** Streaming vidéo, TV en direct, Transcodage, Apps mobiles

#### 🎵 Lyrion Music

Serveur streaming musique

**Fonctionnalités:** Bibliothèque musique, Playlists, Radio, Multi-pièces

#### 📻 Web Radio

Streaming radio Internet

**Fonctionnalités:** Stations radio, Enregistrement, Programmation, Favoris

#### 📸 PhotoPrism

Gestion photos assistée par IA

**Fonctionnalités:** Reconnaissance faciale, Auto-tagging, Recherche, Albums

#### 📺 PeerTube

Plateforme vidéo fédérée

**Fonctionnalités:** Hébergement vidéo, Fédération, Live streaming, Commentaires

#### 🌊 Torrent

Client BitTorrent

**Fonctionnalités:** Téléchargements, RSS, Contrôle distant, Limites bande passante

#### 📰 Newsbin

Client Usenet/NNTP

**Fonctionnalités:** Téléchargements NZB, Traitement auto, Recherche, Catégories

---

### Monitoring

#### 📊 Netdata

Surveillance système temps réel

**Fonctionnalités:** Métriques, Alertes, Graphiques, Plugins

#### 🔬 Deep Packet Inspection

DPI avec netifyd/nDPId

**Fonctionnalités:** Détection protocoles, Identification apps, Analyse flux, Statistiques

#### 🔬 Netifyd DPI

Inspection paquets profonde Netifyd

**Fonctionnalités:** Détection applications, Analyse protocoles, Stats flux, API

#### 🔬 nDPId

Démon nDPI pour analyse trafic

**Fonctionnalités:** Détection protocoles, Suivi flux, API JSON, Temps réel

#### 📱 Device Intelligence

Découverte actifs et empreintes

**Fonctionnalités:** Scan ARP, Recherche vendeur MAC, Détection OS, Services

#### 👁️ Watchdog

Surveillance services et conteneurs

**Fonctionnalités:** Vérifications santé, Auto-redémarrage, Alertes, Logs

#### 🎬 Media Flow

Analyse trafic média

**Fonctionnalités:** Détection flux, Utilisation bande passante, Analyse protocoles, QoE

#### 👀 Glances

Tableau de bord surveillance système

**Fonctionnalités:** CPU/Mémoire, Disque/Réseau, Docker, Interface web

---

### Network

#### 🌐 Network Modes

Configuration topologie réseau

**Fonctionnalités:** Mode routeur, Mode pont, Mode AP, VLAN

#### 📊 QoS Manager

QoS avec HTB/VLAN

**Fonctionnalités:** Contrôle bande passante, Politiques VLAN, 802.1p PCP, Limites utilisateur

#### 📈 Traffic Shaping

Mise en forme trafic TC/CAKE

**Fonctionnalités:** QoS par interface, Algorithme CAKE, Statistiques, Graphes temps réel

#### ⚡ HAProxy

Load balancer avec TLS 1.3

**Fonctionnalités:** Gestion backends, Stats, ACLs, Terminaison SSL, Health checks

#### 🚀 CDN Cache

Cache de diffusion de contenu

**Fonctionnalités:** Gestion cache, Purge, Statistiques, Règles edge

#### 🏗️ Virtual Hosts

Gestion hôtes virtuels Nginx

**Fonctionnalités:** Gestion sites, Certificats SSL, Reverse proxy, Let's Encrypt

#### 🛤️ Routing Manager

Routage statique et basé sur politiques

**Fonctionnalités:** Routes statiques, Routage politique, Multi-WAN, Failover

#### 🔧 Network Tweaks

Réglage des paramètres réseau du noyau

**Fonctionnalités:** Réglage TCP, Tailles buffer, Contrôle congestion, Profils

#### 🔍 Network Diagnostics

Outils de diagnostic réseau

**Fonctionnalités:** Ping/Traceroute, Recherche DNS, Scan ports, Test vitesse

#### 📉 Network Anomaly

Détection d'anomalies réseau

**Fonctionnalités:** Baselines trafic, Alertes anomalies, Détection ML, Visualisation

#### 📶 Modem Manager

Gestion modem 3G/4G/5G

**Fonctionnalités:** État connexion, Force signal, SMS, Failover

---

### Privacy

#### 🧅 Tor Network

Anonymat Tor et services cachés

**Fonctionnalités:** Circuits, Services cachés, Bridges, Proxy transparent

#### 🌐 Exposure Settings

Gestion unifiée de l'exposition

**Fonctionnalités:** Exposition Tor, Certificats SSL, Enregistrements DNS, Accès mesh

#### 🔐 Zero-Knowledge Proofs

Authentification ZKP Hamiltonien

**Fonctionnalités:** Génération preuves, Vérification, Gestion clés, MirrorNet

#### 💬 SimpleX Chat

Messagerie axée sur la vie privée

**Fonctionnalités:** Chiffrement E2E, Sans identifiants, Auto-hébergé, Groupes

#### 🔐 Secret Vault

Gestion des secrets et identifiants

**Fonctionnalités:** Stockage chiffré, Contrôle d'accès, Rotation, Audit

---

### Publishing

#### 📰 Publishing Platform

Tableau de bord publication unifié

**Fonctionnalités:** Multi-plateforme, Planification, Analytiques, Templates

#### 💧 Droplet

Upload et publication fichiers

**Fonctionnalités:** Upload fichiers, Liens partage, Expiration, Protection mot de passe

#### 📝 Metablogizer

Éditeur site statique avec Tor

**Fonctionnalités:** Sites statiques, Publication Tor, Templates, Markdown

#### ✏️ Hexo Blog

Générateur blog statique

**Fonctionnalités:** Markdown, Thèmes, Plugins, Déploiement

#### 🐘 GoToSocial

Serveur social ActivityPub

**Fonctionnalités:** Compatible Mastodon, Fédération, Média, Vie privée

#### 📡 CyberFeed

Agrégateur flux RSS/Atom

**Fonctionnalités:** Gestion flux, Catégories, Recherche, Export

---

### Security

#### 🛡️ CrowdSec

Moteur de sécurité collaboratif avec analyse comportementale

**Fonctionnalités:** Gestion décisions, Alertes, Bouncers, Collections, Listes communautaires

#### 🔥 Web Application Firewall

WAF avec 300+ règles de sécurité OWASP

**Fonctionnalités:** Règles OWASP, Règles custom, Intégration CrowdSec, Logs requêtes

#### 🔥 Vortex Firewall

Pare-feu d'application des menaces basé sur nftables

**Fonctionnalités:** Listes IP, Sets nftables, Flux menaces, Géo-blocage

#### 🔒 System Hardening

Durcissement système et noyau pour conformité ANSSI CSPN

**Fonctionnalités:** Durcissement sysctl, Blacklist modules, Score sécurité, AppArmor

#### 🔍 MITM Proxy

Inspection trafic et proxy WAF avec auto-ban

**Fonctionnalités:** Inspection trafic, Logs requêtes, Auto-ban, Interception SSL

#### 🔐 Auth Guardian

Gestion unifiée de l'authentification

**Fonctionnalités:** OAuth2, LDAP, 2FA/TOTP, Sessions

#### 🛡️ Network Access Control

Guardian client et NAC avec quarantaine

**Fonctionnalités:** Contrôle appareils, Filtrage MAC, Quarantaine, Assignation VLAN

#### 🚫 IP Block Manager

Gestion du blocage IP et réseau

**Fonctionnalités:** Listes IP, Plages réseau, Bans temporaires, Import/Export

#### 🔐 MAC Guard

Contrôle d'accès par adresse MAC

**Fonctionnalités:** Liste MAC blanche/noire, Auto-découverte, Alertes, Liaison VLAN

#### 📡 Traffic Interceptor

Interception et analyse du trafic réseau

**Fonctionnalités:** Capture paquets, Analyse protocoles, Suivi sessions, Forensique

#### 🍪 Cookie Manager

Gestion de la sécurité des cookies et sessions

**Fonctionnalités:** Politiques cookies, Sécurité sessions, Enforcement SameSite, Audit

#### ⚠️ Threat Dashboard

Visualisation unifiée des menaces

**Fonctionnalités:** Flux menaces, Timeline attaques, Niveaux gravité, Corrélation

#### 🔬 Threat Analyst

Analyse des menaces assistée par IA

**Fonctionnalités:** Détection ML, Analyse comportementale, Extraction IOC, Rapports

#### 🔴 CVE Triage

Suivi et triage des vulnérabilités CVE

**Fonctionnalités:** Base CVE, Paquets affectés, Score risque, Remédiation

#### 🛡️ Wazuh SIEM

Intégration SIEM Wazuh

**Fonctionnalités:** Analyse logs, Intégrité fichiers, Détection vulnérabilités, Conformité

#### 🔒 OSSEC HIDS

Détection d'intrusion basée hôte OSSEC

**Fonctionnalités:** Analyse logs, Détection rootkits, Intégrité fichiers, Réponse active

#### 🦞 OpenClaw Scanner

Scanner de vulnérabilités réseau

**Fonctionnalités:** Scan ports, Détection services, Vérifications vulnérabilités, Rapports

#### 🔌 IoT Guard

Surveillance sécurité appareils IoT

**Fonctionnalités:** Empreinte appareils, Détection anomalies, Isolation, Vérif firmware

---

### Services

#### 📦 Services Portal

Portail services C3Box

**Fonctionnalités:** Liens services, Vue état, Accès rapide, Catégories

#### 🦊 Gitea

Serveur Git (LXC)

**Fonctionnalités:** Dépôts, Utilisateurs, SSH/HTTP, LFS, Actions

#### ☁️ Nextcloud

Synchronisation fichiers (LXC)

**Fonctionnalités:** Sync fichiers, WebDAV, CalDAV, CardDAV, Talk

---

### System

#### ⚙️ System Hub

Configuration et gestion système

**Fonctionnalités:** Paramètres, Logs, Services, Mises à jour

#### 💾 Backup Manager

Sauvegarde système et LXC

**Fonctionnalités:** Sauvegarde config, Snapshots LXC, Restauration, Planification

#### 📋 Config Advisor

Recommandations de configuration

**Fonctionnalités:** Audit sécurité, Bonnes pratiques, Optimisation, Rapports

#### 📊 Reporter

Rapports et analytiques système

**Fonctionnalités:** Rapports, Planification, Export, Email

#### 🪞 Mirror Manager

Gestion miroir APT

**Fonctionnalités:** Sync miroir, Bande passante, Planification, Cache

#### 📀 System Cloner

Clonage image système

**Fonctionnalités:** Image disque, Clone USB, Restauration, Compression

#### 👁️ Eye Remote

Interface de gestion à distance

**Fonctionnalités:** Gadget USB, Console série, Média boot, Récupération

#### 🖥️ RTTY Console

Accès terminal distant

**Fonctionnalités:** Terminal web, SSH, Transfert fichiers, Enregistrement

---

### VPN

#### 🔗 WireGuard VPN

VPN moderne avec intégration noyau

**Fonctionnalités:** Gestion pairs, QR codes, Stats trafic, Multi-tunnel

#### 🕸️ Mesh Network

Réseau mesh avec Yggdrasil

**Fonctionnalités:** Découverte pairs, Routage, Chiffrement, Overlay IPv6

#### 🔗 P2P Network

Réseau pair-à-pair

**Fonctionnalités:** Connexions directes, Traversée NAT, Chiffrement, DHT

#### 🔗 MasterLink

Fédération mesh SecuBox

**Fonctionnalités:** Découverte box, Fédération, Politiques partagées, Sync

---

