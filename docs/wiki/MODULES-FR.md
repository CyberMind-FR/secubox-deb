# Modules SecuBox

*Documentation complète des modules*

**Total des modules:** 47

[🇬🇧 English](MODULES-EN.md) | [🇫🇷 Français](MODULES-FR.md) | [🇩🇪 Deutsch](MODULES-DE.md) | [🇨🇳 中文](MODULES-ZH.md)

---

## Aperçu

| Modules | Catégorie | Description |
|--------|----------|-------------|
| 🏠 **SecuBox Hub** | Dashboard | Tableau de bord central |
| 🛡️ **Security Operations Center** | Dashboard | SOC avec horloge mondiale, carte menaces |
| 📋 **Migration Roadmap** | Dashboard | Suivi migration OpenWRT vers Debian |
| 🛡️ **CrowdSec** | Security | Moteur de sécurité collaboratif |
| 🔥 **Web Application Firewall** | Security | WAF avec 300+ règles |
| 🔥 **Vortex Firewall** | Security | Application des menaces nftables |
| 🔒 **System Hardening** | Security | Durcissement système et noyau |
| 🔍 **MITM Proxy** | Security | Inspection trafic et proxy WAF |
| 🔐 **Auth Guardian** | Security | Gestion authentification |
| 🛡️ **Network Access Control** | Security | Guardian client et NAC |
| 🌐 **Network Modes** | Network | Configuration topologie réseau |
| 📊 **QoS Manager** | Network | QoS avec HTB/VLAN |
| 📈 **Traffic Shaping** | Network | Mise en forme trafic TC/CAKE |
| ⚡ **HAProxy** | Network | Tableau de bord load balancer |
| 🚀 **CDN Cache** | Network | Cache de diffusion de contenu |
| 🏗️ **Virtual Hosts** | Network | Gestion hôtes virtuels Nginx |
| 🌍 **DNS Server** | DNS | Gestion zones DNS BIND |
| 🛡️ **Vortex DNS** | DNS | Pare-feu DNS avec RPZ |
| 📡 **Mesh DNS** | DNS | Résolution domaines réseau mesh |
| 🔗 **WireGuard VPN** | VPN | Gestion VPN moderne |
| 🕸️ **Mesh Network** | VPN | Réseau mesh (Yggdrasil) |
| 🔗 **P2P Network** | VPN | Réseau pair-à-pair |
| 🧅 **Tor Network** | Privacy | Anonymat Tor et services cachés |
| 🌐 **Exposure Settings** | Privacy | Exposition unifiée (Tor, SSL, DNS, Mesh) |
| 🔐 **Zero-Knowledge Proofs** | Privacy | Gestion ZKP Hamiltonien |
| 📊 **Netdata** | Monitoring | Surveillance système temps réel |
| 🔬 **Deep Packet Inspection** | Monitoring | DPI avec netifyd |
| 📱 **Device Intelligence** | Monitoring | Découverte actifs et empreintes |
| 👁️ **Watchdog** | Monitoring | Surveillance services et conteneurs |
| 🎬 **Media Flow** | Monitoring | Analyse trafic média |
| 🔐 **Login Portal** | Access | Portail authentification avec JWT |
| 👥 **User Management** | Access | Gestion identité unifiée |
| 📦 **Services Portal** | Services | Portail services C3Box |
| 🦊 **Gitea** | Services | Serveur Git (LXC) |
| ☁️ **Nextcloud** | Services | Synchronisation fichiers (LXC) |
| 📧 **Mail Server** | Email | Serveur mail Postfix/Dovecot |
| 💌 **Webmail** | Email | Webmail Roundcube/SOGo |
| 📰 **Publishing Platform** | Publishing | Tableau de bord publication unifié |
| 💧 **Droplet** | Publishing | Upload et publication fichiers |
| 📝 **Metablogizer** | Publishing | Éditeur site statique avec Tor |
| 🎨 **Streamlit** | Apps | Plateforme apps Streamlit |
| ⚡ **StreamForge** | Apps | Développement apps Streamlit |
| 📦 **APT Repository** | Apps | Gestion dépôt APT |
| ⚙️ **System Hub** | System | Configuration et gestion système |
| 💾 **Backup Manager** | System | Sauvegarde système et LXC |

---

## Modules

### 🏠 SecuBox Hub

**Catégorie:** Dashboard

Tableau de bord central

**Features:**
- Vue système
- Surveillance services
- Actions rapides
- Métriques

![SecuBox Hub](screenshots/vm/hub.png)

---

### 🛡️ Security Operations Center

**Catégorie:** Dashboard

SOC avec horloge mondiale, carte menaces

**Features:**
- Horloge mondiale
- Carte menaces
- Tickets
- Intel P2P
- Alertes

![Security Operations Center](screenshots/vm/soc.png)

---

### 📋 Migration Roadmap

**Catégorie:** Dashboard

Suivi migration OpenWRT vers Debian

**Features:**
- Suivi progression
- État modules
- Vue catégories

![Migration Roadmap](screenshots/vm/roadmap.png)

---

### 🛡️ CrowdSec

**Catégorie:** Security

Moteur de sécurité collaboratif

**Features:**
- Gestion décisions
- Alertes
- Bouncers
- Collections

![CrowdSec](screenshots/vm/crowdsec.png)

---

### 🔥 Web Application Firewall

**Catégorie:** Security

WAF avec 300+ règles

**Features:**
- Règles OWASP
- Règles custom
- Intégration CrowdSec

![Web Application Firewall](screenshots/vm/waf.png)

---

### 🔥 Vortex Firewall

**Catégorie:** Security

Application des menaces nftables

**Features:**
- Listes IP
- Sets nftables
- Flux menaces

![Vortex Firewall](screenshots/vm/vortex-firewall.png)

---

### 🔒 System Hardening

**Catégorie:** Security

Durcissement système et noyau

**Features:**
- Durcissement sysctl
- Blacklist modules
- Score sécurité

![System Hardening](screenshots/vm/hardening.png)

---

### 🔍 MITM Proxy

**Catégorie:** Security

Inspection trafic et proxy WAF

**Features:**
- Inspection trafic
- Logs requêtes
- Auto-ban

![MITM Proxy](screenshots/vm/mitmproxy.png)

---

### 🔐 Auth Guardian

**Catégorie:** Security

Gestion authentification

**Features:**
- OAuth2
- LDAP
- 2FA
- Sessions

![Auth Guardian](screenshots/vm/auth.png)

---

### 🛡️ Network Access Control

**Catégorie:** Security

Guardian client et NAC

**Features:**
- Contrôle appareils
- Filtrage MAC
- Quarantaine

![Network Access Control](screenshots/vm/nac.png)

---

### 🌐 Network Modes

**Catégorie:** Network

Configuration topologie réseau

**Features:**
- Mode routeur
- Mode pont
- Mode AP
- VLAN

![Network Modes](screenshots/vm/netmodes.png)

---

### 📊 QoS Manager

**Catégorie:** Network

QoS avec HTB/VLAN

**Features:**
- Contrôle bande passante
- Politiques VLAN
- 802.1p PCP

![QoS Manager](screenshots/vm/qos.png)

---

### 📈 Traffic Shaping

**Catégorie:** Network

Mise en forme trafic TC/CAKE

**Features:**
- QoS par interface
- Algorithme CAKE
- Statistiques

![Traffic Shaping](screenshots/vm/traffic.png)

---

### ⚡ HAProxy

**Catégorie:** Network

Tableau de bord load balancer

**Features:**
- Gestion backends
- Stats
- ACLs
- Terminaison SSL

![HAProxy](screenshots/vm/haproxy.png)

---

### 🚀 CDN Cache

**Catégorie:** Network

Cache de diffusion de contenu

**Features:**
- Gestion cache
- Purge
- Statistiques

![CDN Cache](screenshots/vm/cdn.png)

---

### 🏗️ Virtual Hosts

**Catégorie:** Network

Gestion hôtes virtuels Nginx

**Features:**
- Gestion sites
- Certificats SSL
- Reverse proxy

![Virtual Hosts](screenshots/vm/vhost.png)

---

### 🌍 DNS Server

**Catégorie:** DNS

Gestion zones DNS BIND

**Features:**
- Gestion zones
- Enregistrements
- DNSSEC

![DNS Server](screenshots/vm/dns.png)

---

### 🛡️ Vortex DNS

**Catégorie:** DNS

Pare-feu DNS avec RPZ

**Features:**
- Listes blocage
- RPZ
- Flux menaces

![Vortex DNS](screenshots/vm/vortex-dns.png)

---

### 📡 Mesh DNS

**Catégorie:** DNS

Résolution domaines réseau mesh

**Features:**
- mDNS/Avahi
- DNS local
- Découverte services

![Mesh DNS](screenshots/vm/meshname.png)

---

### 🔗 WireGuard VPN

**Catégorie:** VPN

Gestion VPN moderne

**Features:**
- Gestion pairs
- QR codes
- Stats trafic

![WireGuard VPN](screenshots/vm/wireguard.png)

---

### 🕸️ Mesh Network

**Catégorie:** VPN

Réseau mesh (Yggdrasil)

**Features:**
- Découverte pairs
- Routage
- Chiffrement

![Mesh Network](screenshots/vm/mesh.png)

---

### 🔗 P2P Network

**Catégorie:** VPN

Réseau pair-à-pair

**Features:**
- Connexions directes
- Traversée NAT
- Chiffrement

![P2P Network](screenshots/vm/p2p.png)

---

### 🧅 Tor Network

**Catégorie:** Privacy

Anonymat Tor et services cachés

**Features:**
- Circuits
- Services cachés
- Bridges

![Tor Network](screenshots/vm/tor.png)

---

### 🌐 Exposure Settings

**Catégorie:** Privacy

Exposition unifiée (Tor, SSL, DNS, Mesh)

**Features:**
- Exposition Tor
- Certificats SSL
- Enregistrements DNS
- Accès mesh

![Exposure Settings](screenshots/vm/exposure.png)

---

### 🔐 Zero-Knowledge Proofs

**Catégorie:** Privacy

Gestion ZKP Hamiltonien

**Features:**
- Génération preuves
- Vérification
- Gestion clés

![Zero-Knowledge Proofs](screenshots/vm/zkp.png)

---

### 📊 Netdata

**Catégorie:** Monitoring

Surveillance système temps réel

**Features:**
- Métriques
- Alertes
- Graphiques
- Plugins

![Netdata](screenshots/vm/netdata.png)

---

### 🔬 Deep Packet Inspection

**Catégorie:** Monitoring

DPI avec netifyd

**Features:**
- Détection protocoles
- Identification apps
- Analyse flux

![Deep Packet Inspection](screenshots/vm/dpi.png)

---

### 📱 Device Intelligence

**Catégorie:** Monitoring

Découverte actifs et empreintes

**Features:**
- Scan ARP
- Recherche vendeur MAC
- Détection OS

![Device Intelligence](screenshots/vm/device-intel.png)

---

### 👁️ Watchdog

**Catégorie:** Monitoring

Surveillance services et conteneurs

**Features:**
- Vérifications santé
- Auto-redémarrage
- Alertes

![Watchdog](screenshots/vm/watchdog.png)

---

### 🎬 Media Flow

**Catégorie:** Monitoring

Analyse trafic média

**Features:**
- Détection flux
- Utilisation bande passante
- Analyse protocoles

![Media Flow](screenshots/vm/mediaflow.png)

---

### 🔐 Login Portal

**Catégorie:** Access

Portail authentification avec JWT

**Features:**
- Auth JWT
- Sessions
- Récupération mot de passe

![Login Portal](screenshots/vm/portal.png)

---

### 👥 User Management

**Catégorie:** Access

Gestion identité unifiée

**Features:**
- CRUD utilisateurs
- Groupes
- Provisioning services

![User Management](screenshots/vm/users.png)

---

### 📦 Services Portal

**Catégorie:** Services

Portail services C3Box

**Features:**
- Liens services
- Vue état
- Accès rapide

![Services Portal](screenshots/vm/c3box.png)

---

### 🦊 Gitea

**Catégorie:** Services

Serveur Git (LXC)

**Features:**
- Dépôts
- Utilisateurs
- SSH/HTTP
- LFS

![Gitea](screenshots/vm/gitea.png)

---

### ☁️ Nextcloud

**Catégorie:** Services

Synchronisation fichiers (LXC)

**Features:**
- Sync fichiers
- WebDAV
- CalDAV
- CardDAV

![Nextcloud](screenshots/vm/nextcloud.png)

---

### 📧 Mail Server

**Catégorie:** Email

Serveur mail Postfix/Dovecot

**Features:**
- Domaines
- Boîtes mail
- DKIM
- SpamAssassin
- ClamAV

![Mail Server](screenshots/vm/mail.png)

---

### 💌 Webmail

**Catégorie:** Email

Webmail Roundcube/SOGo

**Features:**
- Interface web
- Carnet adresses
- Calendrier

![Webmail](screenshots/vm/webmail.png)

---

### 📰 Publishing Platform

**Catégorie:** Publishing

Tableau de bord publication unifié

**Features:**
- Multi-plateforme
- Planification
- Analytiques

![Publishing Platform](screenshots/vm/publish.png)

---

### 💧 Droplet

**Catégorie:** Publishing

Upload et publication fichiers

**Features:**
- Upload fichiers
- Liens partage
- Expiration

![Droplet](screenshots/vm/droplet.png)

---

### 📝 Metablogizer

**Catégorie:** Publishing

Éditeur site statique avec Tor

**Features:**
- Sites statiques
- Publication Tor
- Templates

![Metablogizer](screenshots/vm/metablogizer.png)

---

### 🎨 Streamlit

**Catégorie:** Apps

Plateforme apps Streamlit

**Features:**
- Hébergement apps
- Déploiement
- Gestion

![Streamlit](screenshots/vm/streamlit.png)

---

### ⚡ StreamForge

**Catégorie:** Apps

Développement apps Streamlit

**Features:**
- Templates
- Éditeur code
- Aperçu

![StreamForge](screenshots/vm/streamforge.png)

---

### 📦 APT Repository

**Catégorie:** Apps

Gestion dépôt APT

**Features:**
- Gestion paquets
- Signature GPG
- Multi-distro

![APT Repository](screenshots/vm/repo.png)

---

### ⚙️ System Hub

**Catégorie:** System

Configuration et gestion système

**Features:**
- Paramètres
- Logs
- Services
- Mises à jour

![System Hub](screenshots/vm/system.png)

---

### 💾 Backup Manager

**Catégorie:** System

Sauvegarde système et LXC

**Features:**
- Sauvegarde config
- Snapshots LXC
- Restauration

![Backup Manager](screenshots/vm/backup.png)

---

