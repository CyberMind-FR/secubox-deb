# Modules SecuBox

[English](Modules) | [中文](Modules-ZH)

Liste complete des paquets SecuBox et leurs fonctionnalites.

## Modules Coeur

### secubox-core
**Bibliotheques Partagees & Framework**

- Bibliotheque Python partagee (`secubox_core`)
- Framework authentification JWT
- Gestion configuration (TOML)
- Utilitaires de journalisation
- Configuration nginx de base

### secubox-hub
**Tableau de Bord Central**

- Interface web principale
- Apercu statut modules
- Surveillance sante systeme
- Agregation alertes
- Generation menu dynamique

### secubox-portal
**Portail d'Authentification**

- Connexion/deconnexion JWT
- Gestion sessions
- Reinitialisation mot de passe
- Support multi-utilisateurs

## Modules Securite

### secubox-crowdsec
**IDS/IPS avec CrowdSec**

- Detection menaces temps reel
- Listes de blocage communautaires
- Gestion decisions (ban/captcha)
- Integration bouncers
- Scenarios personnalises

### secubox-waf
**Pare-feu Applicatif Web**

- 300+ regles ModSecurity
- OWASP Core Rule Set
- Regles personnalisees
- Filtrage requetes/reponses
- Protection injection SQL
- Prevention XSS

### secubox-auth
**OAuth2 & Portail Captif**

- Fournisseur OAuth2/OIDC
- Portail captif invites
- Systeme de vouchers
- Integration login social
- Backend RADIUS

### secubox-nac
**Controle d'Acces Reseau**

- Empreinte peripheriques
- Acces base MAC
- Attribution VLAN
- Isolation invites
- Reseau quarantaine

### secubox-users
**Gestion Identite Unifiee**

- Base utilisateurs centrale
- Synchronisation 7 services
- Integration LDAP
- Gestion groupes
- Politiques mot de passe

## Modules Reseau

### secubox-wireguard
**Tableau de Bord VPN**

- Gestion interfaces
- Configuration peers
- Generation cles
- Export QR code
- Statistiques trafic

### secubox-haproxy
**Repartiteur de Charge & Proxy**

- Pools serveurs backend
- Verifications sante
- Terminaison SSL/TLS
- Regles ACL
- Tableau statistiques

### secubox-dpi
**Inspection Approfondie Paquets**

- Detection applications (netifyd)
- Classification protocoles
- Analyse flux
- Surveillance bande passante
- Top consommateurs

### secubox-qos
**Qualite de Service**

- Shaping trafic HTB
- Files prioritaires
- Limites bande passante
- Regles par peripherique
- Stats temps reel

### secubox-netmodes
**Modes Reseau**

- Mode routeur
- Mode bridge
- Mode point d'acces
- Configuration netplan
- Agregation interfaces

### secubox-vhost
**Hotes Virtuels**

- Gestion vhost nginx
- Certificats ACME
- Reverse proxy
- Configuration SSL
- Routage domaines

### secubox-cdn
**Cache CDN**

- Cache proxy Squid
- Cache nginx
- API purge cache
- Gestion stockage
- Statistiques hit rate

## Modules Supervision

### secubox-netdata
**Supervision Temps Reel**

- Metriques systeme
- Statistiques reseau
- Tableaux personnalises
- Configuration alertes
- Donnees historiques

### secubox-mediaflow
**Detection Streaming Media**

- Detection flux
- Utilisation bande passante
- Identification protocoles
- Metriques qualite

### secubox-metrics
**Collection Metriques**

- Format Prometheus
- Metriques personnalisees
- Endpoints API
- Integration tableaux

## Modules DNS & Email

### secubox-dns
**Serveur DNS**

- Zones BIND9
- Support DNSSEC
- Mises a jour dynamiques
- Interface gestion zones
- Journalisation requetes

### secubox-mail
**Serveur Email**

- MTA Postfix
- IMAP/POP3 Dovecot
- SpamAssassin
- Signature DKIM
- Domaines virtuels

### secubox-mail-lxc
**Conteneur LXC Mail**

- Environnement mail isole
- Limites ressources
- Deploiement facile

### secubox-webmail
**Interface Webmail**

- Roundcube / SOGo
- Integration calendrier
- Carnet d'adresses
- Filtres Sieve

## Modules Publication

### secubox-droplet
**Editeur de Fichiers**

- Upload glisser-deposer
- Partage public/prive
- Liens expirants
- Journalisation acces

### secubox-streamlit
**Plateforme Streamlit**

- Hebergement apps Python
- Tableaux de donnees
- Apps interactives
- Instances multiples

### secubox-streamforge
**Gestionnaire Streamlit**

- Deploiement apps
- Controle versions
- Gestion ressources

### secubox-metablogizer
**Generateur Site Statique**

- Contenu Markdown
- Service cache Tor
- Support themes
- Flux RSS

### secubox-publish
**Tableau Publication**

- Interface unifiee
- Tous outils publication
- Gestion contenu

## Modules Systeme

### secubox-system
**Gestion Systeme**

- Controle services
- Visualiseur logs
- Mises a jour paquets
- Redemarrage/arret
- Sauvegarde/restauration

### secubox-hardening
**Durcissement Securite**

- Parametres noyau
- Verrouillage services
- Permissions fichiers
- Journalisation audit

## Metapaquets

### secubox-full
Installe tous les modules. Recommande pour :
- MOCHAbin
- VMs avec 2+ Go RAM
- Deploiements complets

### secubox-lite
Installe modules essentiels. Recommande pour :
- ESPRESSObin (RAM limitee)
- Deploiements minimaux
- Peripheriques edge

## Voir Aussi

- [[Installation-FR]] - Comment installer
- [[API-Reference-FR]] - APIs modules
- [[Configuration-FR]] - Guide configuration
