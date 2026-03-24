#!/usr/bin/env python3
"""
SecuBox Documentation Generator
Generates READMEs for all packages and multilingual wiki pages.
"""

import json
import os
from pathlib import Path
from datetime import datetime

# Module metadata - All 47 modules
MODULES = {
    # Dashboard
    "hub": {"name": "SecuBox Hub", "icon": "🏠", "category": "Dashboard",
        "description": {"en": "Central dashboard and control center", "fr": "Tableau de bord central", "de": "Zentrales Dashboard", "zh": "中央仪表板"},
        "features": {"en": ["System overview", "Service monitoring", "Quick actions", "Metrics"], "fr": ["Vue système", "Surveillance services", "Actions rapides", "Métriques"], "de": ["Systemübersicht", "Service-Überwachung", "Schnellaktionen", "Metriken"], "zh": ["系统概览", "服务监控", "快速操作", "指标"]}},
    "soc": {"name": "Security Operations Center", "icon": "🛡️", "category": "Dashboard",
        "description": {"en": "SOC with world clock, threat map, tickets", "fr": "SOC avec horloge mondiale, carte menaces", "de": "SOC mit Weltuhr, Bedrohungskarte", "zh": "安全运营中心"},
        "features": {"en": ["World clock", "Threat map", "Ticket system", "P2P intel", "Alerts"], "fr": ["Horloge mondiale", "Carte menaces", "Tickets", "Intel P2P", "Alertes"], "de": ["Weltuhr", "Bedrohungskarte", "Ticketsystem", "P2P-Intel", "Warnungen"], "zh": ["世界时钟", "威胁地图", "工单系统", "P2P情报", "告警"]}},
    "roadmap": {"name": "Migration Roadmap", "icon": "📋", "category": "Dashboard",
        "description": {"en": "OpenWRT to Debian migration tracking", "fr": "Suivi migration OpenWRT vers Debian", "de": "OpenWRT zu Debian Migration", "zh": "OpenWRT到Debian迁移跟踪"},
        "features": {"en": ["Progress tracking", "Module status", "Category view"], "fr": ["Suivi progression", "État modules", "Vue catégories"], "de": ["Fortschrittsverfolgung", "Modulstatus", "Kategorieansicht"], "zh": ["进度跟踪", "模块状态", "分类视图"]}},
    # Security
    "crowdsec": {"name": "CrowdSec", "icon": "🛡️", "category": "Security",
        "description": {"en": "Collaborative security engine", "fr": "Moteur de sécurité collaboratif", "de": "Kollaborative Sicherheits-Engine", "zh": "协作式安全引擎"},
        "features": {"en": ["Decision management", "Alerts", "Bouncers", "Collections"], "fr": ["Gestion décisions", "Alertes", "Bouncers", "Collections"], "de": ["Entscheidungsverwaltung", "Warnungen", "Bouncers", "Sammlungen"], "zh": ["决策管理", "告警", "Bouncer", "集合"]}},
    "waf": {"name": "Web Application Firewall", "icon": "🔥", "category": "Security",
        "description": {"en": "WAF with 300+ security rules", "fr": "WAF avec 300+ règles", "de": "WAF mit 300+ Regeln", "zh": "300+规则的WAF"},
        "features": {"en": ["OWASP rules", "Custom rules", "CrowdSec integration"], "fr": ["Règles OWASP", "Règles custom", "Intégration CrowdSec"], "de": ["OWASP-Regeln", "Eigene Regeln", "CrowdSec-Integration"], "zh": ["OWASP规则", "自定义规则", "CrowdSec集成"]}},
    "vortex-firewall": {"name": "Vortex Firewall", "icon": "🔥", "category": "Security",
        "description": {"en": "nftables threat enforcement", "fr": "Application des menaces nftables", "de": "nftables Bedrohungsdurchsetzung", "zh": "nftables威胁执行"},
        "features": {"en": ["IP blocklists", "nftables sets", "Threat feeds"], "fr": ["Listes IP", "Sets nftables", "Flux menaces"], "de": ["IP-Blocklisten", "nftables-Sets", "Bedrohungsfeeds"], "zh": ["IP黑名单", "nftables集合", "威胁源"]}},
    "hardening": {"name": "System Hardening", "icon": "🔒", "category": "Security",
        "description": {"en": "Kernel and system hardening", "fr": "Durcissement système et noyau", "de": "Kernel- und Systemhärtung", "zh": "内核和系统加固"},
        "features": {"en": ["Sysctl hardening", "Module blacklist", "Security score"], "fr": ["Durcissement sysctl", "Blacklist modules", "Score sécurité"], "de": ["Sysctl-Härtung", "Modul-Blacklist", "Sicherheitsbewertung"], "zh": ["sysctl加固", "模块黑名单", "安全评分"]}},
    "mitmproxy": {"name": "MITM Proxy", "icon": "🔍", "category": "Security",
        "description": {"en": "Traffic inspection and WAF proxy", "fr": "Inspection trafic et proxy WAF", "de": "Verkehrsinspektion und WAF-Proxy", "zh": "流量检查和WAF代理"},
        "features": {"en": ["Traffic inspection", "Request logging", "Auto-ban"], "fr": ["Inspection trafic", "Logs requêtes", "Auto-ban"], "de": ["Verkehrsinspektion", "Anforderungsprotokollierung", "Auto-Ban"], "zh": ["流量检查", "请求日志", "自动封禁"]}},
    "auth": {"name": "Auth Guardian", "icon": "🔐", "category": "Security",
        "description": {"en": "Authentication management", "fr": "Gestion authentification", "de": "Authentifizierungsverwaltung", "zh": "认证管理"},
        "features": {"en": ["OAuth2", "LDAP", "2FA", "Session management"], "fr": ["OAuth2", "LDAP", "2FA", "Sessions"], "de": ["OAuth2", "LDAP", "2FA", "Sitzungen"], "zh": ["OAuth2", "LDAP", "双因素", "会话管理"]}},
    "nac": {"name": "Network Access Control", "icon": "🛡️", "category": "Security",
        "description": {"en": "Client guardian and NAC", "fr": "Guardian client et NAC", "de": "Client-Guardian und NAC", "zh": "客户端守护和NAC"},
        "features": {"en": ["Device control", "MAC filtering", "Quarantine"], "fr": ["Contrôle appareils", "Filtrage MAC", "Quarantaine"], "de": ["Gerätesteuerung", "MAC-Filterung", "Quarantäne"], "zh": ["设备控制", "MAC过滤", "隔离"]}},
    # Network
    "netmodes": {"name": "Network Modes", "icon": "🌐", "category": "Network",
        "description": {"en": "Network topology configuration", "fr": "Configuration topologie réseau", "de": "Netzwerktopologie-Konfiguration", "zh": "网络拓扑配置"},
        "features": {"en": ["Router mode", "Bridge mode", "AP mode", "VLAN"], "fr": ["Mode routeur", "Mode pont", "Mode AP", "VLAN"], "de": ["Router-Modus", "Bridge-Modus", "AP-Modus", "VLAN"], "zh": ["路由模式", "桥接模式", "AP模式", "VLAN"]}},
    "qos": {"name": "QoS Manager", "icon": "📊", "category": "Network",
        "description": {"en": "Quality of Service with HTB/VLAN", "fr": "QoS avec HTB/VLAN", "de": "QoS mit HTB/VLAN", "zh": "HTB/VLAN服务质量"},
        "features": {"en": ["Bandwidth control", "VLAN policies", "802.1p PCP"], "fr": ["Contrôle bande passante", "Politiques VLAN", "802.1p PCP"], "de": ["Bandbreitenkontrolle", "VLAN-Richtlinien", "802.1p PCP"], "zh": ["带宽控制", "VLAN策略", "802.1p PCP"]}},
    "traffic": {"name": "Traffic Shaping", "icon": "📈", "category": "Network",
        "description": {"en": "TC/CAKE traffic shaping", "fr": "Mise en forme trafic TC/CAKE", "de": "TC/CAKE Verkehrsformung", "zh": "TC/CAKE流量整形"},
        "features": {"en": ["Per-interface QoS", "CAKE algorithm", "Statistics"], "fr": ["QoS par interface", "Algorithme CAKE", "Statistiques"], "de": ["Pro-Schnittstelle QoS", "CAKE-Algorithmus", "Statistiken"], "zh": ["每接口QoS", "CAKE算法", "统计"]}},
    "haproxy": {"name": "HAProxy", "icon": "⚡", "category": "Network",
        "description": {"en": "Load balancer dashboard", "fr": "Tableau de bord load balancer", "de": "Load-Balancer-Dashboard", "zh": "负载均衡器仪表板"},
        "features": {"en": ["Backend management", "Stats", "ACLs", "SSL termination"], "fr": ["Gestion backends", "Stats", "ACLs", "Terminaison SSL"], "de": ["Backend-Verwaltung", "Statistiken", "ACLs", "SSL-Terminierung"], "zh": ["后端管理", "统计", "ACL", "SSL终止"]}},
    "cdn": {"name": "CDN Cache", "icon": "🚀", "category": "Network",
        "description": {"en": "Content delivery cache", "fr": "Cache de diffusion de contenu", "de": "Content-Delivery-Cache", "zh": "内容分发缓存"},
        "features": {"en": ["Cache management", "Purge", "Statistics"], "fr": ["Gestion cache", "Purge", "Statistiques"], "de": ["Cache-Verwaltung", "Bereinigung", "Statistiken"], "zh": ["缓存管理", "清除", "统计"]}},
    "vhost": {"name": "Virtual Hosts", "icon": "🏗️", "category": "Network",
        "description": {"en": "Nginx virtual host management", "fr": "Gestion hôtes virtuels Nginx", "de": "Nginx Virtual Host Verwaltung", "zh": "Nginx虚拟主机管理"},
        "features": {"en": ["Site management", "SSL certificates", "Reverse proxy"], "fr": ["Gestion sites", "Certificats SSL", "Reverse proxy"], "de": ["Site-Verwaltung", "SSL-Zertifikate", "Reverse-Proxy"], "zh": ["站点管理", "SSL证书", "反向代理"]}},
    # DNS
    "dns": {"name": "DNS Server", "icon": "🌍", "category": "DNS",
        "description": {"en": "BIND DNS zone management", "fr": "Gestion zones DNS BIND", "de": "BIND DNS-Zonenverwaltung", "zh": "BIND DNS区域管理"},
        "features": {"en": ["Zone management", "Records", "DNSSEC"], "fr": ["Gestion zones", "Enregistrements", "DNSSEC"], "de": ["Zonenverwaltung", "Einträge", "DNSSEC"], "zh": ["区域管理", "记录", "DNSSEC"]}},
    "vortex-dns": {"name": "Vortex DNS", "icon": "🛡️", "category": "DNS",
        "description": {"en": "DNS firewall with RPZ", "fr": "Pare-feu DNS avec RPZ", "de": "DNS-Firewall mit RPZ", "zh": "带RPZ的DNS防火墙"},
        "features": {"en": ["Blocklists", "RPZ", "Threat feeds"], "fr": ["Listes blocage", "RPZ", "Flux menaces"], "de": ["Blocklisten", "RPZ", "Bedrohungsfeeds"], "zh": ["黑名单", "RPZ", "威胁源"]}},
    "meshname": {"name": "Mesh DNS", "icon": "📡", "category": "DNS",
        "description": {"en": "Mesh network domain resolution", "fr": "Résolution domaines réseau mesh", "de": "Mesh-Netzwerk-Domänenauflösung", "zh": "Mesh网络域名解析"},
        "features": {"en": ["mDNS/Avahi", "Local DNS", "Service discovery"], "fr": ["mDNS/Avahi", "DNS local", "Découverte services"], "de": ["mDNS/Avahi", "Lokales DNS", "Diensterkennung"], "zh": ["mDNS/Avahi", "本地DNS", "服务发现"]}},
    # VPN & Privacy
    "wireguard": {"name": "WireGuard VPN", "icon": "🔗", "category": "VPN",
        "description": {"en": "Modern VPN management", "fr": "Gestion VPN moderne", "de": "Moderne VPN-Verwaltung", "zh": "现代VPN管理"},
        "features": {"en": ["Peer management", "QR codes", "Traffic stats"], "fr": ["Gestion pairs", "QR codes", "Stats trafic"], "de": ["Peer-Verwaltung", "QR-Codes", "Verkehrsstatistiken"], "zh": ["节点管理", "二维码", "流量统计"]}},
    "mesh": {"name": "Mesh Network", "icon": "🕸️", "category": "VPN",
        "description": {"en": "Mesh networking (Yggdrasil)", "fr": "Réseau mesh (Yggdrasil)", "de": "Mesh-Netzwerk (Yggdrasil)", "zh": "Mesh网络(Yggdrasil)"},
        "features": {"en": ["Peer discovery", "Routing", "Encryption"], "fr": ["Découverte pairs", "Routage", "Chiffrement"], "de": ["Peer-Erkennung", "Routing", "Verschlüsselung"], "zh": ["节点发现", "路由", "加密"]}},
    "p2p": {"name": "P2P Network", "icon": "🔗", "category": "VPN",
        "description": {"en": "Peer-to-peer networking", "fr": "Réseau pair-à-pair", "de": "Peer-to-Peer-Netzwerk", "zh": "点对点网络"},
        "features": {"en": ["Direct connections", "NAT traversal", "Encryption"], "fr": ["Connexions directes", "Traversée NAT", "Chiffrement"], "de": ["Direktverbindungen", "NAT-Traversal", "Verschlüsselung"], "zh": ["直接连接", "NAT穿透", "加密"]}},
    "tor": {"name": "Tor Network", "icon": "🧅", "category": "Privacy",
        "description": {"en": "Tor anonymity and hidden services", "fr": "Anonymat Tor et services cachés", "de": "Tor-Anonymität und versteckte Dienste", "zh": "Tor匿名和隐藏服务"},
        "features": {"en": ["Circuits", "Hidden services", "Bridges"], "fr": ["Circuits", "Services cachés", "Bridges"], "de": ["Schaltkreise", "Versteckte Dienste", "Bridges"], "zh": ["电路", "隐藏服务", "桥接"]}},
    "exposure": {"name": "Exposure Settings", "icon": "🌐", "category": "Privacy",
        "description": {"en": "Unified exposure (Tor, SSL, DNS, Mesh)", "fr": "Exposition unifiée (Tor, SSL, DNS, Mesh)", "de": "Einheitliche Exposition (Tor, SSL, DNS, Mesh)", "zh": "统一暴露设置(Tor, SSL, DNS, Mesh)"},
        "features": {"en": ["Tor exposure", "SSL certs", "DNS records", "Mesh access"], "fr": ["Exposition Tor", "Certificats SSL", "Enregistrements DNS", "Accès mesh"], "de": ["Tor-Exposition", "SSL-Zertifikate", "DNS-Einträge", "Mesh-Zugang"], "zh": ["Tor暴露", "SSL证书", "DNS记录", "Mesh访问"]}},
    "zkp": {"name": "Zero-Knowledge Proofs", "icon": "🔐", "category": "Privacy",
        "description": {"en": "ZKP Hamiltonian management", "fr": "Gestion ZKP Hamiltonien", "de": "ZKP Hamiltonian-Verwaltung", "zh": "ZKP哈密顿管理"},
        "features": {"en": ["Proof generation", "Verification", "Key management"], "fr": ["Génération preuves", "Vérification", "Gestion clés"], "de": ["Beweisgenerierung", "Verifizierung", "Schlüsselverwaltung"], "zh": ["证明生成", "验证", "密钥管理"]}},
    # Monitoring
    "netdata": {"name": "Netdata", "icon": "📊", "category": "Monitoring",
        "description": {"en": "Real-time system monitoring", "fr": "Surveillance système temps réel", "de": "Echtzeit-Systemüberwachung", "zh": "实时系统监控"},
        "features": {"en": ["Metrics", "Alerts", "Charts", "Plugins"], "fr": ["Métriques", "Alertes", "Graphiques", "Plugins"], "de": ["Metriken", "Warnungen", "Diagramme", "Plugins"], "zh": ["指标", "告警", "图表", "插件"]}},
    "dpi": {"name": "Deep Packet Inspection", "icon": "🔬", "category": "Monitoring",
        "description": {"en": "DPI with netifyd", "fr": "DPI avec netifyd", "de": "DPI mit netifyd", "zh": "使用netifyd的DPI"},
        "features": {"en": ["Protocol detection", "App identification", "Flow analysis"], "fr": ["Détection protocoles", "Identification apps", "Analyse flux"], "de": ["Protokollerkennung", "App-Identifizierung", "Flussanalyse"], "zh": ["协议检测", "应用识别", "流量分析"]}},
    "device-intel": {"name": "Device Intelligence", "icon": "📱", "category": "Monitoring",
        "description": {"en": "Asset discovery and fingerprinting", "fr": "Découverte actifs et empreintes", "de": "Asset-Erkennung und Fingerprinting", "zh": "资产发现和指纹识别"},
        "features": {"en": ["ARP scanning", "MAC vendor lookup", "OS detection"], "fr": ["Scan ARP", "Recherche vendeur MAC", "Détection OS"], "de": ["ARP-Scanning", "MAC-Vendor-Suche", "OS-Erkennung"], "zh": ["ARP扫描", "MAC厂商查询", "OS检测"]}},
    "watchdog": {"name": "Watchdog", "icon": "👁️", "category": "Monitoring",
        "description": {"en": "Service and container monitoring", "fr": "Surveillance services et conteneurs", "de": "Service- und Container-Überwachung", "zh": "服务和容器监控"},
        "features": {"en": ["Health checks", "Auto-restart", "Alerts"], "fr": ["Vérifications santé", "Auto-redémarrage", "Alertes"], "de": ["Gesundheitsprüfungen", "Auto-Neustart", "Warnungen"], "zh": ["健康检查", "自动重启", "告警"]}},
    "mediaflow": {"name": "Media Flow", "icon": "🎬", "category": "Monitoring",
        "description": {"en": "Media traffic analytics", "fr": "Analyse trafic média", "de": "Medienverkehrsanalyse", "zh": "媒体流量分析"},
        "features": {"en": ["Stream detection", "Bandwidth usage", "Protocol analysis"], "fr": ["Détection flux", "Utilisation bande passante", "Analyse protocoles"], "de": ["Stream-Erkennung", "Bandbreitennutzung", "Protokollanalyse"], "zh": ["流检测", "带宽使用", "协议分析"]}},
    # Access Control
    "portal": {"name": "Login Portal", "icon": "🔐", "category": "Access",
        "description": {"en": "Authentication portal with JWT", "fr": "Portail authentification avec JWT", "de": "Authentifizierungsportal mit JWT", "zh": "JWT认证门户"},
        "features": {"en": ["JWT auth", "Sessions", "Password recovery"], "fr": ["Auth JWT", "Sessions", "Récupération mot de passe"], "de": ["JWT-Auth", "Sitzungen", "Passwortwiederherstellung"], "zh": ["JWT认证", "会话", "密码恢复"]}},
    "users": {"name": "User Management", "icon": "👥", "category": "Access",
        "description": {"en": "Unified identity management", "fr": "Gestion identité unifiée", "de": "Einheitliche Identitätsverwaltung", "zh": "统一身份管理"},
        "features": {"en": ["User CRUD", "Groups", "Service provisioning"], "fr": ["CRUD utilisateurs", "Groupes", "Provisioning services"], "de": ["Benutzer-CRUD", "Gruppen", "Service-Bereitstellung"], "zh": ["用户CRUD", "组", "服务配置"]}},
    # Services
    "c3box": {"name": "Services Portal", "icon": "📦", "category": "Services",
        "description": {"en": "C3Box services portal", "fr": "Portail services C3Box", "de": "C3Box-Dienstportal", "zh": "C3Box服务门户"},
        "features": {"en": ["Service links", "Status overview", "Quick access"], "fr": ["Liens services", "Vue état", "Accès rapide"], "de": ["Service-Links", "Statusübersicht", "Schnellzugriff"], "zh": ["服务链接", "状态概览", "快速访问"]}},
    "gitea": {"name": "Gitea", "icon": "🦊", "category": "Services",
        "description": {"en": "Git server (LXC)", "fr": "Serveur Git (LXC)", "de": "Git-Server (LXC)", "zh": "Git服务器(LXC)"},
        "features": {"en": ["Repositories", "Users", "SSH/HTTP", "LFS"], "fr": ["Dépôts", "Utilisateurs", "SSH/HTTP", "LFS"], "de": ["Repositories", "Benutzer", "SSH/HTTP", "LFS"], "zh": ["仓库", "用户", "SSH/HTTP", "LFS"]}},
    "nextcloud": {"name": "Nextcloud", "icon": "☁️", "category": "Services",
        "description": {"en": "File sync (LXC)", "fr": "Synchronisation fichiers (LXC)", "de": "Dateisynchronisierung (LXC)", "zh": "文件同步(LXC)"},
        "features": {"en": ["File sync", "WebDAV", "CalDAV", "CardDAV"], "fr": ["Sync fichiers", "WebDAV", "CalDAV", "CardDAV"], "de": ["Dateisync", "WebDAV", "CalDAV", "CardDAV"], "zh": ["文件同步", "WebDAV", "CalDAV", "CardDAV"]}},
    # Email
    "mail": {"name": "Mail Server", "icon": "📧", "category": "Email",
        "description": {"en": "Postfix/Dovecot mail server", "fr": "Serveur mail Postfix/Dovecot", "de": "Postfix/Dovecot-Mailserver", "zh": "Postfix/Dovecot邮件服务器"},
        "features": {"en": ["Domains", "Mailboxes", "DKIM", "SpamAssassin", "ClamAV"], "fr": ["Domaines", "Boîtes mail", "DKIM", "SpamAssassin", "ClamAV"], "de": ["Domänen", "Postfächer", "DKIM", "SpamAssassin", "ClamAV"], "zh": ["域名", "邮箱", "DKIM", "SpamAssassin", "ClamAV"]}},
    "webmail": {"name": "Webmail", "icon": "💌", "category": "Email",
        "description": {"en": "Roundcube/SOGo webmail", "fr": "Webmail Roundcube/SOGo", "de": "Roundcube/SOGo-Webmail", "zh": "Roundcube/SOGo网页邮箱"},
        "features": {"en": ["Web interface", "Address book", "Calendar"], "fr": ["Interface web", "Carnet adresses", "Calendrier"], "de": ["Web-Oberfläche", "Adressbuch", "Kalender"], "zh": ["Web界面", "通讯录", "日历"]}},
    # Publishing
    "publish": {"name": "Publishing Platform", "icon": "📰", "category": "Publishing",
        "description": {"en": "Unified publishing dashboard", "fr": "Tableau de bord publication unifié", "de": "Einheitliches Veröffentlichungs-Dashboard", "zh": "统一发布仪表板"},
        "features": {"en": ["Multi-platform", "Scheduling", "Analytics"], "fr": ["Multi-plateforme", "Planification", "Analytiques"], "de": ["Multi-Plattform", "Planung", "Analysen"], "zh": ["多平台", "计划", "分析"]}},
    "droplet": {"name": "Droplet", "icon": "💧", "category": "Publishing",
        "description": {"en": "File upload and publish", "fr": "Upload et publication fichiers", "de": "Datei-Upload und Veröffentlichung", "zh": "文件上传和发布"},
        "features": {"en": ["File upload", "Share links", "Expiration"], "fr": ["Upload fichiers", "Liens partage", "Expiration"], "de": ["Datei-Upload", "Freigabelinks", "Ablauf"], "zh": ["文件上传", "分享链接", "过期"]}},
    "metablogizer": {"name": "Metablogizer", "icon": "📝", "category": "Publishing",
        "description": {"en": "Static site publisher with Tor", "fr": "Éditeur site statique avec Tor", "de": "Statischer Site-Publisher mit Tor", "zh": "带Tor的静态站点发布器"},
        "features": {"en": ["Static sites", "Tor publishing", "Templates"], "fr": ["Sites statiques", "Publication Tor", "Templates"], "de": ["Statische Sites", "Tor-Veröffentlichung", "Vorlagen"], "zh": ["静态站点", "Tor发布", "模板"]}},
    # Apps
    "streamlit": {"name": "Streamlit", "icon": "🎨", "category": "Apps",
        "description": {"en": "Streamlit app platform", "fr": "Plateforme apps Streamlit", "de": "Streamlit-App-Plattform", "zh": "Streamlit应用平台"},
        "features": {"en": ["App hosting", "Deployment", "Management"], "fr": ["Hébergement apps", "Déploiement", "Gestion"], "de": ["App-Hosting", "Bereitstellung", "Verwaltung"], "zh": ["应用托管", "部署", "管理"]}},
    "streamforge": {"name": "StreamForge", "icon": "⚡", "category": "Apps",
        "description": {"en": "Streamlit app development", "fr": "Développement apps Streamlit", "de": "Streamlit-App-Entwicklung", "zh": "Streamlit应用开发"},
        "features": {"en": ["Templates", "Code editor", "Preview"], "fr": ["Templates", "Éditeur code", "Aperçu"], "de": ["Vorlagen", "Code-Editor", "Vorschau"], "zh": ["模板", "代码编辑器", "预览"]}},
    "repo": {"name": "APT Repository", "icon": "📦", "category": "Apps",
        "description": {"en": "APT repository management", "fr": "Gestion dépôt APT", "de": "APT-Repository-Verwaltung", "zh": "APT仓库管理"},
        "features": {"en": ["Package management", "GPG signing", "Multi-distro"], "fr": ["Gestion paquets", "Signature GPG", "Multi-distro"], "de": ["Paketverwaltung", "GPG-Signierung", "Multi-Distro"], "zh": ["包管理", "GPG签名", "多发行版"]}},
    # System
    "system": {"name": "System Hub", "icon": "⚙️", "category": "System",
        "description": {"en": "System configuration and management", "fr": "Configuration et gestion système", "de": "Systemkonfiguration und -verwaltung", "zh": "系统配置和管理"},
        "features": {"en": ["Settings", "Logs", "Services", "Updates"], "fr": ["Paramètres", "Logs", "Services", "Mises à jour"], "de": ["Einstellungen", "Protokolle", "Dienste", "Updates"], "zh": ["设置", "日志", "服务", "更新"]}},
    "backup": {"name": "Backup Manager", "icon": "💾", "category": "System",
        "description": {"en": "System and LXC backup", "fr": "Sauvegarde système et LXC", "de": "System- und LXC-Backup", "zh": "系统和LXC备份"},
        "features": {"en": ["Config backup", "LXC snapshots", "Restore"], "fr": ["Sauvegarde config", "Snapshots LXC", "Restauration"], "de": ["Config-Backup", "LXC-Snapshots", "Wiederherstellung"], "zh": ["配置备份", "LXC快照", "恢复"]}},
}

LANGUAGES = {
    "en": {"name": "English", "flag": "🇬🇧"},
    "fr": {"name": "Français", "flag": "🇫🇷"},
    "de": {"name": "Deutsch", "flag": "🇩🇪"},
    "zh": {"name": "中文", "flag": "🇨🇳"},
}

def generate_package_readme(module_id: str, module_info: dict, lang: str = "en") -> str:
    """Generate README for a package."""
    name = module_info["name"]
    icon = module_info["icon"]
    category = module_info["category"]
    desc = module_info["description"].get(lang, module_info["description"]["en"])
    features = module_info["features"].get(lang, module_info["features"]["en"])

    labels = {
        "en": {"features": "Features", "install": "Installation", "config": "Configuration", "api": "API Endpoints", "screenshot": "Screenshot", "license": "License"},
        "fr": {"features": "Fonctionnalités", "install": "Installation", "config": "Configuration", "api": "Points d'accès API", "screenshot": "Capture d'écran", "license": "Licence"},
        "de": {"features": "Funktionen", "install": "Installation", "config": "Konfiguration", "api": "API-Endpunkte", "screenshot": "Screenshot", "license": "Lizenz"},
        "zh": {"features": "功能", "install": "安装", "config": "配置", "api": "API端点", "screenshot": "截图", "license": "许可证"},
    }
    L = labels.get(lang, labels["en"])

    readme = f"""# {icon} {name}

{desc}

**Category:** {category}

## {L['screenshot']}

![{name}](../../docs/screenshots/vm/{module_id}.png)

## {L['features']}

"""
    for feature in features:
        readme += f"- {feature}\n"

    readme += f"""
## {L['install']}

```bash
# Add SecuBox repository
curl -fsSL https://apt.secubox.in/install.sh | sudo bash

# Install package
sudo apt install secubox-{module_id}
```

## {L['config']}

Configuration file: `/etc/secubox/{module_id}.toml`

## {L['api']}

- `GET /api/v1/{module_id}/status` - Module status
- `GET /api/v1/{module_id}/health` - Health check

## {L['license']}

MIT License - CyberMind © 2024-2026
"""
    return readme


def generate_wiki_page(lang: str) -> str:
    """Generate wiki page for a language."""
    labels = {
        "en": {
            "title": "SecuBox Modules",
            "subtitle": "Complete module documentation",
            "overview": "Overview",
            "modules": "Modules",
            "category": "Category",
            "description": "Description",
            "screenshot": "Screenshot",
            "total": "Total modules",
        },
        "fr": {
            "title": "Modules SecuBox",
            "subtitle": "Documentation complète des modules",
            "overview": "Aperçu",
            "modules": "Modules",
            "category": "Catégorie",
            "description": "Description",
            "screenshot": "Capture d'écran",
            "total": "Total des modules",
        },
        "de": {
            "title": "SecuBox Module",
            "subtitle": "Vollständige Moduldokumentation",
            "overview": "Übersicht",
            "modules": "Module",
            "category": "Kategorie",
            "description": "Beschreibung",
            "screenshot": "Screenshot",
            "total": "Module insgesamt",
        },
        "zh": {
            "title": "SecuBox模块",
            "subtitle": "完整的模块文档",
            "overview": "概述",
            "modules": "模块",
            "category": "类别",
            "description": "描述",
            "screenshot": "截图",
            "total": "模块总数",
        },
    }
    L = labels.get(lang, labels["en"])

    # Language selector
    lang_links = " | ".join([f"[{LANGUAGES[l]['flag']} {LANGUAGES[l]['name']}](MODULES-{l.upper()}.md)" for l in LANGUAGES])

    wiki = f"""# {L['title']}

*{L['subtitle']}*

**{L['total']}:** 47

{lang_links}

---

## {L['overview']}

| {L['modules']} | {L['category']} | {L['description']} |
|--------|----------|-------------|
"""

    for mid, info in MODULES.items():
        desc = info["description"].get(lang, info["description"]["en"])
        wiki += f"| {info['icon']} **{info['name']}** | {info['category']} | {desc} |\n"

    wiki += f"""
---

## {L['modules']}

"""

    for mid, info in MODULES.items():
        desc = info["description"].get(lang, info["description"]["en"])
        features = info["features"].get(lang, info["features"]["en"])

        wiki += f"""### {info['icon']} {info['name']}

**{L['category']}:** {info['category']}

{desc}

**Features:**
"""
        for f in features:
            wiki += f"- {f}\n"

        wiki += f"""
![{info['name']}](screenshots/vm/{mid}.png)

---

"""

    return wiki


def main():
    base_dir = Path(__file__).parent.parent
    packages_dir = base_dir / "packages"
    docs_dir = base_dir / "docs"
    wiki_dir = docs_dir / "wiki"

    wiki_dir.mkdir(parents=True, exist_ok=True)

    print("Generating package READMEs...")
    for module_id, module_info in MODULES.items():
        pkg_dir = packages_dir / f"secubox-{module_id}"
        if pkg_dir.exists():
            readme_path = pkg_dir / "README.md"
            readme = generate_package_readme(module_id, module_info, "en")
            readme_path.write_text(readme)
            print(f"  Created {readme_path}")

    print("\nGenerating multilingual wiki pages...")
    for lang in LANGUAGES:
        wiki_path = wiki_dir / f"MODULES-{lang.upper()}.md"
        wiki = generate_wiki_page(lang)
        wiki_path.write_text(wiki)
        print(f"  Created {wiki_path}")

    print("\nDone!")


if __name__ == "__main__":
    main()
