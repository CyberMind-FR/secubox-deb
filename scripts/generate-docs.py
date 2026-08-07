#!/usr/bin/env python3
"""
SecuBox Documentation Generator
================================
Generates READMEs for all packages and multilingual wiki pages.

Features:
- Auto-discovers all 120+ modules from packages/
- Generates multilingual wiki pages (EN, FR, DE, ZH)
- Integrates screenshots from docs/screenshots/vm/
- Creates category index pages

Usage:
    python scripts/generate-docs.py
    python scripts/generate-docs.py --include-screenshots
    python scripts/generate-docs.py --lang fr
"""

import argparse
from pathlib import Path
from typing import Optional

# ============================================================================
# Module Metadata - All 120+ modules with multilingual descriptions
# ============================================================================

# Absolute base URL for wiki screenshots — the GitHub wiki is a separate repo, so
# images must be referenced via raw.githubusercontent (relative paths 404 there).
SCREENSHOT_RAW_BASE = (
    "https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/"
    "docs/screenshots/vm"
)

MODULES = {
    # =========================================================================
    # DASHBOARD
    # =========================================================================
    "hub": {
        "name": "SecuBox Hub", "icon": "🏠", "category": "Dashboard",
        "description": {
            "en": "Central dashboard and control center",
            "fr": "Tableau de bord central et centre de contrôle",
            "de": "Zentrales Dashboard und Kontrollzentrum",
            "zh": "中央仪表板和控制中心"
        },
        "features": {
            "en": ["System overview", "Service monitoring", "Quick actions", "Metrics"],
            "fr": ["Vue système", "Surveillance services", "Actions rapides", "Métriques"],
            "de": ["Systemübersicht", "Service-Überwachung", "Schnellaktionen", "Metriken"],
            "zh": ["系统概览", "服务监控", "快速操作", "指标"]
        }
    },
    "soc": {
        "name": "Security Operations Center", "icon": "🛡️", "category": "Dashboard",
        "description": {
            "en": "SOC with world clock, threat map, tickets",
            "fr": "SOC avec horloge mondiale, carte menaces, tickets",
            "de": "SOC mit Weltuhr, Bedrohungskarte, Tickets",
            "zh": "安全运营中心，包含世界时钟、威胁地图、工单"
        },
        "features": {
            "en": ["World clock", "Threat map", "Ticket system", "P2P intel", "Alerts"],
            "fr": ["Horloge mondiale", "Carte menaces", "Tickets", "Intel P2P", "Alertes"],
            "de": ["Weltuhr", "Bedrohungskarte", "Ticketsystem", "P2P-Intel", "Warnungen"],
            "zh": ["世界时钟", "威胁地图", "工单系统", "P2P情报", "告警"]
        }
    },
    "roadmap": {
        "name": "Migration Roadmap", "icon": "📋", "category": "Dashboard",
        "description": {
            "en": "OpenWRT to Debian migration tracking",
            "fr": "Suivi migration OpenWRT vers Debian",
            "de": "OpenWRT zu Debian Migration-Tracking",
            "zh": "OpenWRT到Debian迁移跟踪"
        },
        "features": {
            "en": ["Progress tracking", "Module status", "Category view"],
            "fr": ["Suivi progression", "État modules", "Vue catégories"],
            "de": ["Fortschrittsverfolgung", "Modulstatus", "Kategorieansicht"],
            "zh": ["进度跟踪", "模块状态", "分类视图"]
        }
    },
    "metrics": {
        "name": "System Metrics", "icon": "📈", "category": "Dashboard",
        "description": {
            "en": "Real-time system metrics dashboard",
            "fr": "Tableau de bord métriques système temps réel",
            "de": "Echtzeit-Systemmetriken-Dashboard",
            "zh": "实时系统指标仪表板"
        },
        "features": {
            "en": ["CPU/Memory", "Network stats", "Disk I/O", "Historical data"],
            "fr": ["CPU/Mémoire", "Stats réseau", "I/O disque", "Historique"],
            "de": ["CPU/Speicher", "Netzwerkstatistiken", "Disk-I/O", "Verlaufsdaten"],
            "zh": ["CPU/内存", "网络统计", "磁盘I/O", "历史数据"]
        }
    },
    "admin": {
        "name": "Admin Panel", "icon": "⚙️", "category": "Dashboard",
        "description": {
            "en": "System administration panel",
            "fr": "Panneau d'administration système",
            "de": "Systemverwaltungspanel",
            "zh": "系统管理面板"
        },
        "features": {
            "en": ["User management", "System config", "Logs", "Diagnostics"],
            "fr": ["Gestion utilisateurs", "Config système", "Logs", "Diagnostics"],
            "de": ["Benutzerverwaltung", "Systemkonfiguration", "Logs", "Diagnose"],
            "zh": ["用户管理", "系统配置", "日志", "诊断"]
        }
    },

    # =========================================================================
    # SECURITY
    # =========================================================================
    "crowdsec": {
        "name": "CrowdSec", "icon": "🛡️", "category": "Security",
        "description": {
            "en": "Collaborative security engine with behavior analysis",
            "fr": "Moteur de sécurité collaboratif avec analyse comportementale",
            "de": "Kollaborative Sicherheits-Engine mit Verhaltensanalyse",
            "zh": "具有行为分析的协作式安全引擎"
        },
        "features": {
            "en": ["Decision management", "Alerts", "Bouncers", "Collections", "Community blocklists"],
            "fr": ["Gestion décisions", "Alertes", "Bouncers", "Collections", "Listes communautaires"],
            "de": ["Entscheidungsverwaltung", "Warnungen", "Bouncers", "Sammlungen", "Community-Blocklisten"],
            "zh": ["决策管理", "告警", "Bouncer", "集合", "社区黑名单"]
        }
    },
    "waf": {
        "name": "Web Application Firewall", "icon": "🔥", "category": "Security",
        "description": {
            "en": "WAF with 300+ OWASP security rules",
            "fr": "WAF avec 300+ règles de sécurité OWASP",
            "de": "WAF mit 300+ OWASP-Sicherheitsregeln",
            "zh": "具有300+条OWASP安全规则的WAF"
        },
        "features": {
            "en": ["OWASP rules", "Custom rules", "CrowdSec integration", "Request logging"],
            "fr": ["Règles OWASP", "Règles custom", "Intégration CrowdSec", "Logs requêtes"],
            "de": ["OWASP-Regeln", "Eigene Regeln", "CrowdSec-Integration", "Anforderungsprotokollierung"],
            "zh": ["OWASP规则", "自定义规则", "CrowdSec集成", "请求日志"]
        }
    },
    "vortex-firewall": {
        "name": "Vortex Firewall", "icon": "🔥", "category": "Security",
        "description": {
            "en": "nftables-based threat enforcement firewall",
            "fr": "Pare-feu d'application des menaces basé sur nftables",
            "de": "nftables-basierte Bedrohungsdurchsetzungs-Firewall",
            "zh": "基于nftables的威胁执行防火墙"
        },
        "features": {
            "en": ["IP blocklists", "nftables sets", "Threat feeds", "Geo-blocking"],
            "fr": ["Listes IP", "Sets nftables", "Flux menaces", "Géo-blocage"],
            "de": ["IP-Blocklisten", "nftables-Sets", "Bedrohungsfeeds", "Geo-Blocking"],
            "zh": ["IP黑名单", "nftables集合", "威胁源", "地理封锁"]
        }
    },
    "hardening": {
        "name": "System Hardening", "icon": "🔒", "category": "Security",
        "description": {
            "en": "Kernel and system hardening for ANSSI CSPN compliance",
            "fr": "Durcissement système et noyau pour conformité ANSSI CSPN",
            "de": "Kernel- und Systemhärtung für ANSSI CSPN-Konformität",
            "zh": "符合ANSSI CSPN的内核和系统加固"
        },
        "features": {
            "en": ["Sysctl hardening", "Module blacklist", "Security score", "AppArmor"],
            "fr": ["Durcissement sysctl", "Blacklist modules", "Score sécurité", "AppArmor"],
            "de": ["Sysctl-Härtung", "Modul-Blacklist", "Sicherheitsbewertung", "AppArmor"],
            "zh": ["sysctl加固", "模块黑名单", "安全评分", "AppArmor"]
        }
    },
    "mitmproxy": {
        "name": "MITM Proxy", "icon": "🔍", "category": "Security",
        "description": {
            "en": "Traffic inspection and WAF proxy with auto-ban",
            "fr": "Inspection trafic et proxy WAF avec auto-ban",
            "de": "Verkehrsinspektion und WAF-Proxy mit Auto-Ban",
            "zh": "具有自动封禁功能的流量检查和WAF代理"
        },
        "features": {
            "en": ["Traffic inspection", "Request logging", "Auto-ban", "SSL interception"],
            "fr": ["Inspection trafic", "Logs requêtes", "Auto-ban", "Interception SSL"],
            "de": ["Verkehrsinspektion", "Anforderungsprotokollierung", "Auto-Ban", "SSL-Interception"],
            "zh": ["流量检查", "请求日志", "自动封禁", "SSL拦截"]
        }
    },
    "auth": {
        "name": "Auth Guardian", "icon": "🔐", "category": "Security",
        "description": {
            "en": "Unified authentication management",
            "fr": "Gestion unifiée de l'authentification",
            "de": "Einheitliche Authentifizierungsverwaltung",
            "zh": "统一认证管理"
        },
        "features": {
            "en": ["OAuth2", "LDAP", "2FA/TOTP", "Session management"],
            "fr": ["OAuth2", "LDAP", "2FA/TOTP", "Sessions"],
            "de": ["OAuth2", "LDAP", "2FA/TOTP", "Sitzungen"],
            "zh": ["OAuth2", "LDAP", "双因素/TOTP", "会话管理"]
        }
    },
    "nac": {
        "name": "Network Access Control", "icon": "🛡️", "category": "Security",
        "description": {
            "en": "Client guardian and NAC with quarantine",
            "fr": "Guardian client et NAC avec quarantaine",
            "de": "Client-Guardian und NAC mit Quarantäne",
            "zh": "具有隔离功能的客户端守护和NAC"
        },
        "features": {
            "en": ["Device control", "MAC filtering", "Quarantine", "VLAN assignment"],
            "fr": ["Contrôle appareils", "Filtrage MAC", "Quarantaine", "Assignation VLAN"],
            "de": ["Gerätesteuerung", "MAC-Filterung", "Quarantäne", "VLAN-Zuweisung"],
            "zh": ["设备控制", "MAC过滤", "隔离", "VLAN分配"]
        }
    },
    "ipblock": {
        "name": "IP Block Manager", "icon": "🚫", "category": "Security",
        "description": {
            "en": "IP and network blocking management",
            "fr": "Gestion du blocage IP et réseau",
            "de": "IP- und Netzwerksperrverwaltung",
            "zh": "IP和网络封锁管理"
        },
        "features": {
            "en": ["IP blocklists", "Network ranges", "Temporary bans", "Import/Export"],
            "fr": ["Listes IP", "Plages réseau", "Bans temporaires", "Import/Export"],
            "de": ["IP-Blocklisten", "Netzwerkbereiche", "Temporäre Sperren", "Import/Export"],
            "zh": ["IP黑名单", "网络范围", "临时封禁", "导入/导出"]
        }
    },
    "mac-guard": {
        "name": "MAC Guard", "icon": "🔐", "category": "Security",
        "description": {
            "en": "MAC address access control",
            "fr": "Contrôle d'accès par adresse MAC",
            "de": "MAC-Adress-Zugangskontrolle",
            "zh": "MAC地址访问控制"
        },
        "features": {
            "en": ["MAC whitelist/blacklist", "Auto-discovery", "Alerts", "VLAN binding"],
            "fr": ["Liste MAC blanche/noire", "Auto-découverte", "Alertes", "Liaison VLAN"],
            "de": ["MAC-Whitelist/Blacklist", "Auto-Erkennung", "Warnungen", "VLAN-Bindung"],
            "zh": ["MAC白名单/黑名单", "自动发现", "告警", "VLAN绑定"]
        }
    },
    "interceptor": {
        "name": "Traffic Interceptor", "icon": "📡", "category": "Security",
        "description": {
            "en": "Network traffic interception and analysis",
            "fr": "Interception et analyse du trafic réseau",
            "de": "Netzwerkverkehrs-Interception und -Analyse",
            "zh": "网络流量拦截和分析"
        },
        "features": {
            "en": ["Packet capture", "Protocol analysis", "Session tracking", "Forensics"],
            "fr": ["Capture paquets", "Analyse protocoles", "Suivi sessions", "Forensique"],
            "de": ["Paketerfassung", "Protokollanalyse", "Sitzungsverfolgung", "Forensik"],
            "zh": ["数据包捕获", "协议分析", "会话跟踪", "取证"]
        }
    },
    "cookies": {
        "name": "Cookie Manager", "icon": "🍪", "category": "Security",
        "description": {
            "en": "Cookie and session security management",
            "fr": "Gestion de la sécurité des cookies et sessions",
            "de": "Cookie- und Sitzungssicherheitsverwaltung",
            "zh": "Cookie和会话安全管理"
        },
        "features": {
            "en": ["Cookie policies", "Session security", "SameSite enforcement", "Audit"],
            "fr": ["Politiques cookies", "Sécurité sessions", "Enforcement SameSite", "Audit"],
            "de": ["Cookie-Richtlinien", "Sitzungssicherheit", "SameSite-Durchsetzung", "Audit"],
            "zh": ["Cookie策略", "会话安全", "SameSite执行", "审计"]
        }
    },
    "threats": {
        "name": "Threat Dashboard", "icon": "⚠️", "category": "Security",
        "description": {
            "en": "Unified threat visualization",
            "fr": "Visualisation unifiée des menaces",
            "de": "Einheitliche Bedrohungsvisualisierung",
            "zh": "统一威胁可视化"
        },
        "features": {
            "en": ["Threat feeds", "Attack timeline", "Severity levels", "Correlation"],
            "fr": ["Flux menaces", "Timeline attaques", "Niveaux gravité", "Corrélation"],
            "de": ["Bedrohungsfeeds", "Angriffszeitachse", "Schweregrade", "Korrelation"],
            "zh": ["威胁源", "攻击时间线", "严重级别", "关联"]
        }
    },
    "threat-analyst": {
        "name": "Threat Analyst", "icon": "🔬", "category": "Security",
        "description": {
            "en": "AI-powered threat analysis",
            "fr": "Analyse des menaces assistée par IA",
            "de": "KI-gestützte Bedrohungsanalyse",
            "zh": "AI驱动的威胁分析"
        },
        "features": {
            "en": ["ML detection", "Behavioral analysis", "IOC extraction", "Reports"],
            "fr": ["Détection ML", "Analyse comportementale", "Extraction IOC", "Rapports"],
            "de": ["ML-Erkennung", "Verhaltensanalyse", "IOC-Extraktion", "Berichte"],
            "zh": ["ML检测", "行为分析", "IOC提取", "报告"]
        }
    },
    "cve-triage": {
        "name": "CVE Triage", "icon": "🔴", "category": "Security",
        "description": {
            "en": "CVE vulnerability tracking and triage",
            "fr": "Suivi et triage des vulnérabilités CVE",
            "de": "CVE-Schwachstellenverfolgung und -Triage",
            "zh": "CVE漏洞跟踪和分类"
        },
        "features": {
            "en": ["CVE database", "Affected packages", "Risk scoring", "Remediation"],
            "fr": ["Base CVE", "Paquets affectés", "Score risque", "Remédiation"],
            "de": ["CVE-Datenbank", "Betroffene Pakete", "Risikobewertung", "Behebung"],
            "zh": ["CVE数据库", "受影响包", "风险评分", "修复"]
        }
    },
    "wazuh": {
        "name": "Wazuh SIEM", "icon": "🛡️", "category": "Security",
        "description": {
            "en": "Wazuh SIEM integration",
            "fr": "Intégration SIEM Wazuh",
            "de": "Wazuh SIEM-Integration",
            "zh": "Wazuh SIEM集成"
        },
        "features": {
            "en": ["Log analysis", "File integrity", "Vulnerability detection", "Compliance"],
            "fr": ["Analyse logs", "Intégrité fichiers", "Détection vulnérabilités", "Conformité"],
            "de": ["Log-Analyse", "Dateiintegrität", "Schwachstellenerkennung", "Compliance"],
            "zh": ["日志分析", "文件完整性", "漏洞检测", "合规"]
        }
    },
    "ossec": {
        "name": "OSSEC HIDS", "icon": "🔒", "category": "Security",
        "description": {
            "en": "OSSEC host-based intrusion detection",
            "fr": "Détection d'intrusion basée hôte OSSEC",
            "de": "OSSEC-hostbasierte Einbruchserkennung",
            "zh": "OSSEC主机入侵检测"
        },
        "features": {
            "en": ["Log analysis", "Rootkit detection", "File integrity", "Active response"],
            "fr": ["Analyse logs", "Détection rootkits", "Intégrité fichiers", "Réponse active"],
            "de": ["Log-Analyse", "Rootkit-Erkennung", "Dateiintegrität", "Aktive Reaktion"],
            "zh": ["日志分析", "Rootkit检测", "文件完整性", "主动响应"]
        }
    },
    "openclaw": {
        "name": "OpenClaw Scanner", "icon": "🦞", "category": "Security",
        "description": {
            "en": "Network vulnerability scanner",
            "fr": "Scanner de vulnérabilités réseau",
            "de": "Netzwerk-Schwachstellen-Scanner",
            "zh": "网络漏洞扫描器"
        },
        "features": {
            "en": ["Port scanning", "Service detection", "Vulnerability checks", "Reports"],
            "fr": ["Scan ports", "Détection services", "Vérifications vulnérabilités", "Rapports"],
            "de": ["Port-Scanning", "Diensterkennung", "Schwachstellenprüfungen", "Berichte"],
            "zh": ["端口扫描", "服务检测", "漏洞检查", "报告"]
        }
    },
    "iot-guard": {
        "name": "IoT Guard", "icon": "🔌", "category": "Security",
        "description": {
            "en": "IoT device security monitoring",
            "fr": "Surveillance sécurité appareils IoT",
            "de": "IoT-Gerätesicherheitsüberwachung",
            "zh": "IoT设备安全监控"
        },
        "features": {
            "en": ["Device fingerprinting", "Anomaly detection", "Isolation", "Firmware checks"],
            "fr": ["Empreinte appareils", "Détection anomalies", "Isolation", "Vérif firmware"],
            "de": ["Geräte-Fingerprinting", "Anomalieerkennung", "Isolation", "Firmware-Prüfungen"],
            "zh": ["设备指纹", "异常检测", "隔离", "固件检查"]
        }
    },

    # =========================================================================
    # NETWORK
    # =========================================================================
    "netmodes": {
        "name": "Network Modes", "icon": "🌐", "category": "Network",
        "description": {
            "en": "Network topology configuration",
            "fr": "Configuration topologie réseau",
            "de": "Netzwerktopologie-Konfiguration",
            "zh": "网络拓扑配置"
        },
        "features": {
            "en": ["Router mode", "Bridge mode", "AP mode", "VLAN"],
            "fr": ["Mode routeur", "Mode pont", "Mode AP", "VLAN"],
            "de": ["Router-Modus", "Bridge-Modus", "AP-Modus", "VLAN"],
            "zh": ["路由模式", "桥接模式", "AP模式", "VLAN"]
        }
    },
    "qos": {
        "name": "QoS Manager", "icon": "📊", "category": "Network",
        "description": {
            "en": "Quality of Service with HTB/VLAN",
            "fr": "QoS avec HTB/VLAN",
            "de": "QoS mit HTB/VLAN",
            "zh": "HTB/VLAN服务质量"
        },
        "features": {
            "en": ["Bandwidth control", "VLAN policies", "802.1p PCP", "Per-user limits"],
            "fr": ["Contrôle bande passante", "Politiques VLAN", "802.1p PCP", "Limites utilisateur"],
            "de": ["Bandbreitenkontrolle", "VLAN-Richtlinien", "802.1p PCP", "Pro-Benutzer-Limits"],
            "zh": ["带宽控制", "VLAN策略", "802.1p PCP", "每用户限制"]
        }
    },
    "traffic": {
        "name": "Traffic Shaping", "icon": "📈", "category": "Network",
        "description": {
            "en": "TC/CAKE traffic shaping",
            "fr": "Mise en forme trafic TC/CAKE",
            "de": "TC/CAKE Verkehrsformung",
            "zh": "TC/CAKE流量整形"
        },
        "features": {
            "en": ["Per-interface QoS", "CAKE algorithm", "Statistics", "Real-time graphs"],
            "fr": ["QoS par interface", "Algorithme CAKE", "Statistiques", "Graphes temps réel"],
            "de": ["Pro-Schnittstelle QoS", "CAKE-Algorithmus", "Statistiken", "Echtzeit-Graphen"],
            "zh": ["每接口QoS", "CAKE算法", "统计", "实时图表"]
        }
    },
    "haproxy": {
        "name": "HAProxy", "icon": "⚡", "category": "Network",
        "description": {
            "en": "Load balancer with TLS 1.3",
            "fr": "Load balancer avec TLS 1.3",
            "de": "Load Balancer mit TLS 1.3",
            "zh": "支持TLS 1.3的负载均衡器"
        },
        "features": {
            "en": ["Backend management", "Stats", "ACLs", "SSL termination", "Health checks"],
            "fr": ["Gestion backends", "Stats", "ACLs", "Terminaison SSL", "Health checks"],
            "de": ["Backend-Verwaltung", "Statistiken", "ACLs", "SSL-Terminierung", "Health-Checks"],
            "zh": ["后端管理", "统计", "ACL", "SSL终止", "健康检查"]
        }
    },
    "cdn": {
        "name": "CDN Cache", "icon": "🚀", "category": "Network",
        "description": {
            "en": "Content delivery cache",
            "fr": "Cache de diffusion de contenu",
            "de": "Content-Delivery-Cache",
            "zh": "内容分发缓存"
        },
        "features": {
            "en": ["Cache management", "Purge", "Statistics", "Edge rules"],
            "fr": ["Gestion cache", "Purge", "Statistiques", "Règles edge"],
            "de": ["Cache-Verwaltung", "Bereinigung", "Statistiken", "Edge-Regeln"],
            "zh": ["缓存管理", "清除", "统计", "边缘规则"]
        }
    },
    "vhost": {
        "name": "Virtual Hosts", "icon": "🏗️", "category": "Network",
        "description": {
            "en": "Nginx virtual host management",
            "fr": "Gestion hôtes virtuels Nginx",
            "de": "Nginx Virtual Host Verwaltung",
            "zh": "Nginx虚拟主机管理"
        },
        "features": {
            "en": ["Site management", "SSL certificates", "Reverse proxy", "Let's Encrypt"],
            "fr": ["Gestion sites", "Certificats SSL", "Reverse proxy", "Let's Encrypt"],
            "de": ["Site-Verwaltung", "SSL-Zertifikate", "Reverse-Proxy", "Let's Encrypt"],
            "zh": ["站点管理", "SSL证书", "反向代理", "Let's Encrypt"]
        }
    },
    "routes": {
        "name": "Routing Manager", "icon": "🛤️", "category": "Network",
        "description": {
            "en": "Static and policy-based routing",
            "fr": "Routage statique et basé sur politiques",
            "de": "Statisches und richtlinienbasiertes Routing",
            "zh": "静态和基于策略的路由"
        },
        "features": {
            "en": ["Static routes", "Policy routing", "Multi-WAN", "Failover"],
            "fr": ["Routes statiques", "Routage politique", "Multi-WAN", "Failover"],
            "de": ["Statische Routen", "Policy-Routing", "Multi-WAN", "Failover"],
            "zh": ["静态路由", "策略路由", "多WAN", "故障转移"]
        }
    },
    "nettweak": {
        "name": "Network Tweaks", "icon": "🔧", "category": "Network",
        "description": {
            "en": "Network kernel parameters tuning",
            "fr": "Réglage des paramètres réseau du noyau",
            "de": "Netzwerk-Kernelparameter-Tuning",
            "zh": "网络内核参数调优"
        },
        "features": {
            "en": ["TCP tuning", "Buffer sizes", "Congestion control", "Profiles"],
            "fr": ["Réglage TCP", "Tailles buffer", "Contrôle congestion", "Profils"],
            "de": ["TCP-Tuning", "Puffergrößen", "Überlastungskontrolle", "Profile"],
            "zh": ["TCP调优", "缓冲区大小", "拥塞控制", "配置文件"]
        }
    },
    "netdiag": {
        "name": "Network Diagnostics", "icon": "🔍", "category": "Network",
        "description": {
            "en": "Network troubleshooting tools",
            "fr": "Outils de diagnostic réseau",
            "de": "Netzwerk-Diagnosetools",
            "zh": "网络故障排除工具"
        },
        "features": {
            "en": ["Ping/Traceroute", "DNS lookup", "Port scan", "Speed test"],
            "fr": ["Ping/Traceroute", "Recherche DNS", "Scan ports", "Test vitesse"],
            "de": ["Ping/Traceroute", "DNS-Suche", "Port-Scan", "Geschwindigkeitstest"],
            "zh": ["Ping/Traceroute", "DNS查询", "端口扫描", "速度测试"]
        }
    },
    "network-anomaly": {
        "name": "Network Anomaly", "icon": "📉", "category": "Network",
        "description": {
            "en": "Network anomaly detection",
            "fr": "Détection d'anomalies réseau",
            "de": "Netzwerk-Anomalieerkennung",
            "zh": "网络异常检测"
        },
        "features": {
            "en": ["Traffic baselines", "Anomaly alerts", "ML detection", "Visualization"],
            "fr": ["Baselines trafic", "Alertes anomalies", "Détection ML", "Visualisation"],
            "de": ["Verkehrs-Baselines", "Anomalie-Warnungen", "ML-Erkennung", "Visualisierung"],
            "zh": ["流量基线", "异常告警", "ML检测", "可视化"]
        }
    },
    "modem": {
        "name": "Modem Manager", "icon": "📶", "category": "Network",
        "description": {
            "en": "3G/4G/5G modem management",
            "fr": "Gestion modem 3G/4G/5G",
            "de": "3G/4G/5G-Modemverwaltung",
            "zh": "3G/4G/5G调制解调器管理"
        },
        "features": {
            "en": ["Connection status", "Signal strength", "SMS", "Failover"],
            "fr": ["État connexion", "Force signal", "SMS", "Failover"],
            "de": ["Verbindungsstatus", "Signalstärke", "SMS", "Failover"],
            "zh": ["连接状态", "信号强度", "短信", "故障转移"]
        }
    },

    # =========================================================================
    # DNS
    # =========================================================================
    "dns": {
        "name": "DNS Server", "icon": "🌍", "category": "DNS",
        "description": {
            "en": "BIND DNS zone management",
            "fr": "Gestion zones DNS BIND",
            "de": "BIND DNS-Zonenverwaltung",
            "zh": "BIND DNS区域管理"
        },
        "features": {
            "en": ["Zone management", "Records", "DNSSEC", "Reverse DNS"],
            "fr": ["Gestion zones", "Enregistrements", "DNSSEC", "DNS inverse"],
            "de": ["Zonenverwaltung", "Einträge", "DNSSEC", "Reverse-DNS"],
            "zh": ["区域管理", "记录", "DNSSEC", "反向DNS"]
        }
    },
    "vortex-dns": {
        "name": "Vortex DNS", "icon": "🛡️", "category": "DNS",
        "description": {
            "en": "DNS firewall with RPZ blocklists",
            "fr": "Pare-feu DNS avec listes de blocage RPZ",
            "de": "DNS-Firewall mit RPZ-Blocklisten",
            "zh": "带RPZ黑名单的DNS防火墙"
        },
        "features": {
            "en": ["Blocklists", "RPZ", "Threat feeds", "DoH/DoT"],
            "fr": ["Listes blocage", "RPZ", "Flux menaces", "DoH/DoT"],
            "de": ["Blocklisten", "RPZ", "Bedrohungsfeeds", "DoH/DoT"],
            "zh": ["黑名单", "RPZ", "威胁源", "DoH/DoT"]
        }
    },
    "meshname": {
        "name": "Mesh DNS", "icon": "📡", "category": "DNS",
        "description": {
            "en": "Mesh network domain resolution",
            "fr": "Résolution domaines réseau mesh",
            "de": "Mesh-Netzwerk-Domänenauflösung",
            "zh": "Mesh网络域名解析"
        },
        "features": {
            "en": ["mDNS/Avahi", "Local DNS", "Service discovery", "Mesh integration"],
            "fr": ["mDNS/Avahi", "DNS local", "Découverte services", "Intégration mesh"],
            "de": ["mDNS/Avahi", "Lokales DNS", "Diensterkennung", "Mesh-Integration"],
            "zh": ["mDNS/Avahi", "本地DNS", "服务发现", "Mesh集成"]
        }
    },
    "dns-guard": {
        "name": "DNS Guard", "icon": "🛡️", "category": "DNS",
        "description": {
            "en": "DNS-based threat protection",
            "fr": "Protection basée sur DNS contre les menaces",
            "de": "DNS-basierter Bedrohungsschutz",
            "zh": "基于DNS的威胁防护"
        },
        "features": {
            "en": ["Malware blocking", "Phishing protection", "Analytics", "Whitelist"],
            "fr": ["Blocage malware", "Protection phishing", "Analytiques", "Liste blanche"],
            "de": ["Malware-Blockierung", "Phishing-Schutz", "Analysen", "Whitelist"],
            "zh": ["恶意软件拦截", "钓鱼防护", "分析", "白名单"]
        }
    },
    "dns-provider": {
        "name": "DNS Provider", "icon": "🌐", "category": "DNS",
        "description": {
            "en": "External DNS provider integration",
            "fr": "Intégration fournisseur DNS externe",
            "de": "Externe DNS-Anbieter-Integration",
            "zh": "外部DNS提供商集成"
        },
        "features": {
            "en": ["Cloudflare", "Route53", "DigitalOcean", "Dynamic DNS"],
            "fr": ["Cloudflare", "Route53", "DigitalOcean", "DNS dynamique"],
            "de": ["Cloudflare", "Route53", "DigitalOcean", "Dynamisches DNS"],
            "zh": ["Cloudflare", "Route53", "DigitalOcean", "动态DNS"]
        }
    },
    "ad-guard": {
        "name": "AdGuard", "icon": "🚫", "category": "DNS",
        "description": {
            "en": "AdGuard Home DNS blocking",
            "fr": "Blocage DNS AdGuard Home",
            "de": "AdGuard Home DNS-Blockierung",
            "zh": "AdGuard Home DNS拦截"
        },
        "features": {
            "en": ["Ad blocking", "Tracking protection", "Parental control", "Statistics"],
            "fr": ["Blocage pubs", "Protection tracking", "Contrôle parental", "Statistiques"],
            "de": ["Werbungsblockierung", "Tracking-Schutz", "Jugendschutz", "Statistiken"],
            "zh": ["广告拦截", "追踪保护", "家长控制", "统计"]
        }
    },

    # =========================================================================
    # VPN & PRIVACY
    # =========================================================================
    "wireguard": {
        "name": "WireGuard VPN", "icon": "🔗", "category": "VPN",
        "description": {
            "en": "Modern VPN with kernel integration",
            "fr": "VPN moderne avec intégration noyau",
            "de": "Modernes VPN mit Kernel-Integration",
            "zh": "具有内核集成的现代VPN"
        },
        "features": {
            "en": ["Peer management", "QR codes", "Traffic stats", "Multi-tunnel"],
            "fr": ["Gestion pairs", "QR codes", "Stats trafic", "Multi-tunnel"],
            "de": ["Peer-Verwaltung", "QR-Codes", "Verkehrsstatistiken", "Multi-Tunnel"],
            "zh": ["节点管理", "二维码", "流量统计", "多隧道"]
        }
    },
    "mesh": {
        "name": "Mesh Network", "icon": "🕸️", "category": "VPN",
        "description": {
            "en": "Mesh networking with Yggdrasil",
            "fr": "Réseau mesh avec Yggdrasil",
            "de": "Mesh-Netzwerk mit Yggdrasil",
            "zh": "使用Yggdrasil的Mesh网络"
        },
        "features": {
            "en": ["Peer discovery", "Routing", "Encryption", "IPv6 overlay"],
            "fr": ["Découverte pairs", "Routage", "Chiffrement", "Overlay IPv6"],
            "de": ["Peer-Erkennung", "Routing", "Verschlüsselung", "IPv6-Overlay"],
            "zh": ["节点发现", "路由", "加密", "IPv6覆盖"]
        }
    },
    "p2p": {
        "name": "P2P Network", "icon": "🔗", "category": "VPN",
        "description": {
            "en": "Peer-to-peer networking",
            "fr": "Réseau pair-à-pair",
            "de": "Peer-to-Peer-Netzwerk",
            "zh": "点对点网络"
        },
        "features": {
            "en": ["Direct connections", "NAT traversal", "Encryption", "DHT"],
            "fr": ["Connexions directes", "Traversée NAT", "Chiffrement", "DHT"],
            "de": ["Direktverbindungen", "NAT-Traversal", "Verschlüsselung", "DHT"],
            "zh": ["直接连接", "NAT穿透", "加密", "DHT"]
        }
    },
    "master-link": {
        "name": "MasterLink", "icon": "🔗", "category": "VPN",
        "description": {
            "en": "SecuBox mesh federation",
            "fr": "Fédération mesh SecuBox",
            "de": "SecuBox Mesh-Föderation",
            "zh": "SecuBox网格联邦"
        },
        "features": {
            "en": ["Box discovery", "Federation", "Shared policies", "Sync"],
            "fr": ["Découverte box", "Fédération", "Politiques partagées", "Sync"],
            "de": ["Box-Erkennung", "Föderation", "Gemeinsame Richtlinien", "Sync"],
            "zh": ["盒子发现", "联邦", "共享策略", "同步"]
        }
    },
    "tor": {
        "name": "Tor Network", "icon": "🧅", "category": "Privacy",
        "description": {
            "en": "Tor anonymity and hidden services",
            "fr": "Anonymat Tor et services cachés",
            "de": "Tor-Anonymität und versteckte Dienste",
            "zh": "Tor匿名和隐藏服务"
        },
        "features": {
            "en": ["Circuits", "Hidden services", "Bridges", "Transparent proxy"],
            "fr": ["Circuits", "Services cachés", "Bridges", "Proxy transparent"],
            "de": ["Schaltkreise", "Versteckte Dienste", "Bridges", "Transparenter Proxy"],
            "zh": ["电路", "隐藏服务", "桥接", "透明代理"]
        }
    },
    "exposure": {
        "name": "Exposure Settings", "icon": "🌐", "category": "Privacy",
        "description": {
            "en": "Unified exposure management",
            "fr": "Gestion unifiée de l'exposition",
            "de": "Einheitliche Expositionsverwaltung",
            "zh": "统一暴露管理"
        },
        "features": {
            "en": ["Tor exposure", "SSL certs", "DNS records", "Mesh access"],
            "fr": ["Exposition Tor", "Certificats SSL", "Enregistrements DNS", "Accès mesh"],
            "de": ["Tor-Exposition", "SSL-Zertifikate", "DNS-Einträge", "Mesh-Zugang"],
            "zh": ["Tor暴露", "SSL证书", "DNS记录", "Mesh访问"]
        }
    },
    "zkp": {
        "name": "Zero-Knowledge Proofs", "icon": "🔐", "category": "Privacy",
        "description": {
            "en": "ZKP Hamiltonian authentication",
            "fr": "Authentification ZKP Hamiltonien",
            "de": "ZKP Hamiltonian-Authentifizierung",
            "zh": "ZKP哈密顿认证"
        },
        "features": {
            "en": ["Proof generation", "Verification", "Key management", "MirrorNet"],
            "fr": ["Génération preuves", "Vérification", "Gestion clés", "MirrorNet"],
            "de": ["Beweisgenerierung", "Verifizierung", "Schlüsselverwaltung", "MirrorNet"],
            "zh": ["证明生成", "验证", "密钥管理", "MirrorNet"]
        }
    },
    "simplex": {
        "name": "SimpleX Chat", "icon": "💬", "category": "Privacy",
        "description": {
            "en": "Privacy-focused messaging",
            "fr": "Messagerie axée sur la vie privée",
            "de": "Datenschutzorientiertes Messaging",
            "zh": "注重隐私的消息"
        },
        "features": {
            "en": ["E2E encryption", "No user IDs", "Self-hosted", "Groups"],
            "fr": ["Chiffrement E2E", "Sans identifiants", "Auto-hébergé", "Groupes"],
            "de": ["E2E-Verschlüsselung", "Keine Benutzer-IDs", "Selbst gehostet", "Gruppen"],
            "zh": ["端到端加密", "无用户ID", "自托管", "群组"]
        }
    },
    "vault": {
        "name": "Secret Vault", "icon": "🔐", "category": "Privacy",
        "description": {
            "en": "Secrets and credentials management",
            "fr": "Gestion des secrets et identifiants",
            "de": "Geheimnis- und Anmeldedatenverwaltung",
            "zh": "密钥和凭据管理"
        },
        "features": {
            "en": ["Encrypted storage", "Access control", "Rotation", "Audit"],
            "fr": ["Stockage chiffré", "Contrôle d'accès", "Rotation", "Audit"],
            "de": ["Verschlüsselter Speicher", "Zugriffskontrolle", "Rotation", "Audit"],
            "zh": ["加密存储", "访问控制", "轮换", "审计"]
        }
    },

    # =========================================================================
    # MONITORING
    # =========================================================================
    "netdata": {
        "name": "Netdata", "icon": "📊", "category": "Monitoring",
        "description": {
            "en": "Real-time system monitoring",
            "fr": "Surveillance système temps réel",
            "de": "Echtzeit-Systemüberwachung",
            "zh": "实时系统监控"
        },
        "features": {
            "en": ["Metrics", "Alerts", "Charts", "Plugins"],
            "fr": ["Métriques", "Alertes", "Graphiques", "Plugins"],
            "de": ["Metriken", "Warnungen", "Diagramme", "Plugins"],
            "zh": ["指标", "告警", "图表", "插件"]
        }
    },
    "dpi": {
        "name": "Deep Packet Inspection", "icon": "🔬", "category": "Monitoring",
        "description": {
            "en": "DPI with netifyd/nDPId",
            "fr": "DPI avec netifyd/nDPId",
            "de": "DPI mit netifyd/nDPId",
            "zh": "使用netifyd/nDPId的DPI"
        },
        "features": {
            "en": ["Protocol detection", "App identification", "Flow analysis", "Statistics"],
            "fr": ["Détection protocoles", "Identification apps", "Analyse flux", "Statistiques"],
            "de": ["Protokollerkennung", "App-Identifizierung", "Flussanalyse", "Statistiken"],
            "zh": ["协议检测", "应用识别", "流量分析", "统计"]
        }
    },
    "netifyd": {
        "name": "Netifyd DPI", "icon": "🔬", "category": "Monitoring",
        "description": {
            "en": "Netifyd deep packet inspection",
            "fr": "Inspection paquets profonde Netifyd",
            "de": "Netifyd Deep Packet Inspection",
            "zh": "Netifyd深度包检测"
        },
        "features": {
            "en": ["Application detection", "Protocol analysis", "Flow stats", "API"],
            "fr": ["Détection applications", "Analyse protocoles", "Stats flux", "API"],
            "de": ["Anwendungserkennung", "Protokollanalyse", "Flussstatistiken", "API"],
            "zh": ["应用检测", "协议分析", "流量统计", "API"]
        }
    },
    "ndpid": {
        "name": "nDPId", "icon": "🔬", "category": "Monitoring",
        "description": {
            "en": "nDPI daemon for traffic analysis",
            "fr": "Démon nDPI pour analyse trafic",
            "de": "nDPI-Daemon für Verkehrsanalyse",
            "zh": "用于流量分析的nDPI守护进程"
        },
        "features": {
            "en": ["Protocol detection", "Flow tracking", "JSON API", "Real-time"],
            "fr": ["Détection protocoles", "Suivi flux", "API JSON", "Temps réel"],
            "de": ["Protokollerkennung", "Flussverfolgung", "JSON-API", "Echtzeit"],
            "zh": ["协议检测", "流量跟踪", "JSON API", "实时"]
        }
    },
    "device-intel": {
        "name": "Device Intelligence", "icon": "📱", "category": "Monitoring",
        "description": {
            "en": "Asset discovery and fingerprinting",
            "fr": "Découverte actifs et empreintes",
            "de": "Asset-Erkennung und Fingerprinting",
            "zh": "资产发现和指纹识别"
        },
        "features": {
            "en": ["ARP scanning", "MAC vendor lookup", "OS detection", "Services"],
            "fr": ["Scan ARP", "Recherche vendeur MAC", "Détection OS", "Services"],
            "de": ["ARP-Scanning", "MAC-Vendor-Suche", "OS-Erkennung", "Dienste"],
            "zh": ["ARP扫描", "MAC厂商查询", "OS检测", "服务"]
        }
    },
    "watchdog": {
        "name": "Watchdog", "icon": "👁️", "category": "Monitoring",
        "description": {
            "en": "Service and container monitoring",
            "fr": "Surveillance services et conteneurs",
            "de": "Service- und Container-Überwachung",
            "zh": "服务和容器监控"
        },
        "features": {
            "en": ["Health checks", "Auto-restart", "Alerts", "Logs"],
            "fr": ["Vérifications santé", "Auto-redémarrage", "Alertes", "Logs"],
            "de": ["Gesundheitsprüfungen", "Auto-Neustart", "Warnungen", "Logs"],
            "zh": ["健康检查", "自动重启", "告警", "日志"]
        }
    },
    "mediaflow": {
        "name": "Media Flow", "icon": "🎬", "category": "Monitoring",
        "description": {
            "en": "Media traffic analytics",
            "fr": "Analyse trafic média",
            "de": "Medienverkehrsanalyse",
            "zh": "媒体流量分析"
        },
        "features": {
            "en": ["Stream detection", "Bandwidth usage", "Protocol analysis", "QoE"],
            "fr": ["Détection flux", "Utilisation bande passante", "Analyse protocoles", "QoE"],
            "de": ["Stream-Erkennung", "Bandbreitennutzung", "Protokollanalyse", "QoE"],
            "zh": ["流检测", "带宽使用", "协议分析", "QoE"]
        }
    },
    "glances": {
        "name": "Glances", "icon": "👀", "category": "Monitoring",
        "description": {
            "en": "System monitoring dashboard",
            "fr": "Tableau de bord surveillance système",
            "de": "System-Überwachungs-Dashboard",
            "zh": "系统监控仪表板"
        },
        "features": {
            "en": ["CPU/Memory", "Disk/Network", "Docker", "Web UI"],
            "fr": ["CPU/Mémoire", "Disque/Réseau", "Docker", "Interface web"],
            "de": ["CPU/Speicher", "Disk/Netzwerk", "Docker", "Web-UI"],
            "zh": ["CPU/内存", "磁盘/网络", "Docker", "Web界面"]
        }
    },

    # =========================================================================
    # ACCESS CONTROL
    # =========================================================================
    "portal": {
        "name": "Login Portal", "icon": "🔐", "category": "Access",
        "description": {
            "en": "Authentication portal with JWT",
            "fr": "Portail authentification avec JWT",
            "de": "Authentifizierungsportal mit JWT",
            "zh": "JWT认证门户"
        },
        "features": {
            "en": ["JWT auth", "Sessions", "Password recovery", "Captive portal"],
            "fr": ["Auth JWT", "Sessions", "Récupération mot de passe", "Portail captif"],
            "de": ["JWT-Auth", "Sitzungen", "Passwortwiederherstellung", "Captive Portal"],
            "zh": ["JWT认证", "会话", "密码恢复", "强制门户"]
        }
    },
    "users": {
        "name": "User Management", "icon": "👥", "category": "Access",
        "description": {
            "en": "Unified identity management",
            "fr": "Gestion identité unifiée",
            "de": "Einheitliche Identitätsverwaltung",
            "zh": "统一身份管理"
        },
        "features": {
            "en": ["User CRUD", "Groups", "Service provisioning", "RBAC"],
            "fr": ["CRUD utilisateurs", "Groupes", "Provisioning services", "RBAC"],
            "de": ["Benutzer-CRUD", "Gruppen", "Service-Bereitstellung", "RBAC"],
            "zh": ["用户CRUD", "组", "服务配置", "RBAC"]
        }
    },
    "identity": {
        "name": "Identity Provider", "icon": "🪪", "category": "Access",
        "description": {
            "en": "SAML/OIDC identity provider",
            "fr": "Fournisseur d'identité SAML/OIDC",
            "de": "SAML/OIDC-Identitätsanbieter",
            "zh": "SAML/OIDC身份提供者"
        },
        "features": {
            "en": ["SAML 2.0", "OpenID Connect", "Federation", "SSO"],
            "fr": ["SAML 2.0", "OpenID Connect", "Fédération", "SSO"],
            "de": ["SAML 2.0", "OpenID Connect", "Föderation", "SSO"],
            "zh": ["SAML 2.0", "OpenID Connect", "联邦", "SSO"]
        }
    },

    # =========================================================================
    # SERVICES
    # =========================================================================
    "c3box": {
        "name": "Services Portal", "icon": "📦", "category": "Services",
        "description": {
            "en": "C3Box services portal",
            "fr": "Portail services C3Box",
            "de": "C3Box-Dienstportal",
            "zh": "C3Box服务门户"
        },
        "features": {
            "en": ["Service links", "Status overview", "Quick access", "Categories"],
            "fr": ["Liens services", "Vue état", "Accès rapide", "Catégories"],
            "de": ["Service-Links", "Statusübersicht", "Schnellzugriff", "Kategorien"],
            "zh": ["服务链接", "状态概览", "快速访问", "分类"]
        }
    },
    "gitea": {
        "name": "Gitea", "icon": "🦊", "category": "Services",
        "description": {
            "en": "Git server (LXC)",
            "fr": "Serveur Git (LXC)",
            "de": "Git-Server (LXC)",
            "zh": "Git服务器(LXC)"
        },
        "features": {
            "en": ["Repositories", "Users", "SSH/HTTP", "LFS", "Actions"],
            "fr": ["Dépôts", "Utilisateurs", "SSH/HTTP", "LFS", "Actions"],
            "de": ["Repositories", "Benutzer", "SSH/HTTP", "LFS", "Actions"],
            "zh": ["仓库", "用户", "SSH/HTTP", "LFS", "Actions"]
        }
    },
    "nextcloud": {
        "name": "Nextcloud", "icon": "☁️", "category": "Services",
        "description": {
            "en": "File sync (LXC)",
            "fr": "Synchronisation fichiers (LXC)",
            "de": "Dateisynchronisierung (LXC)",
            "zh": "文件同步(LXC)"
        },
        "features": {
            "en": ["File sync", "WebDAV", "CalDAV", "CardDAV", "Talk"],
            "fr": ["Sync fichiers", "WebDAV", "CalDAV", "CardDAV", "Talk"],
            "de": ["Dateisync", "WebDAV", "CalDAV", "CardDAV", "Talk"],
            "zh": ["文件同步", "WebDAV", "CalDAV", "CardDAV", "Talk"]
        }
    },

    # =========================================================================
    # AI
    # =========================================================================
    "ollama": {
        "name": "Ollama", "icon": "🦙", "category": "AI",
        "description": {
            "en": "Local LLM server",
            "fr": "Serveur LLM local",
            "de": "Lokaler LLM-Server",
            "zh": "本地LLM服务器"
        },
        "features": {
            "en": ["Model management", "API", "Chat", "GPU support"],
            "fr": ["Gestion modèles", "API", "Chat", "Support GPU"],
            "de": ["Modellverwaltung", "API", "Chat", "GPU-Unterstützung"],
            "zh": ["模型管理", "API", "聊天", "GPU支持"]
        }
    },
    "localai": {
        "name": "LocalAI", "icon": "🤖", "category": "AI",
        "description": {
            "en": "OpenAI-compatible local API",
            "fr": "API locale compatible OpenAI",
            "de": "OpenAI-kompatible lokale API",
            "zh": "兼容OpenAI的本地API"
        },
        "features": {
            "en": ["OpenAI API", "Multiple models", "Embeddings", "Image generation"],
            "fr": ["API OpenAI", "Modèles multiples", "Embeddings", "Génération images"],
            "de": ["OpenAI-API", "Mehrere Modelle", "Embeddings", "Bildgenerierung"],
            "zh": ["OpenAI API", "多模型", "嵌入", "图像生成"]
        }
    },
    "ai-gateway": {
        "name": "AI Gateway", "icon": "🚪", "category": "AI",
        "description": {
            "en": "AI model API gateway",
            "fr": "Passerelle API modèles IA",
            "de": "AI-Modell-API-Gateway",
            "zh": "AI模型API网关"
        },
        "features": {
            "en": ["Rate limiting", "Load balancing", "Caching", "Logging"],
            "fr": ["Limitation débit", "Équilibrage charge", "Cache", "Logs"],
            "de": ["Ratenbegrenzung", "Lastverteilung", "Caching", "Protokollierung"],
            "zh": ["速率限制", "负载均衡", "缓存", "日志"]
        }
    },
    "ai-insights": {
        "name": "AI Insights", "icon": "💡", "category": "AI",
        "description": {
            "en": "AI-powered security insights",
            "fr": "Aperçus sécurité assistés par IA",
            "de": "KI-gestützte Sicherheitseinblicke",
            "zh": "AI驱动的安全洞察"
        },
        "features": {
            "en": ["Anomaly detection", "Recommendations", "Predictions", "Reports"],
            "fr": ["Détection anomalies", "Recommandations", "Prédictions", "Rapports"],
            "de": ["Anomalieerkennung", "Empfehlungen", "Vorhersagen", "Berichte"],
            "zh": ["异常检测", "建议", "预测", "报告"]
        }
    },
    "localrecall": {
        "name": "LocalRecall", "icon": "🧠", "category": "AI",
        "description": {
            "en": "Local RAG memory system",
            "fr": "Système mémoire RAG local",
            "de": "Lokales RAG-Gedächtnissystem",
            "zh": "本地RAG记忆系统"
        },
        "features": {
            "en": ["Vector storage", "Semantic search", "Document indexing", "API"],
            "fr": ["Stockage vecteurs", "Recherche sémantique", "Indexation documents", "API"],
            "de": ["Vektorspeicher", "Semantische Suche", "Dokumentenindizierung", "API"],
            "zh": ["向量存储", "语义搜索", "文档索引", "API"]
        }
    },
    "mcp-server": {
        "name": "MCP Server", "icon": "🔌", "category": "AI",
        "description": {
            "en": "Model Context Protocol server",
            "fr": "Serveur Model Context Protocol",
            "de": "Model Context Protocol-Server",
            "zh": "模型上下文协议服务器"
        },
        "features": {
            "en": ["Tool integration", "Context management", "Multi-model", "API"],
            "fr": ["Intégration outils", "Gestion contexte", "Multi-modèle", "API"],
            "de": ["Tool-Integration", "Kontextverwaltung", "Multi-Modell", "API"],
            "zh": ["工具集成", "上下文管理", "多模型", "API"]
        }
    },

    # =========================================================================
    # EMAIL
    # =========================================================================
    "mail": {
        "name": "Mail Server", "icon": "📧", "category": "Email",
        "description": {
            "en": "Postfix/Dovecot mail server",
            "fr": "Serveur mail Postfix/Dovecot",
            "de": "Postfix/Dovecot-Mailserver",
            "zh": "Postfix/Dovecot邮件服务器"
        },
        "features": {
            "en": ["Domains", "Mailboxes", "DKIM", "SpamAssassin", "ClamAV"],
            "fr": ["Domaines", "Boîtes mail", "DKIM", "SpamAssassin", "ClamAV"],
            "de": ["Domänen", "Postfächer", "DKIM", "SpamAssassin", "ClamAV"],
            "zh": ["域名", "邮箱", "DKIM", "SpamAssassin", "ClamAV"]
        }
    },
    "webmail": {
        "name": "Webmail", "icon": "💌", "category": "Email",
        "description": {
            "en": "Roundcube/SOGo webmail",
            "fr": "Webmail Roundcube/SOGo",
            "de": "Roundcube/SOGo-Webmail",
            "zh": "Roundcube/SOGo网页邮箱"
        },
        "features": {
            "en": ["Web interface", "Address book", "Calendar", "Mobile"],
            "fr": ["Interface web", "Carnet adresses", "Calendrier", "Mobile"],
            "de": ["Web-Oberfläche", "Adressbuch", "Kalender", "Mobil"],
            "zh": ["Web界面", "通讯录", "日历", "移动端"]
        }
    },
    "smtp-relay": {
        "name": "SMTP Relay", "icon": "📤", "category": "Email",
        "description": {
            "en": "SMTP relay and smarthost",
            "fr": "Relais SMTP et smarthost",
            "de": "SMTP-Relay und Smarthost",
            "zh": "SMTP中继和智能主机"
        },
        "features": {
            "en": ["Relay", "Authentication", "Rate limiting", "Logging"],
            "fr": ["Relais", "Authentification", "Limitation débit", "Logs"],
            "de": ["Relay", "Authentifizierung", "Ratenbegrenzung", "Protokollierung"],
            "zh": ["中继", "认证", "速率限制", "日志"]
        }
    },
    "jabber": {
        "name": "Jabber/XMPP", "icon": "💬", "category": "Email",
        "description": {
            "en": "XMPP messaging server",
            "fr": "Serveur messagerie XMPP",
            "de": "XMPP-Messaging-Server",
            "zh": "XMPP消息服务器"
        },
        "features": {
            "en": ["Chat", "Groups", "File transfer", "Federation"],
            "fr": ["Chat", "Groupes", "Transfert fichiers", "Fédération"],
            "de": ["Chat", "Gruppen", "Dateiübertragung", "Föderation"],
            "zh": ["聊天", "群组", "文件传输", "联邦"]
        }
    },

    # =========================================================================
    # MEDIA
    # =========================================================================
    "jellyfin": {
        "name": "Jellyfin", "icon": "🎬", "category": "Media",
        "description": {
            "en": "Media server",
            "fr": "Serveur média",
            "de": "Medienserver",
            "zh": "媒体服务器"
        },
        "features": {
            "en": ["Video streaming", "Live TV", "Transcoding", "Mobile apps"],
            "fr": ["Streaming vidéo", "TV en direct", "Transcodage", "Apps mobiles"],
            "de": ["Video-Streaming", "Live-TV", "Transcoding", "Mobile Apps"],
            "zh": ["视频流", "直播电视", "转码", "移动应用"]
        }
    },
    "lyrion": {
        "name": "Lyrion Music", "icon": "🎵", "category": "Media",
        "description": {
            "en": "Music streaming server",
            "fr": "Serveur streaming musique",
            "de": "Musik-Streaming-Server",
            "zh": "音乐流媒体服务器"
        },
        "features": {
            "en": ["Music library", "Playlists", "Radio", "Multi-room"],
            "fr": ["Bibliothèque musique", "Playlists", "Radio", "Multi-pièces"],
            "de": ["Musikbibliothek", "Playlists", "Radio", "Multi-Room"],
            "zh": ["音乐库", "播放列表", "电台", "多房间"]
        }
    },
    "webradio": {
        "name": "Web Radio", "icon": "📻", "category": "Media",
        "description": {
            "en": "Internet radio streaming",
            "fr": "Streaming radio Internet",
            "de": "Internet-Radio-Streaming",
            "zh": "网络电台流媒体"
        },
        "features": {
            "en": ["Radio stations", "Recording", "Schedule", "Favorites"],
            "fr": ["Stations radio", "Enregistrement", "Programmation", "Favoris"],
            "de": ["Radiosender", "Aufnahme", "Zeitplan", "Favoriten"],
            "zh": ["电台", "录制", "计划", "收藏"]
        }
    },
    "photoprism": {
        "name": "PhotoPrism", "icon": "📸", "category": "Media",
        "description": {
            "en": "AI-powered photo management",
            "fr": "Gestion photos assistée par IA",
            "de": "KI-gestützte Fotoverwaltung",
            "zh": "AI驱动的照片管理"
        },
        "features": {
            "en": ["Face recognition", "Auto-tagging", "Search", "Albums"],
            "fr": ["Reconnaissance faciale", "Auto-tagging", "Recherche", "Albums"],
            "de": ["Gesichtserkennung", "Auto-Tagging", "Suche", "Alben"],
            "zh": ["人脸识别", "自动标签", "搜索", "相册"]
        }
    },
    "peertube": {
        "name": "PeerTube", "icon": "📺", "category": "Media",
        "description": {
            "en": "Federated video platform",
            "fr": "Plateforme vidéo fédérée",
            "de": "Föderierte Videoplattform",
            "zh": "联邦视频平台"
        },
        "features": {
            "en": ["Video hosting", "Federation", "Live streaming", "Comments"],
            "fr": ["Hébergement vidéo", "Fédération", "Live streaming", "Commentaires"],
            "de": ["Video-Hosting", "Föderation", "Live-Streaming", "Kommentare"],
            "zh": ["视频托管", "联邦", "直播", "评论"]
        }
    },
    "torrent": {
        "name": "Torrent", "icon": "🌊", "category": "Media",
        "description": {
            "en": "BitTorrent client",
            "fr": "Client BitTorrent",
            "de": "BitTorrent-Client",
            "zh": "BitTorrent客户端"
        },
        "features": {
            "en": ["Downloads", "RSS", "Remote control", "Bandwidth limits"],
            "fr": ["Téléchargements", "RSS", "Contrôle distant", "Limites bande passante"],
            "de": ["Downloads", "RSS", "Fernsteuerung", "Bandbreitenlimits"],
            "zh": ["下载", "RSS", "远程控制", "带宽限制"]
        }
    },
    "newsbin": {
        "name": "Newsbin", "icon": "📰", "category": "Media",
        "description": {
            "en": "Usenet/NNTP client",
            "fr": "Client Usenet/NNTP",
            "de": "Usenet/NNTP-Client",
            "zh": "Usenet/NNTP客户端"
        },
        "features": {
            "en": ["NZB downloads", "Auto-processing", "Search", "Categories"],
            "fr": ["Téléchargements NZB", "Traitement auto", "Recherche", "Catégories"],
            "de": ["NZB-Downloads", "Auto-Verarbeitung", "Suche", "Kategorien"],
            "zh": ["NZB下载", "自动处理", "搜索", "分类"]
        }
    },

    # =========================================================================
    # PUBLISHING
    # =========================================================================
    "publish": {
        "name": "Publishing Platform", "icon": "📰", "category": "Publishing",
        "description": {
            "en": "Unified publishing dashboard",
            "fr": "Tableau de bord publication unifié",
            "de": "Einheitliches Veröffentlichungs-Dashboard",
            "zh": "统一发布仪表板"
        },
        "features": {
            "en": ["Multi-platform", "Scheduling", "Analytics", "Templates"],
            "fr": ["Multi-plateforme", "Planification", "Analytiques", "Templates"],
            "de": ["Multi-Plattform", "Planung", "Analysen", "Vorlagen"],
            "zh": ["多平台", "计划", "分析", "模板"]
        }
    },
    "droplet": {
        "name": "Droplet", "icon": "💧", "category": "Publishing",
        "description": {
            "en": "File upload and publish",
            "fr": "Upload et publication fichiers",
            "de": "Datei-Upload und Veröffentlichung",
            "zh": "文件上传和发布"
        },
        "features": {
            "en": ["File upload", "Share links", "Expiration", "Password protection"],
            "fr": ["Upload fichiers", "Liens partage", "Expiration", "Protection mot de passe"],
            "de": ["Datei-Upload", "Freigabelinks", "Ablauf", "Passwortschutz"],
            "zh": ["文件上传", "分享链接", "过期", "密码保护"]
        }
    },
    "metablogizer": {
        "name": "Metablogizer", "icon": "📝", "category": "Publishing",
        "description": {
            "en": "Static site publisher with Tor",
            "fr": "Éditeur site statique avec Tor",
            "de": "Statischer Site-Publisher mit Tor",
            "zh": "带Tor的静态站点发布器"
        },
        "features": {
            "en": ["Static sites", "Tor publishing", "Templates", "Markdown"],
            "fr": ["Sites statiques", "Publication Tor", "Templates", "Markdown"],
            "de": ["Statische Sites", "Tor-Veröffentlichung", "Vorlagen", "Markdown"],
            "zh": ["静态站点", "Tor发布", "模板", "Markdown"]
        }
    },
    "hexo": {
        "name": "Hexo Blog", "icon": "✏️", "category": "Publishing",
        "description": {
            "en": "Static blog generator",
            "fr": "Générateur blog statique",
            "de": "Statischer Blog-Generator",
            "zh": "静态博客生成器"
        },
        "features": {
            "en": ["Markdown", "Themes", "Plugins", "Deploy"],
            "fr": ["Markdown", "Thèmes", "Plugins", "Déploiement"],
            "de": ["Markdown", "Themes", "Plugins", "Deploy"],
            "zh": ["Markdown", "主题", "插件", "部署"]
        }
    },
    "gotosocial": {
        "name": "GoToSocial", "icon": "🐘", "category": "Publishing",
        "description": {
            "en": "ActivityPub social server",
            "fr": "Serveur social ActivityPub",
            "de": "ActivityPub-Social-Server",
            "zh": "ActivityPub社交服务器"
        },
        "features": {
            "en": ["Mastodon compatible", "Federation", "Media", "Privacy"],
            "fr": ["Compatible Mastodon", "Fédération", "Média", "Vie privée"],
            "de": ["Mastodon-kompatibel", "Föderation", "Medien", "Datenschutz"],
            "zh": ["兼容Mastodon", "联邦", "媒体", "隐私"]
        }
    },
    "cyberfeed": {
        "name": "CyberFeed", "icon": "📡", "category": "Publishing",
        "description": {
            "en": "RSS/Atom feed aggregator",
            "fr": "Agrégateur flux RSS/Atom",
            "de": "RSS/Atom-Feed-Aggregator",
            "zh": "RSS/Atom订阅聚合器"
        },
        "features": {
            "en": ["Feed management", "Categories", "Search", "Export"],
            "fr": ["Gestion flux", "Catégories", "Recherche", "Export"],
            "de": ["Feed-Verwaltung", "Kategorien", "Suche", "Export"],
            "zh": ["订阅管理", "分类", "搜索", "导出"]
        }
    },

    # =========================================================================
    # APPS
    # =========================================================================
    "streamlit": {
        "name": "Streamlit", "icon": "🎨", "category": "Apps",
        "description": {
            "en": "Streamlit app platform",
            "fr": "Plateforme apps Streamlit",
            "de": "Streamlit-App-Plattform",
            "zh": "Streamlit应用平台"
        },
        "features": {
            "en": ["App hosting", "Deployment", "Management", "Logs"],
            "fr": ["Hébergement apps", "Déploiement", "Gestion", "Logs"],
            "de": ["App-Hosting", "Bereitstellung", "Verwaltung", "Logs"],
            "zh": ["应用托管", "部署", "管理", "日志"]
        }
    },
    "streamforge": {
        "name": "StreamForge", "icon": "⚡", "category": "Apps",
        "description": {
            "en": "Streamlit app development",
            "fr": "Développement apps Streamlit",
            "de": "Streamlit-App-Entwicklung",
            "zh": "Streamlit应用开发"
        },
        "features": {
            "en": ["Templates", "Code editor", "Preview", "Deploy"],
            "fr": ["Templates", "Éditeur code", "Aperçu", "Déploiement"],
            "de": ["Vorlagen", "Code-Editor", "Vorschau", "Deploy"],
            "zh": ["模板", "代码编辑器", "预览", "部署"]
        }
    },
    "repo": {
        "name": "APT Repository", "icon": "📦", "category": "Apps",
        "description": {
            "en": "APT repository management",
            "fr": "Gestion dépôt APT",
            "de": "APT-Repository-Verwaltung",
            "zh": "APT仓库管理"
        },
        "features": {
            "en": ["Package management", "GPG signing", "Multi-distro", "Uploads"],
            "fr": ["Gestion paquets", "Signature GPG", "Multi-distro", "Uploads"],
            "de": ["Paketverwaltung", "GPG-Signierung", "Multi-Distro", "Uploads"],
            "zh": ["包管理", "GPG签名", "多发行版", "上传"]
        }
    },

    # =========================================================================
    # IOT
    # =========================================================================
    "domoticz": {
        "name": "Domoticz", "icon": "🏠", "category": "IoT",
        "description": {
            "en": "Home automation",
            "fr": "Domotique",
            "de": "Hausautomation",
            "zh": "家庭自动化"
        },
        "features": {
            "en": ["Devices", "Scenes", "Scripts", "History"],
            "fr": ["Appareils", "Scènes", "Scripts", "Historique"],
            "de": ["Geräte", "Szenen", "Skripte", "Verlauf"],
            "zh": ["设备", "场景", "脚本", "历史"]
        }
    },
    "homeassistant": {
        "name": "Home Assistant", "icon": "🏡", "category": "IoT",
        "description": {
            "en": "Home automation hub",
            "fr": "Hub domotique",
            "de": "Hausautomations-Hub",
            "zh": "家庭自动化中心"
        },
        "features": {
            "en": ["Integrations", "Automations", "Dashboard", "Voice"],
            "fr": ["Intégrations", "Automatisations", "Tableau de bord", "Voix"],
            "de": ["Integrationen", "Automatisierungen", "Dashboard", "Sprache"],
            "zh": ["集成", "自动化", "仪表板", "语音"]
        }
    },
    "zigbee": {
        "name": "Zigbee Gateway", "icon": "📡", "category": "IoT",
        "description": {
            "en": "Zigbee2MQTT gateway",
            "fr": "Passerelle Zigbee2MQTT",
            "de": "Zigbee2MQTT-Gateway",
            "zh": "Zigbee2MQTT网关"
        },
        "features": {
            "en": ["Device pairing", "MQTT", "Groups", "OTA updates"],
            "fr": ["Appairage appareils", "MQTT", "Groupes", "Mises à jour OTA"],
            "de": ["Gerätekopplung", "MQTT", "Gruppen", "OTA-Updates"],
            "zh": ["设备配对", "MQTT", "群组", "OTA更新"]
        }
    },
    "mqtt": {
        "name": "MQTT Broker", "icon": "📡", "category": "IoT",
        "description": {
            "en": "Mosquitto MQTT broker",
            "fr": "Broker MQTT Mosquitto",
            "de": "Mosquitto MQTT-Broker",
            "zh": "Mosquitto MQTT代理"
        },
        "features": {
            "en": ["Topics", "ACL", "TLS", "WebSocket"],
            "fr": ["Topics", "ACL", "TLS", "WebSocket"],
            "de": ["Topics", "ACL", "TLS", "WebSocket"],
            "zh": ["主题", "ACL", "TLS", "WebSocket"]
        }
    },

    # =========================================================================
    # COMMUNICATION
    # =========================================================================
    "matrix": {
        "name": "Matrix Server", "icon": "💬", "category": "Communication",
        "description": {
            "en": "Matrix/Synapse chat server",
            "fr": "Serveur chat Matrix/Synapse",
            "de": "Matrix/Synapse-Chat-Server",
            "zh": "Matrix/Synapse聊天服务器"
        },
        "features": {
            "en": ["E2E encryption", "Federation", "Bridges", "Calls"],
            "fr": ["Chiffrement E2E", "Fédération", "Bridges", "Appels"],
            "de": ["E2E-Verschlüsselung", "Föderation", "Bridges", "Anrufe"],
            "zh": ["端到端加密", "联邦", "桥接", "通话"]
        }
    },
    "jitsi": {
        "name": "Jitsi Meet", "icon": "📹", "category": "Communication",
        "description": {
            "en": "Video conferencing",
            "fr": "Visioconférence",
            "de": "Videokonferenzen",
            "zh": "视频会议"
        },
        "features": {
            "en": ["Video calls", "Screen share", "Recording", "Lobby"],
            "fr": ["Appels vidéo", "Partage écran", "Enregistrement", "Lobby"],
            "de": ["Videoanrufe", "Bildschirmfreigabe", "Aufnahme", "Lobby"],
            "zh": ["视频通话", "屏幕共享", "录制", "等候室"]
        }
    },
    "voip": {
        "name": "VoIP Server", "icon": "📞", "category": "Communication",
        "description": {
            "en": "Asterisk/FreePBX VoIP",
            "fr": "VoIP Asterisk/FreePBX",
            "de": "Asterisk/FreePBX VoIP",
            "zh": "Asterisk/FreePBX VoIP"
        },
        "features": {
            "en": ["Extensions", "Trunks", "IVR", "Voicemail"],
            "fr": ["Extensions", "Trunks", "IVR", "Messagerie vocale"],
            "de": ["Extensions", "Trunks", "IVR", "Voicemail"],
            "zh": ["分机", "中继", "IVR", "语音信箱"]
        }
    },
    "turn": {
        "name": "TURN Server", "icon": "🔄", "category": "Communication",
        "description": {
            "en": "TURN/STUN relay server",
            "fr": "Serveur relais TURN/STUN",
            "de": "TURN/STUN-Relay-Server",
            "zh": "TURN/STUN中继服务器"
        },
        "features": {
            "en": ["NAT traversal", "WebRTC", "TLS", "Statistics"],
            "fr": ["Traversée NAT", "WebRTC", "TLS", "Statistiques"],
            "de": ["NAT-Traversal", "WebRTC", "TLS", "Statistiken"],
            "zh": ["NAT穿透", "WebRTC", "TLS", "统计"]
        }
    },

    # =========================================================================
    # SYSTEM
    # =========================================================================
    "system": {
        "name": "System Hub", "icon": "⚙️", "category": "System",
        "description": {
            "en": "System configuration and management",
            "fr": "Configuration et gestion système",
            "de": "Systemkonfiguration und -verwaltung",
            "zh": "系统配置和管理"
        },
        "features": {
            "en": ["Settings", "Logs", "Services", "Updates"],
            "fr": ["Paramètres", "Logs", "Services", "Mises à jour"],
            "de": ["Einstellungen", "Protokolle", "Dienste", "Updates"],
            "zh": ["设置", "日志", "服务", "更新"]
        }
    },
    "backup": {
        "name": "Backup Manager", "icon": "💾", "category": "System",
        "description": {
            "en": "System and LXC backup",
            "fr": "Sauvegarde système et LXC",
            "de": "System- und LXC-Backup",
            "zh": "系统和LXC备份"
        },
        "features": {
            "en": ["Config backup", "LXC snapshots", "Restore", "Scheduling"],
            "fr": ["Sauvegarde config", "Snapshots LXC", "Restauration", "Planification"],
            "de": ["Config-Backup", "LXC-Snapshots", "Wiederherstellung", "Planung"],
            "zh": ["配置备份", "LXC快照", "恢复", "计划"]
        }
    },
    "config-advisor": {
        "name": "Config Advisor", "icon": "📋", "category": "System",
        "description": {
            "en": "Configuration recommendations",
            "fr": "Recommandations de configuration",
            "de": "Konfigurationsempfehlungen",
            "zh": "配置建议"
        },
        "features": {
            "en": ["Security audit", "Best practices", "Optimization", "Reports"],
            "fr": ["Audit sécurité", "Bonnes pratiques", "Optimisation", "Rapports"],
            "de": ["Sicherheits-Audit", "Best Practices", "Optimierung", "Berichte"],
            "zh": ["安全审计", "最佳实践", "优化", "报告"]
        }
    },
    "reporter": {
        "name": "Reporter", "icon": "📊", "category": "System",
        "description": {
            "en": "System reporting and analytics",
            "fr": "Rapports et analytiques système",
            "de": "Systemberichterstattung und -analyse",
            "zh": "系统报告和分析"
        },
        "features": {
            "en": ["Reports", "Scheduling", "Export", "Email"],
            "fr": ["Rapports", "Planification", "Export", "Email"],
            "de": ["Berichte", "Planung", "Export", "E-Mail"],
            "zh": ["报告", "计划", "导出", "邮件"]
        }
    },
    "mirror": {
        "name": "Mirror Manager", "icon": "🪞", "category": "System",
        "description": {
            "en": "APT mirror management",
            "fr": "Gestion miroir APT",
            "de": "APT-Mirror-Verwaltung",
            "zh": "APT镜像管理"
        },
        "features": {
            "en": ["Mirror sync", "Bandwidth", "Scheduling", "Cache"],
            "fr": ["Sync miroir", "Bande passante", "Planification", "Cache"],
            "de": ["Mirror-Sync", "Bandbreite", "Planung", "Cache"],
            "zh": ["镜像同步", "带宽", "计划", "缓存"]
        }
    },
    "cloner": {
        "name": "System Cloner", "icon": "📀", "category": "System",
        "description": {
            "en": "System image cloning",
            "fr": "Clonage image système",
            "de": "System-Image-Klonen",
            "zh": "系统镜像克隆"
        },
        "features": {
            "en": ["Disk imaging", "Clone to USB", "Restore", "Compression"],
            "fr": ["Image disque", "Clone USB", "Restauration", "Compression"],
            "de": ["Disk-Imaging", "Clone auf USB", "Wiederherstellung", "Kompression"],
            "zh": ["磁盘镜像", "克隆到USB", "恢复", "压缩"]
        }
    },
    "eye-remote": {
        "name": "Eye Remote", "icon": "👁️", "category": "System",
        "description": {
            "en": "Remote management interface",
            "fr": "Interface de gestion à distance",
            "de": "Remote-Verwaltungsoberfläche",
            "zh": "远程管理界面"
        },
        "features": {
            "en": ["USB gadget", "Serial console", "Boot media", "Recovery"],
            "fr": ["Gadget USB", "Console série", "Média boot", "Récupération"],
            "de": ["USB-Gadget", "Serielle Konsole", "Boot-Medium", "Wiederherstellung"],
            "zh": ["USB设备", "串口控制台", "启动媒体", "恢复"]
        }
    },
    "rtty": {
        "name": "RTTY Console", "icon": "🖥️", "category": "System",
        "description": {
            "en": "Remote terminal access",
            "fr": "Accès terminal distant",
            "de": "Remote-Terminal-Zugriff",
            "zh": "远程终端访问"
        },
        "features": {
            "en": ["Web terminal", "SSH", "File transfer", "Recording"],
            "fr": ["Terminal web", "SSH", "Transfert fichiers", "Enregistrement"],
            "de": ["Web-Terminal", "SSH", "Dateiübertragung", "Aufnahme"],
            "zh": ["Web终端", "SSH", "文件传输", "录制"]
        }
    },
    # =========================================================================
    # ADDED 2026-06-26 (#742) — modules discovered but previously undocumented
    # =========================================================================
    # authelia removed 2026-07 — secubox-authelia SSO IdP decommissioned (#64768978,
    # package removed; nginx gate is now a permissive no-op). Do not re-add.
    "avatar": {
        "name": "Avatar Manager", "icon": "🧑", "category": "Apps",
        "description": {
            "en": "Identity and avatar manager",
            "fr": "Gestionnaire d'identité et d'avatar",
            "de": "Identitäts- und Avatar-Manager",
            "zh": "身份与头像管理器"
        },
        "features": {
            "en": ["Identity profiles", "Avatar generation", "Per-user assets"],
            "fr": ["Profils d'identité", "Génération d'avatar", "Ressources par utilisateur"],
            "de": ["Identitätsprofile", "Avatar-Generierung", "Pro-Benutzer-Assets"],
            "zh": ["身份档案", "头像生成", "按用户资源"]
        }
    },
    "certs": {
        "name": "Certificate Manager", "icon": "📜", "category": "Security",
        "description": {
            "en": "ACME / TLS certificate manager",
            "fr": "Gestionnaire de certificats ACME / TLS",
            "de": "ACME-/TLS-Zertifikatsverwaltung",
            "zh": "ACME / TLS 证书管理器"
        },
        "features": {
            "en": ["ACME issuance", "Renewal", "SAN / wildcard", "Inventory"],
            "fr": ["Émission ACME", "Renouvellement", "SAN / wildcard", "Inventaire"],
            "de": ["ACME-Ausstellung", "Erneuerung", "SAN / Wildcard", "Inventar"],
            "zh": ["ACME 签发", "续期", "SAN / 通配符", "清单"]
        }
    },
    "fmrelay": {
        "name": "FM Relay", "icon": "📻", "category": "Media",
        "description": {
            "en": "rtl_fm to Icecast MP3 mount with live RDS metadata",
            "fr": "rtl_fm vers mount MP3 Icecast avec métadonnées RDS live",
            "de": "rtl_fm zu Icecast-MP3-Mount mit Live-RDS-Metadaten",
            "zh": "rtl_fm 转 Icecast MP3 挂载，含实时 RDS 元数据"
        },
        "features": {
            "en": ["SDR FM capture", "Icecast stream", "RDS metadata", "Station presets"],
            "fr": ["Capture FM SDR", "Flux Icecast", "Métadonnées RDS", "Préréglages stations"],
            "de": ["SDR-FM-Empfang", "Icecast-Stream", "RDS-Metadaten", "Senderspeicher"],
            "zh": ["SDR FM 采集", "Icecast 流", "RDS 元数据", "电台预设"]
        }
    },
    "grafana": {
        "name": "Grafana", "icon": "📊", "category": "Monitoring",
        "description": {
            "en": "Security metrics dashboards",
            "fr": "Tableaux de bord métriques de sécurité",
            "de": "Sicherheitsmetrik-Dashboards",
            "zh": "安全指标仪表板"
        },
        "features": {
            "en": ["Time-series dashboards", "Alerting", "Data sources", "Panels"],
            "fr": ["Tableaux time-series", "Alertes", "Sources de données", "Panneaux"],
            "de": ["Zeitreihen-Dashboards", "Alarmierung", "Datenquellen", "Panels"],
            "zh": ["时序仪表板", "告警", "数据源", "面板"]
        }
    },
    "health": {
        "name": "Hub Health", "icon": "❤️", "category": "Dashboard",
        "description": {
            "en": "Service health and status board",
            "fr": "Tableau santé et état des services",
            "de": "Service-Gesundheits- und Statusübersicht",
            "zh": "服务健康与状态面板"
        },
        "features": {
            "en": ["Service health", "Socket checks", "Uptime", "Degradation alerts"],
            "fr": ["Santé services", "Vérifs socket", "Uptime", "Alertes dégradation"],
            "de": ["Service-Gesundheit", "Socket-Prüfungen", "Uptime", "Degradationswarnungen"],
            "zh": ["服务健康", "套接字检查", "运行时间", "降级告警"]
        }
    },
    "ksm": {
        "name": "KSM Optimizer", "icon": "🧠", "category": "System",
        "description": {
            "en": "Kernel same-page memory optimization dashboard",
            "fr": "Tableau d'optimisation mémoire KSM (kernel same-page)",
            "de": "KSM-Speicheroptimierungs-Dashboard (Kernel Same-Page)",
            "zh": "内核同页内存（KSM）优化仪表板"
        },
        "features": {
            "en": ["Page sharing stats", "Memory saved", "Tuning", "Per-VM view"],
            "fr": ["Stats partage de pages", "Mémoire économisée", "Réglage", "Vue par VM"],
            "de": ["Page-Sharing-Statistik", "Gesparter Speicher", "Tuning", "Pro-VM-Ansicht"],
            "zh": ["页共享统计", "节省内存", "调优", "按虚拟机视图"]
        }
    },
    "magicmirror": {
        "name": "MagicMirror", "icon": "🪞", "category": "Apps",
        "description": {
            "en": "MagicMirror smart-display management",
            "fr": "Gestion de l'affichage intelligent MagicMirror",
            "de": "MagicMirror-Smart-Display-Verwaltung",
            "zh": "MagicMirror 智能显示管理"
        },
        "features": {
            "en": ["Module layout", "Widgets", "Themes", "Remote control"],
            "fr": ["Disposition modules", "Widgets", "Thèmes", "Contrôle distant"],
            "de": ["Modul-Layout", "Widgets", "Themes", "Fernsteuerung"],
            "zh": ["模块布局", "小部件", "主题", "远程控制"]
        }
    },
    "metabolizer": {
        "name": "Metabolizer", "icon": "🧪", "category": "Monitoring",
        "description": {
            "en": "Log processor and analyzer",
            "fr": "Processeur et analyseur de logs",
            "de": "Log-Prozessor und -Analysator",
            "zh": "日志处理与分析器"
        },
        "features": {
            "en": ["Log parsing", "Pattern analysis", "Pipelines", "Enrichment"],
            "fr": ["Parsing de logs", "Analyse de motifs", "Pipelines", "Enrichissement"],
            "de": ["Log-Parsing", "Musteranalyse", "Pipelines", "Anreicherung"],
            "zh": ["日志解析", "模式分析", "管道", "丰富化"]
        }
    },
        "name": "Metoblizer", "icon": "🗄️", "category": "Monitoring",
        "description": {
            "en": "Centralized log aggregator",
            "fr": "Agrégateur de logs centralisé",
            "de": "Zentralisierter Log-Aggregator",
            "zh": "集中式日志聚合器"
        },
        "features": {
            "en": ["Log collection", "Central store", "Search", "Retention"],
            "fr": ["Collecte de logs", "Stockage central", "Recherche", "Rétention"],
            "de": ["Log-Sammlung", "Zentraler Speicher", "Suche", "Aufbewahrung"],
            "zh": ["日志收集", "中央存储", "搜索", "保留"]
        }
    },
    "metacatalog": {
        "name": "Metacatalog", "icon": "📇", "category": "Services",
        "description": {
            "en": "Service catalog and registry",
            "fr": "Catalogue et registre de services",
            "de": "Servicekatalog und -registry",
            "zh": "服务目录与注册表"
        },
        "features": {
            "en": ["Service registry", "Discovery", "Metadata", "Catalog UI"],
            "fr": ["Registre services", "Découverte", "Métadonnées", "UI catalogue"],
            "de": ["Service-Registry", "Discovery", "Metadaten", "Katalog-UI"],
            "zh": ["服务注册", "发现", "元数据", "目录界面"]
        }
    },
    "picobrew": {
        "name": "PicoBrew", "icon": "🍺", "category": "IoT",
        "description": {
            "en": "Homebrew / fermentation controller",
            "fr": "Contrôleur de brassage / fermentation",
            "de": "Homebrew-/Fermentationssteuerung",
            "zh": "自酿 / 发酵控制器"
        },
        "features": {
            "en": ["Temperature control", "Recipes", "Fermentation log", "Sensors"],
            "fr": ["Contrôle température", "Recettes", "Journal fermentation", "Capteurs"],
            "de": ["Temperatursteuerung", "Rezepte", "Fermentationslog", "Sensoren"],
            "zh": ["温度控制", "配方", "发酵日志", "传感器"]
        }
    },
    "podcaster": {
        "name": "Podcaster", "icon": "🎙️", "category": "Media",
        "description": {
            "en": "Modern podcast manager",
            "fr": "Gestionnaire de podcasts moderne",
            "de": "Moderner Podcast-Manager",
            "zh": "现代播客管理器"
        },
        "features": {
            "en": ["Feed management", "Episodes", "Transcoding", "RSS publish"],
            "fr": ["Gestion des flux", "Épisodes", "Transcodage", "Publication RSS"],
            "de": ["Feed-Verwaltung", "Episoden", "Transcodierung", "RSS-Veröffentlichung"],
            "zh": ["订阅源管理", "剧集", "转码", "RSS 发布"]
        }
    },
    "redroid": {
        "name": "ReDroid", "icon": "🤖", "category": "Apps",
        "description": {
            "en": "Android-in-container runtime",
            "fr": "Runtime Android en conteneur",
            "de": "Android-im-Container-Laufzeit",
            "zh": "容器中的 Android 运行时"
        },
        "features": {
            "en": ["Android container", "ADB", "App install", "Screen view"],
            "fr": ["Conteneur Android", "ADB", "Installation d'apps", "Vue écran"],
            "de": ["Android-Container", "ADB", "App-Installation", "Bildschirmansicht"],
            "zh": ["Android 容器", "ADB", "应用安装", "屏幕查看"]
        }
    },
    "rezapp": {
        "name": "RezApp", "icon": "📦", "category": "Services",
        "description": {
            "en": "Application deployment and management",
            "fr": "Déploiement et gestion d'applications",
            "de": "Anwendungsbereitstellung und -verwaltung",
            "zh": "应用部署与管理"
        },
        "features": {
            "en": ["App deploy", "Lifecycle", "Config", "Status"],
            "fr": ["Déploiement d'apps", "Cycle de vie", "Config", "État"],
            "de": ["App-Deploy", "Lebenszyklus", "Konfiguration", "Status"],
            "zh": ["应用部署", "生命周期", "配置", "状态"]
        }
    },
    "rustdesk": {
        "name": "RustDesk", "icon": "🖥️", "category": "Access",
        "description": {
            "en": "Self-hosted remote desktop relay",
            "fr": "Relais de bureau distant auto-hébergé",
            "de": "Selbstgehostetes Remote-Desktop-Relay",
            "zh": "自托管远程桌面中继"
        },
        "features": {
            "en": ["Relay server", "ID server", "Sessions", "Self-hosted"],
            "fr": ["Serveur relais", "Serveur d'ID", "Sessions", "Auto-hébergé"],
            "de": ["Relay-Server", "ID-Server", "Sitzungen", "Selbstgehostet"],
            "zh": ["中继服务器", "ID 服务器", "会话", "自托管"]
        }
    },
    "saas-relay": {
        "name": "SaaS Relay", "icon": "🔌", "category": "Network",
        "description": {
            "en": "SaaS / API proxy relay",
            "fr": "Relais proxy SaaS / API",
            "de": "SaaS-/API-Proxy-Relay",
            "zh": "SaaS / API 代理中继"
        },
        "features": {
            "en": ["API proxy", "Rate limiting", "Routing", "Credentials vault"],
            "fr": ["Proxy API", "Limitation de débit", "Routage", "Coffre identifiants"],
            "de": ["API-Proxy", "Ratenbegrenzung", "Routing", "Anmeldedaten-Tresor"],
            "zh": ["API 代理", "限流", "路由", "凭据保险库"]
        }
    },
    "security-posture": {
        "name": "Security Posture", "icon": "🎯", "category": "Security",
        "description": {
            "en": "Honest board-truthful security scorecard",
            "fr": "Carte de score de sécurité honnête (vérité board)",
            "de": "Ehrliche, board-wahrheitsgemäße Sicherheits-Scorecard",
            "zh": "诚实的、基于真实状态的安全评分卡"
        },
        "features": {
            "en": ["Scorecard", "Control checks", "Gaps", "Trend"],
            "fr": ["Scorecard", "Vérifs de contrôles", "Écarts", "Tendance"],
            "de": ["Scorecard", "Kontrollprüfungen", "Lücken", "Trend"],
            "zh": ["评分卡", "控制检查", "差距", "趋势"]
        }
    },
    "sentinelle": {
        "name": "SENTINELLE-GSM", "icon": "📡", "category": "Security",
        "description": {
            "en": "Passive rogue-BTS sensor (MIND layer)",
            "fr": "Capteur passif de fausse BTS (couche MIND)",
            "de": "Passiver Rogue-BTS-Sensor (MIND-Schicht)",
            "zh": "被动式伪基站传感器（MIND 层）"
        },
        "features": {
            "en": ["IMSI-catcher detection", "Cell survey", "Anomaly alerts", "Passive RF"],
            "fr": ["Détection IMSI-catcher", "Relevé cellules", "Alertes anomalies", "RF passif"],
            "de": ["IMSI-Catcher-Erkennung", "Zell-Survey", "Anomalie-Warnungen", "Passives HF"],
            "zh": ["IMSI 捕集器检测", "基站勘测", "异常告警", "被动射频"]
        }
    },
    "threatmesh": {
        "name": "ThreatMesh", "icon": "🕸️", "category": "Security",
        "description": {
            "en": "Sovereign threat-intel mesh (CrowdSec CAPI replacement)",
            "fr": "Mesh de threat-intel souverain (remplace CrowdSec CAPI)",
            "de": "Souveränes Threat-Intel-Mesh (CrowdSec-CAPI-Ersatz)",
            "zh": "主权威胁情报网格（替代 CrowdSec CAPI）"
        },
        "features": {
            "en": ["P2P intel sharing", "Sovereign feed", "Confidence gating", "Blocklist sync"],
            "fr": ["Partage intel P2P", "Feed souverain", "Filtrage par confiance", "Sync blocklist"],
            "de": ["P2P-Intel-Sharing", "Souveräner Feed", "Vertrauens-Gating", "Blocklist-Sync"],
            "zh": ["P2P 情报共享", "主权源", "置信度门控", "黑名单同步"]
        }
    },
    "toolbox": {
        "name": "ToolBoX (Cabine)", "icon": "🧰", "category": "Security",
        "description": {
            "en": "Captive AP + consented MITM privacy analyzer",
            "fr": "AP captif + analyseur MITM de vie privée consenti",
            "de": "Captive-AP + einvernehmlicher MITM-Datenschutz-Analysator",
            "zh": "强制门户 AP + 知情同意的 MITM 隐私分析器"
        },
        "features": {
            "en": ["Captive portal", "R0-R4 levels", "Tracker exposure", "Tor egress"],
            "fr": ["Portail captif", "Niveaux R0-R4", "Exposition trackers", "Sortie Tor"],
            "de": ["Captive Portal", "R0-R4-Stufen", "Tracker-Aufdeckung", "Tor-Ausgang"],
            "zh": ["强制门户", "R0-R4 等级", "追踪器暴露", "Tor 出口"]
        }
    },
    "vm": {
        "name": "VM Manager", "icon": "💻", "category": "System",
        "description": {
            "en": "Virtualization management",
            "fr": "Gestion de la virtualisation",
            "de": "Virtualisierungsverwaltung",
            "zh": "虚拟化管理"
        },
        "features": {
            "en": ["VM lifecycle", "Console", "Snapshots", "Resource limits"],
            "fr": ["Cycle de vie VM", "Console", "Snapshots", "Limites ressources"],
            "de": ["VM-Lebenszyklus", "Konsole", "Snapshots", "Ressourcenlimits"],
            "zh": ["虚拟机生命周期", "控制台", "快照", "资源限制"]
        }
    },
    "yacy": {
        "name": "YaCy", "icon": "🔎", "category": "Network",
        "description": {
            "en": "Peer-to-peer search engine",
            "fr": "Moteur de recherche pair-à-pair",
            "de": "Peer-to-Peer-Suchmaschine",
            "zh": "点对点搜索引擎"
        },
        "features": {
            "en": ["P2P index", "Crawler", "Private search", "Federation"],
            "fr": ["Index P2P", "Crawler", "Recherche privée", "Fédération"],
            "de": ["P2P-Index", "Crawler", "Private Suche", "Föderation"],
            "zh": ["P2P 索引", "爬虫", "私密搜索", "联邦"]
        }
    },
}

LANGUAGES = {
    "en": {"name": "English", "flag": "🇬🇧"},
    "fr": {"name": "Français", "flag": "🇫🇷"},
    "de": {"name": "Deutsch", "flag": "🇩🇪"},
    "zh": {"name": "中文", "flag": "🇨🇳"},
}


def check_screenshot_exists(module_id: str, screenshots_dir: Path) -> bool:
    """Check if screenshot exists for module."""
    return (screenshots_dir / f"{module_id}.png").exists()


def generate_package_readme(module_id: str, module_info: dict, lang: str = "en", include_screenshot: bool = True) -> str:
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

"""

    if include_screenshot:
        readme += f"""## {L['screenshot']}

![{name}](../../docs/screenshots/vm/{module_id}.png)

"""

    readme += f"""## {L['features']}

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

LicenseRef-CMSD-1.0 (Source-Disclosed License) — CyberMind © 2024-2026.
See [LICENCE-CMSD-1.0.md](../../LICENCE-CMSD-1.0.md).
"""
    return readme


def generate_wiki_page(lang: str, include_screenshots: bool = True, screenshots_dir: Optional[Path] = None) -> str:
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
            "features": "Features",
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
            "features": "Fonctionnalités",
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
            "features": "Funktionen",
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
            "features": "功能",
        },
    }
    L = labels.get(lang, labels["en"])

    # Language selector
    lang_links = " | ".join([f"[{LANGUAGES[l]['flag']} {LANGUAGES[l]['name']}](MODULES-{l.upper()}.md)" for l in LANGUAGES])

    wiki = f"""# {L['title']}

*{L['subtitle']}*

**{L['total']}:** {len(MODULES)}

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

    # Group by category
    by_category = {}
    for mid, info in MODULES.items():
        cat = info["category"]
        if cat not in by_category:
            by_category[cat] = []
        by_category[cat].append((mid, info))

    for category, modules_list in sorted(by_category.items()):
        wiki += f"### {category}\n\n"

        for mid, info in modules_list:
            desc = info["description"].get(lang, info["description"]["en"])
            features = info["features"].get(lang, info["features"]["en"])

            wiki += f"""#### {info['icon']} {info['name']}

{desc}

**{L['features']}:** {', '.join(features)}

"""
            # Add screenshot if exists. Use an ABSOLUTE raw.githubusercontent URL
            # (not a relative path): the GitHub wiki is a SEPARATE repo, so a
            # relative screenshots/vm/ path would 404 there. This matches the
            # convention already used by the published wiki/ pages.
            if include_screenshots:
                if screenshots_dir and check_screenshot_exists(mid, screenshots_dir):
                    wiki += (f"![{info['name']}]"
                             f"({SCREENSHOT_RAW_BASE}/{mid}.png)\n\n")

        wiki += "---\n\n"

    return wiki


def generate_category_index(lang: str = "en") -> str:
    """Generate category index page."""
    labels = {
        "en": {"title": "Module Categories", "count": "modules"},
        "fr": {"title": "Catégories de Modules", "count": "modules"},
        "de": {"title": "Modul-Kategorien", "count": "Module"},
        "zh": {"title": "模块分类", "count": "个模块"},
    }
    L = labels.get(lang, labels["en"])

    # Count by category
    categories = {}
    for info in MODULES.values():
        cat = info["category"]
        if cat not in categories:
            categories[cat] = 0
        categories[cat] += 1

    md = f"# {L['title']}\n\n"

    for cat, count in sorted(categories.items(), key=lambda x: -x[1]):
        md += f"- **{cat}**: {count} {L['count']}\n"

    return md


def main():
    parser = argparse.ArgumentParser(description="Generate SecuBox documentation")
    parser.add_argument("--include-screenshots", action="store_true", help="Include screenshots in docs")
    parser.add_argument("--lang", help="Generate for specific language only")
    parser.add_argument("--readme-only", action="store_true", help="Generate package READMEs only")
    parser.add_argument("--wiki-only", action="store_true", help="Generate wiki pages only")
    args = parser.parse_args()

    base_dir = Path(__file__).parent.parent
    packages_dir = base_dir / "packages"
    docs_dir = base_dir / "docs"
    wiki_dir = docs_dir / "wiki"
    screenshots_dir = docs_dir / "screenshots" / "vm"

    wiki_dir.mkdir(parents=True, exist_ok=True)

    languages = [args.lang] if args.lang else list(LANGUAGES.keys())

    if not args.wiki_only:
        print(f"Generating package READMEs for {len(MODULES)} modules...")
        created = 0
        for module_id, module_info in MODULES.items():
            pkg_dir = packages_dir / f"secubox-{module_id}"
            if pkg_dir.exists():
                readme_path = pkg_dir / "README.md"
                has_screenshot = check_screenshot_exists(module_id, screenshots_dir)
                readme = generate_package_readme(
                    module_id, module_info, "en",
                    include_screenshot=args.include_screenshots and has_screenshot
                )
                readme_path.write_text(readme)
                created += 1
        print(f"  Created {created} READMEs")

    if not args.readme_only:
        print(f"\nGenerating multilingual wiki pages ({', '.join(languages)})...")
        for lang in languages:
            wiki_path = wiki_dir / f"MODULES-{lang.upper()}.md"
            wiki = generate_wiki_page(
                lang,
                include_screenshots=args.include_screenshots,
                screenshots_dir=screenshots_dir
            )
            wiki_path.write_text(wiki)
            print(f"  Created {wiki_path.name}")

        # Category index
        for lang in languages:
            index_path = wiki_dir / f"CATEGORIES-{lang.upper()}.md"
            index = generate_category_index(lang)
            index_path.write_text(index)
            print(f"  Created {index_path.name}")

    print(f"\nDone! Total modules: {len(MODULES)}")


if __name__ == "__main__":
    main()
