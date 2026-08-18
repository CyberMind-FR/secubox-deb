<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# OPAD — Guide Opérationnel

**SecuBox-Deb v2.4.0 · Exploitation et maintenance**

---

**Référence** : CM-OPS-OPAD-2026-05
**Version** : 2.4.0
**Date** : 2026-05-12
**Auteur** : Gérald Kerma — CyberMind
**Classification** : Public

---

## Table des matières

1. [Prérequis](#1-prérequis)
2. [Installation et configuration](#2-installation-et-configuration)
3. [Opérations courantes](#3-opérations-courantes)
4. [Gestion des règles de politique](#4-gestion-des-règles-de-politique)
5. [Troubleshooting](#5-troubleshooting)
6. [Escalade vers in-path](#6-escalade-vers-in-path)
7. [Rollback et récupération 4R](#7-rollback-et-récupération-4r)
8. [Monitoring et alertes](#8-monitoring-et-alertes)
9. [Maintenance](#9-maintenance)
10. [Contacts et support](#10-contacts-et-support)

---

## 1. Prérequis

### 1.1 Matériel supporté

| Plateforme | Architecture | Statut | Notes |
|------------|--------------|--------|-------|
| MOCHAbin | arm64 (Armada 7040) | **PRODUCTION** | Cible primaire |
| ESPRESSObin v7 | arm64 (Armada 3720) | **BETA** | Lite edition |
| ESPRESSObin Ultra | arm64 (Armada 3720) | **BETA** | 2× WAN capable |
| VM x86_64 | x86_64 | **DÉVELOPPEMENT** | Tests uniquement |

### 1.2 Dépendances système

Installer les paquets Debian requis :

```bash
apt update
apt install -y \
  libpcap-dev \
  python3-scapy \
  python3-pydantic \
  python3-fastapi \
  python3-uvicorn \
  bpfcc-tools \
  linux-headers-$(uname -r)
```

### 1.3 Vérification kernel BPF JIT

OPAD nécessite BPF JIT activé pour performances optimales :

```bash
# Vérifier BPF JIT
sysctl net.core.bpf_jit_enable

# Si désactivé, activer temporairement
sysctl -w net.core.bpf_jit_enable=1

# Activer de manière permanente
echo "net.core.bpf_jit_enable=1" >> /etc/sysctl.d/99-secubox-opad.conf
sysctl -p /etc/sysctl.d/99-secubox-opad.conf
```

**Sortie attendue** : `net.core.bpf_jit_enable = 1`

### 1.4 Vérification des capacités kernel

```bash
# Modules requis
lsmod | grep -E 'nf_nat|nf_conntrack|sch_prio|cls_bpf|act_bpf'

# Charger si manquants
modprobe nf_nat nf_conntrack sch_prio cls_bpf act_bpf
```

---

## 2. Installation et configuration

### 2.1 Déploiement initial

```bash
# 1. Installer le paquet
apt install secubox-wall

# 2. Vérifier le service
systemctl status secubox-wall

# 3. Vérifier le mode OPAD
curl -s http://localhost:9999/api/v1/wall/status | jq '.mode'
# Sortie attendue: "opad"

# 4. Valider le profil par défaut
secubox-params validate --module wall --profile active
```

### 2.2 Configuration profil 3-broche

Le profil OPAD utilise le système **double-buffer** :

```
/etc/secubox/wall/
├── active/          ← Configuration live (lecture seule en production)
├── shadow/          ← Édition, validation avant swap
└── rollback/
    ├── R1/          ← Snapshot le plus récent
    ├── R2/
    ├── R3/
    └── R4/          ← Snapshot le plus ancien
```

#### Workflow standard

```bash
# 1. Éditer la configuration dans shadow
secubox-params edit --module wall --profile shadow

# 2. Valider le profil
secubox-params validate --module wall --profile shadow

# 3. Swap shadow → active (crée snapshot automatique)
secubox-params swap --module wall

# 4. Redémarrer le service
systemctl restart secubox-wall
```

### 2.3 Configuration des interfaces

OPAD nécessite les interfaces d'observation en **mode promiscuous** :

```bash
# Configuration netplan (exemple /etc/netplan/00-secubox.yaml)
network:
  version: 2
  ethernets:
    eth0:
      dhcp4: false
      promisc: true    # Mode promiscuous pour observation
      addresses:
        - 192.168.1.1/24

    eth1:
      dhcp4: false
      promisc: true
      addresses:
        - 192.168.2.1/24

# Appliquer
netplan generate && netplan apply

# Vérifier
ip link show eth0 | grep PROMISC
```

### 2.4 Profil minimal (JSON)

Exemple de profil OPAD `active/opad-profile.json` :

```json
{
  "mode": "opad",
  "observation": {
    "interfaces": ["eth0", "eth1"],
    "promiscuous": true,
    "bpf_filter": "not port 22 and not port 9999"
  },
  "primitives": {
    "dns-r": {
      "enabled": true,
      "ttl": 0,
      "spoof_ip": "127.0.0.1"
    },
    "dhcp-r": {
      "enabled": true,
      "nak_rate_limit": "10/s"
    },
    "rst-i": {
      "enabled": true,
      "seq_window": 4096
    },
    "arp-r": {
      "enabled": false
    }
  },
  "policy": {
    "default_action": "observe",
    "rules_file": "active/policy-rules.json"
  },
  "metrics": {
    "prometheus_port": 9100,
    "log_level": "info"
  }
}
```

---

## 3. Opérations courantes

### 3.1 Vérification du statut

```bash
# Status systemd
systemctl status secubox-wall

# Status API détaillé
curl -s http://localhost:9999/api/v1/wall/status | jq
```

**Exemple de réponse JSON** :

```json
{
  "mode": "opad",
  "status": "active",
  "uptime_seconds": 86400,
  "observation": {
    "interfaces": ["eth0", "eth1"],
    "packets_observed": 1245678,
    "packets_matched": 3421
  },
  "primitives": {
    "dns-r": {
      "enabled": true,
      "injections_total": 142,
      "injections_lost": 2
    },
    "dhcp-r": {
      "enabled": true,
      "naks_sent": 89
    },
    "rst-i": {
      "enabled": true,
      "resets_sent": 56
    },
    "arp-r": {
      "enabled": false
    }
  },
  "policy": {
    "rules_count": 8,
    "matches_total": 3421
  }
}
```

### 3.2 Métriques temps réel

```bash
# Métriques Prometheus
curl -s http://localhost:9100/metrics | grep secubox_opad

# Statistiques par primitive
curl -s http://localhost:9999/api/v1/wall/metrics | jq '.primitives'
```

### 3.3 Consultation des logs

```bash
# Logs temps réel
journalctl -u secubox-wall -f

# Filtrer par niveau
journalctl -u secubox-wall -p warning -n 100

# Rechercher alertes DEPOT
journalctl -u secubox-wall | grep "ALERTE_DEPOT"

# Exemple de log:
# [OPAD] [DNS-R] ALERTE_DEPOT: 3 packets lost in 1s (threshold: 2)

# Rechercher injections perdues
journalctl -u secubox-wall | grep "OPAD_INJECT_LOST"

# Logs JSON structurés
journalctl -u secubox-wall -o json | jq '.MESSAGE'
```

---

## 4. Gestion des règles de politique

### 4.1 Lister les règles

```bash
# Via API
curl -s http://localhost:9999/api/v1/wall/policy/rules | jq

# Via fichier
cat /etc/secubox/wall/active/policy-rules.json | jq
```

### 4.2 Ajouter une règle

#### Exemple 1 : Bloquer un domaine (DNS-R)

```bash
curl -X POST http://localhost:9999/api/v1/wall/policy/rules \
  -H "Content-Type: application/json" \
  -d '{
    "id": "block-malware-domain",
    "primitive": "dns-r",
    "action": "inject",
    "match": {
      "domain": "malware.example.com"
    },
    "params": {
      "ttl": 0,
      "spoof_ip": "127.0.0.1"
    },
    "enabled": true,
    "priority": 100
  }'
```

#### Exemple 2 : Quarantaine d'un device (DHCP-R)

```bash
curl -X POST http://localhost:9999/api/v1/wall/policy/rules \
  -H "Content-Type: application/json" \
  -d '{
    "id": "quarantine-infected-host",
    "primitive": "dhcp-r",
    "action": "nak",
    "match": {
      "mac": "aa:bb:cc:dd:ee:ff"
    },
    "params": {
      "reason": "Infected device - contact IT"
    },
    "enabled": true,
    "priority": 200
  }'
```

#### Exemple 3 : RST vers IP externe (RST-I)

```bash
curl -X POST http://localhost:9999/api/v1/wall/policy/rules \
  -H "Content-Type: application/json" \
  -d '{
    "id": "block-c2-server",
    "primitive": "rst-i",
    "action": "inject",
    "match": {
      "dst_ip": "198.51.100.123",
      "protocol": "tcp"
    },
    "params": {
      "seq_window": 4096
    },
    "enabled": true,
    "priority": 300
  }'
```

### 4.3 Modifier une règle

```bash
# 1. Récupérer l'ID de la règle
curl -s http://localhost:9999/api/v1/wall/policy/rules | jq '.[] | select(.id=="block-malware-domain")'

# 2. Modifier (PATCH ou PUT)
curl -X PATCH http://localhost:9999/api/v1/wall/policy/rules/block-malware-domain \
  -H "Content-Type: application/json" \
  -d '{
    "enabled": false
  }'
```

### 4.4 Supprimer une règle

```bash
curl -X DELETE http://localhost:9999/api/v1/wall/policy/rules/block-malware-domain
```

### 4.5 Recharger les règles

```bash
# Après modification manuelle du fichier policy-rules.json
curl -X POST http://localhost:9999/api/v1/wall/policy/reload

# Ou via systemd
systemctl reload secubox-wall
```

---

## 5. Troubleshooting

### 5.1 DNS-R : Problèmes d'injection

| Symptôme | Cause probable | Solution |
|----------|----------------|----------|
| Clients reçoivent réponse légitime | Injection trop lente (latence DÉPÔT) | Vérifier `ALERTE_DEPOT` dans logs, réduire charge CPU |
| `OPAD_INJECT_LOST` dans logs | Race condition perdue | Activer escalade in-path (INV-08) si critique |
| TTL non respecté | Bug client cache | Forcer TTL=0 dans règle primitive |
| Injection fonctionne sporadiquement | Interface non promiscuous | `ip link show eth0 \| grep PROMISC` |

**Commandes de diagnostic** :

```bash
# Capturer trafic DNS
tcpdump -i eth0 -nn port 53 -c 100

# Vérifier latence injection
curl -s http://localhost:9100/metrics | grep secubox_opad_dns_latency

# Tester règle manuellement
dig @8.8.8.8 malware.example.com  # Devrait recevoir 127.0.0.1
```

### 5.2 DHCP-R : NAK non effectifs

| Symptôme | Cause probable | Solution |
|----------|----------------|----------|
| Client obtient IP malgré NAK | Serveur DHCP légitime plus rapide | Escalade in-path pour drop hard |
| NAK envoyés mais ignorés | Client stateful DHCPv6 | Ajouter règle pour DHCPv6 (port 547) |
| Rate limit atteint | Trop de NAK/s | Augmenter `nak_rate_limit` dans profil |

**Commandes de diagnostic** :

```bash
# Capturer DHCP
tcpdump -i eth0 -nn port 67 or port 68 -v

# Vérifier NAK count
curl -s http://localhost:9999/api/v1/wall/metrics | jq '.primitives["dhcp-r"].naks_sent'

# Tester règle
# (sur client) dhclient -r eth0 && dhclient eth0
```

### 5.3 RST-I : Connexion non coupée

| Symptôme | Cause probable | Solution |
|----------|----------------|----------|
| Connexion TCP établie malgré RST | SEQ hors fenêtre | Augmenter `seq_window` à 65535 (max) |
| RST envoyés mais ignorés | Client ignore RST (rare) | Escalade in-path pour drop dans nftables |
| RST sur mauvais sens | Bug direction detection | Vérifier logs OPAD, reporter bug |

**Commandes de diagnostic** :

```bash
# Capturer RST
tcpdump -i eth0 'tcp[tcpflags] & tcp-rst != 0' -nn -c 20

# Tester règle
curl -v http://198.51.100.123  # Devrait timeout/reset
```

### 5.4 ARP-R : Empoisonnement détecté

| Symptôme | Cause probable | Solution |
|----------|----------------|----------|
| Fausses réponses ARP persistent | Race condition ARP | Activer in-path + static ARP sur clients critiques |
| Alerts ARP floods | Attaque MITM active | Activer primitive ARP-R + bloquer MAC source |
| Réponses ARP non injectées | Interface non promiscuous | Vérifier `ip link show \| grep PROMISC` |

**Commandes de diagnostic** :

```bash
# Capturer ARP
tcpdump -i eth0 arp -nn -e

# Vérifier table ARP
ip neigh show

# Scanner ARP spoofing (arpwatch)
apt install arpwatch
systemctl start arpwatch
journalctl -u arpwatch -f
```

---

## 6. Escalade vers in-path

### 6.1 Quand escalader

Escalader vers **in-path** (mode invasif INV-08) dans ces cas :

1. **Client ARP statique** : Injection ARP-R inefficace
2. **Besoin drop hard** : RST-I ou DNS-R perdent race condition
3. **Deep packet inspection** : Besoin modifier payload (WAF)
4. **Conformité réglementaire** : Audit exige interception certaine

**ATTENTION** : Escalade = point unique de défaillance (SPOF). Tester en maintenance window.

### 6.2 Procédure INV-08

```bash
# 1. Vérifier état actuel
curl -s http://localhost:9999/api/v1/wall/status | jq '.mode'
# Sortie: "opad"

# 2. Planifier escalade (dry-run)
curl -X POST http://localhost:9999/api/v1/wall/escalate \
  -H "Content-Type: application/json" \
  -d '{
    "target_mode": "in-path",
    "dry_run": true
  }' | jq

# 3. Activer escalade
secubox-wall escalate --mode in-path --confirm

# 4. Vérifier
curl -s http://localhost:9999/api/v1/wall/status | jq '.mode'
# Sortie: "in-path"

# 5. Surveiller
journalctl -u secubox-wall -f
```

**Changements effectués** :

- nftables : ajout hook `PREROUTING` + `FORWARD`
- tc : qdisc `prio` remplacé par `htb` avec redirect
- Interfaces : mode bridge activé (`brctl addif secubox-br0 eth0`)

### 6.3 Révocation (retour OPAD)

```bash
# 1. Révoquer escalade
curl -X DELETE http://localhost:9999/api/v1/wall/escalate

# 2. Vérifier
curl -s http://localhost:9999/api/v1/wall/status | jq '.mode'
# Sortie: "opad"

# 3. Redémarrer service (recommandé)
systemctl restart secubox-wall
```

---

## 7. Rollback et récupération 4R

### 7.1 Actions 4R

| Action | Mnémotechnique | Description | Commande |
|--------|----------------|-------------|----------|
| **Run** | Exécuter | Swap shadow → active | `secubox-params swap --module wall` |
| **Rollback** | Retour arrière | Restaurer snapshot Rn | `secubox-params rollback --module wall --target R1` |
| **Revert** | Annuler | Swap active → shadow | `secubox-params revert --module wall` |
| **Rebuild** | Reconstruction | Régénérer depuis source | `secubox-params rebuild --module wall --from-template` |

### 7.2 Structure snapshots

```
/etc/secubox/wall/rollback/
├── R1/
│   ├── opad-profile.json
│   ├── policy-rules.json
│   └── .timestamp    # 2026-05-12T14:30:00Z
├── R2/
│   └── .timestamp    # 2026-05-11T09:15:00Z
├── R3/
│   └── .timestamp    # 2026-05-10T16:45:00Z
└── R4/
    └── .timestamp    # 2026-05-09T11:00:00Z
```

**Règle de rotation** : Chaque `swap` crée un nouveau snapshot R1, les autres se décalent (R1→R2, R2→R3, R3→R4, R4 supprimé).

### 7.3 Restauration d'urgence

#### Scenario 1 : Configuration cassée après swap

```bash
# 1. Identifier le problème
systemctl status secubox-wall
# Sortie: failed

# 2. Consulter logs
journalctl -u secubox-wall -n 50 --no-pager

# 3. Rollback immédiat vers R1
secubox-params rollback --module wall --target R1

# 4. Redémarrer
systemctl restart secubox-wall

# 5. Vérifier
systemctl status secubox-wall
```

#### Scenario 2 : Tous les snapshots corrompus

```bash
# 1. Rebuild depuis template factory
secubox-params rebuild --module wall --from-template

# 2. Vérifier template source
ls -la /usr/share/secubox/wall/templates/

# 3. Restaurer
cp -r /usr/share/secubox/wall/templates/* /etc/secubox/wall/active/

# 4. Redémarrer
systemctl restart secubox-wall
```

### 7.4 Audit trail

Chaque action 4R est loggée dans `/var/log/secubox/audit.log` :

```bash
# Consulter audit trail
tail -f /var/log/secubox/audit.log

# Exemple d'entrée:
# 2026-05-12T14:30:15Z [WALL] ACTION=swap USER=root FROM=shadow TO=active SNAPSHOT=R1
# 2026-05-12T14:35:42Z [WALL] ACTION=rollback USER=root FROM=active TO=R1 REASON="config_invalid"
```

---

## 8. Monitoring et alertes

### 8.1 Métriques Prometheus

Endpoint : `http://localhost:9100/metrics`

#### Métriques principales

```prometheus
# Compteurs injections
secubox_opad_injection_total{primitive="dns-r"} 142
secubox_opad_injection_total{primitive="dhcp-r"} 89
secubox_opad_injection_total{primitive="rst-i"} 56

# Injections perdues (race condition)
secubox_opad_injection_lost_total{primitive="dns-r"} 2

# Latence injection (ms)
secubox_opad_injection_latency_ms{primitive="dns-r",quantile="0.5"} 0.8
secubox_opad_injection_latency_ms{primitive="dns-r",quantile="0.99"} 3.2

# Packets observés
secubox_opad_packets_observed_total 1245678

# Règles de politique matchées
secubox_opad_policy_matches_total{rule_id="block-malware-domain"} 89
secubox_opad_policy_matches_total{rule_id="quarantine-infected-host"} 12
```

### 8.2 Alertes Prometheus recommandées

```yaml
# /etc/prometheus/alerts/secubox-opad.yml
groups:
  - name: secubox_opad
    interval: 30s
    rules:
      # Alerte 1 : Service dégradé
      - alert: OPADServiceDegraded
        expr: up{job="secubox-wall"} == 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "OPAD service down on {{ $labels.instance }}"
          description: "secubox-wall systemd unit not responding"

      # Alerte 2 : Injections perdues (burst)
      - alert: OPADInjectLostBurst
        expr: rate(secubox_opad_injection_lost_total[1m]) > 0.1
        for: 2m
        labels:
          severity: warning
        annotations:
          summary: "OPAD losing injections on {{ $labels.instance }}"
          description: "Primitive {{ $labels.primitive }} losing race conditions ({{ $value }}/s)"

      # Alerte 3 : Latence excessive
      - alert: OPADLatencyHigh
        expr: secubox_opad_injection_latency_ms{quantile="0.99"} > 5
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "OPAD high latency on {{ $labels.instance }}"
          description: "P99 latency {{ $value }}ms (threshold: 5ms)"

      # Alerte 4 : Observation arrêtée
      - alert: OPADObservationDown
        expr: rate(secubox_opad_packets_observed_total[5m]) == 0
        for: 2m
        labels:
          severity: critical
        annotations:
          summary: "OPAD not observing traffic on {{ $labels.instance }}"
          description: "No packets observed in last 5 minutes - check interfaces"

      # Alerte 5 : Escalade in-path active
      - alert: OPADEscalationActive
        expr: secubox_opad_mode{mode="in-path"} == 1
        for: 10m
        labels:
          severity: info
        annotations:
          summary: "OPAD escalated to in-path mode on {{ $labels.instance }}"
          description: "System running in invasive mode - verify if intentional"
```

### 8.3 Grafana dashboard

Importer le dashboard pré-configuré :

```bash
# Télécharger dashboard JSON
curl -o /tmp/opad-dashboard.json \
  https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/monitoring/grafana/opad-dashboard.json

# Importer dans Grafana
grafana-cli admin import-dashboard /tmp/opad-dashboard.json
```

**Panels inclus** :

- Injections totales (time series)
- Injections perdues (gauge)
- Latence P50/P95/P99 (heatmap)
- Policy matches par règle (bar chart)
- Escalations in-path (stat)

---

## 9. Maintenance

### 9.1 Mise à jour

```bash
# 1. Vérifier version actuelle
dpkg -l | grep secubox-wall

# 2. Mettre à jour
apt update
apt install --only-upgrade secubox-wall

# 3. Vérifier changelog
zcat /usr/share/doc/secubox-wall/changelog.Debian.gz | head -n 20

# 4. Redémarrer
systemctl restart secubox-wall

# 5. Valider
curl -s http://localhost:9999/api/v1/wall/status | jq '.version'
```

### 9.2 Sauvegarde configuration

```bash
# Backup manuel
tar -czf /backup/secubox-wall-$(date +%Y%m%d).tar.gz \
  /etc/secubox/wall/active/ \
  /etc/secubox/wall/rollback/

# Restauration
tar -xzf /backup/secubox-wall-20260512.tar.gz -C /
systemctl restart secubox-wall
```

**Automatisation cron** :

```bash
# /etc/cron.daily/secubox-wall-backup
#!/bin/bash
set -euo pipefail
BACKUP_DIR="/backup/secubox-wall"
DATE=$(date +%Y%m%d)
mkdir -p "$BACKUP_DIR"
tar -czf "$BACKUP_DIR/wall-$DATE.tar.gz" /etc/secubox/wall/active/ /etc/secubox/wall/rollback/
find "$BACKUP_DIR" -name "wall-*.tar.gz" -mtime +30 -delete
```

### 9.3 Rotation logs

Configuration logrotate `/etc/logrotate.d/secubox-wall` :

```
/var/log/secubox/wall/*.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 0640 secubox-wall secubox-wall
    sharedscripts
    postrotate
        systemctl reload secubox-wall > /dev/null 2>&1 || true
    endscript
}
```

### 9.4 Nettoyage cache BPF

```bash
# Lister objets BPF
bpftool prog list

# Lister maps BPF
bpftool map list

# Nettoyer objets orphelins (après crash)
bpftool prog show | awk '/secubox_opad/ {print $1}' | xargs -n1 bpftool prog detach

# Supprimer maps orphelines
bpftool map show | awk '/secubox_opad/ {print $1}' | xargs -n1 bpftool map delete
```

### 9.5 Vérification intégrité

```bash
# Checksum binaires
debsums secubox-wall

# Permissions
dpkg-statoverride --list | grep secubox-wall

# Capabilities binaires
getcap /usr/bin/secubox-wall
# Sortie attendue: cap_net_admin,cap_net_raw=ep
```

---

## 10. Contacts et support

### 10.1 Documentation

- **Architecture OPAD** : `/usr/share/doc/secubox-wall/OPAD-ARCHITECTURE.md`
- **Threat Model** : `/usr/share/doc/secubox-wall/OPAD-THREAT-MODEL.md`
- **Compliance CSPN** : `/usr/share/doc/secubox-wall/OPAD-CSPN.md`
- **Site web** : https://secubox.in

### 10.2 Support technique

- **Issues GitHub** : https://github.com/CyberMind-FR/secubox-deb/issues
- **Email** : support@cybermind.fr
- **Matrice** : #secubox:matrix.org

### 10.3 Reporting bugs

Template issue GitHub :

```markdown
### Environnement
- SecuBox version: [dpkg -l | grep secubox-wall]
- Kernel: [uname -r]
- Board: [MOCHAbin / ESPRESSObin / VM]

### Symptôme
[Description du problème]

### Reproduction
1. [Étape 1]
2. [Étape 2]
3. [Étape 3]

### Logs
```
[journalctl -u secubox-wall -n 100 --no-pager]
```

### Attendu vs Observé
- **Attendu** : [comportement attendu]
- **Observé** : [comportement observé]
```

### 10.4 Contribution

Le projet SecuBox-Deb est **open source** (licence à définir) :

```bash
# Cloner le repo
git clone https://github.com/CyberMind-FR/secubox-deb.git

# Créer une branche feature
git checkout -b feature/opad-improvement

# Soumettre PR
gh pr create --title "feat(wall): improve DNS-R latency" --body "..."
```

---

## Annexes

### A. Glossaire

| Terme | Définition |
|-------|------------|
| **OPAD** | Out-of-Path Active Defense |
| **Primitive** | Mécanisme d'injection (DNS-R, DHCP-R, RST-I, ARP-R) |
| **DÉPÔT** | Delay between observation and injection |
| **INV-08** | Escalation to in-path mode (invasive) |
| **4R** | Run, Rollback, Revert, Rebuild |
| **SPOF** | Single Point Of Failure |

### B. Codes d'erreur API

| Code | Message | Cause |
|------|---------|-------|
| 200 | OK | Succès |
| 400 | Invalid request | JSON malformé ou champs manquants |
| 404 | Rule not found | ID règle inexistant |
| 409 | Conflict | Règle duplicate ou escalation déjà active |
| 500 | Internal error | Bug ou crash backend |
| 503 | Service unavailable | Service en cours de redémarrage |

### C. Ports réseau

| Port | Protocole | Service | Notes |
|------|-----------|---------|-------|
| 9999 | HTTP | API REST OPAD | Localhost uniquement |
| 9100 | HTTP | Prometheus metrics | Localhost uniquement |
| 53 | UDP/TCP | Observation DNS | Promiscuous mode |
| 67-68 | UDP | Observation DHCP | Promiscuous mode |

---

**FIN DU DOCUMENT**

---

**Changelog**

| Version | Date | Auteur | Changements |
|---------|------|--------|-------------|
| 2.4.0 | 2026-05-12 | G. Kerma | Version initiale OPAD operations guide |

---

**Licence** : [À définir] — CyberMind · https://cybermind.fr
