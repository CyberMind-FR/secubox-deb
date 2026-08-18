<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# OPAD — Off-Path Active Defense

**Doctrine WALL SecuBox v2.4.0**

---

## Métadonnées

| Champ | Valeur |
|-------|--------|
| **Référence** | CM-WALL-OPAD-2026-05 |
| **Version** | 2.4.0 |
| **Status** | Canonique |
| **Date** | 2026-05-12 |
| **Auteur** | Gérald Kerma (CyberMind) |
| **Portée** | Module WALL (SecuBox-Deb) |
| **Révision précédente** | D-2025-IDGP-INLINE (déprécié) |

---

## 1. Identité

### 1.1 Définition

**OPAD** (Off-Path Active Defense) est la doctrine architecturale du module **WALL** de SecuBox-Deb v2.4.0+. Elle définit un mode de protection réseau où la SecuBox observe le trafic en **position off-path** (hors du chemin de données) et injecte des réponses de disruption ciblée lorsque nécessaire, **sans jamais être un point de passage obligatoire**.

### 1.2 Doctrine en une ligne

> **"La SecuBox n'est pas dans le chemin. Elle est à côté du chemin, et elle gagne des courses. Quand elle est là, elle protège par disruption ciblée. Quand elle n'est pas là, le réseau ne le remarque pas."**

### 1.3 Périmètre

- **Module concerné** : WALL (protection réseau active)
- **Composants** : DNS-R, DHCP-R, RST-I, ARP-R
- **Cible** : Certification ANSSI CSPN (critère "fail-silent")
- **Contrainte** : Zéro rupture possible du flux utilisateur

---

## 2. Contexte et motivation

### 2.1 Problème avec la doctrine in-path (IDGP)

La doctrine précédente **D-2025-IDGP-INLINE** (In-line Data Guardian Protocol) plaçait la SecuBox en **bridge transparent** dans le chemin de données :

**Limites identifiées :**

| Problème | Impact |
|----------|--------|
| **Single Point of Failure** | Panne matérielle = coupure réseau totale |
| **Latency ajoutée** | Analyse en ligne → délai minimum 2-5ms par paquet |
| **Surface d'attaque** | SecuBox devient cible prioritaire (DoS, exploitation kernel) |
| **Complexité opérationnelle** | Maintenance = fenêtre de downtime obligatoire |
| **Scalabilité** | Goulot d'étranglement à 1 Gbps+ |

### 2.2 Solution OPAD : observation off-path + injection active

**Principe :** La SecuBox écoute le trafic en **mode observation** (port mirror, TAP, span) et injecte des réponses **plus rapides** que les réponses légitimes lorsqu'une menace est détectée.

**Topologie :**

```
                    ┌──────────────┐
                    │   Internet   │
                    └──────┬───────┘
                           │
                    ┌──────▼───────┐
                    │   Routeur    │
                    │   (Opérateur)│
                    └──────┬───────┘
                           │
           ┌───────────────┼───────────────┐
           │               │               │
    ┏━━━━━▼━━━━━┓   ┌─────▼─────┐   ┌───▼────┐
    ┃ SecuBox   ┃   │  Switch   │   │ Clients│
    ┃ (OPAD)    ┃◄──┤  (SPAN)   │   │  LAN   │
    ┃ OFF-PATH  ┃   └───────────┘   └────────┘
    ┗━━━━━┬━━━━━┛
          │
          └─► Injection (DNS-R, DHCP-R, RST-I, ARP-R)

Legend:
  ━━━ : Off-path observation + injection
  ─── : Data path (aucun forwarding SecuBox)
```

**Avantages :**

- ✅ **Retrait transparent** : débrancher la SecuBox = aucun impact
- ✅ **Zéro latency** : pas dans le chemin de données
- ✅ **Surface d'attaque minimale** : pas de forwarding = pas de DoS possible
- ✅ **Scalabilité** : observation passive peut suivre 10 Gbps+
- ✅ **Maintenance sans downtime** : mises à jour sans coupure réseau

---

## 3. Principes fondamentaux

### PROP-P1 : Observer plus, agir moins

**Énoncé :**
_La SecuBox maximise l'observation passive (logs, stats, détection) et minimise l'injection active (disruption). L'injection est réservée aux menaces confirmées de haute criticité._

**Implication :**
- Logs exhaustifs (DÉPÔT) avant injection
- Seuils configurables par primitif (target_success_rate)
- Mode **dry-run** disponible pour audit

---

### PROP-P2 : Zéro rupture possible

**Énoncé :**
_Aucune configuration OPAD ne peut provoquer une coupure réseau totale. Le retrait physique de la SecuBox doit être sans effet sur la connectivité des clients._

**Implication :**
- Pas de forwarding IPv4/IPv6 (INV-02)
- Pas de rôle de gateway
- Pas de modification de la table ARP statique des clients

---

### PROP-P3 : Surface d'attaque minimale

**Énoncé :**
_La SecuBox en mode OPAD n'expose aucun service directement attaquable depuis le LAN ou le WAN. Elle est invisible au scan réseau._

**Implication :**
- Aucune réponse ICMP echo (INV-05)
- Aucune écoute TCP/UDP sur IP LAN (sauf management SSH sur VLAN admin)
- Aucune surface WAN (INV-06)

---

### PROP-P4 : Escalade explicite et révocable

**Énoncé :**
_Si OPAD est insuffisant (ex: TLS C2), la SecuBox peut passer en mode escaladé (DHCP force-gateway) pour activer l'interception. Ce mode est explicite, journalisé, et révocable sans redémarrage._

**Implication :**
- Mode **opad-with-escalation** disponible
- Rollback 4R obligatoire avant escalade
- Event OPAD_ESCALATE → journal audit (CSPN)

---

## 4. Invariants OPAD

### Table des invariants

| ID | Invariant | Description | Conséquence |
|----|-----------|-------------|-------------|
| **INV-01** | **Retrait sans rupture** | Débrancher physiquement la SecuBox ne provoque aucune coupure réseau | Architecture off-path obligatoire |
| **INV-02** | **Aucun forwarding** | La SecuBox ne forward jamais le trafic utilisateur (pas de rôle bridge/router) | Pas de `/proc/sys/net/ipv4/ip_forward=1` |
| **INV-03** | **Journalisation systématique** | Toute injection active génère un event **ALERTE·DÉPÔT** avant l'injection | Traçabilité CSPN complète |
| **INV-04** | **Marquage des échecs** | Les injections perdues (race échouée) sont loguées avec code **OPAD_INJECT_LOST** | Métrique de taux de succès |
| **INV-05** | **Silence LAN** | La SecuBox ne répond jamais à ICMP echo, ARP who-has (sauf injection ARP-R), scan TCP | Invisibilité réseau |
| **INV-06** | **Surface WAN nulle** | Aucun port ouvert sur IP WAN (même pas SSH) | Attaque WAN impossible |
| **INV-07** | **Fail-silent** | En cas de crash du daemon WALL, le réseau continue sans protection (pas de fail-closed) | Disponibilité > sécurité |
| **INV-08** | **Escalade révocable** | Tout mode escaladé (in-path) doit pouvoir revenir en OPAD sans redémarrage | Commande `opad revert` disponible |

---

## 5. Primitifs d'injection

### 5.1 DNS-R (DNS Race)

#### 5.1.1 Mécanisme

La SecuBox écoute les requêtes DNS (port 53 UDP) en mode promiscuous. Lorsqu'une requête correspond à une règle de blocage (malware domain, C2, phishing), elle injecte une **réponse DNS falsifiée** avec un TTL court, avant que le resolver légitime ne réponde.

**Condition de succès :** Réponse OPAD arrive avant la réponse du resolver légitime (typiquement < 10ms).

#### 5.1.2 Paramètres

| Paramètre | Type | Valeur par défaut | Description |
|-----------|------|-------------------|-------------|
| `enabled` | bool | `true` | Activer DNS-R |
| `target_success_rate` | float | `0.99` | Taux de race gagnée visé (99%) |
| `modes` | list | `["nxdomain", "sinkhole"]` | Modes de réponse |
| `sinkhole_ip` | IPv4 | `10.254.254.254` | IP de sinkhole (si mode sinkhole) |
| `ttl` | int | `60` | TTL de la réponse injectée (secondes) |
| `blocklists` | list | `["crowdsec", "abuse.ch"]` | Sources de domaines malveillants |
| `dry_run` | bool | `false` | Log uniquement, pas d'injection |

#### 5.1.3 Modes de réponse

- **nxdomain** : RCODE=3 (domain does not exist)
- **sinkhole** : IP de sinkhole (captive portal ou honeypot)
- **redirect_captive** : Redirection vers page d'avertissement SecuBox

#### 5.1.4 Journalisation

```json
{
  "event": "OPAD_DNS_RACE",
  "timestamp": "2026-05-12T14:32:01.234Z",
  "src_ip": "192.168.1.42",
  "query": "evil-c2.example.com",
  "qtype": "A",
  "action": "sinkhole",
  "sinkhole_ip": "10.254.254.254",
  "result": "success",
  "race_time_ms": 4.2
}
```

---

### 5.2 DHCP-R (DHCP Race)

#### 5.2.1 Mécanisme

La SecuBox écoute les DHCPDISCOVER (broadcast) et injecte un **DHCPOFFER falsifié** avant le serveur DHCP légitime. L'offre OPAD peut :
- **Quarantaine** : proposer une IP isolée (VLAN quarantaine)
- **Redirect gateway** : forcer la SecuBox comme gateway (mode escaladé)
- **Deny** : offre avec bail expiré immédiatement (DoS ciblé)

#### 5.2.2 Paramètres

| Paramètre | Type | Valeur par défaut | Description |
|-----------|------|-------------------|-------------|
| `enabled` | bool | `false` | Activer DHCP-R (désactivé par défaut) |
| `target_success_rate` | float | `0.95` | Taux de race gagnée visé |
| `quarantine_pool` | CIDR | `192.168.99.0/24` | Pool d'IP quarantaine |
| `lease_time_s` | int | `300` | Durée du bail forcé (5 min) |
| `escalate_to_gateway` | bool | `false` | Forcer SecuBox comme gateway (escalade) |

#### 5.2.3 Journalisation

```json
{
  "event": "OPAD_DHCP_RACE",
  "timestamp": "2026-05-12T14:35:22.123Z",
  "src_mac": "aa:bb:cc:dd:ee:ff",
  "hostname": "suspect-device",
  "action": "quarantine",
  "offered_ip": "192.168.99.42",
  "result": "success",
  "race_time_ms": 8.1
}
```

---

### 5.3 RST-I (TCP RST Injection)

#### 5.3.1 Mécanisme

La SecuBox analyse les flux TCP établis (via observation de SYN/SYN-ACK) et injecte des **segments RST** avec SEQ/ACK corrects pour terminer immédiatement une connexion identifiée comme malveillante (C2, exfiltration, malware callback).

**Timing critique :** RST doit arriver avant le prochain segment légitime (fenêtre typique : 50-200ms).

#### 5.3.2 Paramètres

| Paramètre | Type | Valeur par défaut | Description |
|-----------|------|-------------------|-------------|
| `enabled` | bool | `true` | Activer RST-I |
| `target_success_rate` | float | `0.90` | Taux de disruption réussie |
| `double_ended` | bool | `true` | Envoyer RST aux deux endpoints (client+serveur) |
| `timing_window_ms` | int | `100` | Fenêtre d'injection (ms) |
| `trigger_sources` | list | `["crowdsec", "suricata"]` | Sources de détection malveillante |

#### 5.3.3 Journalisation

```json
{
  "event": "OPAD_RST_INJECT",
  "timestamp": "2026-05-12T14:40:11.456Z",
  "src_ip": "192.168.1.42",
  "dst_ip": "1.2.3.4",
  "dst_port": 443,
  "reason": "crowdsec_c2_detected",
  "double_ended": true,
  "result": "success"
}
```

---

### 5.4 ARP-R (ARP Redirect)

#### 5.4.1 Mécanisme

La SecuBox injecte des **réponses ARP falsifiées** (gratuitous ARP ou réponse à ARP who-has) pour rediriger le trafic d'un client suspect vers un captive portal ou un honeypot, sans modifier la configuration du client.

**Usage typique :** Quarantaine soft d'un device compromis détecté par NAC/AUTH.

#### 5.4.2 Paramètres

| Paramètre | Type | Valeur par défaut | Description |
|-----------|------|-------------------|-------------|
| `enabled` | bool | `false` | Activer ARP-R (désactivé par défaut) |
| `target_success_rate` | float | `0.98` | Taux de race gagnée |
| `refresh_interval_s` | int | `60` | Intervalle de rafraîchissement (gratuitous ARP) |
| `captive_mac` | MAC | `auto` | MAC du captive portal (auto = MAC SecuBox) |
| `target_gateway` | bool | `true` | Rediriger les requêtes vers gateway |

#### 5.4.3 Journalisation

```json
{
  "event": "OPAD_ARP_REDIRECT",
  "timestamp": "2026-05-12T14:45:33.789Z",
  "target_ip": "192.168.1.42",
  "target_mac": "aa:bb:cc:dd:ee:ff",
  "spoofed_ip": "192.168.1.1",
  "captive_mac": "00:11:22:33:44:55",
  "result": "success"
}
```

---

## 6. Modes opératoires

### 6.1 Mode **opad-only** (défaut canonique)

**Description :** SecuBox en observation pure + injection active (DNS-R, RST-I). Aucun forwarding, aucun rôle de gateway.

**Configuration :**

```toml
[wall.opad]
mode = "opad-only"
primitives = ["dns-r", "rst-i"]

[wall.opad.dns-r]
enabled = true
target_success_rate = 0.99

[wall.opad.rst-i]
enabled = true
target_success_rate = 0.90
```

**Propriétés :**
- ✅ INV-01 à INV-07 respectés
- ✅ Zéro latency
- ✅ Retrait transparent

---

### 6.2 Mode **opad-with-escalation**

**Description :** OPAD par défaut, avec possibilité d'activer ponctuellement DHCP-R ou ARP-R pour forcer la SecuBox comme gateway (interception TLS).

**Configuration :**

```toml
[wall.opad]
mode = "opad-with-escalation"
escalation_trigger = "manual"  # ou "auto" (si AUTH détecte menace critique)

[wall.opad.dhcp-r]
enabled = false  # activé à la demande
escalate_to_gateway = true

[wall.opad.arp-r]
enabled = false
```

**Workflow d'escalade :**

1. Détection menace critique (ex: TLS C2 non blockable par DNS-R)
2. Event `OPAD_ESCALATE_REQUEST` → journal audit
3. Snapshot 4R de la config active
4. Activation DHCP-R avec `escalate_to_gateway=true`
5. Nouveau DHCP lease force gateway → SecuBox devient in-path
6. Après résolution : `opad revert` → rollback 4R → retour opad-only

**Propriétés :**
- ✅ INV-08 respecté (escalade révocable)
- ⚠️ INV-01 temporairement violé (mode in-path)
- ✅ Traçabilité CSPN complète (logs escalade/revert)

---

### 6.3 Mode **legacy-in-path** (déprécié)

**Description :** Mode bridge transparent (D-2025-IDGP-INLINE). Conservé pour compatibilité, mais non recommandé.

**Status :** Déprécié depuis v2.4.0. Sera supprimé en v3.0.0.

**Migration :** Utiliser `opad-with-escalation` pour cas nécessitant interception.

---

## 7. Profil de configuration 3-broche

### 7.1 Structure

La configuration OPAD suit le modèle **3-broche** (3-prong) :

```
/etc/secubox/wall/
├── active/
│   ├── observation.toml      ← Broche 1: Observation
│   ├── injection.toml         ← Broche 2: Injection
│   └── policy.toml            ← Broche 3: Politique
├── shadow/
│   ├── observation.toml
│   ├── injection.toml
│   └── policy.toml
└── rollback/
    ├── R1/ (timestamp: 2026-05-12T14:00:00Z)
    ├── R2/ (timestamp: 2026-05-12T13:00:00Z)
    ├── R3/ (timestamp: 2026-05-12T12:00:00Z)
    └── R4/ (timestamp: 2026-05-12T11:00:00Z)
```

### 7.2 Broche 1 : Observation

**Responsabilité :** Définir les sources d'observation (interfaces, SPAN ports, TAP).

**Exemple :**

```toml
[observation]
interfaces = ["eth1", "eth2"]  # Interfaces LAN à observer
mode = "promiscuous"
bpf_filter = "not port 22"  # Exclure SSH management

[observation.span]
enabled = true
span_port = "eth0"  # Port SPAN du switch
vlan_strip = true
```

### 7.3 Broche 2 : Injection

**Responsabilité :** Définir les primitifs d'injection actifs et leurs paramètres.

**Exemple :**

```toml
[injection.dns-r]
enabled = true
target_success_rate = 0.99
modes = ["nxdomain", "sinkhole"]
sinkhole_ip = "10.254.254.254"

[injection.rst-i]
enabled = true
target_success_rate = 0.90
double_ended = true

[injection.dhcp-r]
enabled = false

[injection.arp-r]
enabled = false
```

### 7.4 Broche 3 : Politique

**Responsabilité :** Définir les règles de décision (quand injecter).

**Exemple :**

```toml
[policy]
mode = "opad-only"
escalation_trigger = "manual"

[policy.triggers]
# DNS-R : bloquer domaines malveillants
dns_blocklists = ["crowdsec", "abuse.ch", "phishing-army"]
dns_custom_block = ["evil.example.com", "*.malware.net"]

# RST-I : terminer connexions C2
rst_on_crowdsec_alert = true
rst_on_suricata_alert = true
rst_confidence_threshold = 0.85

# DHCP-R : quarantaine MAC suspects
dhcp_quarantine_sources = ["auth-guardian"]

# ARP-R : rediriger devices compromis
arp_redirect_sources = ["nac"]
```

---

## 8. Intégration avec les modules

### 8.1 Table d'intégration

| Module | Rôle OPAD | Event envoyé vers WALL | Event reçu depuis WALL |
|--------|-----------|------------------------|------------------------|
| **AUTH** | Fournisseur de décision (ban user → RST-I) | `AUTH_BAN_USER` | `OPAD_RST_SUCCESS` |
| **WALL** | Exécuteur OPAD (injection) | — | — |
| **BOOT** | Configuration réseau (SPAN setup) | — | `OPAD_INIT_STATUS` |
| **MIND** | Analyse comportement → détection anomalies | `MIND_ANOMALY_DETECTED` | `OPAD_INJECT_STATS` |
| **ROOT** | Journalisation audit CSPN | — | `OPAD_*` (tous events) |
| **MESH** | Sync blacklists entre SecuBox (MirrorNet) | `MESH_BLOCKLIST_UPDATE` | — |

### 8.2 Flux d'événements

```
┌─────────┐      MIND_ANOMALY_DETECTED      ┌──────────┐
│  MIND   │─────────────────────────────────►│  WALL    │
└─────────┘                                  │ (OPAD)   │
                                             └────┬─────┘
┌─────────┐      AUTH_BAN_USER                    │
│  AUTH   │─────────────────────────────────►────┤
└─────────┘                                       │
                                                  │
                                         Décision interne
                                         (policy.toml)
                                                  │
                                                  ▼
                                         ┌────────────────┐
                                         │  Injection     │
                                         │  (DNS-R/RST-I) │
                                         └────────┬───────┘
                                                  │
                     ┌────────────────────────────┼────────────────┐
                     │                            │                │
                     ▼                            ▼                ▼
              ┌──────────┐               ┌──────────┐      ┌──────────┐
              │   ROOT   │               │  MIND    │      │   AUTH   │
              │ (Audit)  │               │ (Stats)  │      │(Feedback)│
              └──────────┘               └──────────┘      └──────────┘
                OPAD_*                OPAD_INJECT_STATS   OPAD_RST_SUCCESS
```

---

## 9. Journalisation et audit

### 9.1 Types d'événements

| Event | Criticité | Description |
|-------|-----------|-------------|
| `OPAD_INIT` | INFO | Démarrage module OPAD |
| `OPAD_DNS_RACE` | ALERTE | Injection DNS-R |
| `OPAD_DHCP_RACE` | ALERTE | Injection DHCP-R |
| `OPAD_RST_INJECT` | ALERTE | Injection RST-I |
| `OPAD_ARP_REDIRECT` | ALERTE | Injection ARP-R |
| `OPAD_INJECT_LOST` | WARN | Race perdue (injection échouée) |
| `OPAD_ESCALATE` | CRITICAL | Passage en mode escaladé (in-path) |
| `OPAD_REVERT` | INFO | Retour mode opad-only |
| `OPAD_CONFIG_SWAP` | INFO | Swap active/shadow |
| `OPAD_ROLLBACK` | WARN | Rollback 4R activé |

### 9.2 Format de log

**Standard :** JSON structuré, un event par ligne, conforme CSPN.

**Exemple :**

```json
{
  "timestamp": "2026-05-12T14:32:01.234Z",
  "module": "wall",
  "component": "opad",
  "event": "OPAD_DNS_RACE",
  "severity": "alert",
  "src_ip": "192.168.1.42",
  "src_mac": "aa:bb:cc:dd:ee:ff",
  "query": "evil-c2.example.com",
  "qtype": "A",
  "action": "sinkhole",
  "sinkhole_ip": "10.254.254.254",
  "result": "success",
  "race_time_ms": 4.2,
  "trigger_source": "crowdsec",
  "session_id": "opad-20260512-143201-abc123"
}
```

**Destination :** `/var/log/secubox/wall/opad.log` (rotation journalière, retention 90j).

---

## 10. Périmètre déclaré

### 10.1 Couvert (◉)

| Menace | Primitif | Efficacité |
|--------|----------|------------|
| Malware DNS (C2, phishing) | DNS-R | 99% |
| Connexion TCP malveillante (C2, exfiltration) | RST-I | 90% |
| Device compromis (quarantaine) | DHCP-R / ARP-R | 95% |
| Blocklists dynamiques (CrowdSec, Suricata) | DNS-R + RST-I | 98% |

### 10.2 Partiel (◐)

| Menace | Limitation | Solution alternative |
|--------|-----------|----------------------|
| TLS C2 (SNI chiffré) | DNS-R inefficace si IP hardcodée | Mode escaladé + TLS interception |
| HTTP/3 QUIC | RST-I incompatible (UDP) | Blocage nftables en amont |
| P2P mesh (Tor, I2P) | Pas de DNS resolution | DPI + RST-I sur détection protocole |

### 10.3 Hors portée (✕)

| Menace | Raison | Module responsable |
|--------|--------|-------------------|
| TLS interception (MITM) | Nécessite in-path | Mode escaladé (hors OPAD canonique) |
| Hard drop (blocage nftables) | Pas d'injection, juste drop | WALL nftables |
| VLAN isolation | Configuration switch | BOOT netplan |
| QoS / rate-limiting | Nécessite in-path | QOS module (à venir) |
| Protection WAN (DDoS) | Pas de surface WAN | Upstream (opérateur) |

---

## 11. Historique doctrinal

### 11.1 Version actuelle

**CM-WALL-OPAD-2026-05** (v2.4.0)
- Status : Canonique
- Date : 2026-05-12
- Auteur : Gérald Kerma

### 11.2 Versions dépréciées

| Référence | Nom | Date | Raison dépréciation |
|-----------|-----|------|---------------------|
| D-2025-IDGP-INLINE | In-line Data Guardian Protocol | 2025-03-15 | Single point of failure, latency |
| D-2024-BRIDGE-TRANSPARENT | Bridge transparent nftables | 2024-06-10 | Complexité opérationnelle, fail-closed |

### 11.3 Migration depuis D-2025-IDGP-INLINE

**Checklist :**

1. ✅ Désactiver `ip_forward` et bridge nftables
2. ✅ Configurer SPAN port ou TAP sur switch
3. ✅ Créer profil 3-broche (observation + injection + policy)
4. ✅ Activer DNS-R et RST-I
5. ✅ Tester retrait physique SecuBox → pas de coupure réseau
6. ✅ Auditer logs → vérifier INV-03 (ALERTE·DÉPÔT avant injection)

---

## 12. Références

### 12.1 Spécifications techniques

- **SPEC-WALL-OPAD-2026-05.md** : Spécification complète du module WALL OPAD
- **SCHEMA-OPAD-CONFIG.json** : Schéma JSON de validation des fichiers TOML
- **MODELS-OPAD-EVENTS.json** : Modèles d'événements (pour parsing logs)

### 12.2 Documentation complémentaire

- **CSPN-MATRIX-WALL.md** : Mapping critères ANSSI CSPN ↔ invariants OPAD
- **OPS-GUIDE-OPAD.md** : Guide opérationnel (installation, monitoring, troubleshooting)
- **TEST-SUITE-OPAD.md** : Suite de tests de validation (pytest + scapy)

### 12.3 Code source

- **`packages/secubox-wall/api/opad/`** : Implémentation Python (FastAPI)
- **`packages/secubox-wall/daemon/opad.c`** : Daemon C (injection bas-niveau)
- **`packages/secubox-wall/scripts/opad-cli.sh`** : CLI d'administration

---

## Signature

**Document canonique validé pour production SecuBox v2.4.0+.**

**Auteur :** Gérald Kerma (CyberMind)
**Date :** 2026-05-12
**Référence :** CM-WALL-OPAD-2026-05
**Version :** 2.4.0
**Status :** Canonique

---

**EOF**
