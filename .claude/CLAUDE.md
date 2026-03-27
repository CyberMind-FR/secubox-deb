# SecuBox-Deb — Project Knowledge for Claude

## Identité du projet

**SecuBox-Deb** est la plateforme de cybersécurité CyberMind basée sur **Debian** (migration depuis OpenWrt).
Cible : certification **ANSSI CSPN**. Infrastructure : MOCHAbin/ESPRESSObin (Marvell Armada 3720, ARM64).

Développeur : Gérald Kerma (Gandalf) — CyberMind, Notre-Dame-du-Cruet, Savoie.

---

## Stack technique

### Base
- **OS** : Debian 12 (Bookworm) ARM64 — pas d'OpenWrt, pas de LuCI
- **Kernel** : 6.x avec modules netfilter, tc, eBPF
- **Transport mesh** : Tailscale (WireGuard-based)
- **Conteneurs** : Docker / Podman sur Debian

### Sécurité active
- **Firewall** : nftables (pas iptables)
- **IDS/IPS** : Suricata + CrowdSec
- **WAF** : HAProxy + mitmproxy
- **DNS** : Unbound (Vortex DNS) + blocklists
- **DPI** : nDPId + netifyd (dual-stream via tc mirred)
- **Auth ZKP** : SecuBox-ZKP (Hamiltonian NP / GK-HAM-2025)
- **P2P mesh** : MirrorNet (did:plc + WireGuard + Chain of Hamiltonians)

### Stack applicatif
- **Backend** : Python 3.11+ (FastAPI / Flask), Bash, C
- **Frontend** : HTML/CSS/JS vanilla ou React — palette cyberpunk/hermétique
- **Config** : YAML + TOML, double-buffer / 4R versioning (PARAMETERS module)
- **Pipeline** : 5-stage production pipeline (collect → process → analyze → report → alert)

---

## Conventions de code

### Python
```python
# Entête standard SecuBox-Deb
"""
SecuBox-Deb :: <NomModule>
CyberMind — https://cybermind.fr
Author: Gérald Kerma <gandalf@gk2.net>
License: Proprietary / ANSSI CSPN candidate
"""
```

### Bash
```bash
#!/usr/bin/env bash
# SecuBox-Deb :: <nom_script>
# CyberMind — Gérald Kerma
set -euo pipefail
readonly MODULE="<nom>"
readonly VERSION="<semver>"
```

### nftables
- Toujours commencer par `flush ruleset`
- Tables : `inet filter`, `inet nat`, `netdev ingress`
- Politique par défaut : DROP (jamais ACCEPT implicite)
- Logging : `log prefix "[SECUBOX-<MODULE>] " level info`

### Double-buffer / 4R (PARAMETERS module)
```
active/    → config live, lecture seule en prod
shadow/    → édition, validation avant swap
rollback/  → 4 snapshots horodatés (R1..R4)
pending/   → version en attente de ZKP validation
```

---

## Architecture des modules

```
secubox-deb/
├── .claude/
│   └── CLAUDE.md              ← ce fichier
├── core/
│   ├── parameters/            ← double-buffer config
│   ├── zkp/                   ← SecuBox-ZKP auth
│   └── mirrornet/             ← P2P mesh
├── modules/
│   ├── firewall/              ← nftables rules
│   ├── dpi/                   ← nDPId + netifyd
│   ├── dns/                   ← Unbound Vortex
│   ├── waf/                   ← HAProxy + mitmproxy
│   ├── ids/                   ← Suricata + CrowdSec
│   └── dashboard/             ← C3BOX UI
├── api/                       ← FastAPI REST
├── scripts/                   ← install, deploy, diag
├── tests/
│   ├── unit/
│   ├── integration/
│   └── cspn/                  ← tests critères ANSSI
└── docs/
    ├── architecture/
    └── cspn/
```

---

## Contraintes ANSSI CSPN

1. **Séparation des privilèges** formelle par couche (L1/L2/L3)
2. **Chiffrement** : TLS 1.3 minimum, pas de TLS 1.0/1.1
3. **Authentification** : ZKP hamiltonien (GK-HAM-2025) — pas de secrets en clair
4. **Logs** : immuables, horodatés RFC 3339, rotation sécurisée
5. **Rollback** : toute modification config → snapshot 4R obligatoire
6. **Surface d'attaque** : minimale — désactiver tout service non utilisé
7. **Tests** : couverture ≥ 80%, tests de régression sur chaque PR

---

## Palette UI (C3BOX / Dashboard)

```css
--cosmos-black: #0a0a0f;
--gold-hermetic: #c9a84c;
--cinnabar: #e63946;
--matrix-green: #00ff41;
--void-purple: #6e40c9;
--cyber-cyan: #00d4ff;
--text-primary: #e8e6d9;
--text-muted: #6b6b7a;
```

Fonts : **Cinzel** (titres), **IM Fell English** (corps hermétique), **JetBrains Mono** (code/terminal)

---

## Commandes fréquentes

```bash
# Status global SecuBox
systemctl status secubox-* --no-pager

# Reload firewall (nftables)
nft -f /etc/secubox/firewall/active/rules.nft

# Swap double-buffer (PARAMETERS)
secubox-params swap --module <nom> --validate-zkp

# Rollback R1
secubox-params rollback --module <nom> --target R1

# DPI status
systemctl status ndpid netifyd

# Logs live (format CSPN)
journalctl -u secubox-* -f --output json | jq '.MESSAGE'

# Tests CSPN
pytest tests/cspn/ -v --tb=short
```

---

## GK-HAM-2025 / Ham-Hash (référence)

Architecture ZKP 3 niveaux (twins asymétriques) :
- **L1** : Auth twins Prover/Verifier — NIZKProof hamiltonien, rotation G 24h PFS
- **L2** : Routing twins double-buffer active/shadow — atomic swap conditionné ZKP, rollback 4R
- **L3** : Endpoint twins service/witness MirrorNet P2P — did:plc, WireGuard, Chain of Hamiltonians → HamCoin

---

## Ce que Claude NE doit PAS faire

- Utiliser `iptables` (remplacé par nftables)
- Utiliser `uci` / LuCI (c'est SecuBox-OpenWrt — abandonné)
- Écrire des secrets en clair dans le code
- Utiliser des politiques firewall ACCEPT par défaut
- Suggérer des bibliothèques Python avec vulns connues
- Ignorer le schéma double-buffer pour les configs
- Mentionner "CrowdSec Ambassador" ou "CyberMind Produits SASU"

---

## Références externes

- ANSSI CSPN : https://www.ssi.gouv.fr/entreprise/certification_cspn/
- nDPId : https://github.com/utoni/nDPId
- CrowdSec : https://docs.crowdsec.net
- Suricata : https://docs.suricata.io
- nftables : https://wiki.nftables.org
