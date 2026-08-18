<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# CLAUDE.md — module `secubox-egress`

> Emplacement cible : `packages/secubox-egress/CLAUDE.md`
> Réf. spec : CM-WALL-EGRESS-2026-06 **v0.1.0-draft** (2026-06-02) · Module : WALL ↔ MIND · Licence : LicenseRef-CMSD-1.0
> Spec complète : [`docs/specs/CM-WALL-EGRESS-2026-06.md`](../../docs/specs/CM-WALL-EGRESS-2026-06.md)
> Compagnon de : [`secubox-mesh`](../secubox-mesh/CLAUDE.md) (CM-MESH-MPCIE-2026-06)

Contexte opérationnel de l'agent pour construire le module **WALL/EGRESS** de SecuBox-Deb
(détection egress + corrélation menaces : exfil, C2, beaconing, evil-twin↔flux). Lis tout avant d'agir.

---

## 0. Contexte agent

Conventions héritées de `secubox-deb` (ne PAS dévier) :

- Plan de contrôle : **FastAPI + Uvicorn**. Jamais de RPCD.
- Config : **TOML** (`tomllib`), lecture seule au runtime.
- Packaging : **`.deb`/`apt`**, `debhelper` (`dh`).
- Pattern **3-broches** : CTL / LXC / BUNDLE.
- Mapping : **WALL↔MIND** (alimenter le dashboard génératif).
- Doctrine **OPAD** : détection passive par défaut, réaction off-path opt-in, journalisée.

---

## 1. Definition of Done

Le module est terminé quand TOUT ce qui suit est vrai :

1. `apt build` produit un `.deb` installable (`secubox-egress_*.deb`), lintian sans blocage.
2. `systemctl status secubox-egress` actif, Uvicorn écoute en local (port dédié).
3. Les 5 endpoints répondent (cf. §5).
4. La config se charge depuis `/etc/secubox/egress.toml` ; secrets hors TOML.
5. **R1 (métadonnées) actif par défaut** ; **R2 (contenu) désactivé** ; `ips_inline = false`.
6. Suricata OU Zeek tourne en mode IDS passif (`engine = suricata|zeek|both`), capture sur span/tap dédié.
7. `unbound` souverain + RPZ chargé ; détection DoH active.
8. Feeds intel (abuse.ch Feodo/ThreatFox, ET Open, Spamhaus DROP/EDROP) téléchargés + intégrés en mémoire.
9. En-têtes `LicenseRef-CMSD-1.0` sur chaque fichier source.

---

## 2. Garde-fous (NON négociables)

### 2.1 Frontière R1/R2 — INTANGIBLE

- **Sur accès ouvert (BYOH, public)** : R1 uniquement (métadonnées : flux, DNS, TLS-méta, IP-intel, NIDS signatures).
- **R2 (TLS-break / inspection de contenu)** : autorisé UNIQUEMENT sur segments **consentis/gérés** (quarantaine, honeypot, endpoints managés, infra de test). Toute activation R2 doit :
  - être déclenchée par appel API authentifié explicite,
  - être journalisée immuablement,
  - cibler un VLAN/segment dont le consentement est tracé (référence CGU/quarantaine).
- **Jamais de TLS-break en silence sur un usager du réseau ouvert.** Le module DOIT refuser d'activer R2 sur le VLAN de l'accès ouvert (validation TOML + runtime).

### 2.2 OPAD

- **Détection passive par défaut** (IDS sur span/tap, pas inline).
- **Réaction off-path, opt-in, journalisée** : RPZ block, drop nftables, quarantaine VLAN, steering.
- **IPS inline** = opt-in explicite, tracé.
- Pas d'auto-quarantaine sur un seul signal — exiger corrélation multi-signaux (§9 point 4 de la spec).

### 2.3 ECH-readiness

ECH (Encrypted ClientHello) chiffre le SNI. Le module NE DOIT PAS bâtir ses détections sur le seul SNI. **Poids principal** sur :

- **L0 flux** (cadence/beaconing)
- **L2 JA4** (empreinte TLS cliente, indépendante du SNI)
- **L3 IP/ASN/cloud-intel**

SNI = `best_effort` dégradé en TOML, jamais critère unique de décision.

### 2.4 Secrets / Intel

- Clés MISP, tokens feeds privés : `misp_url_ref` et `feeds.X.token_ref` = `file://` ou `vault://`, jamais en clair dans le TOML.
- Feeds publics (abuse.ch, ET Open, Spamhaus DROP) : pas de secret, juste URL + hash de pinning optionnel.

### 2.5 Légalité (LCEN)

- Conservation logs R1 conforme à la durée légale.
- Pas d'exfiltration de données R1 vers un tiers sans base légale documentée.
- Documenter dans le `README.md` du package les bases juridiques d'opération.

---

## 3. Arborescence à créer

```
packages/secubox-egress/
├── CLAUDE.md                       # ce fichier
├── pyproject.toml
├── secubox_egress/
│   ├── __init__.py
│   ├── api.py                      # router FastAPI (CTL)
│   ├── models.py                   # schémas pydantic
│   ├── config.py                   # loader TOML + résolution secrets
│   ├── flow.py                     # L0 : conntrack/IPFIX + détection beaconing (RITA-like)
│   ├── dns.py                      # L1 : unbound + RPZ + détection DoH/DGA/tunneling
│   ├── tls_meta.py                 # L2 : JA3/JA4 + issuer cert (+ SNI dégradé sous ECH)
│   ├── intel.py                    # L3 : ingestion feeds (abuse.ch/ET/Spamhaus/MISP)
│   ├── nids.py                     # L4 : Suricata/Zeek control plane
│   ├── correlate.py                # corrélation RDS (radio↔flux), multi-signaux
│   └── react.py                    # OPAD réactions off-path (quarantaine VLAN, drop, RPZ)
├── conf/
│   ├── egress.toml                 # template TOML (BUNDLE)
│   ├── unbound-rpz.conf.j2
│   ├── suricata.yaml.j2
│   └── zeek-local.zeek.j2
├── rules/
│   ├── feodo.rules.example         # placeholder ; vrais feeds téléchargés au runtime
│   └── threatfox.rules.example
├── systemd/
│   └── secubox-egress.service
└── debian/
    ├── control
    ├── rules
    ├── changelog
    ├── compat
    ├── secubox-egress.postinst
    └── secubox-egress.install
```

---

## 4. Schéma TOML (`conf/egress.toml`)

```toml
# /etc/secubox/egress.toml — LicenseRef-CMSD-1.0
schema_version = 1

[wall.regime]
content_inspection = false      # R2 désactivé par défaut (accès ouvert)
ips_inline         = false      # IDS passif par défaut ; inline = opt-in
open_access_vlan   = 100        # VLAN de l'accès ouvert (R2 INTERDIT dessus)

[wall.flow]
ipfix      = true
ipfix_port = 4739
beaconing  = true               # détection de périodicité (RITA-like)
beaconing_min_samples = 32      # nombre min de flux avant scoring

[wall.dns]
resolver   = "unbound"
rpz        = true
rpz_zones  = ["malware.rpz", "phishing.rpz"]
doh_detect = true

[wall.tls]
ja4        = true
sni        = "best_effort"      # dégradé sous ECH (cf. §6 spec)

[wall.intel]
feeds = [
  "abuse.ch/feodo",
  "abuse.ch/threatfox",
  "abuse.ch/sslbl",
  "et-open",
  "spamhaus-drop",
]
refresh_interval_s = 3600
misp_url_ref = "file:///etc/secubox/secrets/misp"   # JAMAIS en clair

[wall.nids]
engine = "suricata"             # suricata | zeek | both
capture_iface = "wlan-bh"       # span/tap du backhaul mesh

[wall.react]
quarantine_vlan = 99            # VLAN de quarantaine (consenti, OK pour R2)
multi_signal_threshold = 2      # nb min de signaux concordants avant auto-quarantaine

[opad]
reactive = false                # passif par défaut
```

---

## 5. Contrat API (FastAPI — `api.py`)

| Méthode | Route | Rôle |
|---|---|---|
| GET | `/wall/flows` | flux actifs + scores anomalie/beaconing |
| GET | `/wall/dns` | requêtes, hits RPZ, suspicions tunneling/DoH |
| GET | `/wall/alerts` | alertes NIDS (Suricata/Zeek) |
| GET | `/wall/intel` | état des feeds, derniers matchs cloud-C2 |
| POST | `/wall/quarantine` | quarantaine client (réaction off-path, journalisée) |

Réponses typées pydantic. Pas d'I/O bloquante dans le handler — `asyncio.to_thread` pour les wrappers `subprocess` / lecteurs IPFIX.

### Stub `api.py`

```python
# packages/secubox-egress/secubox_egress/api.py — LicenseRef-CMSD-1.0
from __future__ import annotations
import asyncio
from fastapi import APIRouter, HTTPException
from .config import load_config
from .models import Flow, DNSEvent, Alert, IntelStatus, QuarantineRequest
from . import flow, dns, nids, intel, react

router = APIRouter(prefix="/wall", tags=["egress"])
_cfg = load_config()  # /etc/secubox/egress.toml

@router.get("/flows", response_model=list[Flow])
async def flows() -> list[Flow]:
    return await asyncio.to_thread(flow.list_flows, _cfg)

@router.get("/dns", response_model=list[DNSEvent])
async def dns_events() -> list[DNSEvent]:
    return await asyncio.to_thread(dns.recent_events, _cfg)

@router.get("/alerts", response_model=list[Alert])
async def alerts() -> list[Alert]:
    return await asyncio.to_thread(nids.list_alerts, _cfg)

@router.get("/intel", response_model=IntelStatus)
async def intel_status() -> IntelStatus:
    return await asyncio.to_thread(intel.status, _cfg)

@router.post("/quarantine")
async def quarantine(req: QuarantineRequest) -> dict:
    # OPAD : action off-path, journalisée.
    # Refuse R2 (TLS-break) sur VLAN de l'accès ouvert.
    if req.regime == "r2" and req.vlan == _cfg.wall.regime.open_access_vlan:
        raise HTTPException(403, "R2 interdit sur le VLAN de l'accès ouvert")
    return await asyncio.to_thread(react.quarantine, req, _cfg)
```

### Stub `correlate.py` (corrélation RDS multi-signaux)

```python
# secubox_egress/correlate.py — LicenseRef-CMSD-1.0
"""
Corrélation RDS : un signal n'est PAS suffisant.
Exige multi_signal_threshold signaux concordants pour escalader vers
quarantaine. Pondère par fraîcheur de l'intel et par confiance source.
"""
from __future__ import annotations
import logging
from .models import Signal, Verdict

log = logging.getLogger("secubox.egress.correlate")

def correlate(signals: list[Signal], cfg) -> Verdict:
    """
    Inputs typés :
      - radio : evil-twin détecté par guardian-radio (CM-MESH §4bis)
      - flow  : beaconing périodique
      - dns   : RPZ hit ou suspicion DoH/tunneling
      - intel : match cloud-C2 (ASN/IP/JA4)
    """
    fresh = [s for s in signals if s.is_fresh()]
    if len(fresh) < cfg.wall.react.multi_signal_threshold:
        return Verdict(action="observe", reason="single-signal, OPAD passif")
    log.info("Multi-signal verdict: %d signaux concordants", len(fresh))
    return Verdict(
        action="quarantine",
        reason=f"corrélation {[s.kind for s in fresh]}",
        signals=fresh,
    )
```

---

## 6. NIDS — Suricata / Zeek

### Suricata 7.x

- Mode IDS passif (`af-packet` sur l'interface de capture, pas `nfq`).
- Règles : ET Open Ruleset + custom rules ingérées depuis `wall.intel.feeds`.
- `eve.json` consommé par `nids.py` pour exposer `/wall/alerts`.
- JA4 activé via `tls.fingerprint.ja4` (Suricata 7.0+).

### Zeek (alternative)

- Logs `conn.log` / `dns.log` / `ssl.log` / `notice.log` consommés.
- Intel framework chargé avec les feeds.
- Plus de flexibilité scripting, charge CPU souvent meilleure que Suricata sur ARM64.

Le choix se fait via `wall.nids.engine = suricata | zeek | both`. Les deux peuvent tourner en parallèle si la charge le permet (Armada 7040 quad-A72 — point ouvert §9 spec).

---

## 7. Packaging `.deb`

### `debian/control`

```
Source: secubox-egress
Section: net
Priority: optional
Maintainer: Gérald Kerma <root@cybermind.fr>
Build-Depends: debhelper-compat (= 13), dh-python, python3-all
Standards-Version: 4.6.2

Package: secubox-egress
Architecture: arm64
Depends: ${python3:Depends}, ${misc:Depends},
 python3-fastapi, python3-uvicorn, python3-jinja2,
 python3-aiohttp, python3-yaml,
 suricata, zeek, unbound, conntrack, nftables,
 nfdump, goflow2 | nfacctd
Recommends: misp-modules, python3-pymisp
Description: SecuBox-Deb EGRESS module — flow/DNS/TLS-meta/NIDS detection + RDS correlation (OPAD)
EOF
```

### `debian/secubox-egress.postinst`

```bash
#!/bin/sh
set -e
case "$1" in
  configure)
    install -d -m 0700 /etc/secubox/secrets
    install -d -m 0755 /var/lib/secubox/egress/intel
    install -d -m 0755 /var/lib/secubox/egress/rpz
    deb-systemd-helper enable secubox-egress.service >/dev/null || true
    deb-systemd-invoke start secubox-egress.service  >/dev/null || true
    ;;
esac
#DEBHELPER#
```

### `systemd/secubox-egress.service`

```ini
[Unit]
Description=SecuBox-Deb EGRESS control plane (flow + DNS + NIDS + intel)
After=network.target suricata.service unbound.service
Wants=suricata.service unbound.service

[Service]
ExecStart=/usr/bin/uvicorn secubox_egress.app:app --host 127.0.0.1 --port 8745
Restart=on-failure
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=/run /var/lib/secubox/egress /etc/secubox

[Install]
WantedBy=multi-user.target
```

---

## 8. Ordre des tâches

1. Échafauder l'arborescence (§3) + `pyproject.toml` + licences.
2. `models.py` (Flow, DNSEvent, Alert, Intel, Signal, Verdict, QuarantineRequest) + `config.py` (loader TOML + résolution secrets).
3. `intel.py` (ingestion feeds, refresh background, cache local sous `/var/lib/secubox/egress/intel/`).
4. `dns.py` (unbound + RPZ + DoH detection via known-resolver IP list).
5. `flow.py` (NetFlow/IPFIX collector via goflow2 ou nfacctd, scoring beaconing RITA-like).
6. `tls_meta.py` (JA3/JA4 depuis Suricata `eve.json`).
7. `nids.py` (control plane Suricata/Zeek, parse `eve.json` / Zeek logs).
8. `correlate.py` (corrélation multi-signaux + verdict OPAD).
9. `react.py` (quarantaine VLAN via nftables, RPZ block, drop targeted).
10. `api.py` (5 endpoints, `to_thread`, validation R2-not-on-open-access).
11. `debian/` + unit ; build `.deb` ; lintian.
12. Tests DoD §1 sur banc Maurienne.

---

## 9. Tests d'acceptation (bench Maurienne)

- **Beaconing** : générer un flux périodique vers une IP de test, vérifier détection après ≥ `beaconing_min_samples` flux.
- **DoH detection** : forcer un client à `1.1.1.1:443` via DoH, vérifier alerte `wall.dns.doh_detect`.
- **DNS tunneling** : pousser des requêtes à entropie élevée vers un domaine test, vérifier alerte.
- **Intel match** : injecter une IP du feed Feodo dans le flux, vérifier hit + alerte.
- **Corrélation RDS** : simuler un evil-twin (signal radio) + un client beacon (signal flow) → vérifier `correlate.correlate()` renvoie `action=quarantine`.
- **R2 refus** : POST `/wall/quarantine` avec `regime=r2, vlan=open_access_vlan` → 403.
- **ECH** : simuler un client ECH (SNI chiffré), vérifier que la détection bascule sur JA4 + IP-intel sans s'effondrer.

---

## 10. Hors périmètre (NE PAS faire)

- **TLS-break sur l'accès ouvert** (R2 réservé aux segments consentis).
- App cliente (séparée).
- Couche L3 MirrorNet / `did:plc` / HamCoin (consommateur en aval, pas dans ce module).
- Détection bâtie sur le SNI seul (ECH le casse — §6 spec).
- Quarantaine sur signal unique (corrélation multi-signaux requise).
- Stocker les payloads R1 en clair (métadonnées uniquement, conformément LCEN).

---

## 11. Points ouverts (à instrumenter avant gel CSPN)

Repris du §9 de la spec :

1. **ECH** — calibrer la bascule SNI→JA4/IP/cadence ; mesurer le taux de couverture résiduel.
2. **Charge sur Armada 7040** — dimensionner le débit inspectable.
3. **Fraîcheur intel** — cadence de refresh vs partitions mesh (nœuds isolés).
4. **Faux positifs cloud-intel** — exiger corrélation multi-signaux (déjà câblé dans `correlate.py`).
5. **Périmètre R2** — définir précisément les segments consentis avant toute activation.

---

*CyberMind — Gérald Kerma. Document interne, FR faisant foi. LicenseRef-CMSD-1.0.*
