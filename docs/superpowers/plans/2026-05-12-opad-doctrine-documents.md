<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# OPAD Doctrine Documents Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Create 5 doctrinal documents for OPAD (Off-Path Active Defense) doctrine v2.4.0

**Architecture:** Documentation-first approach. Create JSON Schema and Pydantic models first (for validation), then doctrine documents (OPAD.md, CSPN.matrix.md), and finally operational guide. All documents reference CM-WALL-OPAD-2026-05.

**Tech Stack:** Markdown, JSON Schema draft-07, Python 3.11+ (Pydantic v2), pytest

---

## File Structure

```
secubox-deb/
├── doctrine/
│   └── opad/
│       ├── OPAD.md                 # Task 4: Core doctrine (~1500 lines)
│       ├── CSPN.matrix.md          # Task 5: ANSSI matrix (~800 lines)
│       └── OPAD-OPERATIONS.md      # Task 6: Operations guide (~600 lines)
├── schemas/
│   └── opad-profile.schema.json    # Task 2: JSON Schema (~300 lines)
├── common/
│   └── secubox_core/
│       └── opad/
│           ├── __init__.py         # Task 3: Package init
│           └── models.py           # Task 3: Pydantic models (~250 lines)
└── tests/
    └── test_opad_schema.py         # Task 3: Schema validation tests
```

---

## Task 1: Create Directory Structure

**Files:**
- Create: `doctrine/opad/` (directory)
- Create: `schemas/` (directory)
- Create: `common/secubox_core/opad/` (directory)

- [ ] **Step 1: Create doctrine/opad directory**

```bash
mkdir -p doctrine/opad
```

- [ ] **Step 2: Create schemas directory**

```bash
mkdir -p schemas
```

- [ ] **Step 3: Create common/secubox_core/opad directory**

```bash
mkdir -p common/secubox_core/opad
```

- [ ] **Step 4: Verify directory structure**

```bash
ls -la doctrine/opad schemas common/secubox_core/opad
```

Expected: Three empty directories exist

- [ ] **Step 5: Commit structure**

```bash
git add doctrine schemas common/secubox_core/opad
git commit -m "chore(opad): create directory structure for doctrine documents

Refs: CM-WALL-OPAD-2026-05"
```

---

## Task 2: Create JSON Schema for OPAD Profile

**Files:**
- Create: `schemas/opad-profile.schema.json`

- [ ] **Step 1: Create the JSON Schema file**

Create file `schemas/opad-profile.schema.json`:

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "$id": "https://secubox.in/schemas/opad-profile.schema.json",
  "title": "OPAD Profile",
  "description": "Profil de configuration 3-broche OPAD v2.4.0 (Off-Path Active Defense)",
  "type": "object",
  "required": ["version", "mode", "observation", "injection", "policy"],

  "properties": {
    "version": {
      "type": "string",
      "const": "2.4.0",
      "description": "Version du schéma OPAD"
    },

    "mode": {
      "type": "string",
      "enum": ["opad-only", "opad-with-escalation", "legacy-in-path"],
      "default": "opad-only",
      "description": "Mode opératoire OPAD"
    },

    "observation": {
      "type": "object",
      "description": "Broche 1 : Configuration de l'observation passive",
      "required": ["interfaces"],
      "properties": {
        "interfaces": {
          "type": "array",
          "items": { "type": "string" },
          "minItems": 1,
          "description": "Interfaces réseau en mode promiscuous"
        },
        "bpf_filter": {
          "type": "string",
          "description": "Filtre BPF optionnel pour limiter la capture"
        },
        "protocols": {
          "type": "object",
          "description": "Protocoles à observer",
          "properties": {
            "dns": { "type": "boolean", "default": true },
            "dhcp": { "type": "boolean", "default": true },
            "arp": { "type": "boolean", "default": true },
            "tcp": { "type": "boolean", "default": true }
          },
          "additionalProperties": false
        },
        "fingerprinting": {
          "type": "object",
          "description": "Configuration du fingerprinting passif",
          "properties": {
            "dhcp_fingerprint": { "type": "boolean", "default": true },
            "ja3": { "type": "boolean", "default": true },
            "ja4": { "type": "boolean", "default": true },
            "user_agent": { "type": "boolean", "default": true }
          },
          "additionalProperties": false
        }
      },
      "additionalProperties": false
    },

    "injection": {
      "type": "object",
      "description": "Broche 2 : Configuration des primitifs d'injection",
      "properties": {
        "dns_race": {
          "$ref": "#/definitions/dns_race_config"
        },
        "dhcp_race": {
          "$ref": "#/definitions/dhcp_race_config"
        },
        "rst_inject": {
          "$ref": "#/definitions/rst_inject_config"
        },
        "arp_redirect": {
          "$ref": "#/definitions/arp_redirect_config"
        }
      },
      "additionalProperties": false
    },

    "policy": {
      "type": "object",
      "description": "Broche 3 : Configuration des règles de décision",
      "properties": {
        "default_action": {
          "type": "string",
          "enum": ["allow", "observe", "disrupt"],
          "default": "observe",
          "description": "Action par défaut si aucune règle ne match"
        },
        "rules": {
          "type": "array",
          "items": { "$ref": "#/definitions/policy_rule" },
          "description": "Liste des règles de politique (premier match gagne)"
        },
        "escalation": {
          "$ref": "#/definitions/escalation_config"
        }
      },
      "additionalProperties": false
    }
  },

  "definitions": {
    "dns_race_config": {
      "type": "object",
      "description": "Configuration du primitif DNS Race (DNS-R)",
      "properties": {
        "enabled": {
          "type": "boolean",
          "default": true,
          "description": "Activer le primitif DNS-R"
        },
        "target_success_rate": {
          "type": "number",
          "minimum": 0.9,
          "maximum": 1.0,
          "default": 0.99,
          "description": "Taux de succès cible (≥99% recommandé)"
        },
        "modes": {
          "type": "array",
          "items": {
            "type": "string",
            "enum": ["nxdomain", "sinkhole", "redirect_captive"]
          },
          "default": ["nxdomain", "sinkhole", "redirect_captive"],
          "description": "Modes de réponse DNS disponibles"
        },
        "sinkhole_ip": {
          "type": "string",
          "format": "ipv4",
          "default": "127.0.0.1",
          "description": "IP de sinkhole pour les domaines bloqués"
        },
        "ttl": {
          "type": "integer",
          "minimum": 1,
          "maximum": 86400,
          "default": 300,
          "description": "TTL des réponses DNS injectées (secondes)"
        }
      },
      "additionalProperties": false
    },

    "dhcp_race_config": {
      "type": "object",
      "description": "Configuration du primitif DHCP Race (DHCP-R)",
      "properties": {
        "enabled": {
          "type": "boolean",
          "default": true,
          "description": "Activer le primitif DHCP-R"
        },
        "target_success_rate": {
          "type": "number",
          "minimum": 0.9,
          "maximum": 1.0,
          "default": 0.95,
          "description": "Taux de succès cible (≥95% recommandé)"
        },
        "quarantine_pool": {
          "type": "object",
          "description": "Pool d'adresses IP de quarantaine",
          "properties": {
            "start": {
              "type": "string",
              "format": "ipv4",
              "description": "Première IP du pool"
            },
            "end": {
              "type": "string",
              "format": "ipv4",
              "description": "Dernière IP du pool"
            },
            "lease_time": {
              "type": "integer",
              "minimum": 60,
              "default": 300,
              "description": "Durée du bail DHCP (secondes)"
            },
            "gateway": {
              "type": "string",
              "format": "ipv4",
              "description": "Gateway (captive portal SecuBox)"
            }
          },
          "required": ["start", "end", "gateway"],
          "additionalProperties": false
        }
      },
      "additionalProperties": false
    },

    "rst_inject_config": {
      "type": "object",
      "description": "Configuration du primitif TCP RST Injection (RST-I)",
      "properties": {
        "enabled": {
          "type": "boolean",
          "default": true,
          "description": "Activer le primitif RST-I"
        },
        "target_success_rate": {
          "type": "number",
          "minimum": 0.85,
          "maximum": 1.0,
          "default": 0.90,
          "description": "Taux de succès cible (≥90% recommandé)"
        },
        "double_ended": {
          "type": "boolean",
          "default": true,
          "description": "Envoyer RST vers les deux endpoints"
        },
        "timing_window_ms": {
          "type": "integer",
          "minimum": 1,
          "maximum": 100,
          "default": 10,
          "description": "Fenêtre de timing pour l'injection (ms)"
        }
      },
      "additionalProperties": false
    },

    "arp_redirect_config": {
      "type": "object",
      "description": "Configuration du primitif ARP Redirect (ARP-R)",
      "properties": {
        "enabled": {
          "type": "boolean",
          "default": true,
          "description": "Activer le primitif ARP-R"
        },
        "target_success_rate": {
          "type": "number",
          "minimum": 0.95,
          "maximum": 1.0,
          "default": 0.98,
          "description": "Taux de succès cible (≥98% recommandé)"
        },
        "refresh_interval_s": {
          "type": "integer",
          "minimum": 10,
          "maximum": 300,
          "default": 30,
          "description": "Intervalle de refresh ARP (secondes)"
        },
        "captive_mac": {
          "type": "string",
          "pattern": "^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$",
          "description": "Adresse MAC du captive portal SecuBox"
        }
      },
      "additionalProperties": false
    },

    "policy_rule": {
      "type": "object",
      "description": "Règle de politique OPAD",
      "required": ["id", "match", "action"],
      "properties": {
        "id": {
          "type": "string",
          "minLength": 1,
          "maxLength": 64,
          "description": "Identifiant unique de la règle"
        },
        "priority": {
          "type": "integer",
          "minimum": 0,
          "maximum": 9999,
          "default": 1000,
          "description": "Priorité (0 = plus haute)"
        },
        "match": {
          "type": "object",
          "description": "Critères de correspondance",
          "properties": {
            "source_mac": {
              "type": "string",
              "pattern": "^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$",
              "description": "Adresse MAC source"
            },
            "dest_domain": {
              "type": "string",
              "description": "Domaine destination (supporte wildcards *.example.com)"
            },
            "dest_ip": {
              "type": "string",
              "description": "IP ou CIDR destination"
            },
            "protocol": {
              "type": "string",
              "enum": ["dns", "dhcp", "tcp", "arp"],
              "description": "Protocole concerné"
            },
            "mind_score_above": {
              "type": "number",
              "minimum": 0.0,
              "maximum": 1.0,
              "description": "Seuil de score MIND"
            },
            "device_authorized": {
              "type": "boolean",
              "description": "Device autorisé dans AUTH"
            }
          },
          "additionalProperties": false
        },
        "action": {
          "type": "string",
          "enum": [
            "allow",
            "observe",
            "dns_nxdomain",
            "dns_sinkhole",
            "dns_redirect",
            "dhcp_quarantine",
            "tcp_rst",
            "arp_redirect"
          ],
          "description": "Action à exécuter"
        },
        "log_level": {
          "type": "string",
          "enum": ["none", "info", "alert"],
          "default": "info",
          "description": "Niveau de journalisation"
        }
      },
      "additionalProperties": false
    },

    "escalation_config": {
      "type": "object",
      "description": "Configuration de l'escalade vers mode in-path",
      "properties": {
        "allow_in_path": {
          "type": "boolean",
          "default": false,
          "description": "Autoriser l'escalade vers in-path"
        },
        "require_explicit_consent": {
          "type": "boolean",
          "default": true,
          "description": "Requérir consentement explicite (INV-08)"
        },
        "auto_revert_after_s": {
          "type": "integer",
          "minimum": 60,
          "default": 3600,
          "description": "Retour automatique à OPAD après N secondes"
        },
        "audit_all_escalations": {
          "type": "boolean",
          "default": true,
          "description": "Journaliser toutes les escalades"
        }
      },
      "additionalProperties": false
    }
  },

  "additionalProperties": false
}
```

- [ ] **Step 2: Validate JSON syntax**

```bash
python3 -c "import json; json.load(open('schemas/opad-profile.schema.json'))" && echo "JSON valid"
```

Expected: `JSON valid`

- [ ] **Step 3: Validate as JSON Schema**

```bash
python3 -c "
from jsonschema import Draft7Validator
import json
schema = json.load(open('schemas/opad-profile.schema.json'))
Draft7Validator.check_schema(schema)
print('JSON Schema valid')
"
```

Expected: `JSON Schema valid`

- [ ] **Step 4: Commit JSON Schema**

```bash
git add schemas/opad-profile.schema.json
git commit -m "feat(opad): add JSON Schema for 3-prong profile

JSON Schema draft-07 for OPAD profile configuration:
- Broche 1: Observation (interfaces, protocols, fingerprinting)
- Broche 2: Injection (DNS-R, DHCP-R, RST-I, ARP-R)
- Broche 3: Policy (rules, escalation)

Refs: CM-WALL-OPAD-2026-05"
```

---

## Task 3: Create Pydantic Models

**Files:**
- Create: `common/secubox_core/opad/__init__.py`
- Create: `common/secubox_core/opad/models.py`
- Create: `tests/test_opad_schema.py`

- [ ] **Step 1: Create package __init__.py**

Create file `common/secubox_core/opad/__init__.py`:

```python
"""
SecuBox-Deb :: OPAD (Off-Path Active Defense)
CyberMind — https://cybermind.fr

Modèles et utilitaires pour la doctrine OPAD v2.4.0.
Référence : CM-WALL-OPAD-2026-05
"""

from .models import (
    OPADMode,
    PolicyAction,
    LogLevel,
    Protocol,
    OPADProfile,
    ObservationConfig,
    InjectionConfig,
    PolicyConfig,
    DNSRaceConfig,
    DHCPRaceConfig,
    RSTInjectConfig,
    ARPRedirectConfig,
    PolicyRule,
    OPADEvent,
    OPADInjectResult,
)

__all__ = [
    "OPADMode",
    "PolicyAction",
    "LogLevel",
    "Protocol",
    "OPADProfile",
    "ObservationConfig",
    "InjectionConfig",
    "PolicyConfig",
    "DNSRaceConfig",
    "DHCPRaceConfig",
    "RSTInjectConfig",
    "ARPRedirectConfig",
    "PolicyRule",
    "OPADEvent",
    "OPADInjectResult",
]

__version__ = "2.4.0"
```

- [ ] **Step 2: Create models.py**

Create file `common/secubox_core/opad/models.py`:

```python
"""
SecuBox-Deb :: OPAD Profile Models
CyberMind — https://cybermind.fr
Référence : CM-WALL-OPAD-2026-05

Modèles Pydantic pour le profil de configuration 3-broche OPAD.
Compatibles avec schemas/opad-profile.schema.json
"""

from __future__ import annotations

import re
from enum import Enum
from typing import List, Optional

from pydantic import BaseModel, Field, field_validator


# ============================================================
# ENUMS
# ============================================================


class OPADMode(str, Enum):
    """Mode opératoire OPAD."""

    OPAD_ONLY = "opad-only"
    OPAD_WITH_ESCALATION = "opad-with-escalation"
    LEGACY_IN_PATH = "legacy-in-path"  # Déprécié


class PolicyAction(str, Enum):
    """Actions disponibles dans les règles de politique."""

    ALLOW = "allow"
    OBSERVE = "observe"
    DNS_NXDOMAIN = "dns_nxdomain"
    DNS_SINKHOLE = "dns_sinkhole"
    DNS_REDIRECT = "dns_redirect"
    DHCP_QUARANTINE = "dhcp_quarantine"
    TCP_RST = "tcp_rst"
    ARP_REDIRECT = "arp_redirect"


class DefaultAction(str, Enum):
    """Action par défaut si aucune règle ne match."""

    ALLOW = "allow"
    OBSERVE = "observe"
    DISRUPT = "disrupt"


class LogLevel(str, Enum):
    """Niveau de journalisation."""

    NONE = "none"
    INFO = "info"
    ALERT = "alert"


class Protocol(str, Enum):
    """Protocoles observables/injectables."""

    DNS = "dns"
    DHCP = "dhcp"
    TCP = "tcp"
    ARP = "arp"


# ============================================================
# BROCHE 1 : OBSERVATION
# ============================================================


class ProtocolsConfig(BaseModel):
    """Configuration des protocoles à observer."""

    dns: bool = True
    dhcp: bool = True
    arp: bool = True
    tcp: bool = True

    model_config = {"extra": "forbid"}


class FingerprintingConfig(BaseModel):
    """Configuration du fingerprinting passif."""

    dhcp_fingerprint: bool = True
    ja3: bool = True
    ja4: bool = True
    user_agent: bool = True

    model_config = {"extra": "forbid"}


class ObservationConfig(BaseModel):
    """Broche 1 : Configuration de l'observation passive."""

    interfaces: List[str] = Field(..., min_length=1)
    bpf_filter: Optional[str] = None
    protocols: ProtocolsConfig = Field(default_factory=ProtocolsConfig)
    fingerprinting: FingerprintingConfig = Field(default_factory=FingerprintingConfig)

    model_config = {"extra": "forbid"}


# ============================================================
# BROCHE 2 : INJECTION
# ============================================================


class DNSRaceConfig(BaseModel):
    """Configuration du primitif DNS Race (DNS-R)."""

    enabled: bool = True
    target_success_rate: float = Field(default=0.99, ge=0.9, le=1.0)
    modes: List[str] = Field(
        default=["nxdomain", "sinkhole", "redirect_captive"]
    )
    sinkhole_ip: str = "127.0.0.1"
    ttl: int = Field(default=300, ge=1, le=86400)

    model_config = {"extra": "forbid"}


class QuarantinePool(BaseModel):
    """Pool d'adresses IP de quarantaine DHCP."""

    start: str
    end: str
    lease_time: int = Field(default=300, ge=60)
    gateway: str

    model_config = {"extra": "forbid"}


class DHCPRaceConfig(BaseModel):
    """Configuration du primitif DHCP Race (DHCP-R)."""

    enabled: bool = True
    target_success_rate: float = Field(default=0.95, ge=0.9, le=1.0)
    quarantine_pool: Optional[QuarantinePool] = None

    model_config = {"extra": "forbid"}


class RSTInjectConfig(BaseModel):
    """Configuration du primitif TCP RST Injection (RST-I)."""

    enabled: bool = True
    target_success_rate: float = Field(default=0.90, ge=0.85, le=1.0)
    double_ended: bool = True
    timing_window_ms: int = Field(default=10, ge=1, le=100)

    model_config = {"extra": "forbid"}


class ARPRedirectConfig(BaseModel):
    """Configuration du primitif ARP Redirect (ARP-R)."""

    enabled: bool = True
    target_success_rate: float = Field(default=0.98, ge=0.95, le=1.0)
    refresh_interval_s: int = Field(default=30, ge=10, le=300)
    captive_mac: Optional[str] = None

    model_config = {"extra": "forbid"}

    @field_validator("captive_mac")
    @classmethod
    def validate_mac(cls, v: Optional[str]) -> Optional[str]:
        """Valide le format MAC address."""
        if v is None:
            return v
        pattern = r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$"
        if not re.match(pattern, v):
            raise ValueError("Format MAC invalide (attendu: XX:XX:XX:XX:XX:XX)")
        return v.lower()


class InjectionConfig(BaseModel):
    """Broche 2 : Configuration des primitifs d'injection."""

    dns_race: DNSRaceConfig = Field(default_factory=DNSRaceConfig)
    dhcp_race: DHCPRaceConfig = Field(default_factory=DHCPRaceConfig)
    rst_inject: RSTInjectConfig = Field(default_factory=RSTInjectConfig)
    arp_redirect: ARPRedirectConfig = Field(default_factory=ARPRedirectConfig)

    model_config = {"extra": "forbid"}


# ============================================================
# BROCHE 3 : POLITIQUE
# ============================================================


class RuleMatch(BaseModel):
    """Critères de correspondance pour une règle de politique."""

    source_mac: Optional[str] = None
    dest_domain: Optional[str] = None
    dest_ip: Optional[str] = None
    protocol: Optional[Protocol] = None
    mind_score_above: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    device_authorized: Optional[bool] = None

    model_config = {"extra": "forbid"}

    @field_validator("source_mac")
    @classmethod
    def validate_source_mac(cls, v: Optional[str]) -> Optional[str]:
        """Valide le format MAC address."""
        if v is None:
            return v
        pattern = r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$"
        if not re.match(pattern, v):
            raise ValueError("Format MAC invalide (attendu: XX:XX:XX:XX:XX:XX)")
        return v.lower()


class PolicyRule(BaseModel):
    """Règle de politique OPAD (premier match gagne)."""

    id: str = Field(..., min_length=1, max_length=64)
    priority: int = Field(default=1000, ge=0, le=9999)
    match: RuleMatch
    action: PolicyAction
    log_level: LogLevel = LogLevel.INFO

    model_config = {"extra": "forbid"}


class EscalationConfig(BaseModel):
    """Configuration de l'escalade vers mode in-path."""

    allow_in_path: bool = False
    require_explicit_consent: bool = True
    auto_revert_after_s: int = Field(default=3600, ge=60)
    audit_all_escalations: bool = True

    model_config = {"extra": "forbid"}


class PolicyConfig(BaseModel):
    """Broche 3 : Configuration des règles de décision."""

    default_action: DefaultAction = DefaultAction.OBSERVE
    rules: List[PolicyRule] = Field(default_factory=list)
    escalation: EscalationConfig = Field(default_factory=EscalationConfig)

    model_config = {"extra": "forbid"}


# ============================================================
# PROFIL COMPLET
# ============================================================


class OPADProfile(BaseModel):
    """
    Profil de configuration OPAD complet (3 broches).

    Référence : CM-WALL-OPAD-2026-05
    Version : 2.4.0
    """

    version: str = Field(default="2.4.0")
    mode: OPADMode = OPADMode.OPAD_ONLY
    observation: ObservationConfig
    injection: InjectionConfig = Field(default_factory=InjectionConfig)
    policy: PolicyConfig = Field(default_factory=PolicyConfig)

    model_config = {
        "extra": "forbid",
        "json_schema_extra": {
            "example": {
                "version": "2.4.0",
                "mode": "opad-only",
                "observation": {
                    "interfaces": ["eth0"],
                    "protocols": {
                        "dns": True,
                        "dhcp": True,
                        "arp": True,
                        "tcp": True,
                    },
                },
                "injection": {
                    "dns_race": {"enabled": True, "sinkhole_ip": "10.0.0.1"}
                },
                "policy": {"default_action": "observe", "rules": []},
            }
        },
    }


# ============================================================
# ÉVÉNEMENTS OPAD (pour journalisation ROOT)
# ============================================================


class OPADEvent(BaseModel):
    """Événement OPAD pour journalisation signée ROOT."""

    timestamp: str  # RFC 3339
    event_type: str  # ALERTE_DEPOT, OPAD_INJECT_LOST, etc.
    primitive: Optional[Protocol] = None
    source_mac: Optional[str] = None
    target: Optional[str] = None
    action_taken: Optional[PolicyAction] = None
    success: bool = True
    details: Optional[dict] = None


class OPADInjectResult(BaseModel):
    """Résultat d'une tentative d'injection."""

    primitive: Protocol
    target: str
    race_won: bool
    latency_ms: float
    event_id: str
```

- [ ] **Step 3: Create test file**

Create file `tests/test_opad_schema.py`:

```python
"""
Tests de validation pour le schéma OPAD et les modèles Pydantic.
"""

import json
from pathlib import Path

import pytest
from jsonschema import Draft7Validator, validate
from pydantic import ValidationError

from common.secubox_core.opad import (
    OPADProfile,
    OPADMode,
    ObservationConfig,
    InjectionConfig,
    PolicyConfig,
    PolicyRule,
    RuleMatch,
    PolicyAction,
)


SCHEMA_PATH = Path("schemas/opad-profile.schema.json")


@pytest.fixture
def opad_schema():
    """Charge le schéma JSON."""
    with open(SCHEMA_PATH) as f:
        return json.load(f)


@pytest.fixture
def minimal_profile():
    """Profil OPAD minimal valide."""
    return {
        "version": "2.4.0",
        "mode": "opad-only",
        "observation": {
            "interfaces": ["eth0"]
        },
        "injection": {},
        "policy": {}
    }


@pytest.fixture
def full_profile():
    """Profil OPAD complet."""
    return {
        "version": "2.4.0",
        "mode": "opad-only",
        "observation": {
            "interfaces": ["eth0", "eth1"],
            "bpf_filter": "port 53 or port 67",
            "protocols": {
                "dns": True,
                "dhcp": True,
                "arp": True,
                "tcp": True
            },
            "fingerprinting": {
                "dhcp_fingerprint": True,
                "ja3": True,
                "ja4": True,
                "user_agent": True
            }
        },
        "injection": {
            "dns_race": {
                "enabled": True,
                "target_success_rate": 0.99,
                "modes": ["nxdomain", "sinkhole"],
                "sinkhole_ip": "10.0.0.1",
                "ttl": 300
            },
            "dhcp_race": {
                "enabled": True,
                "quarantine_pool": {
                    "start": "10.99.0.10",
                    "end": "10.99.0.250",
                    "lease_time": 300,
                    "gateway": "10.99.0.1"
                }
            },
            "rst_inject": {
                "enabled": True,
                "double_ended": True,
                "timing_window_ms": 10
            },
            "arp_redirect": {
                "enabled": True,
                "refresh_interval_s": 30,
                "captive_mac": "aa:bb:cc:dd:ee:ff"
            }
        },
        "policy": {
            "default_action": "observe",
            "rules": [
                {
                    "id": "block-malware",
                    "priority": 100,
                    "match": {
                        "dest_domain": "*.malware.com"
                    },
                    "action": "dns_sinkhole",
                    "log_level": "alert"
                }
            ],
            "escalation": {
                "allow_in_path": False,
                "require_explicit_consent": True,
                "auto_revert_after_s": 3600,
                "audit_all_escalations": True
            }
        }
    }


class TestJSONSchemaValidity:
    """Tests de validité du JSON Schema."""

    def test_schema_is_valid_draft7(self, opad_schema):
        """Le schéma est un JSON Schema draft-07 valide."""
        Draft7Validator.check_schema(opad_schema)

    def test_minimal_profile_validates(self, opad_schema, minimal_profile):
        """Un profil minimal passe la validation."""
        validate(instance=minimal_profile, schema=opad_schema)

    def test_full_profile_validates(self, opad_schema, full_profile):
        """Un profil complet passe la validation."""
        validate(instance=full_profile, schema=opad_schema)

    def test_missing_interfaces_fails(self, opad_schema):
        """Un profil sans interfaces échoue."""
        invalid = {
            "version": "2.4.0",
            "mode": "opad-only",
            "observation": {},
            "injection": {},
            "policy": {}
        }
        with pytest.raises(Exception):
            validate(instance=invalid, schema=opad_schema)

    def test_invalid_mode_fails(self, opad_schema, minimal_profile):
        """Un mode invalide échoue."""
        minimal_profile["mode"] = "invalid-mode"
        with pytest.raises(Exception):
            validate(instance=minimal_profile, schema=opad_schema)


class TestPydanticModels:
    """Tests des modèles Pydantic."""

    def test_minimal_profile_pydantic(self, minimal_profile):
        """Un profil minimal est valide via Pydantic."""
        profile = OPADProfile(**minimal_profile)
        assert profile.mode == OPADMode.OPAD_ONLY
        assert profile.observation.interfaces == ["eth0"]

    def test_full_profile_pydantic(self, full_profile):
        """Un profil complet est valide via Pydantic."""
        profile = OPADProfile(**full_profile)
        assert profile.injection.dns_race.sinkhole_ip == "10.0.0.1"
        assert len(profile.policy.rules) == 1
        assert profile.policy.rules[0].id == "block-malware"

    def test_invalid_mac_fails(self):
        """Une adresse MAC invalide échoue."""
        with pytest.raises(ValidationError):
            OPADProfile(
                version="2.4.0",
                mode="opad-only",
                observation=ObservationConfig(interfaces=["eth0"]),
                injection=InjectionConfig(
                    arp_redirect={"captive_mac": "invalid"}
                ),
            )

    def test_invalid_success_rate_fails(self):
        """Un taux de succès hors limites échoue."""
        with pytest.raises(ValidationError):
            OPADProfile(
                version="2.4.0",
                mode="opad-only",
                observation=ObservationConfig(interfaces=["eth0"]),
                injection=InjectionConfig(
                    dns_race={"target_success_rate": 0.5}
                ),
            )

    def test_policy_rule_creation(self):
        """Création d'une règle de politique."""
        rule = PolicyRule(
            id="test-rule",
            priority=100,
            match=RuleMatch(dest_domain="*.example.com"),
            action=PolicyAction.DNS_SINKHOLE,
        )
        assert rule.id == "test-rule"
        assert rule.action == PolicyAction.DNS_SINKHOLE

    def test_export_json_schema(self):
        """Le modèle Pydantic exporte un JSON Schema."""
        schema = OPADProfile.model_json_schema()
        assert schema["title"] == "OPADProfile"
        assert "observation" in schema["properties"]


class TestSchemaEquivalence:
    """Tests d'équivalence JSON Schema <-> Pydantic."""

    def test_pydantic_validates_same_as_jsonschema(
        self, opad_schema, full_profile
    ):
        """Pydantic et JSON Schema acceptent le même profil."""
        # JSON Schema valide
        validate(instance=full_profile, schema=opad_schema)
        # Pydantic valide
        profile = OPADProfile(**full_profile)
        # Les valeurs sont identiques
        assert profile.version == full_profile["version"]
        assert profile.mode.value == full_profile["mode"]


class TestInvariants:
    """Tests des invariants OPAD."""

    def test_default_mode_is_opad_only(self):
        """INV: Le mode par défaut est opad-only."""
        profile = OPADProfile(
            observation=ObservationConfig(interfaces=["eth0"])
        )
        assert profile.mode == OPADMode.OPAD_ONLY

    def test_escalation_requires_consent_by_default(self):
        """INV-08: L'escalade requiert un consentement explicite."""
        profile = OPADProfile(
            observation=ObservationConfig(interfaces=["eth0"])
        )
        assert profile.policy.escalation.require_explicit_consent is True
        assert profile.policy.escalation.allow_in_path is False
```

- [ ] **Step 4: Run tests**

```bash
cd /home/reepost/CyberMindStudio/secubox-deb/secubox-deb
PYTHONPATH=. pytest tests/test_opad_schema.py -v
```

Expected: All tests pass

- [ ] **Step 5: Commit Pydantic models and tests**

```bash
git add common/secubox_core/opad tests/test_opad_schema.py
git commit -m "feat(opad): add Pydantic models and validation tests

Pydantic v2 models equivalent to JSON Schema:
- OPADProfile: Complete 3-prong configuration
- Enums: OPADMode, PolicyAction, LogLevel, Protocol
- Observation, Injection, Policy configs
- OPADEvent and OPADInjectResult for logging

Tests verify JSON Schema and Pydantic equivalence.

Refs: CM-WALL-OPAD-2026-05"
```

---

## Task 4: Create OPAD.md Core Doctrine

**Files:**
- Create: `doctrine/opad/OPAD.md`

- [ ] **Step 1: Create OPAD.md**

Create file `doctrine/opad/OPAD.md`:

```markdown
# OPAD — Off-Path Active Defense

## Doctrine WALL SecuBox v2.4.0

**Référence** : CM-WALL-OPAD-2026-05
**Version** : 2.4.0
**Statut** : Canonique
**Langue autoritaire** : Français
**Date** : 2026-05-12

---

## 1. Identité

### 1.1 Définition

**OPAD** (Off-Path Active Defense) est la doctrine de sécurité réseau canonique de SecuBox-Deb v2.4.0. Elle définit une posture de protection où l'appliance de sécurité n'est **jamais** dans le chemin de données (data path), mais observe passivement le trafic et intervient activement par injection de paquets.

### 1.2 Doctrine en une ligne

> **La SecuBox n'est pas dans le chemin. Elle est à côté du chemin, et elle gagne des courses. Quand elle est là, elle protège par disruption ciblée. Quand elle n'est pas là, le réseau ne le remarque pas.**

### 1.3 Périmètre

Cette doctrine s'applique au module **WALL** de SecuBox-Deb et définit les interactions avec les modules AUTH, BOOT, MIND, ROOT et MESH.

---

## 2. Contexte et motivation

### 2.1 Problème : la doctrine in-path

L'approche traditionnelle (IDGP — In-line Deep Guard Protection) place l'appliance de sécurité dans le chemin de données :

```
[Clients LAN] ←→ [SecuBox Bridge] ←→ [Gateway/WAN]
```

**Problèmes identifiés** :

| Problème | Impact | Sévérité |
|----------|--------|----------|
| Point de défaillance unique | Crash SecuBox = rupture réseau totale | CRITIQUE |
| Latence additionnelle | Chaque paquet traverse SecuBox | ÉLEVÉE |
| Surface d'attaque | SecuBox exposée sur le réseau | ÉLEVÉE |
| Complexité de déploiement | Nécessite reconfiguration réseau | MOYENNE |

### 2.2 Solution : la posture off-path

OPAD place SecuBox **hors** du chemin de données :

```
[Clients LAN] ←→ [Switch] ←→ [Gateway/WAN]
                    ↑
              [SecuBox]
              (observe + injecte)
```

**Garanties** :

| Propriété | Garantie | Invariant |
|-----------|----------|-----------|
| Résilience | Retrait SecuBox = aucun impact | INV-01 |
| Performance | Zéro latence sur trafic normal | INV-02 |
| Discrétion | Invisible aux scans réseau | INV-05, INV-06 |
| Simplicité | Plug-and-play, aucune reconfiguration | — |

---

## 3. Principes fondamentaux

### PROP-P1 : Observer plus, agir moins

SecuBox observe **tout** le trafic en mode promiscuous, mais n'intervient que sur les flux qui violent la politique de sécurité. L'action est toujours une exception, jamais la règle.

### PROP-P2 : Zéro rupture possible

Aucun mode de défaillance de SecuBox (crash, redémarrage, déconnexion, mise à jour) ne peut bloquer, ralentir ou dégrader le trafic utilisateur. Le réseau fonctionne **identiquement** avec ou sans SecuBox.

### PROP-P3 : Surface d'attaque minimale

- Côté LAN : aucune réponse aux sollicitations IP actives (ICMP, TCP SYN, etc.)
- Côté WAN : aucune interface, aucun port ouvert
- Management : interface dédiée, hors bande, non routable

### PROP-P4 : Escalade explicite et révocable

Toute escalade vers un mode in-path (bridge, NAT, proxy) :
- Requiert une action utilisateur **explicite** et **documentée**
- Est journalisée de manière **immutable**
- Est **révocable** à tout moment
- A une durée de vie **limitée** (timeout automatique)

---

## 4. Invariants OPAD

Ces 8 invariants sont **non-négociables**. Toute implémentation DOIT les garantir et les tester.

| ID | Invariant | Description | Test de vérification |
|----|-----------|-------------|---------------------|
| **INV-01** | Retrait sans rupture | Le retrait physique de SecuBox laisse le trafic LAN↔WAN inchangé | Débrancher SecuBox, vérifier que ping continue |
| **INV-02** | Aucun forwarding | Aucun paquet de données utilisateur ne transite par SecuBox en tant que forwarder | Inspection topologique, traceroute |
| **INV-03** | Journalisation systématique | Toute action d'engagement est précédée d'un événement ALERTE·DÉPÔT horodaté et signé | Déclencher injection, vérifier log ROOT |
| **INV-04** | Marquage des échecs | Tout échec d'injection (course perdue) est marqué OPAD_INJECT_LOST | Simuler course perdue, vérifier log |
| **INV-05** | Silence LAN | Aucune interface SecuBox côté LAN ne répond aux sondages IP-actifs | nmap depuis LAN = 0 réponse |
| **INV-06** | Surface WAN nulle | Aucun port ouvert côté WAN | Scan externe = 0 port |
| **INV-07** | Fail-silent | Tout crash silencieux, aucun impact trafic | kill -9 démons, vérifier trafic OK |
| **INV-08** | Escalade révocable | Toute escalade in-path requiert action explicite, journalisée, révocable | Test escalade + révocation |

---

## 5. Primitifs d'injection

OPAD définit 4 primitifs d'injection, chacun ciblant un protocole spécifique.

### 5.1 DNS Race (DNS-R)

**Objectif** : Répondre au client DNS avant le serveur légitime.

**Mécanisme** :
```
1. Client → DNS Query → [Switch] → Serveur DNS
                           ↓
                      [SecuBox observe]
                           ↓
2. SecuBox → DNS Reply (forgée) → Client
3. Serveur DNS → DNS Reply (ignorée, arrive après) → Client
```

**Paramètres** :

| Paramètre | Valeur défaut | Plage | Description |
|-----------|---------------|-------|-------------|
| `enabled` | `true` | bool | Activer DNS-R |
| `target_success_rate` | `0.99` | 0.9-1.0 | Taux de succès cible |
| `modes` | `["nxdomain", "sinkhole", "redirect_captive"]` | enum[] | Modes de réponse |
| `sinkhole_ip` | `127.0.0.1` | IPv4 | IP pour sinkhole |
| `ttl` | `300` | 1-86400 | TTL des réponses (sec) |

**Modes de réponse** :

| Mode | Effet | Usage |
|------|-------|-------|
| `nxdomain` | NXDOMAIN (domaine inexistant) | Bloquer l'accès |
| `sinkhole` | Réponse avec IP locale | Rediriger vers page de blocage |
| `redirect_captive` | Réponse avec IP captive portal | Authentification requise |

**Taux de succès** : ≥ 99% (SecuBox physiquement plus proche du client que le serveur DNS)

### 5.2 DHCP Race (DHCP-R)

**Objectif** : Attribuer une IP de quarantaine avant le serveur DHCP légitime.

**Mécanisme** :
```
1. Client → DHCP DISCOVER (broadcast)
                    ↓
              [SecuBox observe]
                    ↓
2. SecuBox → DHCP OFFER (IP quarantaine) → Client
3. Serveur DHCP → DHCP OFFER (IP légitime, ignorée) → Client
4. Client → DHCP REQUEST → SecuBox
5. SecuBox → DHCP ACK → Client (IP quarantaine attribuée)
```

**Paramètres** :

| Paramètre | Valeur défaut | Plage | Description |
|-----------|---------------|-------|-------------|
| `enabled` | `true` | bool | Activer DHCP-R |
| `target_success_rate` | `0.95` | 0.9-1.0 | Taux de succès cible |
| `quarantine_pool.start` | — | IPv4 | Début du pool |
| `quarantine_pool.end` | — | IPv4 | Fin du pool |
| `quarantine_pool.lease_time` | `300` | ≥60 | Durée du bail (sec) |
| `quarantine_pool.gateway` | — | IPv4 | Gateway (captive portal) |

**Pool de quarantaine** :
- Plage IP dédiée (ex: 10.99.0.0/24)
- Gateway pointe vers le captive portal SecuBox
- Lease court (300s) pour réévaluation rapide

**Taux de succès** : ≥ 95%

### 5.3 TCP RST Injection (RST-I)

**Objectif** : Couper une connexion TCP établie par injection de paquets RST.

**Mécanisme** :
```
1. Client ←→ TCP connexion ←→ Serveur
                   ↓
             [SecuBox observe SYN/ACK ou DATA]
                   ↓
2. SecuBox → TCP RST (seq calculé) → Client
3. SecuBox → TCP RST (seq calculé) → Serveur
4. Connexion coupée des deux côtés
```

**Paramètres** :

| Paramètre | Valeur défaut | Plage | Description |
|-----------|---------------|-------|-------------|
| `enabled` | `true` | bool | Activer RST-I |
| `target_success_rate` | `0.90` | 0.85-1.0 | Taux de succès cible |
| `double_ended` | `true` | bool | RST vers les deux endpoints |
| `timing_window_ms` | `10` | 1-100 | Fenêtre de timing (ms) |

**Calcul du sequence number** :
```python
rst_seq = observed_ack_num
rst_ack = observed_seq_num + payload_len
```

**Taux de succès** : ≥ 90% (limité par fenêtre TCP et timing réseau)

### 5.4 ARP Redirect (ARP-R)

**Objectif** : Rediriger le trafic d'un device vers le captive portal.

**Mécanisme** :
```
1. Device connaît : Gateway IP = Gateway MAC
                         ↓
2. SecuBox → Gratuitous ARP : "Gateway IP = SecuBox Captive MAC"
                         ↓
3. Device met à jour son cache ARP
                         ↓
4. Device → Trafic → SecuBox Captive (au lieu de Gateway)
                         ↓
5. Refresh périodique pour maintenir la redirection
```

**Paramètres** :

| Paramètre | Valeur défaut | Plage | Description |
|-----------|---------------|-------|-------------|
| `enabled` | `true` | bool | Activer ARP-R |
| `target_success_rate` | `0.98` | 0.95-1.0 | Taux de succès cible |
| `refresh_interval_s` | `30` | 10-300 | Intervalle de refresh (sec) |
| `captive_mac` | — | MAC | Adresse MAC du captive portal |

**Comportement** :
- Arrêt du refresh = retour automatique à la normale (ARP expire)
- Inefficace si le client a un ARP statique (détectable, escalade possible)

**Taux de succès** : ≥ 98%

---

## 6. Modes opératoires

### 6.1 `opad-only` (défaut canonique)

**Description** : Mode OPAD pur, aucune possibilité d'escalade.

**Caractéristiques** :
- Observation passive : ✅
- Injection active : ✅
- Forwarding : ❌ JAMAIS
- Escalade : ❌ IMPOSSIBLE

**Fichier de mode** : `/etc/secubox/mode` contient `opad-only`

### 6.2 `opad-with-escalation`

**Description** : Mode OPAD avec possibilité d'escalade temporaire vers in-path.

**Caractéristiques** :
- Observation passive : ✅
- Injection active : ✅
- Forwarding : ⚠️ UNIQUEMENT après escalade explicite
- Escalade : ✅ Requiert consentement (INV-08)

**Conditions d'escalade** :
1. Détection d'une menace non-traitable par OPAD (ex: ARP statique sur client)
2. Demande explicite de l'utilisateur
3. Journalisation ROOT de la demande
4. Timeout automatique (défaut: 3600s)
5. Révocation possible à tout moment

### 6.3 `legacy-in-path` (déprécié)

**Description** : Mode bridge transparent hérité de la doctrine IDGP.

**Caractéristiques** :
- ⚠️ **DÉPRÉCIÉ** — WARNING affiché au boot
- Observation : via bridge
- Forwarding : ✅ TOUJOURS (viole INV-01, INV-02)
- Conservé pour migration uniquement
- Sera supprimé en v3.0

---

## 7. Profil de configuration 3-broche

Le profil OPAD est structuré en 3 broches :

```
┌─────────────────────────────────────────┐
│            PROFIL OPAD 3-BROCHE          │
├─────────────┬─────────────┬─────────────┤
│  BROCHE 1   │  BROCHE 2   │  BROCHE 3   │
│ OBSERVATION │  INJECTION  │  POLITIQUE  │
├─────────────┼─────────────┼─────────────┤
│ interfaces  │ dns_race    │ rules[]     │
│ bpf_filter  │ dhcp_race   │ default_act │
│ protocols   │ rst_inject  │ escalation  │
│ fingerprint │ arp_redirect│             │
└─────────────┴─────────────┴─────────────┘
```

### 7.1 Broche 1 : Observation

Configure ce que SecuBox observe :
- Interfaces en mode promiscuous
- Filtre BPF optionnel
- Protocoles activés (DNS, DHCP, ARP, TCP)
- Fingerprinting (DHCP fingerprint, JA3/JA4, User-Agent)

### 7.2 Broche 2 : Injection

Configure les primitifs d'injection :
- DNS-R : paramètres de DNS race
- DHCP-R : pool de quarantaine
- RST-I : paramètres de RST injection
- ARP-R : paramètres de redirection ARP

### 7.3 Broche 3 : Politique

Configure les règles de décision :
- Action par défaut (allow, observe, disrupt)
- Liste de règles (premier match gagne)
- Configuration d'escalade

### 7.4 Stockage (double-buffer 4R)

```
/etc/secubox/opad/
├── active/
│   └── profile.json    ← Config live (lecture seule)
├── shadow/
│   └── profile.json    ← Édition en cours
├── rollback/
│   ├── R1/             ← Snapshot le plus récent
│   ├── R2/
│   ├── R3/
│   └── R4/             ← Snapshot J-7
└── pending/
    └── profile.json    ← En attente validation
```

---

## 8. Intégration avec les modules SecuBox

### 8.1 Mapping modules → OPAD

| Module | Rôle OPAD | Interactions |
|--------|-----------|--------------|
| **AUTH** | Registre devices autorisés | WALL consulte `device_authorized` pour policy match |
| **WALL** | Moteur OPAD (observer + inject) | Cœur de l'implémentation |
| **BOOT** | Sélection mode au démarrage | Valide profil, refuse si incohérent |
| **MIND** | Scoring comportemental | WALL consulte `mind_score` pour seuils |
| **ROOT** | Journalisation signée | Reçoit tous les événements OPAD |
| **MESH** | Synchronisation hors-bande | Ne participe JAMAIS au chemin LAN |

### 8.2 Flux d'événements

```
[Paquet observé sur interface]
            │
            ▼
    [WALL/Observer]
    Parse DNS/DHCP/TCP/ARP
            │
            ▼
    [WALL/Policy Engine]
            │
    ┌───────┴───────┐
    ▼               ▼
[AUTH]           [MIND]
device?          score?
    │               │
    └───────┬───────┘
            ▼
    [Décision: action?]
            │
    ┌───────┴───────┐
    ▼               ▼
[allow/observe]  [WALL/Injector]
    │               │
    │           [Injection]
    │               │
    └───────┬───────┘
            ▼
    [ROOT/Logger]
    (événement signé)
```

---

## 9. Journalisation et audit

### 9.1 Types d'événements

| Event Type | Déclencheur | Sévérité |
|------------|-------------|----------|
| `ALERTE_DEPOT` | Avant toute injection | INFO |
| `OPAD_INJECT_SUCCESS` | Injection réussie (course gagnée) | INFO |
| `OPAD_INJECT_LOST` | Course perdue | WARNING |
| `OPAD_ESCALATION_REQUEST` | Demande d'escalade | WARNING |
| `OPAD_ESCALATION_GRANTED` | Escalade accordée | ALERT |
| `OPAD_ESCALATION_REVOKED` | Escalade révoquée | INFO |
| `OPAD_DEGRADED` | Taux de succès dégradé | WARNING |

### 9.2 Format de log

Tous les événements OPAD sont journalisés dans `/var/log/secubox/audit.log` au format JSON, signés par ROOT :

```json
{
  "timestamp": "2026-05-12T14:30:00.123Z",
  "event_type": "OPAD_INJECT_SUCCESS",
  "primitive": "dns_race",
  "source_mac": "aa:bb:cc:dd:ee:ff",
  "target": "malware.example.com",
  "action_taken": "dns_sinkhole",
  "success": true,
  "latency_ms": 1.2,
  "signature": "ROOT:sha256:..."
}
```

---

## 10. Périmètre déclaré

### 10.1 Couvert (◉)

OPAD couvre les menaces suivantes avec un taux de protection élevé :

- Résolution DNS vers domaines malveillants
- Exfiltration DNS tunnel
- DHCP rogue / spoofing
- Connexions C2 (Command & Control)
- IP spoofing sur LAN
- Mouvements latéraux TCP
- Devices non autorisés

### 10.2 Partiel (◐)

OPAD offre une protection partielle pour :

- Connexions chiffrées (TLS) — uniquement au niveau handshake
- Traffic UDP hors DNS/DHCP
- Attaques au niveau applicatif

### 10.3 Hors portée (✕)

OPAD **NE COUVRE PAS** et ne prétend pas couvrir :

| Capacité | Raison |
|----------|--------|
| Interception TLS | Nécessite MitM (in-path), viole INV-02 |
| Drop hard de paquet | Nécessite forwarding, viole INV-02 |
| Segmentation VLAN stricte | Hors périmètre fonctionnel WALL |
| Bandwidth shaping | Nécessite tc inline, viole INV-02 |
| Protection WAN entrante | Surface WAN = 0 par design |

---

## 11. Historique doctrinal

### 11.1 Doctrine actuelle

- **CM-WALL-OPAD-2026-05** : OPAD v2.4.0 (ce document)

### 11.2 Doctrines dépréciées

| Référence | Nom | Statut | Raison |
|-----------|-----|--------|--------|
| D-2025-IDGP-INLINE | IDGP In-Path | Déprécié | Viole PROP-P2, INV-01, INV-02 |
| D-2024-BRIDGE-TRANSPARENT | Bridge Transparent | Déprécié | Viole PROP-P2, INV-01 |

---

## 12. Références

- **Spec** : `docs/superpowers/specs/2026-05-12-opad-doctrine-design.md`
- **JSON Schema** : `schemas/opad-profile.schema.json`
- **Pydantic Models** : `common/secubox_core/opad/models.py`
- **Matrice CSPN** : `doctrine/opad/CSPN.matrix.md`
- **Guide opérationnel** : `doctrine/opad/OPAD-OPERATIONS.md`

---

*Document généré le 2026-05-12. Référence CM-WALL-OPAD-2026-05.*
```

- [ ] **Step 2: Verify markdown syntax**

```bash
python3 -c "import sys; content = open('doctrine/opad/OPAD.md').read(); print(f'Lines: {len(content.splitlines())}')"
```

Expected: ~500+ lines

- [ ] **Step 3: Commit OPAD.md**

```bash
git add doctrine/opad/OPAD.md
git commit -m "docs(opad): add core doctrine document OPAD.md

Comprehensive OPAD doctrine including:
- 4 principles (PROP-P1 to P4)
- 8 invariants (INV-01 to INV-08)
- 4 injection primitives (DNS-R, DHCP-R, RST-I, ARP-R)
- 3 operating modes
- 3-prong profile structure
- Module integration mapping

Refs: CM-WALL-OPAD-2026-05"
```

---

## Task 5: Create CSPN.matrix.md

**Files:**
- Create: `doctrine/opad/CSPN.matrix.md`

- [ ] **Step 1: Create CSPN.matrix.md**

Create file `doctrine/opad/CSPN.matrix.md`:

```markdown
# Matrice CSPN — OPAD SecuBox v2.4.0

## Analyse menace × capacité pour certification ANSSI

**Référence** : CM-CSPN-OPAD-MATRIX-2026-05
**Cible d'évaluation** : SecuBox-Deb v2.4.0 — Module WALL (OPAD)
**Niveau visé** : CSPN (Certification de Sécurité de Premier Niveau)
**Date** : 2026-05-12

---

## 1. Périmètre d'évaluation

### 1.1 Composants inclus

| Composant | Description | Criticité |
|-----------|-------------|-----------|
| WALL/Observer | Capture promiscuous BPF, parsing protocoles | Haute |
| WALL/Injector | Moteurs DNS-R, DHCP-R, RST-I, ARP-R | Haute |
| WALL/Policy | Moteur de règles, évaluation politique | Haute |
| ROOT/Logger | Journalisation signée, audit trail | Haute |
| AUTH/Registry | Registre devices autorisés | Moyenne |
| MIND/Scoring | Scoring comportemental | Moyenne |

### 1.2 Composants exclus

| Composant | Raison d'exclusion |
|-----------|-------------------|
| Stack réseau Debian | Composant tiers, hors périmètre |
| Kernel Linux | Composant tiers, hors périmètre |
| Firmware matériel | Composant tiers, non auditable |
| CrowdSec | Dépendance optionnelle, évaluation séparée |
| Suricata | Dépendance optionnelle, évaluation séparée |

---

## 2. Capacités OPAD

### 2.1 Primitifs d'injection

| ID | Primitif | Protocole | Taux succès | Latence |
|----|----------|-----------|-------------|---------|
| CAP-01 | DNS-R (DNS Race) | UDP/53 | ≥ 99% | < 2ms |
| CAP-02 | DHCP-R (DHCP Race) | UDP/67-68 | ≥ 95% | < 5ms |
| CAP-03 | RST-I (TCP RST Injection) | TCP | ≥ 90% | < 10ms |
| CAP-04 | ARP-R (ARP Redirect) | ARP | ≥ 98% | < 1ms |

### 2.2 Capacités d'observation

| ID | Capacité | Description |
|----|----------|-------------|
| CAP-10 | Observation DNS | Parsing complet des requêtes/réponses DNS |
| CAP-11 | Observation DHCP | Parsing DISCOVER/OFFER/REQUEST/ACK |
| CAP-12 | Observation TCP | Suivi des connexions, extraction seq/ack |
| CAP-13 | Observation ARP | Détection ARP request/reply/gratuitous |
| CAP-14 | Fingerprinting DHCP | Identification device par options DHCP |
| CAP-15 | Fingerprinting TLS | Extraction JA3/JA4 fingerprint |
| CAP-16 | Fingerprinting HTTP | Extraction User-Agent |

### 2.3 Capacités de politique

| ID | Capacité | Description |
|----|----------|-------------|
| CAP-20 | Match MAC source | Filtrage par adresse MAC |
| CAP-21 | Match domaine | Filtrage par domaine (wildcards supportés) |
| CAP-22 | Match IP destination | Filtrage par IP ou CIDR |
| CAP-23 | Match protocole | Filtrage par protocole (dns/dhcp/tcp/arp) |
| CAP-24 | Match score MIND | Seuil de score comportemental |
| CAP-25 | Match autorisation AUTH | Device autorisé ou non |

---

## 3. Catalogue des menaces

### 3.1 Catégorie DNS (M01-M05)

| ID | Menace | Description | Vecteur |
|----|--------|-------------|---------|
| M01 | Résolution DNS malveillante | Accès à domaine C2/malware | Client → DNS → Malware |
| M02 | DNS tunneling (exfiltration) | Exfiltration données via DNS | Client → DNS encode → Ext |
| M03 | DNS rebinding | Contournement same-origin | Malware → DNS → LAN |
| M04 | DNS cache poisoning | Injection réponse DNS falsifiée | Attacker → DNS cache |
| M05 | DNS amplification | Utilisation comme réflecteur | Ext → DNS → Victime |

### 3.2 Catégorie Réseau (M06-M12)

| ID | Menace | Description | Vecteur |
|----|--------|-------------|---------|
| M06 | DHCP rogue | Serveur DHCP malveillant | Attacker DHCP → Clients |
| M07 | DHCP starvation | Épuisement pool DHCP | Attacker → DHCP flood |
| M08 | IP spoofing LAN | Usurpation d'identité IP | Attacker → Spoof → Target |
| M09 | ARP spoofing | Man-in-the-middle ARP | Attacker → ARP → Clients |
| M10 | MAC flooding | Saturation table CAM switch | Attacker → MAC flood |
| M11 | VLAN hopping | Évasion segmentation VLAN | Attacker → Double tag |
| M12 | Rogue gateway | Gateway malveillante | Attacker GW → Clients |

### 3.3 Catégorie Malware (M13-M20)

| ID | Menace | Description | Vecteur |
|----|--------|-------------|---------|
| M13 | Connexion C2 TCP | Communication Command & Control | Client → TCP → C2 |
| M14 | Connexion C2 HTTPS | Communication C2 chiffrée | Client → TLS → C2 |
| M15 | Lateral movement TCP | Propagation interne TCP | Infected → TCP → Peer |
| M16 | Lateral movement SMB | Propagation via SMB | Infected → SMB → Peer |
| M17 | Ransomware propagation | Chiffrement réseau | Infected → SMB/RDP → Peers |
| M18 | Cryptominer | Minage crypto non autorisé | Client → Pool mining |
| M19 | Botnet enrollment | Recrutement dans botnet | Malware → C2 → Botnet |
| M20 | Data exfiltration TCP | Exfiltration données TCP | Client → TCP → Ext |

### 3.4 Catégorie Accès (M21-M26)

| ID | Menace | Description | Vecteur |
|----|--------|-------------|---------|
| M21 | Device non autorisé | Device inconnu sur LAN | Unknown → LAN |
| M22 | Rogue access point | AP Wi-Fi malveillant | Attacker AP → Clients |
| M23 | Credential theft | Vol d'identifiants | Attacker → Intercept → Creds |
| M24 | Session hijacking | Vol de session | Attacker → Intercept → Session |
| M25 | Privilege escalation | Élévation de privilèges | User → Exploit → Admin |
| M26 | Unauthorized service | Service non autorisé | User → Service → LAN |

### 3.5 Catégorie Données (M27-M31)

| ID | Menace | Description | Vecteur |
|----|--------|-------------|---------|
| M27 | Data exfiltration DNS | Exfiltration via DNS | Client → DNS → Ext |
| M28 | Data exfiltration HTTPS | Exfiltration chiffrée | Client → HTTPS → Ext |
| M29 | Data interception | Interception données transit | Attacker → Intercept → Data |
| M30 | Database exfiltration | Vol base de données | Attacker → DB → Ext |
| M31 | PII leakage | Fuite données personnelles | Client → Service → Ext |

### 3.6 Catégorie Crypto (M32-M36)

| ID | Menace | Description | Vecteur |
|----|--------|-------------|---------|
| M32 | TLS interception | MitM sur TLS | Attacker → Proxy → Server |
| M33 | Certificate spoofing | Faux certificat | Attacker cert → Client |
| M34 | Downgrade attack | Forcer protocole faible | Attacker → Downgrade → Weak |
| M35 | Key extraction | Vol de clé privée | Attacker → Memory → Key |
| M36 | Weak cipher exploitation | Exploitation chiffrement faible | Attacker → Weak cipher → Data |

---

## 4. Matrice menace × capacité

### 4.1 Légende

| Symbole | Signification |
|---------|---------------|
| ◉ | Couvert — protection effective |
| ◐ | Partiel — protection limitée |
| ✕ | Hors portée — explicitement non couvert |
| — | Non applicable |

### 4.2 Matrice complète

| ID | Menace | DNS-R | DHCP-R | RST-I | ARP-R | Obs | Couv |
|----|--------|-------|--------|-------|-------|-----|------|
| **DNS** ||||||| |
| M01 | Résolution DNS malveillante | ◉ | — | — | — | ◉ | ◉ |
| M02 | DNS tunneling | ◉ | — | — | — | ◉ | ◉ |
| M03 | DNS rebinding | ◉ | — | — | — | ◉ | ◉ |
| M04 | DNS cache poisoning | ◉ | — | — | — | ◉ | ◉ |
| M05 | DNS amplification | — | — | — | — | ◉ | ◐ |
| **Réseau** ||||||| |
| M06 | DHCP rogue | — | ◉ | — | — | ◉ | ◉ |
| M07 | DHCP starvation | — | ◐ | — | — | ◉ | ◐ |
| M08 | IP spoofing LAN | — | ◉ | — | ◉ | ◉ | ◉ |
| M09 | ARP spoofing | — | — | — | ◉ | ◉ | ◉ |
| M10 | MAC flooding | — | — | — | — | ◉ | ◐ |
| M11 | VLAN hopping | — | — | — | — | — | ✕ |
| M12 | Rogue gateway | — | ◉ | — | ◉ | ◉ | ◉ |
| **Malware** ||||||| |
| M13 | Connexion C2 TCP | ◉ | — | ◉ | — | ◉ | ◉ |
| M14 | Connexion C2 HTTPS | ◉ | — | ◐ | — | ◉ | ◐ |
| M15 | Lateral movement TCP | — | — | ◉ | — | ◉ | ◉ |
| M16 | Lateral movement SMB | — | — | ◉ | — | ◉ | ◉ |
| M17 | Ransomware propagation | — | — | ◉ | — | ◉ | ◐ |
| M18 | Cryptominer | ◉ | — | ◉ | — | ◉ | ◉ |
| M19 | Botnet enrollment | ◉ | — | ◉ | — | ◉ | ◉ |
| M20 | Data exfiltration TCP | — | — | ◐ | — | ◉ | ◐ |
| **Accès** ||||||| |
| M21 | Device non autorisé | — | ◉ | — | ◉ | ◉ | ◉ |
| M22 | Rogue access point | — | — | — | — | ◉ | ◐ |
| M23 | Credential theft | — | — | — | — | ◐ | ◐ |
| M24 | Session hijacking | — | — | ◉ | — | ◐ | ◐ |
| M25 | Privilege escalation | — | — | — | — | — | ✕ |
| M26 | Unauthorized service | — | — | ◉ | — | ◉ | ◐ |
| **Données** ||||||| |
| M27 | Data exfiltration DNS | ◉ | — | — | — | ◉ | ◉ |
| M28 | Data exfiltration HTTPS | — | — | — | — | ◐ | ◐ |
| M29 | Data interception | — | — | — | — | — | ✕ |
| M30 | Database exfiltration | — | — | ◐ | — | ◉ | ◐ |
| M31 | PII leakage | — | — | — | — | ◐ | ◐ |
| **Crypto** ||||||| |
| M32 | TLS interception | — | — | — | — | — | ✕ |
| M33 | Certificate spoofing | — | — | — | — | ◐ | ◐ |
| M34 | Downgrade attack | — | — | — | — | — | ✕ |
| M35 | Key extraction | — | — | — | — | — | — |
| M36 | Weak cipher exploitation | — | — | — | — | — | — |

---

## 5. Résumé de couverture

### 5.1 Par catégorie

| Catégorie | Total | ◉ | ◐ | ✕ | — | Couverture |
|-----------|-------|---|---|---|---|------------|
| DNS | 5 | 4 | 1 | 0 | 0 | 90% |
| Réseau | 7 | 5 | 2 | 1 | 0 | 86% |
| Malware | 8 | 5 | 3 | 0 | 0 | 81% |
| Accès | 6 | 2 | 3 | 1 | 0 | 58% |
| Données | 5 | 1 | 3 | 1 | 0 | 50% |
| Crypto | 5 | 0 | 1 | 2 | 2 | 10% |
| **Total** | **36** | **17** | **13** | **5** | **2** | **72%** |

### 5.2 Synthèse

- **Menaces totales** : 36
- **Couvertes (◉)** : 17 (47%)
- **Partielles (◐)** : 13 (36%)
- **Hors portée (✕)** : 5 (14%)
- **Non applicables (—)** : 2 (6%)
- **Couverture active** : 83% (30/36 menaces avec protection ≥ partielle)

---

## 6. Périmètre explicitement exclu

Ces capacités sont **explicitement hors portée** de la doctrine OPAD. Cette exclusion est intentionnelle et documentée pour le dossier CSPN.

| ID | Capacité | Raison d'exclusion | Invariant violé |
|----|----------|-------------------|-----------------|
| X01 | Interception TLS | Nécessite position MitM (in-path) | INV-02 |
| X02 | Drop hard de paquet | Nécessite contrôle du forwarding | INV-02 |
| X03 | Segmentation VLAN stricte | Hors périmètre fonctionnel WALL, relève du switch | — |
| X04 | Bandwidth shaping (QoS) | Nécessite tc inline sur chemin de données | INV-02 |
| X05 | Protection WAN entrante | Surface WAN = 0 par design (INV-06) | — |

### 6.1 Justification X01 : Interception TLS

L'interception TLS requiert un proxy MitM qui :
1. Reçoit la connexion client
2. Établit une connexion vers le serveur
3. Présente un certificat CA au client

Cette architecture viole fondamentalement INV-02 (aucun forwarding) et PROP-P2 (zéro rupture).

**Alternative OPAD** : Observation du handshake TLS (fingerprint JA3/JA4), blocking au niveau DNS ou RST sur handshake.

### 6.2 Justification X02 : Drop de paquet

Le drop de paquet nécessite que SecuBox soit sur le chemin de données :

```
Client → [SecuBox DROP] → ✕ (paquet détruit)
```

Ceci viole INV-02 et INV-01. OPAD ne peut pas garantir qu'un paquet n'atteigne pas sa destination.

**Alternative OPAD** : Disruption (RST-I, ARP-R) plutôt que drop. Le paquet arrive, mais la connexion est coupée.

---

## 7. Traçabilité vers invariants

| Invariant | Menaces protégées | Capacités utilisées |
|-----------|-------------------|---------------------|
| INV-01 | Toutes | Architecture OPAD |
| INV-02 | Toutes | Architecture OPAD |
| INV-03 | Toutes | ROOT/Logger |
| INV-04 | M13-M20 (via RST-I) | RST-I + ROOT/Logger |
| INV-05 | M21 (device non autorisé) | Architecture OPAD |
| INV-06 | Toutes | Architecture OPAD |
| INV-07 | Toutes | Architecture OPAD |
| INV-08 | M11, M29, M32 (escalade requise) | Escalation config |

---

## 8. Références

- **Doctrine OPAD** : `doctrine/opad/OPAD.md`
- **JSON Schema** : `schemas/opad-profile.schema.json`
- **Tests invariants** : `tests/test_opad_invariants.py`
- **ANSSI CSPN** : https://www.ssi.gouv.fr/entreprise/certification_cspn/

---

*Document généré le 2026-05-12. Référence CM-CSPN-OPAD-MATRIX-2026-05.*
```

- [ ] **Step 2: Commit CSPN.matrix.md**

```bash
git add doctrine/opad/CSPN.matrix.md
git commit -m "docs(opad): add CSPN threat × capability matrix

36 threats across 6 categories:
- DNS (5): 90% coverage
- Network (7): 86% coverage
- Malware (8): 81% coverage
- Access (6): 58% coverage
- Data (5): 50% coverage
- Crypto (5): 10% coverage

Overall: 72% active coverage (30/36 threats)
5 explicitly excluded capabilities with justification.

Refs: CM-CSPN-OPAD-MATRIX-2026-05"
```

---

## Task 6: Create OPAD-OPERATIONS.md

**Files:**
- Create: `doctrine/opad/OPAD-OPERATIONS.md`

- [ ] **Step 1: Create OPAD-OPERATIONS.md**

Create file `doctrine/opad/OPAD-OPERATIONS.md`:

```markdown
# OPAD — Guide Opérationnel

## SecuBox-Deb v2.4.0 · Exploitation et maintenance

**Référence** : CM-OPS-OPAD-2026-05
**Version** : 2.4.0
**Date** : 2026-05-12

---

## 1. Prérequis

### 1.1 Matériel supporté

| Plateforme | Status | Interfaces observation | Notes |
|------------|--------|------------------------|-------|
| MOCHAbin (Armada 7040) | ✅ PROD | eth0, eth1, eth2 | Cible production |
| ESPRESSObin (Armada 3720) | 🔶 BETA | lan0, lan1, wan | Tests uniquement |
| ESPRESSObin Ultra | 🔶 BETA | eth0, eth1, eth2 | Tests uniquement |
| VM x86_64 | 🔶 DEV | eth0 | Développement |

### 1.2 Dépendances système

```bash
# Vérifier les dépendances
dpkg -l | grep -E 'libpcap|python3|scapy'

# Installer si manquant
apt install libpcap-dev python3-scapy python3-pydantic
```

### 1.3 Vérification kernel

```bash
# BPF JIT requis
cat /proc/sys/net/core/bpf_jit_enable
# Attendu: 1 ou 2

# Si désactivé
echo 1 | sudo tee /proc/sys/net/core/bpf_jit_enable
```

---

## 2. Installation et configuration

### 2.1 Déploiement initial

```bash
# Installation du paquet
apt install secubox-wall

# Vérification du mode
cat /etc/secubox/mode
# Attendu: opad-only

# Validation du profil
secubox-validate /etc/secubox/opad/active/profile.json
# Attendu: Profile valid
```

### 2.2 Configuration du profil 3-broche

```bash
# Édition du profil (copie vers shadow)
secubox-params edit --module opad

# Modifier le profil shadow
vim /etc/secubox/opad/shadow/profile.json

# Validation avant swap
secubox-params validate --module opad
# Attendu: Validation passed

# Application atomique (swap shadow → active)
secubox-params swap --module opad

# Vérification
secubox-params status --module opad
```

### 2.3 Configuration des interfaces

```bash
# Lister les interfaces disponibles
ip link show

# Activer le mode promiscuous sur l'interface d'observation
ip link set eth1 promisc on

# Vérifier
ip link show eth1 | grep PROMISC
# Attendu: PROMISC dans les flags

# Vérifier la capture
tcpdump -i eth1 -c 5 -n
```

### 2.4 Profil minimal

```json
{
  "version": "2.4.0",
  "mode": "opad-only",
  "observation": {
    "interfaces": ["eth1"],
    "protocols": {
      "dns": true,
      "dhcp": true,
      "arp": true,
      "tcp": true
    }
  },
  "injection": {
    "dns_race": { "enabled": true },
    "dhcp_race": { "enabled": false },
    "rst_inject": { "enabled": false },
    "arp_redirect": { "enabled": false }
  },
  "policy": {
    "default_action": "observe",
    "rules": []
  }
}
```

---

## 3. Opérations courantes

### 3.1 Vérification du statut

```bash
# Status du service
systemctl status secubox-wall

# Status OPAD détaillé
curl -s http://localhost/api/v1/wall/status | jq
```

Exemple de réponse :
```json
{
  "mode": "opad-only",
  "uptime_s": 3600,
  "observation": {
    "interfaces": ["eth1"],
    "packets_observed": 1234567,
    "protocols": {
      "dns": 45000,
      "dhcp": 120,
      "arp": 8900,
      "tcp": 1180547
    }
  },
  "injection": {
    "dns_race": { "attempts": 150, "won": 148, "lost": 2 },
    "dhcp_race": { "attempts": 0, "won": 0, "lost": 0 },
    "rst_inject": { "attempts": 0, "won": 0, "lost": 0 },
    "arp_redirect": { "attempts": 0, "won": 0, "lost": 0 }
  }
}
```

### 3.2 Métriques temps réel

```bash
# Métriques d'injection
curl -s http://localhost/api/v1/wall/metrics | jq '.injection_rates'

# Métriques Prometheus
curl -s http://localhost:9101/metrics | grep secubox_opad
```

### 3.3 Consultation des logs

```bash
# Logs OPAD (journald)
journalctl -u secubox-wall -f

# Événements ALERTE·DÉPÔT uniquement
journalctl -u secubox-wall | grep ALERTE_DEPOT

# Courses perdues
journalctl -u secubox-wall | grep OPAD_INJECT_LOST

# Audit log signé
tail -f /var/log/secubox/audit.log | jq
```

---

## 4. Gestion des règles de politique

### 4.1 Lister les règles

```bash
curl -s http://localhost/api/v1/wall/policy/rules | jq
```

### 4.2 Ajouter une règle

**Bloquer un domaine** :
```bash
curl -X POST http://localhost/api/v1/wall/policy/rules \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $JWT" \
  -d '{
    "id": "block-malware-domain",
    "priority": 100,
    "match": {
      "dest_domain": "*.malware.example.com"
    },
    "action": "dns_sinkhole",
    "log_level": "alert"
  }'
```

**Quarantaine d'un device** :
```bash
curl -X POST http://localhost/api/v1/wall/policy/rules \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $JWT" \
  -d '{
    "id": "quarantine-suspect",
    "priority": 50,
    "match": {
      "source_mac": "aa:bb:cc:dd:ee:ff"
    },
    "action": "dhcp_quarantine",
    "log_level": "alert"
  }'
```

**Couper les connexions vers une IP** :
```bash
curl -X POST http://localhost/api/v1/wall/policy/rules \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $JWT" \
  -d '{
    "id": "rst-c2-server",
    "priority": 100,
    "match": {
      "dest_ip": "185.X.X.X/32",
      "protocol": "tcp"
    },
    "action": "tcp_rst",
    "log_level": "alert"
  }'
```

### 4.3 Supprimer une règle

```bash
curl -X DELETE http://localhost/api/v1/wall/policy/rules/block-malware-domain \
  -H "Authorization: Bearer $JWT"
```

---

## 5. Troubleshooting

### 5.1 DNS-R : Taux de succès faible

| Symptôme | Cause probable | Solution |
|----------|----------------|----------|
| Taux < 95% | SecuBox trop loin du client | Rapprocher du switch client |
| Taux < 95% | Latence réseau élevée | Vérifier liens réseau |
| Latence > 10ms | CPU saturé | Réduire nombre de règles |
| Aucune injection | Interface non promisc | `ip link set ethX promisc on` |
| Aucune injection | BPF filter trop restrictif | Vérifier config observation |

**Diagnostic** :
```bash
# Vérifier observation DNS
curl -s http://localhost/api/v1/wall/status | jq '.observation.protocols.dns'

# Vérifier injections DNS
curl -s http://localhost/api/v1/wall/metrics | jq '.injection.dns_race'

# Capture manuelle
tcpdump -i eth1 -n port 53 -c 10
```

### 5.2 DHCP-R : Client obtient IP légitime

| Symptôme | Cause probable | Solution |
|----------|----------------|----------|
| Client IP normale | Serveur DHCP plus rapide | Rapprocher SecuBox |
| Client IP normale | DHCP-R désactivé | Vérifier config injection |
| Pool épuisé | Trop de clients quarantaine | Étendre plage pool |

**Diagnostic** :
```bash
# Vérifier DHCP observé
curl -s http://localhost/api/v1/wall/status | jq '.observation.protocols.dhcp'

# Vérifier pool quarantaine
cat /etc/secubox/opad/active/profile.json | jq '.injection.dhcp_race.quarantine_pool'
```

### 5.3 RST-I : Connexion persiste

| Symptôme | Cause probable | Solution |
|----------|----------------|----------|
| Connexion active | Seq number hors fenêtre | Augmenter timing_window_ms |
| Taux < 85% | Connexions très rapides | Normal pour connexions courtes |
| RST ignoré | Middlebox filtre RST | Utiliser autre primitif |

### 5.4 ARP-R : Redirection échoue

| Symptôme | Cause probable | Solution |
|----------|----------------|----------|
| Pas de redirection | ARP statique sur client | Escalade requise |
| Redirection instable | Refresh trop lent | Réduire refresh_interval_s |
| Boucle ARP | Conflit avec autre outil | Vérifier pas de conflit |

---

## 6. Escalade vers in-path

### 6.1 Quand escalader

L'escalade est nécessaire quand OPAD ne peut pas traiter une menace :
- Client avec ARP statique
- Besoin de drop hard (pas de disruption)
- Inspection deep packet requise

### 6.2 Procédure d'escalade (INV-08)

```bash
# 1. Demander l'escalade
curl -X POST http://localhost/api/v1/wall/escalate \
  -H "Authorization: Bearer $JWT" \
  -d '{"reason": "ARP statique détecté sur device X"}'

# Réponse : demande enregistrée, attente confirmation
```

```bash
# 2. Confirmer l'escalade (action utilisateur explicite)
secubox-wall escalate --confirm --timeout 3600

# 3. Vérifier le mode
cat /etc/secubox/mode
# Attendu: opad-with-escalation (mode actif: in-path)
```

### 6.3 Révocation

```bash
# Retour immédiat à OPAD
curl -X DELETE http://localhost/api/v1/wall/escalate \
  -H "Authorization: Bearer $JWT"

# OU via CLI
secubox-wall escalate --revoke

# Vérification
cat /etc/secubox/mode
# Attendu: opad-only
```

---

## 7. Rollback et récupération (4R)

### 7.1 Actions 4R

| Action | Commande | Effet |
|--------|----------|-------|
| **Run** | `secubox-params swap --module opad` | Appliquer shadow → active |
| **Rollback** | `secubox-params rollback --module opad` | Annuler dernier swap |
| **Revert** | `secubox-params revert --module opad --target R2` | Restaurer snapshot R2 |
| **Rebuild** | `secubox-params rebuild --module opad` | Régénérer depuis défauts |

### 7.2 Snapshots disponibles

```bash
ls -la /etc/secubox/opad/rollback/
# R1/ : snapshot le plus récent
# R2/ : snapshot précédent
# R3/ : snapshot J-1
# R4/ : snapshot J-7
```

### 7.3 Restauration d'urgence

```bash
# En cas de problème avec le profil actif
secubox-params rollback --module opad

# Si le service ne démarre pas
systemctl stop secubox-wall
cp /etc/secubox/opad/rollback/R1/profile.json /etc/secubox/opad/active/
systemctl start secubox-wall
```

---

## 8. Monitoring et alertes

### 8.1 Métriques Prometheus

Métriques exposées sur `:9101/metrics` :

```prometheus
# Compteurs d'injection
secubox_opad_injection_total{primitive="dns_race",result="won"} 1234
secubox_opad_injection_total{primitive="dns_race",result="lost"} 12

# Compteurs d'observation
secubox_opad_observation_packets_total{protocol="dns"} 45000

# Latence
secubox_opad_injection_latency_ms{primitive="dns_race",quantile="0.99"} 1.5

# Règles matchées
secubox_opad_policy_matches_total{rule_id="block-malware",action="dns_sinkhole"} 89
```

### 8.2 Alertes recommandées

| Alerte | Condition | Sévérité | Action |
|--------|-----------|----------|--------|
| `OPADDegraded` | Taux succès < 90% pendant 5min | WARNING | Vérifier positionnement |
| `OPADInjectLostBurst` | > 100 courses perdues/min | CRITICAL | Investigation immédiate |
| `OPADObservationDown` | 0 paquets observés pendant 60s | CRITICAL | Vérifier interface |
| `OPADEscalationActive` | Mode in-path actif | INFO | Surveillance |

### 8.3 Dashboards

Dashboard Grafana disponible : `/var/lib/grafana/dashboards/secubox-opad.json`

---

## 9. Maintenance

### 9.1 Mise à jour

```bash
# Mise à jour du paquet
apt update && apt install secubox-wall

# Le service redémarre automatiquement
# Vérifier
systemctl status secubox-wall
```

### 9.2 Sauvegarde

```bash
# Sauvegarder le profil
cp -r /etc/secubox/opad /backup/secubox-opad-$(date +%Y%m%d)

# Sauvegarder les logs d'audit
cp /var/log/secubox/audit.log /backup/
```

### 9.3 Rotation des logs

La rotation est gérée par logrotate :
```
/etc/logrotate.d/secubox-wall
```

---

## 10. Contacts et support

- **Documentation** : https://docs.secubox.in/opad
- **Issues** : https://github.com/CyberMind-FR/secubox-deb/issues
- **Email** : support@cybermind.fr

---

*Document généré le 2026-05-12. Référence CM-OPS-OPAD-2026-05.*
```

- [ ] **Step 2: Commit OPAD-OPERATIONS.md**

```bash
git add doctrine/opad/OPAD-OPERATIONS.md
git commit -m "docs(opad): add operational guide OPAD-OPERATIONS.md

Comprehensive operations guide including:
- Installation and configuration
- Profile management (3-prong)
- Policy rules CRUD
- Troubleshooting per primitive
- Escalation procedures (INV-08)
- 4R rollback/recovery
- Monitoring and alerting

Refs: CM-OPS-OPAD-2026-05"
```

---

## Task 7: Final Validation and Integration

**Files:**
- Verify: All 5 documents created
- Update: `.claude/HISTORY.md`

- [ ] **Step 1: Verify all files exist**

```bash
ls -la doctrine/opad/
ls -la schemas/
ls -la common/secubox_core/opad/
```

Expected:
```
doctrine/opad/:
- OPAD.md
- CSPN.matrix.md
- OPAD-OPERATIONS.md

schemas/:
- opad-profile.schema.json

common/secubox_core/opad/:
- __init__.py
- models.py
```

- [ ] **Step 2: Run all tests**

```bash
PYTHONPATH=. pytest tests/test_opad_schema.py -v
```

Expected: All tests pass

- [ ] **Step 3: Validate JSON Schema**

```bash
python3 -c "
from jsonschema import Draft7Validator
import json

schema = json.load(open('schemas/opad-profile.schema.json'))
Draft7Validator.check_schema(schema)

# Test with minimal profile
profile = {
    'version': '2.4.0',
    'mode': 'opad-only',
    'observation': {'interfaces': ['eth0']},
    'injection': {},
    'policy': {}
}
from jsonschema import validate
validate(instance=profile, schema=schema)
print('All validations passed')
"
```

- [ ] **Step 4: Update HISTORY.md**

Append to `.claude/HISTORY.md`:

```markdown
## 2026-05-12 — Session 150: OPAD Doctrine Documents

### Objective
Create 5 doctrinal documents for OPAD (Off-Path Active Defense) v2.4.0.

### Completed
- **doctrine/opad/OPAD.md**: Core doctrine (~500 lines)
  - 4 principles (PROP-P1 to P4)
  - 8 invariants (INV-01 to INV-08)
  - 4 injection primitives (DNS-R, DHCP-R, RST-I, ARP-R)
  - 3 operating modes

- **doctrine/opad/CSPN.matrix.md**: ANSSI matrix (~400 lines)
  - 36 threats across 6 categories
  - 72% active coverage
  - 5 explicitly excluded capabilities

- **schemas/opad-profile.schema.json**: JSON Schema (~300 lines)
  - Draft-07 compliant
  - 3-prong profile structure

- **common/secubox_core/opad/models.py**: Pydantic models (~250 lines)
  - Equivalent to JSON Schema
  - FastAPI integration ready

- **doctrine/opad/OPAD-OPERATIONS.md**: Operations guide (~400 lines)
  - Installation, configuration
  - Troubleshooting
  - Escalation procedures

### Reference
CM-WALL-OPAD-2026-05
```

- [ ] **Step 5: Final commit**

```bash
git add .claude/HISTORY.md
git commit -m "docs: update HISTORY.md with OPAD doctrine session

Session 150: Created 5 OPAD doctrinal documents.
Reference: CM-WALL-OPAD-2026-05"
```

- [ ] **Step 6: Summary**

```bash
echo "=== OPAD Doctrine Documents Created ==="
wc -l doctrine/opad/*.md schemas/*.json common/secubox_core/opad/*.py
git log --oneline -10
```

---

## Self-Review Checklist

- [x] **Spec coverage**: All 5 documents from spec are implemented
- [x] **Placeholder scan**: No TBD/TODO in plan
- [x] **Type consistency**: OPADProfile, OPADMode, PolicyAction consistent across files
- [x] **File paths**: All paths match spec exactly
- [x] **Code completeness**: All code blocks contain actual implementation
