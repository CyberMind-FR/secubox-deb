# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: OPAD (Observe-Perturb-Apply-Decide) Models
CyberMind — https://cybermind.fr
Author: Gérald Kerma <gandalf@gk2.net>
License: Proprietary / ANSSI CSPN candidate

OPAD v2.4.0 Pydantic models for 3-prong configuration:
- Broche 1: Observation (passive monitoring)
- Broche 2: Injection (perturbation primitives)
- Broche 3: Policy (decision engine)
"""

from .models import (
    # Enums
    OPADMode,
    PolicyAction,
    DefaultAction,
    LogLevel,
    Protocol,
    DNSRaceMode,
    ProtocolMatch,

    # Observation (Broche 1)
    ProtocolsConfig,
    FingerprintingConfig,
    ObservationConfig,

    # Injection (Broche 2)
    DNSRaceConfig,
    QuarantinePool,
    DHCPRaceConfig,
    RSTInjectConfig,
    ARPRedirectConfig,
    InjectionConfig,

    # Policy (Broche 3)
    RuleMatch,
    PolicyRule,
    EscalationConfig,
    PolicyConfig,

    # Main Profile
    OPADProfile,

    # Event Models
    OPADEvent,
    OPADInjectResult,
)

__all__ = [
    # Enums
    "OPADMode",
    "PolicyAction",
    "DefaultAction",
    "LogLevel",
    "Protocol",
    "DNSRaceMode",
    "ProtocolMatch",

    # Observation
    "ProtocolsConfig",
    "FingerprintingConfig",
    "ObservationConfig",

    # Injection
    "DNSRaceConfig",
    "QuarantinePool",
    "DHCPRaceConfig",
    "RSTInjectConfig",
    "ARPRedirectConfig",
    "InjectionConfig",

    # Policy
    "RuleMatch",
    "PolicyRule",
    "EscalationConfig",
    "PolicyConfig",

    # Main
    "OPADProfile",

    # Events
    "OPADEvent",
    "OPADInjectResult",
]
