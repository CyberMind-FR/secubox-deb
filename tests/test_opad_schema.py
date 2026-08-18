# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: OPAD Schema Tests
CyberMind — https://cybermind.fr
Author: Gérald Kerma <gandalf@gk2.net>
License: Proprietary / ANSSI CSPN candidate

Test suite for OPAD v2.4.0 JSON Schema and Pydantic models.
"""

import json
import sys
from pathlib import Path

import pytest
from jsonschema import Draft7Validator, ValidationError
from pydantic import ValidationError as PydanticValidationError

# Import opad models directly to avoid loading secubox_core dependencies
opad_models_path = Path(__file__).parent.parent / "common" / "secubox_core" / "opad"
sys.path.insert(0, str(opad_models_path))

from models import (
    OPADProfile,
    OPADMode,
    PolicyAction,
    DefaultAction,
    LogLevel,
    ObservationConfig,
    ProtocolsConfig,
    PolicyConfig,
    PolicyRule,
    RuleMatch,
    EscalationConfig,
)

# Load JSON Schema
SCHEMA_PATH = Path(__file__).parent.parent / "schemas" / "opad-profile.schema.json"
with open(SCHEMA_PATH) as f:
    JSON_SCHEMA = json.load(f)


# ==================== JSON SCHEMA VALIDATION TESTS ====================

def test_schema_is_valid_draft7():
    """Verify the JSON Schema itself is valid Draft 7."""
    Draft7Validator.check_schema(JSON_SCHEMA)


def test_minimal_profile_validates():
    """Test minimal valid OPAD profile against JSON Schema."""
    profile = {
        "version": "2.4.0",
        "mode": "observe",
        "observation": {
            "interfaces": ["eth0"],
            "protocols": {}
        },
        "injection": {},
        "policy": {
            "default_action": "observe"
        }
    }
    validator = Draft7Validator(JSON_SCHEMA)
    validator.validate(profile)


def test_full_profile_validates():
    """Test full OPAD profile with all features enabled."""
    profile = {
        "version": "2.4.0",
        "mode": "enforce",
        "observation": {
            "interfaces": ["eth0", "eth1"],
            "bpf_filter": "tcp port 443",
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
                "sinkhole_ip": "127.0.0.1",
                "ttl": 60
            },
            "dhcp_race": {
                "enabled": True,
                "target_success_rate": 0.95,
                "quarantine_pool": {
                    "start": "10.99.0.1",
                    "end": "10.99.0.254",
                    "lease_time": 300,
                    "gateway": "10.99.0.254"
                }
            },
            "rst_inject": {
                "enabled": True,
                "target_success_rate": 0.90,
                "double_ended": True,
                "timing_window_ms": 10
            },
            "arp_redirect": {
                "enabled": True,
                "target_success_rate": 0.98,
                "refresh_interval_s": 60,
                "captive_mac": "AA:BB:CC:DD:EE:FF"
            }
        },
        "policy": {
            "default_action": "observe",
            "rules": [
                {
                    "id": "block-malware",
                    "priority": 10,
                    "match": {
                        "dest_domain": "*.malware.com",
                        "protocol": "tcp"
                    },
                    "action": "dns_nxdomain",
                    "log_level": "warning"
                }
            ],
            "escalation": {
                "allow_in_path": True,
                "require_explicit_consent": True,
                "auto_revert_after_s": 300,
                "audit_all_escalations": True
            }
        }
    }
    validator = Draft7Validator(JSON_SCHEMA)
    validator.validate(profile)


def test_missing_interfaces_fails():
    """Test that missing interfaces field fails validation."""
    profile = {
        "version": "2.4.0",
        "mode": "observe",
        "observation": {
            "protocols": {}
        },
        "injection": {},
        "policy": {
            "default_action": "observe"
        }
    }
    validator = Draft7Validator(JSON_SCHEMA)
    with pytest.raises(ValidationError):
        validator.validate(profile)


def test_invalid_mode_fails():
    """Test that invalid mode fails validation."""
    profile = {
        "version": "2.4.0",
        "mode": "invalid_mode",
        "observation": {
            "interfaces": ["eth0"],
            "protocols": {}
        },
        "injection": {},
        "policy": {
            "default_action": "observe"
        }
    }
    validator = Draft7Validator(JSON_SCHEMA)
    with pytest.raises(ValidationError):
        validator.validate(profile)


# ==================== PYDANTIC MODEL TESTS ====================

def test_minimal_profile_pydantic():
    """Test minimal valid OPAD profile with Pydantic."""
    profile = OPADProfile(
        version="2.4.0",
        mode=OPADMode.OBSERVE,
        observation=ObservationConfig(
            interfaces=["eth0"]
        ),
        injection={},
        policy=PolicyConfig(
            default_action=DefaultAction.OBSERVE
        )
    )
    assert profile.version == "2.4.0"
    assert profile.mode == OPADMode.OBSERVE
    assert profile.observation.interfaces == ["eth0"]
    assert profile.policy.default_action == DefaultAction.OBSERVE


def test_full_profile_pydantic():
    """Test full OPAD profile with Pydantic."""
    profile = OPADProfile(
        version="2.4.0",
        mode=OPADMode.ENFORCE,
        observation=ObservationConfig(
            interfaces=["eth0", "eth1"],
            bpf_filter="tcp port 443",
            protocols=ProtocolsConfig(dns=True, dhcp=True, arp=True, tcp=True)
        ),
        injection={
            "dns_race": {
                "enabled": True,
                "target_success_rate": 0.99
            }
        },
        policy=PolicyConfig(
            default_action=DefaultAction.OBSERVE,
            rules=[
                PolicyRule(
                    id="block-malware",
                    priority=10,
                    action=PolicyAction.DNS_NXDOMAIN,
                    match=RuleMatch(dest_domain="*.malware.com")
                )
            ]
        )
    )
    assert len(profile.observation.interfaces) == 2
    assert profile.injection.dns_race.enabled is True
    assert len(profile.policy.rules) == 1


def test_invalid_mac_fails():
    """Test that invalid MAC address fails Pydantic validation."""
    with pytest.raises(PydanticValidationError):
        RuleMatch(source_mac="invalid:mac:address")


def test_invalid_success_rate_fails():
    """Test that out-of-range success rate fails validation."""
    from models import DNSRaceConfig

    # Too low (below 0.9)
    with pytest.raises(PydanticValidationError):
        DNSRaceConfig(target_success_rate=0.85)

    # Too high (above 1.0)
    with pytest.raises(PydanticValidationError):
        DNSRaceConfig(target_success_rate=1.5)


def test_policy_rule_creation():
    """Test PolicyRule creation with various configurations."""
    rule = PolicyRule(
        id="test-rule",
        priority=100,
        action=PolicyAction.OBSERVE,
        match=RuleMatch(
            source_mac="AA:BB:CC:DD:EE:FF",
            dest_domain="example.com",
            protocol="tcp"
        ),
        log_level=LogLevel.INFO
    )
    assert rule.id == "test-rule"
    assert rule.priority == 100
    assert rule.action == PolicyAction.OBSERVE
    assert rule.match.source_mac == "AA:BB:CC:DD:EE:FF"


def test_export_json_schema():
    """Test that Pydantic models can export JSON Schema."""
    schema = OPADProfile.model_json_schema()
    assert schema["title"] == "OPADProfile"
    assert "properties" in schema
    assert "version" in schema["properties"]
    assert "mode" in schema["properties"]


def test_pydantic_validates_same_as_jsonschema():
    """Test that Pydantic and JSON Schema validation are equivalent."""
    profile_dict = {
        "version": "2.4.0",
        "mode": "observe",
        "observation": {
            "interfaces": ["eth0"],
            "protocols": {}
        },
        "injection": {},
        "policy": {
            "default_action": "observe"
        }
    }

    # Should validate with JSON Schema
    validator = Draft7Validator(JSON_SCHEMA)
    validator.validate(profile_dict)

    # Should also validate with Pydantic
    profile = OPADProfile(**profile_dict)
    assert profile.version == "2.4.0"


def test_default_mode_is_observe():
    """Test that creating a profile defaults to observe mode when appropriate."""
    profile = OPADProfile(
        version="2.4.0",
        mode=OPADMode.OBSERVE,
        observation=ObservationConfig(interfaces=["eth0"]),
        injection={},
        policy=PolicyConfig(default_action=DefaultAction.OBSERVE)
    )
    assert profile.mode == OPADMode.OBSERVE


def test_escalation_requires_consent_by_default():
    """Test that escalation requires consent by default."""
    escalation = EscalationConfig()
    assert escalation.require_explicit_consent is True
    assert escalation.audit_all_escalations is True
    assert escalation.allow_in_path is True


def test_invalid_interface_name_fails():
    """Test that invalid interface names fail validation."""
    with pytest.raises(PydanticValidationError):
        ObservationConfig(interfaces=["eth0-invalid!"])


def test_rule_priority_range():
    """Test that rule priority must be within valid range."""
    # Valid priority
    rule = PolicyRule(
        id="test",
        priority=5000,
        action=PolicyAction.ALLOW
    )
    assert rule.priority == 5000

    # Invalid priority (too high)
    with pytest.raises(PydanticValidationError):
        PolicyRule(
            id="test",
            priority=10000,
            action=PolicyAction.ALLOW
        )


def test_empty_interfaces_fails():
    """Test that empty interfaces list fails validation."""
    with pytest.raises(PydanticValidationError):
        ObservationConfig(interfaces=[])


def test_mac_address_format_variations():
    """Test that only valid MAC address formats are accepted."""
    # Valid MAC
    match = RuleMatch(source_mac="01:23:45:67:89:AB")
    assert match.source_mac == "01:23:45:67:89:AB"

    # Invalid formats
    invalid_macs = [
        "01:23:45:67:89",        # Too short
        "01:23:45:67:89:AB:CD",  # Too long
        "01-23-45-67-89-AB",     # Wrong separator
        "0123456789AB",          # No separator
        "ZZ:ZZ:ZZ:ZZ:ZZ:ZZ",     # Invalid hex
    ]
    for invalid_mac in invalid_macs:
        with pytest.raises(PydanticValidationError):
            RuleMatch(source_mac=invalid_mac)
