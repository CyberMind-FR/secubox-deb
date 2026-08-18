# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: OPAD Pydantic Models
CyberMind — https://cybermind.fr
Author: Gérald Kerma <gandalf@gk2.net>
License: Proprietary / ANSSI CSPN candidate

Pydantic v2 models for OPAD v2.4.0 configuration profiles.
"""

import re
from datetime import datetime
from enum import Enum
from typing import List, Optional, Dict, Any

from pydantic import BaseModel, Field, field_validator, ConfigDict


# ==================== ENUMS ====================

class OPADMode(str, Enum):
    """Global OPAD operation mode."""
    OBSERVE = "observe"
    ENFORCE = "enforce"


class PolicyAction(str, Enum):
    """Policy rule action types."""
    ALLOW = "allow"
    OBSERVE = "observe"
    DNS_NXDOMAIN = "dns_nxdomain"
    DNS_SINKHOLE = "dns_sinkhole"
    DNS_REDIRECT = "dns_redirect"
    DHCP_QUARANTINE = "dhcp_quarantine"
    TCP_RST = "tcp_rst"
    ARP_REDIRECT = "arp_redirect"


class DefaultAction(str, Enum):
    """Default action for unmatched traffic."""
    ALLOW = "allow"
    OBSERVE = "observe"
    DISRUPT = "disrupt"


class LogLevel(str, Enum):
    """Log level for rules and events."""
    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"


class Protocol(str, Enum):
    """Network protocols."""
    DNS = "dns"
    DHCP = "dhcp"
    TCP = "tcp"
    ARP = "arp"


class DNSRaceMode(str, Enum):
    """DNS race injection modes."""
    NXDOMAIN = "nxdomain"
    SINKHOLE = "sinkhole"
    REDIRECT_CAPTIVE = "redirect_captive"


class ProtocolMatch(str, Enum):
    """Protocol match for policy rules."""
    TCP = "tcp"
    UDP = "udp"
    ICMP = "icmp"
    ANY = "any"


# ==================== VALIDATORS ====================

MAC_PATTERN = re.compile(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")


def validate_mac_address(mac: str) -> str:
    """Validate MAC address format."""
    if not MAC_PATTERN.match(mac):
        raise ValueError(f"Invalid MAC address format: {mac}")
    return mac


# ==================== BROCHE 1: OBSERVATION ====================

class ProtocolsConfig(BaseModel):
    """Protocol observation configuration."""
    model_config = ConfigDict(extra="forbid")

    dns: bool = True
    dhcp: bool = True
    arp: bool = True
    tcp: bool = False


class FingerprintingConfig(BaseModel):
    """Device fingerprinting configuration."""
    model_config = ConfigDict(extra="forbid")

    dhcp_fingerprint: bool = True
    ja3: bool = Field(default=False, description="TLS JA3 fingerprinting")
    ja4: bool = Field(default=False, description="TLS JA4 fingerprinting")
    user_agent: bool = Field(default=False, description="HTTP User-Agent parsing")


class ObservationConfig(BaseModel):
    """Broche 1: Observation configuration."""
    model_config = ConfigDict(extra="forbid")

    interfaces: List[str] = Field(
        ...,
        min_length=1,
        description="Network interfaces to observe"
    )
    bpf_filter: Optional[str] = Field(
        default=None,
        description="Optional BPF filter for packet capture"
    )
    protocols: ProtocolsConfig = Field(default_factory=ProtocolsConfig)
    fingerprinting: FingerprintingConfig = Field(default_factory=FingerprintingConfig)

    @field_validator("interfaces")
    @classmethod
    def validate_interfaces(cls, v: List[str]) -> List[str]:
        """Validate interface names."""
        if not v:
            raise ValueError("At least one interface is required")
        interface_pattern = re.compile(r"^[a-z0-9]+$")
        for iface in v:
            if not interface_pattern.match(iface):
                raise ValueError(f"Invalid interface name: {iface}")
        return v


# ==================== BROCHE 2: INJECTION ====================

class DNSRaceConfig(BaseModel):
    """DNS race injection configuration."""
    model_config = ConfigDict(extra="forbid")

    enabled: bool = False
    target_success_rate: float = Field(
        default=0.99,
        ge=0.9,
        le=1.0,
        description="Target success rate for winning DNS race (0.9-1.0)"
    )
    modes: List[DNSRaceMode] = Field(
        default_factory=list,
        description="Enabled DNS race modes"
    )
    sinkhole_ip: str = Field(
        default="127.0.0.1",
        description="IP address for sinkhole mode"
    )
    ttl: int = Field(
        default=60,
        ge=0,
        le=3600,
        description="TTL for injected DNS responses (seconds)"
    )


class QuarantinePool(BaseModel):
    """DHCP quarantine IP pool configuration."""
    model_config = ConfigDict(extra="forbid")

    start: str = Field(..., description="Start of quarantine IP pool")
    end: str = Field(..., description="End of quarantine IP pool")
    lease_time: int = Field(
        default=300,
        ge=60,
        le=86400,
        description="Lease time in seconds"
    )
    gateway: str = Field(..., description="Gateway IP for quarantine network")


class DHCPRaceConfig(BaseModel):
    """DHCP race injection configuration."""
    model_config = ConfigDict(extra="forbid")

    enabled: bool = False
    target_success_rate: float = Field(
        default=0.95,
        ge=0.9,
        le=1.0,
        description="Target success rate for winning DHCP race"
    )
    quarantine_pool: Optional[QuarantinePool] = None


class RSTInjectConfig(BaseModel):
    """TCP RST injection configuration."""
    model_config = ConfigDict(extra="forbid")

    enabled: bool = False
    target_success_rate: float = Field(
        default=0.90,
        ge=0.85,
        le=1.0,
        description="Target success rate for RST injection (min 0.85)"
    )
    double_ended: bool = Field(
        default=True,
        description="Send RST to both client and server"
    )
    timing_window_ms: int = Field(
        default=10,
        ge=1,
        le=100,
        description="Timing window for RST injection (milliseconds)"
    )


class ARPRedirectConfig(BaseModel):
    """ARP redirection configuration."""
    model_config = ConfigDict(extra="forbid")

    enabled: bool = False
    target_success_rate: float = Field(
        default=0.98,
        ge=0.95,
        le=1.0,
        description="Target success rate for ARP redirection (min 0.95)"
    )
    refresh_interval_s: int = Field(
        default=60,
        ge=10,
        le=300,
        description="ARP table refresh interval (seconds)"
    )
    captive_mac: Optional[str] = Field(
        default=None,
        description="MAC address for captive portal gateway"
    )

    @field_validator("captive_mac")
    @classmethod
    def validate_captive_mac(cls, v: Optional[str]) -> Optional[str]:
        """Validate MAC address format."""
        if v is not None:
            return validate_mac_address(v)
        return v


class InjectionConfig(BaseModel):
    """Broche 2: Injection (perturbation) configuration."""
    model_config = ConfigDict(extra="forbid")

    dns_race: Optional[DNSRaceConfig] = None
    dhcp_race: Optional[DHCPRaceConfig] = None
    rst_inject: Optional[RSTInjectConfig] = None
    arp_redirect: Optional[ARPRedirectConfig] = None


# ==================== BROCHE 3: POLICY ====================

class RuleMatch(BaseModel):
    """Policy rule match conditions (all conditions are AND-ed)."""
    model_config = ConfigDict(extra="forbid")

    source_mac: Optional[str] = Field(default=None, description="Source MAC address")
    dest_domain: Optional[str] = Field(
        default=None,
        description="Destination domain (supports wildcards: *.example.com)"
    )
    dest_ip: Optional[str] = Field(
        default=None,
        description="Destination IP address or CIDR"
    )
    protocol: ProtocolMatch = Field(default=ProtocolMatch.ANY)
    mind_score_above: Optional[float] = Field(
        default=None,
        ge=0,
        le=1,
        description="Trigger if MIND adversarial score above threshold"
    )
    device_authorized: Optional[bool] = Field(
        default=None,
        description="Match only authorized/unauthorized devices"
    )

    @field_validator("source_mac")
    @classmethod
    def validate_source_mac(cls, v: Optional[str]) -> Optional[str]:
        """Validate MAC address format."""
        if v is not None:
            return validate_mac_address(v)
        return v


class PolicyRule(BaseModel):
    """Policy rule configuration."""
    model_config = ConfigDict(extra="forbid")

    id: str = Field(..., min_length=1, max_length=64, description="Unique rule identifier")
    priority: int = Field(
        ...,
        ge=0,
        le=9999,
        description="Rule priority (0=highest, 9999=lowest)"
    )
    match: Optional[RuleMatch] = None
    action: PolicyAction
    log_level: LogLevel = LogLevel.INFO


class EscalationConfig(BaseModel):
    """Policy escalation configuration."""
    model_config = ConfigDict(extra="forbid")

    allow_in_path: bool = Field(
        default=True,
        description="Allow temporary escalation to allow mode"
    )
    require_explicit_consent: bool = Field(
        default=True,
        description="Require user consent for escalation"
    )
    auto_revert_after_s: int = Field(
        default=300,
        ge=60,
        description="Auto-revert escalation after N seconds (min 60)"
    )
    audit_all_escalations: bool = Field(
        default=True,
        description="Log all escalation events to audit log"
    )


class PolicyConfig(BaseModel):
    """Broche 3: Policy configuration."""
    model_config = ConfigDict(extra="forbid")

    default_action: DefaultAction
    rules: List[PolicyRule] = Field(default_factory=list)
    escalation: Optional[EscalationConfig] = None


# ==================== MAIN PROFILE ====================

class OPADProfile(BaseModel):
    """OPAD v2.4.0 complete configuration profile."""
    model_config = ConfigDict(extra="forbid")

    version: str = Field(
        ...,
        pattern=r"^\d+\.\d+\.\d+$",
        description="Schema version (semver)"
    )
    mode: OPADMode
    observation: ObservationConfig
    injection: InjectionConfig
    policy: PolicyConfig


# ==================== EVENT MODELS ====================

class OPADEvent(BaseModel):
    """OPAD event record for logging and audit."""
    model_config = ConfigDict(extra="forbid")

    timestamp: datetime
    event_type: str = Field(..., description="Event type (e.g., 'dns_race', 'policy_match')")
    primitive: Optional[str] = Field(
        default=None,
        description="Injection primitive used (dns_race, dhcp_race, rst_inject, arp_redirect)"
    )
    source_mac: Optional[str] = None
    target: Optional[str] = Field(
        default=None,
        description="Target of action (domain, IP, etc.)"
    )
    action_taken: PolicyAction
    success: bool
    details: Optional[Dict[str, Any]] = Field(default_factory=dict)

    @field_validator("source_mac")
    @classmethod
    def validate_source_mac(cls, v: Optional[str]) -> Optional[str]:
        """Validate MAC address format."""
        if v is not None:
            return validate_mac_address(v)
        return v


class OPADInjectResult(BaseModel):
    """Result of an OPAD injection primitive."""
    model_config = ConfigDict(extra="forbid")

    primitive: str = Field(..., description="Injection primitive name")
    target: str = Field(..., description="Target (domain, IP, MAC, etc.)")
    race_won: bool = Field(..., description="Whether the race was won")
    latency_ms: Optional[float] = Field(default=None, description="Latency in milliseconds")
    event_id: Optional[str] = Field(default=None, description="Reference to OPADEvent")
