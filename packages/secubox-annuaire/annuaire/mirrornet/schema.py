# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""
SecuBox-Deb :: annuaire :: mirrornet — profile schema (Pydantic v2)
CyberMind — https://cybermind.fr

Two SEPARATE schemas, merged explicitly:

  NetworkProfile — inherited from the network, SIGNED and PROPAGATED (it is the
    payload of a ConfigBlob revision chained through annuaire.log.Journal).

  NodeOverride   — LOCAL to the node, NEVER propagated (identity, role, radio,
    wg listen port, a keystore REFERENCE — never a key).

`effective(net, node)` is the explicit merge that the generators consume. No
implicit inheritance, no hidden defaults across the boundary: what is inherited
and what is local is spelled out by which model a field lives in.

Invariant enforced HERE (schema-time rejection, named error + test):
  - `witness.encrypt_payload = true` is REFUSED. Witness bearers (Meshtastic,
    AX.25) carry fingerprints and signatures IN CLEAR; on amateur bands
    encryption is illegal, and the anchoring doctrine assumes a PUBLIC channel.

Deliberately ABSENT (invariant #4): no `anygw`-equivalent. LibreMesh's shared
MAC/IP breaks per-peer attribution and is incompatible with did:plc and the L3
twins. If a reason to add it ever appears, RAISE it — do not implement it.
"""
from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, ConfigDict, Field, field_validator

DID_PLC_PATTERN = r"^did:plc:[0-9a-f]{32}$"


class L2Kind(str, Enum):
    """Layer-2 mesh technology. Only batman-adv today; enum keeps it explicit."""

    BATADV = "batadv"


class L3Kind(str, Enum):
    """Layer-3 routing authority. babeld is the SINGLE routing authority
    (see invariant #5: WireGuard interfaces carry `Table = off`)."""

    BABELD = "babeld"


class TransportKind(str, Enum):
    """A parallel relay transport carried by the mesh."""

    WG = "wg"          # WireGuard tunnel (service peers)
    BATADV = "batadv"  # native batman-adv L2 link
    WITNESS = "witness"  # low-bandwidth witness bearer (Meshtastic / AX.25)


class WitnessBearer(str, Enum):
    """Out-of-band anchoring carrier. Public, cleartext (see encrypt_payload)."""

    MESHTASTIC = "meshtastic"
    AX25 = "ax25"


class NodeRole(str, Enum):
    """A node is either a service peer (full L2/L3 participant) or a witness
    (anchoring only — no wg-quick, no batman-adv; see invariant #2)."""

    SERVICE = "service"
    WITNESS = "witness"


class MeshCfg(BaseModel):
    """L2/L3 technologies and the mesh interfaces they run over."""

    model_config = ConfigDict(extra="forbid")

    l2: L2Kind
    l3: L3Kind
    ifaces: list[str] = Field(..., min_length=1)


class Addressing(BaseModel):
    """ULA addressing plan for the mesh."""

    model_config = ConfigDict(extra="forbid")

    prefix: str = Field(..., description="ULA prefix, e.g. fd00:secu::/48")


class Transport(BaseModel):
    """One relay transport with its priority (lower prio = preferred)."""

    model_config = ConfigDict(extra="forbid")

    kind: TransportKind
    prio: int = Field(..., ge=0)
    enabled: bool = True


class WitnessCfg(BaseModel):
    """Witness anchoring configuration. The payload is ALWAYS cleartext."""

    model_config = ConfigDict(extra="forbid")

    bearer: WitnessBearer
    encrypt_payload: bool = False

    @field_validator("encrypt_payload")
    @classmethod
    def _reject_encrypt(cls, v: bool) -> bool:
        if v:
            raise ValueError(
                "INVARIANT witness.encrypt_payload: witness bearers (Meshtastic, "
                "AX.25) carry fingerprints and signatures IN CLEAR; encryption is "
                "illegal on amateur bands and the anchoring doctrine assumes a "
                "PUBLIC channel — encrypt_payload must be false"
            )
        return v


class NetworkProfile(BaseModel):
    """Inherited from the network, SIGNED and PROPAGATED.

    This is exactly the object carried inside a ConfigBlob.payload and chained
    through the journal. `rev` is the monotonic revision (maps to
    ConfigBlob.version); the BLAKE2b chain over the parent revision is computed
    from `canonical_bytes(NetworkProfile)` (see mirrornet.canonical, step 2).
    """

    model_config = ConfigDict(extra="forbid")

    profile: str = Field(..., min_length=1, description="network profile name")
    rev: int = Field(..., ge=0, description="monotonic revision; higher supersedes")
    mesh: MeshCfg
    addressing: Addressing
    transports: list[Transport] = Field(..., min_length=1)
    witness: WitnessCfg


class WgLocal(BaseModel):
    """Node-local WireGuard settings (never propagated)."""

    model_config = ConfigDict(extra="forbid")

    listen_port: int = Field(..., ge=1, le=65535)


class NodeOverride(BaseModel):
    """LOCAL to the node, NEVER propagated. Carries identity, role, radio, the
    wg listen port and a keystore REFERENCE — never a private key."""

    model_config = ConfigDict(extra="forbid")

    node: str = Field(..., min_length=1, description="node name")
    did: str = Field(..., pattern=DID_PLC_PATTERN)
    role: NodeRole
    radio: dict[str, object] | None = Field(
        default=None, description="opaque radio settings (channel, txpower, …)"
    )
    wg: WgLocal | None = Field(
        default=None, description="node-local wg settings; required for service peers"
    )
    key_ref: str = Field(
        ...,
        min_length=1,
        description="opaque reference into the ROOT keystore; resolved at unit "
        "start. NEVER a key. (invariant #3)",
    )


class EffectiveProfile(BaseModel):
    """The explicit merge of the inherited network profile and the node
    override. The generators consume THIS — they never read the two halves
    independently, so the merge is the single, auditable combination point."""

    model_config = ConfigDict(extra="forbid")

    network: NetworkProfile
    node: NodeOverride


def effective(net: NetworkProfile, node: NodeOverride) -> EffectiveProfile:
    """Explicit merge: inherited network config + local node override.

    The two field sets are DISJOINT by design (network config vs node identity/
    role/radio/wg/key), so the merge is a deterministic combination, not a
    value-clobbering override. If a future need arises for the node to override
    a specific inherited value (e.g. locally disable one transport), add it as
    an explicit optional field on NodeOverride and apply it HERE — never as a
    hidden precedence rule.
    """
    return EffectiveProfile(network=net, node=node)
