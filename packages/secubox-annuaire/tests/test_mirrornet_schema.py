# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Tests — MirrorNet profile schema (step 1)."""
from __future__ import annotations

import pytest
from pydantic import ValidationError

from annuaire.mirrornet.schema import (
    Addressing,
    EffectiveProfile,
    MeshCfg,
    NetworkProfile,
    NodeOverride,
    NodeRole,
    Transport,
    WgLocal,
    WitnessCfg,
    effective,
)

DID = "did:plc:" + "0" * 32


def _net(**over: object) -> NetworkProfile:
    base = dict(
        profile="gondwana",
        rev=3,
        mesh=MeshCfg(l2="batadv", l3="babeld", ifaces=["bat0"]),
        addressing=Addressing(prefix="fd00:secu::/48"),
        transports=[Transport(kind="wg", prio=10, enabled=True)],
        witness=WitnessCfg(bearer="meshtastic", encrypt_payload=False),
    )
    base.update(over)
    return NetworkProfile(**base)  # type: ignore[arg-type]


def _node(**over: object) -> NodeOverride:
    base: dict[str, object] = dict(
        node="alpha", did=DID, role=NodeRole.SERVICE,
        wg=WgLocal(listen_port=51822), key_ref="keystore://mirrornet/alpha",
    )
    base.update(over)
    return NodeOverride(**base)  # type: ignore[arg-type]


def test_valid_network_and_node_parse() -> None:
    net = _net()
    node = _node()
    assert net.rev == 3 and net.mesh.l2.value == "batadv"
    assert node.role is NodeRole.SERVICE and node.key_ref.startswith("keystore://")


def test_extra_keys_forbidden_on_both() -> None:
    with pytest.raises(ValidationError):
        NetworkProfile(**{**_net().model_dump(), "surprise": 1})  # type: ignore[arg-type]
    with pytest.raises(ValidationError):
        NodeOverride(**{**_node().model_dump(), "secret_key": "AAA"})  # type: ignore[arg-type]


def test_invariant_encrypt_payload_rejected_with_named_error() -> None:
    with pytest.raises(ValidationError) as ei:
        WitnessCfg(bearer="ax25", encrypt_payload=True)
    assert "witness.encrypt_payload" in str(ei.value)


def test_did_plc_pattern_enforced() -> None:
    with pytest.raises(ValidationError):
        _node(did="did:plc:NOTHEX")
    with pytest.raises(ValidationError):
        _node(did="plc:" + "0" * 32)


def test_role_enum_only_service_or_witness() -> None:
    with pytest.raises(ValidationError):
        _node(role="router")  # type: ignore[arg-type]
    assert _node(role=NodeRole.WITNESS).role is NodeRole.WITNESS


def test_no_anygw_field_anywhere_invariant_4() -> None:
    # The shared-gateway concept is deliberately absent; extra=forbid means any
    # attempt to smuggle it in is rejected rather than silently accepted.
    assert "anygw" not in NetworkProfile.model_fields
    assert "anygw" not in NodeOverride.model_fields
    with pytest.raises(ValidationError):
        NetworkProfile(**{**_net().model_dump(), "anygw": True})  # type: ignore[arg-type]


def test_transports_and_ifaces_non_empty() -> None:
    with pytest.raises(ValidationError):
        _net(transports=[])
    with pytest.raises(ValidationError):
        MeshCfg(l2="batadv", l3="babeld", ifaces=[])


def test_effective_is_explicit_combination() -> None:
    net, node = _net(), _node()
    eff = effective(net, node)
    assert isinstance(eff, EffectiveProfile)
    assert eff.network is net and eff.node is node
