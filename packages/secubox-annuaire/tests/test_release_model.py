# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
import pytest
from pydantic import ValidationError
from annuaire.model import (Op, RINGS, Artifact, Evolution, RingState, RingAssign)

DID = "did:plc:" + "a" * 32


def test_ops_and_rings():
    assert Op.RELEASE_PROMOTE == "release_promote"
    assert Op.RING_ASSIGN == "ring_assign"
    assert RINGS == ["draft", "internal", "published"]


def test_evolution_needs_artifact_and_forbids_extra():
    e = Evolution(evo_id="e1", artifacts=[Artifact(kind="deb", name="secubox-dpi",
                  version="1.2.3", hash="ab", arch="arm64")], notes="x", issued_by=DID)
    assert e.artifacts[0].name == "secubox-dpi"
    with pytest.raises(ValidationError):
        Evolution(evo_id="e1", artifacts=[], notes="x", issued_by=DID)
    with pytest.raises(ValidationError):
        Evolution(evo_id="e1", artifacts=[Artifact(kind="deb", name="x", version="1",
                  hash="ab")], notes="x", issued_by=DID, sneaky=True)


def test_ringstate_and_assign_reject_bad_ring():
    RingState(evo_id="e1", ring="internal", issued_by=DID)
    RingAssign(box_did=DID, ring="published", issued_by=DID)
    with pytest.raises(ValidationError):
        RingState(evo_id="e1", ring="prod", issued_by=DID)
    with pytest.raises(ValidationError):
        RingAssign(box_did=DID, ring="prod", issued_by=DID)


def test_artifact_kind_validated():
    with pytest.raises(ValidationError):
        Artifact(kind="rpm", name="x", version="1", hash="ab")
