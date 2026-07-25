# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
import sys; from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]; sys.path.insert(0, str(ROOT))
from annuaire.model import Op, Grant, LAYER_ORDER, NON_DELEGATABLE, ConfigBlob


def test_grant_ops_exist():
    assert Op.GRANT_ISSUE == "grant_issue" and Op.GRANT_REVOKE == "grant_revoke"


def test_layer_order_and_non_delegatable():
    assert LAYER_ORDER == ["baseline", "override", "local"]
    assert "auth" in NON_DELEGATABLE and "secrets" in NON_DELEGATABLE


def test_grant_model_forbids_extra():
    g = Grant(grant_id="g1", center_did="did:plc:"+("a"*32), capability="config",
              scope="firewall", layer="baseline", issued_by="did:plc:"+("b"*32))
    assert g.layer == "baseline" and g.sig is None
    import pytest
    with pytest.raises(Exception):
        Grant(grant_id="g1", center_did="x", capability="config", scope="s",
              layer="baseline", issued_by="y", bogus=1)


def test_configblob_has_layer_default_baseline():
    b = ConfigBlob(config_id="cfg-firewall", publisher="did:plc:"+("a"*32),
                   scope="firewall", version=1, content_hash="deadbeef")
    assert b.layer == "baseline"


# ---------------------------------------------------------------------------
# path traversal via scope — CRITICAL, defense in depth: a Grant/ConfigBlob
# carrying a traversal scope must be invalid AT CONSTRUCTION, before it ever
# reaches config_apply.py's filesystem-boundary guard.
# ---------------------------------------------------------------------------

def test_grant_rejects_traversal_scope():
    import pydantic
    import pytest
    with pytest.raises(pydantic.ValidationError):
        Grant(grant_id="g1", center_did="did:plc:"+("a"*32), capability="config",
              scope="../evil", layer="baseline", issued_by="did:plc:"+("b"*32))


def test_grant_rejects_slash_scope():
    import pydantic
    import pytest
    with pytest.raises(pydantic.ValidationError):
        Grant(grant_id="g1", center_did="did:plc:"+("a"*32), capability="config",
              scope="etc/passwd", layer="baseline", issued_by="did:plc:"+("b"*32))


def test_configblob_rejects_traversal_scope():
    import pydantic
    import pytest
    with pytest.raises(pydantic.ValidationError):
        ConfigBlob(config_id="cfg-x", publisher="did:plc:"+("a"*32),
                   scope="../../etc/pwned", version=1, content_hash="deadbeef")
