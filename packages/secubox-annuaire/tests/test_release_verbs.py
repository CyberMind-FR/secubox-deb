# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
import os
import pytest
from annuaire.log import Journal
from annuaire.crypto import public_from_private, did_from_pubkey
from annuaire import verbs, releases as rl
from annuaire.model import Op


def _key():
    p = os.urandom(32)
    return p, did_from_pubkey(public_from_private(p))


def test_publish_born_draft(tmp_path):
    j = Journal(str(tmp_path / "j.db"))
    cpriv, cdid = _key()
    verbs.release_publish(j, cpriv, [{"kind": "deb", "name": "secubox-dpi",
        "version": "1.2.3", "hash": "ab", "arch": "arm64"}], "note", evo_id="e1")
    assert rl.current_ring(list(j.iter_entries()), "e1") == "draft"


def test_promote_requires_release_grant(tmp_path):
    j = Journal(str(tmp_path / "j.db"))
    bpriv, bdid = _key()      # the box
    cpriv, cdid = _key()      # the center
    verbs.release_publish(j, cpriv, [{"kind": "deb", "name": "x", "version": "1",
        "hash": "ab", "arch": "arm64"}], "n", evo_id="e1")
    # no grant yet -> promote by center rejected on the box's view
    with pytest.raises(ValueError):
        verbs.release_promote(j, cpriv, bdid, "e1")
    # box grants release to center
    verbs.grant_issue(j, bpriv, bdid, cdid, scope="release", layer="baseline",
                      capability="release")
    verbs.release_promote(j, cpriv, bdid, "e1")
    assert rl.current_ring(list(j.iter_entries()), "e1") == "internal"


def test_ring_assign_requires_grant(tmp_path):
    j = Journal(str(tmp_path / "j.db"))
    bpriv, bdid = _key(); cpriv, cdid = _key()
    with pytest.raises(ValueError):
        verbs.ring_assign(j, cpriv, bdid, bdid, "internal")
    verbs.grant_issue(j, bpriv, bdid, cdid, scope="release", layer="baseline",
                      capability="release")
    verbs.ring_assign(j, cpriv, bdid, bdid, "internal")
    assert rl.box_ring(list(j.iter_entries()), bdid, self_did=bdid) == "internal"
