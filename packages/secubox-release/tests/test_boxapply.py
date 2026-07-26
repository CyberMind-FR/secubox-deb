# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
import pytest
from release import boxapply as bx


def test_sources_line():
    assert bx.sources_line("internal") == "deb https://apt.secubox.in internal main contrib"
    with pytest.raises(ValueError):
        bx.sources_line("prod")


def test_apply_4r_swaps_on_success(tmp_path):
    target = tmp_path / "secubox-ring.list"
    target.write_text("deb https://apt.secubox.in published main contrib\n")
    r = bx.apply_4r("internal", str(target), apt_update_fn=lambda p: True)
    assert r["applied"] is True
    assert "internal" in target.read_text()


def test_apply_4r_rolls_back_on_apt_failure(tmp_path):
    target = tmp_path / "secubox-ring.list"
    target.write_text("deb https://apt.secubox.in published main contrib\n")
    with pytest.raises(bx.ApplyError):
        bx.apply_4r("internal", str(target), apt_update_fn=lambda p: False)
    # prior 'published' ring preserved — box not bricked
    assert "published" in target.read_text()
