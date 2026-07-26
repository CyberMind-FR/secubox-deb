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


def test_apply_4r_invalid_ring_leaves_no_shadow(tmp_path):
    target = tmp_path / "secubox-ring.list"
    target.write_text("deb https://apt.secubox.in published main contrib\n")
    with pytest.raises(ValueError):
        bx.apply_4r("prod", str(target), apt_update_fn=lambda p: True)
    assert not (tmp_path / "secubox-ring.list.shadow").exists()
    assert "published" in target.read_text()  # live ring untouched


def test_apply_4r_failure_leaves_no_rollback(tmp_path):
    target = tmp_path / "secubox-ring.list"
    target.write_text("deb https://apt.secubox.in published main contrib\n")
    with pytest.raises(bx.ApplyError):
        bx.apply_4r("internal", str(target), apt_update_fn=lambda p: False)
    assert not (tmp_path / "secubox-ring.list.rollback").exists()
    assert not (tmp_path / "secubox-ring.list.shadow").exists()
    assert "published" in target.read_text()


def test_apply_4r_fn_raising_is_failclosed(tmp_path):
    def boom(p):
        raise RuntimeError("apt exploded")
    target = tmp_path / "secubox-ring.list"
    target.write_text("deb https://apt.secubox.in published main contrib\n")
    with pytest.raises(bx.ApplyError):
        bx.apply_4r("internal", str(target), apt_update_fn=boom)
    assert "published" in target.read_text()  # fail-closed, prior preserved
