# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

# tests/test_filters_adlearn.py
from secubox_toolbox import filters
def test_ad_learn_default_true(monkeypatch, tmp_path):
    monkeypatch.setattr(filters, "FILTERS_PATH", str(tmp_path / "f.json"))
    assert filters.get_filters(force=True)["ad_learn"] is True
def test_ad_learn_set_bool(monkeypatch, tmp_path):
    monkeypatch.setattr(filters, "FILTERS_PATH", str(tmp_path / "f.json"))
    assert filters.set_filters({"ad_learn": False})["ad_learn"] is False
