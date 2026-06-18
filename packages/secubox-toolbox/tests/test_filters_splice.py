# tests/test_filters_splice.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
import json
from secubox_toolbox import filters


def test_default_is_observe(monkeypatch, tmp_path):
    monkeypatch.setattr(filters, "FILTERS_PATH", str(tmp_path / "f.json"))
    assert filters.get_filters(force=True)["tls_splice"] == "observe"


def test_bad_value_falls_back(monkeypatch, tmp_path):
    fp = tmp_path / "f.json"; fp.write_text(json.dumps({"tls_splice": "bogus"}))
    monkeypatch.setattr(filters, "FILTERS_PATH", str(fp))
    assert filters.get_filters(force=True)["tls_splice"] == "observe"


def test_set_filters_accepts_valid(monkeypatch, tmp_path):
    monkeypatch.setattr(filters, "FILTERS_PATH", str(tmp_path / "f.json"))
    out = filters.set_filters({"tls_splice": "on"})
    assert out["tls_splice"] == "on"
    out = filters.set_filters({"tls_splice": "nope"})
    assert out["tls_splice"] == "on"  # invalid ignored, prior kept
