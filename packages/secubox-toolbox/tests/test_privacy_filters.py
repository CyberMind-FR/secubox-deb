# SPDX-License-Identifier: LicenseRef-CMSD-1.0
import importlib
import json
import os
from secubox_toolbox import filters


def test_privacy_defaults_safe(monkeypatch, tmp_path):
    monkeypatch.setattr(filters, "FILTERS_PATH", str(tmp_path / "f.json"))
    f = filters.get_filters(force=True)
    assert f["privacy_enforce"] is False     # ships dark
    assert f["privacy_poison"] is True
    assert f["privacy_anonymize"] is True
    assert f["privacy_ip_drop"] is False
    assert f["privacy_dns_feed"] is True
    assert f["fortknox_sites"] == []


def test_set_privacy_toggles(monkeypatch, tmp_path):
    p = tmp_path / "f.json"
    monkeypatch.setattr(filters, "FILTERS_PATH", str(p))
    filters.set_filters({"privacy_enforce": True,
                         "fortknox_sites": ["bank.example.com"]})
    saved = json.loads(p.read_text())
    assert saved["privacy_enforce"] is True
    assert saved["fortknox_sites"] == ["bank.example.com"]


def test_filters_path_env_override(monkeypatch, tmp_path):
    import secubox_toolbox.filters as flt
    p = tmp_path / "f.json"
    p.write_text('{"privacy_enforce": true}')
    monkeypatch.setenv("SECUBOX_FILTERS_PATH", str(p))
    importlib.reload(flt)
    try:
        assert flt.FILTERS_PATH == str(p)
        assert flt.get_filters(force=True)["privacy_enforce"] is True
    finally:
        monkeypatch.delenv("SECUBOX_FILTERS_PATH", raising=False)
        importlib.reload(flt)   # restore default for other tests
