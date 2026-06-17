# SPDX-License-Identifier: LicenseRef-CMSD-1.0
from secubox_toolbox import privacy


def test_registrable_basic():
    assert privacy.registrable("www.google-analytics.com") == "google-analytics.com"
    assert privacy.registrable("a.b.example.co.uk") == "example.co.uk"
    assert privacy.registrable("example.com") == "example.com"
    assert privacy.registrable("") == ""


def test_is_tracker_static():
    assert privacy.is_tracker("www.google-analytics.com") is True
    assert privacy.is_tracker("connect.facebook.net") is True
    assert privacy.is_tracker("example.com") is False


def test_classify_non_tracker_is_none():
    assert privacy.classify("cdn.example.com", beacon_hint=False) == "none"


def test_classify_unknown_tracker_defaults_loadbearing():
    assert privacy.classify("criteo.com", beacon_hint=False) == "loadbearing"


def test_classify_beacon_hint_is_pure():
    assert privacy.classify("google-analytics.com", beacon_hint=True) == "pure"


def test_is_tracker_learned_list(tmp_path, monkeypatch):
    learned = tmp_path / "learned-trackers.txt"
    learned.write_text("# comment line\nexample-tracker.net\nsub.evil.example\n")
    monkeypatch.setattr(privacy, "LEARNED_PATH", str(learned))
    privacy._lists_cache["mtime"] = (0.0, 0.0)  # force reload
    assert privacy.is_tracker("example-tracker.net") is True
    assert privacy.is_tracker("www.example-tracker.net") is True   # registrable match
    assert privacy.is_tracker("not-listed.example.org") is False
    assert privacy.classify("example-tracker.net", beacon_hint=False) == "loadbearing"
