# SPDX-License-Identifier: LicenseRef-CMSD-1.0
import re

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


def test_fake_id_deterministic(tmp_path, monkeypatch):
    key = tmp_path / "privacy-jar.key"
    key.write_text("0123456789abcdef0123456789abcdef")
    monkeypatch.setattr(privacy, "JAR_KEY_PATH", str(key))
    privacy._jar_key_cache["v"] = None  # reset cache
    a = privacy.fake_id("clientHASH1", "criteo.com", "_ga")
    b = privacy.fake_id("clientHASH1", "criteo.com", "_ga")
    assert a == b and a is not None


def test_fake_id_differs_per_client(tmp_path, monkeypatch):
    key = tmp_path / "privacy-jar.key"
    key.write_text("0123456789abcdef0123456789abcdef")
    monkeypatch.setattr(privacy, "JAR_KEY_PATH", str(key))
    privacy._jar_key_cache["v"] = None
    a = privacy.fake_id("clientHASH1", "criteo.com", "_ga")
    b = privacy.fake_id("clientHASH2", "criteo.com", "_ga")
    assert a != b


def test_fake_id_format_shaping_ga(tmp_path, monkeypatch):
    key = tmp_path / "privacy-jar.key"
    key.write_text("k" * 32)
    monkeypatch.setattr(privacy, "JAR_KEY_PATH", str(key))
    privacy._jar_key_cache["v"] = None
    val = privacy.fake_id("c", "google-analytics.com", "_ga")
    assert re.match(r"^GA1\.2\.\d+\.\d+$", val), val


def test_fake_id_missing_key_returns_none(tmp_path, monkeypatch):
    monkeypatch.setattr(privacy, "JAR_KEY_PATH", str(tmp_path / "nope.key"))
    privacy._jar_key_cache["v"] = None
    assert privacy.fake_id("c", "criteo.com", "_ga") is None


def test_verdict_first_party_allows():
    v = privacy.verdict(host="api.example.com", site="example.com",
                        beacon_hint=False, fortknox=False)
    assert v == "allow"


def test_verdict_fortknox_blocks_third_party():
    v = privacy.verdict(host="cdn.other.com", site="example.com",
                        beacon_hint=False, fortknox=True)
    assert v == "block"


def test_verdict_fortknox_allows_first_party():
    v = privacy.verdict(host="static.example.com", site="example.com",
                        beacon_hint=False, fortknox=True)
    assert v == "allow"


def test_verdict_pure_tracker_blocks():
    v = privacy.verdict(host="google-analytics.com", site="example.com",
                        beacon_hint=True, fortknox=False)
    assert v == "block"


def test_verdict_loadbearing_tracker_poisons():
    v = privacy.verdict(host="criteo.com", site="example.com",
                        beacon_hint=False, fortknox=False)
    assert v == "poison"


def test_verdict_non_tracker_allows():
    v = privacy.verdict(host="fonts.googleapis.com", site="example.com",
                        beacon_hint=False, fortknox=False)
    assert v == "allow"
