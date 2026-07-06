from secubox_toolbox import sentinel_link as sl


def test_assess_clean_when_no_detections():
    a = sl.assess([])
    assert a["tier"] == "clean"
    assert a["count"] == 0
    assert a["strongest"] is None


def test_assess_report_only_spyware_is_suspicious():
    dets = [{"class": "spyware_pegasus", "severity": 95, "confidence": 95,
             "action": "report", "evidence": {}, "mac_hash": "aa", "ts": 1}]
    a = sl.assess(dets)
    assert a["tier"] == "suspicious"
    assert a["worst_severity"] == 95
    assert a["dominant_class"] == "spyware_pegasus"
    assert a["strongest"]["class"] == "spyware_pegasus"


def test_assess_high_conf_block_spyware_is_compromised():
    dets = [{"class": "spyware_pegasus", "severity": 95, "confidence": 95,
             "action": "block", "evidence": {}, "mac_hash": "aa", "ts": 1}]
    assert sl.assess(dets)["tier"] == "compromised"


def test_assess_zero_click_never_compromised_even_if_block():
    # zero-click is heuristic — must stay suspicious regardless of action.
    dets = [{"class": "zero_click", "severity": 90, "confidence": 90,
             "action": "block", "evidence": {}, "mac_hash": "aa", "ts": 1}]
    assert sl.assess(dets)["tier"] == "suspicious"


def test_assess_low_confidence_block_is_not_compromised():
    dets = [{"class": "malware_generic", "severity": 90, "confidence": 60,
             "action": "block", "evidence": {}, "mac_hash": "aa", "ts": 1}]
    assert sl.assess(dets)["tier"] == "suspicious"


def test_disposition_labels():
    assert sl.disposition("block") == "Bloquée"
    assert sl.disposition("report") == "Détectée — observée"
    assert sl.disposition("") == "Détectée — observée"


def test_fetch_stats_failsafe_when_daemon_down(monkeypatch):
    # Point at a base but make the HTTP call raise → {} (never raises out).
    monkeypatch.setattr(sl, "daemon_base", lambda: "http://127.0.0.1:9")
    assert sl.fetch_stats() == {}
    assert sl.fetch_verdicts() == []
    assert sl.fetch_detections("aa") == []


def test_fetch_stats_none_base_returns_empty(monkeypatch):
    monkeypatch.setattr(sl, "daemon_base", lambda: None)
    assert sl.fetch_stats() == {}
    assert sl.fetch_verdicts() == []


def test_assess_never_raises_on_malformed_detection():
    dets = [{"class": "malware_generic", "severity": None, "confidence": "n/a",
             "action": "block", "evidence": {}, "mac_hash": "aa", "ts": 1}]
    a = sl.assess(dets)  # must not raise
    assert a["tier"] in ("suspicious", "compromised", "clean")
    assert a["count"] == 1


def test_fetch_verdicts_bad_limit_does_not_raise(monkeypatch):
    monkeypatch.setattr(sl, "daemon_base", lambda: None)
    assert sl.fetch_verdicts(limit="oops") == []
