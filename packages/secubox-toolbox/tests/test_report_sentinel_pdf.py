from secubox_toolbox import reports


def _report(sentinel):
    return {"mac_hash": "aa", "generated_at": "2026-07-06T00:00:00Z",
            "device_type": "phone", "sentinel": sentinel}


def test_pdf_renders_with_sentinel_detection():
    rep = _report({
        "active": True,
        "assess": {"tier": "compromised", "worst_severity": 95, "worst_confidence": 95,
                   "count": 1, "dominant_class": "spyware_pegasus",
                   "strongest": {"class": "spyware_pegasus"}},
        "detections": [{"class": "spyware_pegasus", "severity": 95, "confidence": 95,
                        "action": "block", "evidence": {"source": "amnesty-mvt"},
                        "mac_hash": "aa", "ts": 1, "report": "R"}],
    })
    out = reports.render_pdf(rep)
    assert isinstance(out, (bytes, bytearray)) and len(out) > 500


def test_pdf_renders_with_sentinel_inactive():
    rep = _report({"active": False, "assess": {"tier": "clean"}, "detections": []})
    out = reports.render_pdf(rep)
    assert isinstance(out, (bytes, bytearray)) and len(out) > 500


def test_pdf_renders_when_sentinel_key_absent():
    rep = {"mac_hash": "aa", "generated_at": "2026-07-06T00:00:00Z", "device_type": "phone"}
    out = reports.render_pdf(rep)  # must not KeyError
    assert isinstance(out, (bytes, bytearray)) and len(out) > 500


def test_text_fallback_includes_sentinel_line():
    rep = _report({
        "active": True,
        "assess": {"tier": "compromised", "worst_severity": 95, "worst_confidence": 95,
                   "count": 1, "dominant_class": "spyware_pegasus", "strongest": None},
        "detections": [{"class": "spyware_pegasus", "severity": 95, "confidence": 95,
                        "action": "block", "evidence": {}, "mac_hash": "aa", "ts": 1, "report": "R"}],
    })
    txt = reports._render_text_fallback(rep)
    assert "SENTINELLE" in txt.upper()
    assert "spyware_pegasus" in txt
