from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]

def test_panel_calls_exposure_api_with_reach_options():
    html = (ROOT / "www" / "exposure" / "index.html").read_text()
    assert "/api/v1/exposure/" in html
    for v in ("localhost", "lan", "wan"):
        assert v in html
    assert "mesh" in html and "tor" in html.lower()
