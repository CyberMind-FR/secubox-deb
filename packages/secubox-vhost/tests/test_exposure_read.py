from pathlib import Path
import sys
ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "packages" / "secubox-vhost"))
from api.exposure_read import read_exposure

def test_missing_is_wan(tmp_path):
    assert read_exposure("x.example", snippet_dir=tmp_path) == {"reach": "wan", "mesh": False}

def test_lan_with_mesh(tmp_path):
    (tmp_path / "x.example.conf").write_text(
        "allow 127.0.0.1;\nallow 10.0.0.0/8;\nallow 192.168.0.0/16;\nallow 10.10.0.0/24;\ndeny all;\n")
    assert read_exposure("x.example", snippet_dir=tmp_path) == {"reach": "lan", "mesh": True}

def test_localhost(tmp_path):
    (tmp_path / "x.example.conf").write_text("allow 127.0.0.1;\ndeny all;\n")
    assert read_exposure("x.example", snippet_dir=tmp_path) == {"reach": "localhost", "mesh": False}

def test_empty_is_wan(tmp_path):
    (tmp_path / "x.example.conf").write_text("")
    assert read_exposure("x.example", snippet_dir=tmp_path) == {"reach": "wan", "mesh": False}
