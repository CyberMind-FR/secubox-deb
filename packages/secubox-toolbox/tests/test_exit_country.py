import subprocess, os
from pathlib import Path
CTL = Path(__file__).resolve().parents[1] / "sbin" / "secubox-toolbox-tor-reconcile"
def _emit(codes, tmp_path):
    f = tmp_path / "cc.txt"; f.write_text(codes)
    return subprocess.run(["bash", str(CTL), "__emit_exit_country", str(f)],
                          capture_output=True, text=True)
def test_valid_codes_emit_exitnodes(tmp_path):
    r = _emit("DE\nFR\n", tmp_path)
    assert "exitnodes {de},{fr}" in r.stdout.lower()
    assert "StrictNodes 1" in r.stdout
def test_empty_emits_nothing(tmp_path):
    assert _emit("\n", tmp_path).stdout.strip() == ""
def test_bad_code_skipped(tmp_path):
    r = _emit("DE\nXXX\n12\n", tmp_path)
    assert "{de}" in r.stdout.lower()
    assert "xxx" not in r.stdout.lower() and "{12}" not in r.stdout.lower()
