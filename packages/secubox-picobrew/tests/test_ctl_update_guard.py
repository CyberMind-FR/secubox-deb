# SPDX-License-Identifier: LicenseRef-CMSD-1.0
"""Une mise à jour en plein brassage est inacceptable : la machine chauffe du
moût. On vérifie que le refus est inconditionnel et antérieur à toute action."""
import subprocess, os
from pathlib import Path

CTL = str(Path(__file__).resolve().parents[1] / "sbin" / "picobrewctl")
SHA = "0123456789abcdef0123456789abcdef01234567"

def _run(args, session_file):
    env = dict(os.environ, PICOBREW_SESSION_FILE=str(session_file))
    return subprocess.run(["bash", CTL, *args], capture_output=True, text=True, env=env)

def test_update_refuses_while_a_session_is_active(tmp_path):
    s = tmp_path / "session.active"; s.write_text("brewing")
    p = _run(["update", SHA], s)
    assert p.returncode != 0
    assert "session" in (p.stderr + p.stdout).lower()

def test_update_rejects_a_non_sha_ref(tmp_path):
    s = tmp_path / "none"
    p = _run(["update", "main"], s)
    assert p.returncode != 0

def test_update_requires_an_explicit_ref(tmp_path):
    s = tmp_path / "none"
    p = _run(["update"], s)
    assert p.returncode != 0
