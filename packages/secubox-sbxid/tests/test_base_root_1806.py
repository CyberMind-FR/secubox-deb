# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Une base ouverte par root revient au compte du service (#1806)."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "common"))

from api import store  # noqa: E402


class _Pw:
    pw_uid, pw_gid = 4242, 4243


def test_root_rend_la_base_a_secubox(tmp_path, monkeypatch):
    db = tmp_path / "sbx.db"
    appels = []
    monkeypatch.setattr(store.os, "geteuid", lambda: 0)
    monkeypatch.setattr(store.os, "chown", lambda p, u, g: appels.append((Path(p).name, u, g)))
    import pwd
    monkeypatch.setattr(pwd, "getpwnam", lambda n: _Pw())
    vrai_stat = Path.stat

    class _St:
        def __init__(self, s): self._s = s
        def __getattr__(self, k): return 0 if k == "st_uid" else getattr(self._s, k)
    monkeypatch.setattr(Path, "stat", lambda self, *a, **k: _St(vrai_stat(self, *a, **k)))
    store.ouvre(db).close()
    assert ("sbx.db", 4242, 4243) in appels


def test_hors_root_rien_n_est_touche(tmp_path, monkeypatch):
    appels = []
    monkeypatch.setattr(store.os, "chown", lambda *a: appels.append(a))
    store.ouvre(tmp_path / "sbx.db").close()
    assert appels == []
