# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""#1366 — le journal d'authentification n'est jamais modifiable par tous."""
import importlib
import os
import stat


def _main(env_files, monkeypatch):
    audit = env_files["data_dir"] / "audit.log"
    monkeypatch.setenv("SECUBOX_AUTH_AUDIT", str(audit))
    import api.main as m
    return importlib.reload(m), audit


def _mode(p):
    return stat.S_IMODE(os.stat(p).st_mode)


def test_journal_cree_en_0640(env_files, monkeypatch):
    m, audit = _main(env_files, monkeypatch)
    old = os.umask(0)
    try:
        m._append_audit("login_success", "gk2", {"jti": "x"})
    finally:
        os.umask(old)
    assert _mode(audit) == 0o640
    assert '"login_success"' in audit.read_text()


def test_journal_0666_herite_est_resserre(env_files, monkeypatch):
    m, audit = _main(env_files, monkeypatch)
    audit.write_text('{"event": "ancien"}\n')
    os.chmod(audit, 0o666)
    m._append_audit("login_success", "gk2", {})
    assert _mode(audit) == 0o640
    lignes = audit.read_text().splitlines()
    assert len(lignes) == 2 and "ancien" in lignes[0]


def test_sauvegarde_retire_l_ecriture_pour_tous_sans_toucher_la_lecture(env_files, monkeypatch):
    m, _ = _main(env_files, monkeypatch)
    p = env_files["data_dir"] / "sessions.json"
    p.write_text("[]")
    os.chmod(p, 0o666)
    m._save(p, [])
    assert _mode(p) == 0o664
    os.chmod(p, 0o644)
    m._save(p, [])
    assert _mode(p) == 0o644
