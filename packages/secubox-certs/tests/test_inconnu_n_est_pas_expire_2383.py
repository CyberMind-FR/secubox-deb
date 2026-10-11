# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""#2383 — un certificat qu'on ne PEUT PAS LIRE n'est pas un certificat expiré ; et un échec de lecture n'est jamais mémorisé."""
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

RACINE = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(RACINE / "common"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import api.main as M  # noqa: E402

pytestmark = pytest.mark.skipif(shutil.which("openssl") is None, reason="openssl absent")


def _pem(chemin: Path, jours: int):
    cle = chemin.with_suffix(".key")
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(cle), "-out", str(chemin),
                    "-days", str(jours), "-subj", "/CN=exemple.test"], check=True, capture_output=True)
    chemin.write_bytes(chemin.read_bytes() + cle.read_bytes())
    cle.unlink()


@pytest.fixture
def dossier(tmp_path, monkeypatch):
    monkeypatch.setattr(M, "CERTS_DIR", tmp_path)
    M._PEM_MEMO.clear()
    return tmp_path


def test_un_fichier_illisible_est_inconnu_pas_expire(dossier):
    _pem(dossier / "ok.pem", 90)
    (dossier / "vide.pem").write_text("pas un certificat")          # openssl échoue, comme un fichier root 0600 pour secubox
    par = {c["domain"]: c for c in M.scan_certificates()}
    assert par["ok.pem".removesuffix(".pem")]["status"] == "healthy"
    assert par["vide"]["status"] == "unknown" and par["vide"]["days"] is None


def test_le_resume_ne_compte_pas_l_inconnu_comme_expire(dossier):
    _pem(dossier / "ok.pem", 90)
    (dossier / "vide.pem").write_text("x")
    r = M.resume(M.scan_certificates())
    assert r["expired"] == 0 and r["unknown"] == 1 and r["healthy"] == 1


def test_un_echec_n_est_pas_memorise(dossier):
    f = dossier / "c.pem"
    f.write_text("x")
    assert M._infos_pem(f) == (None, None)
    _pem(f, 90)                                                   # le fichier devient lisible SANS changer de taille ni de date garantie
    os.utime(f, ns=(1, 1))
    f.write_bytes(f.read_bytes())
    assert M._infos_pem(f)[0] is not None


def test_un_vrai_certificat_expire_reste_expire():
    assert M.get_cert_status(-3) == "expired" and M.get_cert_status(None) == "unknown"


def test_haproxyctl_ecrit_les_certificats_lisibles_par_secubox():
    """#2383 — cert sync ne laisse plus de .pem en root 0600 (illisibles pour le module certs)."""
    src = (RACINE / "packages/secubox-haproxy/sbin/haproxyctl").read_text(encoding="utf-8")
    assert 'chmod 0640 "$tmp"' in src and 'chown haproxy:secubox "$tmp"' in src
    assert 'chmod 0600 "$tmp"' not in src


def test_le_renouvellement_groupe_ignore_les_inconnus():
    import inspect
    assert 'c["days"] is not None and c["days"] <= 30' in inspect.getsource(M.renew_all_expiring)
