# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Un openssl par certificat MODIFIÉ, pas deux par certificat et par scan (#1835).

Avec de vrais certificats auto-signés : la sortie d'openssl est celle de la
box, pas une imitation.
"""
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


def _cert(dossier: Path, nom: str, cn: str):
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "30",
                    "-subj", f"/O=Banc/CN={cn}", "-keyout", str(dossier / f"{nom}.key"),
                    "-out", str(dossier / f"{nom}.pem")], check=True, capture_output=True)


@pytest.fixture
def certs(monkeypatch, tmp_path):
    for i in range(3):
        _cert(tmp_path, f"site{i}.exemple", f"Autorite {i}")
    monkeypatch.setattr(M, "CERTS_DIR", tmp_path)
    monkeypatch.setattr(M, "_PEM_MEMO", {})
    vrai = subprocess.run
    lances = []

    def compte(args, *a, **k):
        if args[:2] == ["openssl", "x509"]:
            lances.append(args)
        return vrai(args, *a, **k)

    monkeypatch.setattr(M.subprocess, "run", compte)
    return tmp_path, lances


def test_un_appel_par_certificat_puis_aucun(certs):
    dossier, lances = certs
    premier = M.scan_certificates()
    assert len(lances) == 3
    assert {c["issuer"] for c in premier} == {"Autorite 0", "Autorite 1", "Autorite 2"}
    assert all(25 <= c["days"] <= 30 and c["status"] == "warning" for c in premier)
    second = M.scan_certificates()
    assert len(lances) == 3 and second == premier


def test_meme_resultat_que_les_deux_appels(certs):
    dossier, _ = certs
    pem = dossier / "site1.exemple.pem"
    assert M._infos_pem(pem) == (M.parse_pem_expiry(pem), M.get_cert_issuer(pem))


def test_certificat_renouvele_relu(certs):
    dossier, lances = certs
    M.scan_certificates()
    _cert(dossier, "site1.exemple", "Nouvelle autorite")
    st = (dossier / "site1.exemple.pem").stat()
    os.utime(dossier / "site1.exemple.pem", ns=(st.st_atime_ns, st.st_mtime_ns + 1_000_000))
    par = {c["domain"]: c for c in M.scan_certificates()}
    assert par["site1.exemple"]["issuer"] == "Nouvelle autorite"
    assert len(lances) == 4
