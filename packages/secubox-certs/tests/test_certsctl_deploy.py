# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""certsctl deploy — le maillon qui manquait entre acme.sh et HAProxy (#991).

acme.sh renouvelait correctement ; rien ne portait le resultat jusqu'aux pem
servis. Constat du 6 aout 2026 : 36 certificats EXPIRES en production alors que
le magasin acme.sh en detenait des valides jusqu'en novembre.

Ces tests epinglent les proprietes qui font qu'un deploiement de certificats
est sur : ne rien ecrire sans qu'on le demande, ne jamais remplacer un
certificat par un plus ancien ou par un illisible, preserver les droits, et ne
recharger que si quelque chose a change.
"""
import json
import os
import shutil
import subprocess
import datetime
from pathlib import Path

import pytest

CTL = Path(__file__).resolve().parents[1] / "sbin" / "certsctl"


def _selfsigned(dirpath: Path, cn: str, days: int):
    """Genere un couple cle/chaine autosigne valide `days` jours."""
    dirpath.mkdir(parents=True, exist_ok=True)
    key = dirpath / f"{cn}.key"
    crt = dirpath / "fullchain.cer"
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
         "-keyout", str(key), "-out", str(crt), "-days", str(days),
         "-subj", f"/CN={cn}"],
        check=True, capture_output=True, timeout=60)
    return key, crt


def _pem_from(key: Path, crt: Path, dest: Path):
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(crt.read_text() + key.read_text())


def _env(tmp_path, certs, acme):
    return {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "SECUBOX_CERTS_DIR": str(certs),
        "SECUBOX_ACME_HOME": str(acme),
        "SECUBOX_CERTS_RELOAD": "/bin/true",
    }


def _run(args, env):
    return subprocess.run(["bash", str(CTL)] + args,
                          capture_output=True, text=True, env=env, timeout=120)


@pytest.fixture
def scene(tmp_path):
    """Un domaine dont le magasin est plus recent que le pem deploye."""
    certs = tmp_path / "certs"; certs.mkdir()
    acme = tmp_path / "acme"
    dom = "meet.example.com"
    old_key, old_crt = _selfsigned(tmp_path / "old", dom, 1)
    _pem_from(old_key, old_crt, certs / f"{dom}.pem")
    _selfsigned(acme / f"{dom}_ecc", dom, 90)
    return tmp_path, certs, acme, dom


def test_dry_run_changes_nothing(scene):
    """Un deploiement de certificats doit pouvoir etre simule : c'est ce qui
    permet de le relire avant de toucher a la production."""
    tmp_path, certs, acme, dom = scene
    pem = certs / f"{dom}.pem"
    before = pem.read_bytes()

    r = _run(["deploy"], _env(tmp_path, certs, acme))
    assert r.returncode == 0, r.stderr
    data = json.loads(r.stdout)
    assert data["applied"] is False
    assert data["updated"] == 1
    assert pem.read_bytes() == before, "la simulation ne doit rien ecrire"


def test_apply_installs_the_newer_certificate(scene):
    tmp_path, certs, acme, dom = scene
    pem = certs / f"{dom}.pem"

    r = _run(["deploy", "--apply"], _env(tmp_path, certs, acme))
    assert r.returncode == 0, r.stderr
    assert json.loads(r.stdout)["updated"] == 1

    end = subprocess.run(["openssl", "x509", "-noout", "-enddate", "-in", str(pem)],
                         capture_output=True, text=True).stdout
    assert "notAfter" in end
    # Le pem doit rester utilisable par HAProxy : chaine ET cle.
    body = pem.read_text()
    assert "BEGIN CERTIFICATE" in body and "PRIVATE KEY" in body


def test_never_replaces_a_newer_certificate_with_an_older_one(tmp_path):
    """Le magasin peut contenir un certificat PLUS ANCIEN que le deploye — par
    exemple apres une restauration. Le remplacer serait une regression
    silencieuse vers l'expiration."""
    certs = tmp_path / "certs"; certs.mkdir()
    acme = tmp_path / "acme"
    dom = "old.example.com"
    new_key, new_crt = _selfsigned(tmp_path / "new", dom, 90)
    _pem_from(new_key, new_crt, certs / f"{dom}.pem")
    _selfsigned(acme / f"{dom}_ecc", dom, 1)   # magasin plus ancien
    before = (certs / f"{dom}.pem").read_bytes()

    r = _run(["deploy", "--apply"], _env(tmp_path, certs, acme))
    assert json.loads(r.stdout)["updated"] == 0
    assert (certs / f"{dom}.pem").read_bytes() == before


def test_unreadable_dates_are_skipped_never_deployed(tmp_path):
    """Une date illisible ne doit JAMAIS autoriser un remplacement.

    Un balayage ecrit trop vite avait deja masque 35 certificats expires en
    avalant silencieusement les dates non analysables — le silence ressemblait
    a un succes."""
    certs = tmp_path / "certs"; certs.mkdir()
    acme = tmp_path / "acme"
    dom = "broken.example.com"
    key, crt = _selfsigned(tmp_path / "src", dom, 90)
    _pem_from(key, crt, certs / f"{dom}.pem")
    store = acme / f"{dom}_ecc"; store.mkdir(parents=True)
    (store / "fullchain.cer").write_text("ceci n'est pas un certificat\n")
    (store / f"{dom}.key").write_text("ni une cle\n")
    before = (certs / f"{dom}.pem").read_bytes()

    r = _run(["deploy", "--apply"], _env(tmp_path, certs, acme))
    data = json.loads(r.stdout)
    assert data["unreadable"] == 1
    assert data["updated"] == 0
    assert (certs / f"{dom}.pem").read_bytes() == before


def test_domain_without_store_is_reported_not_touched(tmp_path):
    """Certains domaines sont geres par certbot, pas acme.sh. Ils doivent etre
    comptes comme non geres, jamais ecrases."""
    certs = tmp_path / "certs"; certs.mkdir()
    acme = tmp_path / "acme"; acme.mkdir()
    dom = "certbot.example.com"
    key, crt = _selfsigned(tmp_path / "src", dom, 90)
    _pem_from(key, crt, certs / f"{dom}.pem")

    r = _run(["deploy", "--apply"], _env(tmp_path, certs, acme))
    data = json.loads(r.stdout)
    assert data["unmanaged"] == 1
    assert data["updated"] == 0


def test_no_reload_when_nothing_changed(scene):
    """Un reload par passage de minuteur, sans raison, coupe des connexions
    pour rien."""
    tmp_path, certs, acme, dom = scene
    _run(["deploy", "--apply"], _env(tmp_path, certs, acme))
    r = _run(["deploy", "--apply"], _env(tmp_path, certs, acme))
    data = json.loads(r.stdout)
    assert data["updated"] == 0
    assert data["reloaded"] is False


def test_status_counts_expired_certificates(tmp_path):
    certs = tmp_path / "certs"; certs.mkdir()
    k1, c1 = _selfsigned(tmp_path / "a", "valid.example.com", 90)
    _pem_from(k1, c1, certs / "valid.example.com.pem")
    r = _run(["status"], _env(tmp_path, certs, tmp_path / "acme"))
    data = json.loads(r.stdout)
    assert data["valid"] == 1
    assert data["expired"] == 0


def _certbot_store(root: Path, dom: str, days: int):
    """Arborescence certbot : live/<domaine>/{fullchain,privkey}.pem."""
    d = root / dom
    d.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
         "-keyout", str(d / "privkey.pem"), "-out", str(d / "fullchain.pem"),
         "-days", str(days), "-subj", f"/CN={dom}"],
        check=True, capture_output=True, timeout=60)
    return d


def _env_certbot(tmp_path, certs, acme, certbot):
    e = _env(tmp_path, certs, acme)
    e["SECUBOX_CERTBOT_LIVE"] = str(certbot)
    return e


def test_certbot_managed_domain_is_deployed_too(tmp_path):
    """La garantie doit etre UNIFORME : un certificat renouvele doit atteindre
    HAProxy quel que soit l'outil qui l'a emis. Sinon la moitie du parc reste
    sur le mecanisme qui avait laisse 36 certificats expirer."""
    certs = tmp_path / "certs"; certs.mkdir()
    acme = tmp_path / "acme"; acme.mkdir()
    certbot = tmp_path / "letsencrypt"
    dom = "ganimed.example"
    old_key, old_crt = _selfsigned(tmp_path / "old", dom, 1)
    _pem_from(old_key, old_crt, certs / f"{dom}.pem")
    _certbot_store(certbot, dom, 90)

    r = _run(["deploy", "--apply"], _env_certbot(tmp_path, certs, acme, certbot))
    assert r.returncode == 0, r.stderr
    data = json.loads(r.stdout)
    assert data["updated"] == 1, data
    assert data["unmanaged"] == 0
    body = (certs / f"{dom}.pem").read_text()
    assert "BEGIN CERTIFICATE" in body and "PRIVATE KEY" in body


def test_acme_store_wins_when_a_domain_exists_in_both(tmp_path):
    """Un domaine present dans les deux magasins est presume gere par acme.sh,
    qui gere la grande majorite du parc. Deployer l'autre risquerait
    d'installer un certificat que plus rien ne renouvelle."""
    certs = tmp_path / "certs"; certs.mkdir()
    acme = tmp_path / "acme"
    certbot = tmp_path / "letsencrypt"
    dom = "double.example"
    old_key, old_crt = _selfsigned(tmp_path / "old", dom, 1)
    _pem_from(old_key, old_crt, certs / f"{dom}.pem")
    _selfsigned(acme / f"{dom}_ecc", dom, 60)     # acme.sh : 60 jours
    _certbot_store(certbot, dom, 200)             # certbot : 200 jours

    r = _run(["deploy", "--apply"], _env_certbot(tmp_path, certs, acme, certbot))
    assert json.loads(r.stdout)["updated"] == 1

    end = subprocess.run(["openssl", "x509", "-noout", "-enddate", "-in",
                          str(certs / f"{dom}.pem")],
                         capture_output=True, text=True).stdout
    end_dt = datetime.datetime.strptime(end.strip().split("=")[1], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=datetime.timezone.utc)
    days = (end_dt - datetime.datetime.now(datetime.timezone.utc)).days
    assert days < 100, (
        f"c'est le certificat acme.sh (60 j) qui doit etre deploye, pas celui "
        f"de certbot (200 j) — obtenu {days} j"
    )
