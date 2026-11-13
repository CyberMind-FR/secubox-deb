# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3691 : nginx journalisait le jeton d'accès PeerTube (`socket.io?accessToken=`) et les jetons du Hall (`?jeton=`) en
clair. Le format masque désormais ces paramètres ; ce qui était déjà écrit est masqué à longueur égale."""
import gzip
import importlib.machinery
import importlib.util
import os
import re
from pathlib import Path

RACINE = Path(__file__).resolve().parents[3]
SCRIPT = RACINE / "packages/secubox-core/sbin/secubox-masquer-jetons-journaux"
CONF = RACINE / "common/nginx/secubox-hosts-log.conf"

LIGNE = (b'peertube.x 1.2.3.4 - - [13/Nov/2026:04:00:00 +0100] "GET /socket.io/?accessToken=abc123DEF&EIO=4 HTTP/1.1" '
         b'101 0 "https://hall.x/i/acces/?jeton=zzz" "Mozilla"\n')


def charger(monkeypatch, dossier):
    monkeypatch.setenv("SECUBOX_JOURNAUX_NGINX", str(dossier))
    chargeur = importlib.machinery.SourceFileLoader("masquer3691", str(SCRIPT))
    spec = importlib.util.spec_from_loader("masquer3691", chargeur)
    mod = importlib.util.module_from_spec(spec)
    chargeur.exec_module(mod)
    return mod


def test_masque_a_longueur_egale(monkeypatch, tmp_path):
    m = charger(monkeypatch, tmp_path)
    sortie = m.masquer(LIGNE)
    assert len(sortie) == len(LIGNE)
    assert b"abc123DEF" not in sortie and b"zzz" not in sortie
    assert b"accessToken=XXXXXXXXX&EIO=4" in sortie and b"jeton=XXX\"" in sortie


def test_idempotent_et_respecte_le_format_masque(monkeypatch, tmp_path):
    m = charger(monkeypatch, tmp_path)
    une = m.masquer(LIGNE)
    assert m.masquer(une) == une
    deja = b'"GET /x?token=MASQUE&a=1 HTTP/1.1"'
    assert m.masquer(deja) == deja
    propre = b'"GET /x?a=1&tokenize=2 HTTP/1.1"'
    assert m.masquer(propre) == propre


def test_journal_reecrit_en_place(monkeypatch, tmp_path):
    m = charger(monkeypatch, tmp_path)
    j = tmp_path / "peertube_access.log"
    j.write_bytes(b"ligne sans jeton\n" + LIGNE + b"autre\n")
    inode, taille = j.stat().st_ino, j.stat().st_size
    assert m.main() == 0
    assert j.stat().st_ino == inode and j.stat().st_size == taille
    assert b"abc123DEF" not in j.read_bytes()
    assert j.read_bytes().startswith(b"ligne sans jeton\n") and j.read_bytes().endswith(b"autre\n")


def test_archive_gz_reecrite_droits_conserves(monkeypatch, tmp_path):
    m = charger(monkeypatch, tmp_path)
    a = tmp_path / "secubox-hosts.log.3.gz"
    with gzip.open(a, "wb") as f:
        f.write(LIGNE * 3)
    os.chmod(a, 0o640)
    assert m.main() == 0
    with gzip.open(a, "rb") as f:
        assert b"abc123DEF" not in f.read()
    assert (a.stat().st_mode & 0o777) == 0o640
    assert not [p for p in tmp_path.iterdir() if ".masque-" in p.name]


def test_ignore_les_liens_et_autres_fichiers(monkeypatch, tmp_path):
    m = charger(monkeypatch, tmp_path)
    cible = tmp_path / "ailleurs.txt"
    cible.write_bytes(LIGNE)
    (tmp_path / "lien.log").symlink_to(cible)
    assert m.main() == 0
    assert cible.read_bytes() == LIGNE


def test_format_nginx_masque_requete_et_referent():
    conf = CONF.read_text()
    assert re.search(r"log_format sbx_host .*\"\$sbx_requete\".*", conf, re.S)
    assert "$sbx_referent" in conf and "log_format sbx_masque" in conf
    # le format de domaine ne journalise plus jamais la requête ni le référent bruts
    formats = conf[conf.index("log_format sbx_host"):]
    assert '"$request"' not in formats and '"$http_referer"' not in formats
    for nom in ("accessToken", "jeton", "token"):
        assert nom in conf
