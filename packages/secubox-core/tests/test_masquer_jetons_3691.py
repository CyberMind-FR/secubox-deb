# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3691 : nginx journalisait le jeton d'accès PeerTube (`socket.io?accessToken=`) et les jetons du Hall (`?jeton=`) en
clair. Le format masque désormais ces paramètres ; ce qui est déjà écrit (et les journaux d'erreurs) est masqué à
longueur égale par un programme root qui ne suit aucun lien."""
import gzip
import importlib.machinery
import importlib.util
import json
import os
import re
from pathlib import Path

import pytest

RACINE = Path(__file__).resolve().parents[3]
SCRIPT = RACINE / "packages/secubox-core/sbin/secubox-masquer-jetons-journaux"
CONF = RACINE / "common/nginx/secubox-hosts-log.conf"
UNITE = RACINE / "packages/secubox-core/systemd/secubox-masquer-jetons-journaux.timer"

LIGNE = (b'peertube.x 1.2.3.4 - - [13/Nov/2026:04:00:00 +0100] "GET /socket.io/?accessToken=abc123DEF&EIO=4 HTTP/1.1" '
         b'101 0 "https://hall.x/i/acces/?jeton=zzz" "Mozilla"\n')


@pytest.fixture
def m():
    chargeur = importlib.machinery.SourceFileLoader("masquer3691", str(SCRIPT))
    spec = importlib.util.spec_from_loader("masquer3691", chargeur)
    mod = importlib.util.module_from_spec(spec)
    chargeur.exec_module(mod)
    return mod


def lancer(m, dossier, tmp_path):
    return m.main(str(dossier), str(tmp_path / "etat.json"))


def test_masque_a_longueur_egale(m):
    sortie = m.masquer(LIGNE)
    assert len(sortie) == len(LIGNE)
    assert b"abc123DEF" not in sortie and b"zzz" not in sortie
    assert b"accessToken=XXXXXXXXX&EIO=4" in sortie and b"jeton=XXX\"" in sortie


def test_casse_et_noms_de_secrets(m):
    for brut in (b"/x?TOKEN=s1 ", b"/x?Jeton=s1 ", b"/x?refresh_token=s1 ", b"/x?a=1;api_key=s1 ", b"/x?jwt=s1 ",
                 b"/x?password=s1 ", b"/x?sig=s1 "):
        assert b"s1" not in m.masquer(brut), brut
    for propre in (b"/x?author=ok&design=ok&monkey=ok ", b"/x?tokenize=ok "):
        assert m.masquer(propre) == propre


def test_idempotent_et_respecte_le_format_masque(m):
    une = m.masquer(LIGNE)
    assert m.masquer(une) == une
    deja = b'"GET /x?token=MASQUE&a=1 HTTP/1.1"'
    assert m.masquer(deja) == deja


def test_journal_reecrit_en_place(m, tmp_path):
    d = tmp_path / "nginx"
    d.mkdir()
    j = d / "peertube_access.log"
    j.write_bytes(b"ligne sans jeton\n" + LIGNE + b"autre\n")
    inode, taille = j.stat().st_ino, j.stat().st_size
    assert lancer(m, d, tmp_path) == 0
    assert j.stat().st_ino == inode and j.stat().st_size == taille
    assert b"abc123DEF" not in j.read_bytes()
    assert j.read_bytes().startswith(b"ligne sans jeton\n") and j.read_bytes().endswith(b"autre\n")


def test_ne_relit_que_la_suite_et_laisse_la_ligne_en_cours(m, tmp_path):
    d = tmp_path / "nginx"
    d.mkdir()
    j = d / "error.log"
    j.write_bytes(LIGNE)
    assert lancer(m, d, tmp_path) == 0
    etat = json.loads((tmp_path / "etat.json").read_text())
    assert list(etat.values()) == [len(LIGNE)]
    with open(j, "ab") as f:
        f.write(LIGNE + b"request: \"GET /x?token=PARTIEL")    # ligne en cours d'écriture : pas encore de fin
    assert lancer(m, d, tmp_path) == 0
    contenu = j.read_bytes()
    assert contenu.count(b"abc123DEF") == 0 and contenu.endswith(b"token=PARTIEL")


def test_archive_gz_reecrite_droits_et_date_conserves(m, tmp_path):
    d = tmp_path / "nginx"
    d.mkdir()
    a = d / "secubox-hosts.log.3.gz"
    with gzip.open(a, "wb") as f:
        f.write(LIGNE * 3)
    os.chmod(a, 0o640)
    os.utime(a, (1_700_000_000, 1_700_000_000))
    assert lancer(m, d, tmp_path) == 0
    with gzip.open(a, "rb") as f:
        assert b"abc123DEF" not in f.read()
    assert (a.stat().st_mode & 0o777) == 0o640 and int(a.stat().st_mtime) == 1_700_000_000
    assert not [p for p in d.iterdir() if ".masque-" in p.name]


def test_ne_suit_ni_lien_ni_fifo_ni_lien_dur(m, tmp_path):
    d = tmp_path / "nginx"
    d.mkdir()
    cible = tmp_path / "fichier-root.conf"
    cible.write_bytes(LIGNE)
    (d / "lien.log").symlink_to(cible)
    (d / "dur.log").hardlink_to(cible)
    os.mkfifo(d / "fifo.log")
    gz = tmp_path / "ailleurs.gz"
    with gzip.open(gz, "wb") as f:
        f.write(LIGNE)
    (d / "x.log.2.gz").symlink_to(gz)
    assert lancer(m, d, tmp_path) == 0            # la FIFO ne bloque pas
    assert cible.read_bytes() == LIGNE
    with gzip.open(gz, "rb") as f:
        assert f.read() == LIGNE


def test_dossier_absent(m, tmp_path):
    assert lancer(m, tmp_path / "absent", tmp_path) == 0


def _dossier_lie(tmp_path):
    vrai = tmp_path / "data-log-nginx"
    vrai.mkdir(mode=0o755)
    (vrai / "access.log").write_bytes(LIGNE)
    lien = tmp_path / "var-log-nginx"
    lien.symlink_to(vrai)
    return vrai, lien


def test_dossier_lien_de_confiance_suivi(m, tmp_path):
    # gk2 : /var/log/nginx -> /data/log/nginx ; le programme sortait avec 0 sans rien masquer.
    vrai, lien = _dossier_lie(tmp_path)
    assert m.main(str(lien), str(tmp_path / "etat.json"), os.getuid()) == 0
    assert b"abc123DEF" not in (vrai / "access.log").read_bytes()


def test_lien_d_un_autre_proprietaire_refuse_et_signale(m, tmp_path, capsys):
    vrai, lien = _dossier_lie(tmp_path)
    assert m.main(str(lien), str(tmp_path / "etat.json"), os.getuid() + 1) == 1
    assert (vrai / "access.log").read_bytes() == LIGNE
    assert "PermissionError" in capsys.readouterr().err


def test_cible_inscriptible_par_tous_refusee(m, tmp_path):
    vrai, lien = _dossier_lie(tmp_path)
    vrai.chmod(0o777)
    assert m.main(str(lien), str(tmp_path / "etat.json"), os.getuid()) == 1
    assert (vrai / "access.log").read_bytes() == LIGNE


def test_dossier_inutilisable_est_une_erreur(m, tmp_path):
    f = tmp_path / "pas-un-dossier"
    f.write_bytes(b"")
    assert m.main(str(f), str(tmp_path / "etat.json"), os.getuid()) == 1


def _regex_nginx():
    motifs = re.findall(r'"~\*(\^.*?\$)"\s+"\$1MASQUE\$2";', CONF.read_text())
    assert len(motifs) == 5 and len(set(motifs)) == 1     # trois passes sur la requête, deux sur le référent
    return re.compile(motifs[0], re.I)


def test_format_nginx_masque_trois_jetons_et_respecte_les_noms_anodins():
    rx = _regex_nginx()
    req = "GET /x?TOKEN=s1&Jeton=s2&refresh_token=s3&author=ok HTTP/1.1"
    for _ in range(3):
        req = rx.sub(lambda mm: mm.group(1) + "MASQUE" + mm.group(2), req, count=1)
    assert "s1" not in req and "s2" not in req and "s3" not in req and "author=ok" in req


def test_format_nginx_utilise_les_variables_masquees():
    conf = CONF.read_text()
    formats = conf[conf.index("log_format sbx_host"):]
    assert '"$sbx_requete"' in formats and '"$sbx_referent"' in formats and "log_format sbx_masque" in conf
    assert '"$request"' not in formats and '"$http_referer"' not in formats


def test_passe_horaire_sur_l_horloge():
    texte = UNITE.read_text()
    assert "OnCalendar=hourly" in texte and "OnUnitActiveSec" not in texte
