# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""L'agrégateur (Hall hors ligne 4 à 8 min) n'est relancé que si le code qu'il sert a changé (#3941)."""
import subprocess
from pathlib import Path

import pytest

DEB = Path(__file__).resolve().parents[1] / "debian"


@pytest.fixture
def banc(tmp_path):
    api = tmp_path / "usr/lib/secubox/system/api"
    api.mkdir(parents=True)
    (api / "main.py").write_text("a = 1\n")
    (tmp_path / "run").mkdir()
    bin_ = tmp_path / "bin"
    bin_.mkdir()
    (bin_ / "systemctl").write_text(f'#!/bin/sh\necho "$*" >> {tmp_path}/appels\n')
    (bin_ / "systemctl").chmod(0o755)
    (tmp_path / "appels").write_text("")

    def joue(texte, *args, shell="sh"):
        texte = texte.replace("/usr/lib/secubox", f"{tmp_path}/usr/lib/secubox") \
            .replace("/usr/share/secubox", f"{tmp_path}/usr/share/secubox").replace("/run/secubox-system.", f"{tmp_path}/run/")
        return subprocess.run([shell, "-c", "set -e\n" + texte, "x", *args], capture_output=True, text=True, timeout=60,
                              env={"PATH": f"{bin_}:/usr/bin:/bin"})

    pre = (DEB / "preinst").read_text().replace("#DEBHELPER#", "")
    post = (DEB / "postinst").read_text().split("# >>> empreinte-agregateur")[1].split("# <<< empreinte-agregateur")[0]
    joue.preinst = lambda *a: joue(pre, *(a or ("upgrade", "1.0")))
    joue.postinst = lambda: joue(post[post.index("\n"):], shell="bash")
    joue.appels = lambda: (tmp_path / "appels").read_text()
    joue.api, joue.tmp = api, tmp_path
    return joue


def relance(b):
    return "try-restart secubox-aggregator" in b.appels()


def test_code_identique_pas_de_relance(banc):
    assert banc.preinst().returncode == 0
    (banc.api / "page.html").write_text("autre")
    r = banc.postinst()
    assert r.returncode == 0, r.stderr
    assert not relance(banc) and list((banc.tmp / "run").iterdir()) == []


@pytest.mark.parametrize("geste", ["modifie", "ajoute", "retire"])
def test_code_change_relance(banc, geste):
    banc.preinst()
    f = banc.api / "main.py"
    if geste == "modifie":
        f.write_text("a = 2\n")
    elif geste == "ajoute":
        (banc.api / "neuf.py").write_text("")
    else:
        f.unlink()
    assert banc.postinst().returncode == 0 and relance(banc)


def test_system_hub_compte(banc):
    banc.preinst()
    d = banc.tmp / "usr/share/secubox/system-hub/api"
    d.mkdir(parents=True)
    (d / "main.py").write_text("x")
    banc.postinst()
    assert relance(banc)


def test_premiere_installation_ou_empreinte_absente_relance(banc):
    assert banc.preinst("install").returncode == 0
    assert banc.postinst().returncode == 0 and relance(banc)


def test_empreinte_perimee_effacee_a_l_installation(banc):
    banc.preinst()
    banc.preinst("install")
    banc.postinst()
    assert relance(banc)


def test_une_seule_relance_dans_le_paquet():
    t = "\n".join(x for x in (DEB / "postinst").read_text().splitlines() if not x.lstrip().startswith("#"))
    assert t.count("secubox-aggregator") == 1
    assert (DEB / "preinst").read_text().startswith("#!/bin/sh\nset -e")
