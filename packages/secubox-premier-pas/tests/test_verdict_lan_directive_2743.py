# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2743 — le postinst de premier-pas teste la DIRECTIVE X-SecuBox-LAN, pas la chaîne (le commentaire de secubox-proxy.conf la contient).

CONSTAT (RPi400) : mon postinst (#2731) faisait `grep -q "X-SecuBox-LAN"`, trouvait le COMMENTAIRE, concluait « déjà posée » et retirait la route de session : la page distante
répondait encore « pas du réseau local ». Exécute le VRAI bloc sous `set -e`, avec un faux nginx."""
import subprocess
from pathlib import Path

PKG = Path(__file__).resolve().parents[1]
POST = (PKG / "debian" / "postinst").read_text()
COMMENTAIRE = "# Elle vaut `proxy_set_header X-SecuBox-LAN $lan_client;`, et `$lan_client` vient du hub.\nproxy_set_header Host $host;\n"


def bloc():
    d = POST.index("    # Verdict LAN de l'ouverture distante (#2731)")
    f = POST.index("    if [ -d /run/systemd/system ]; then\n        systemctl restart secubox-aggregator")
    return POST[d:f]


def lance(tmp_path, snippet, geo=True):
    (tmp_path / "secubox.d").mkdir(exist_ok=True)
    s = tmp_path / "secubox-proxy.conf"
    s.write_text(snippet)
    g = tmp_path / "geo.conf"
    if geo:
        g.write_text("geo $lan_client { default 0; }\n")
    src = tmp_path / "source.conf"
    src.write_text("location = /api/v1/premier-pas/session { }\n")
    faux = tmp_path / "bin"
    faux.mkdir(exist_ok=True)
    (faux / "nginx").write_text("#!/bin/sh\nexit 0\n")
    (faux / "systemctl").write_text("#!/bin/sh\nexit 0\n")
    for f in ("nginx", "systemctl"):
        (faux / f).chmod(0o755)
    script = tmp_path / "bloc.sh"
    script.write_text("set -e\n" + bloc() + "echo FIN\n")
    r = subprocess.run(["bash", str(script)], capture_output=True, text=True,
                       env={"PATH": f"{faux}:/usr/bin:/bin", "SECUBOX_PROXY_SNIPPET": str(s), "SECUBOX_LAN_GEO": str(g),
                            "SECUBOX_NGINX_SECUBOX_D": str(tmp_path / "secubox.d"), "PREMIER_PAS_SESSION_SOURCE": str(src)})
    return r, tmp_path / "secubox.d" / "premier-pas-session.conf"


def test_un_snippet_dont_la_ligne_n_est_qu_un_commentaire_recoit_la_route_de_session(tmp_path):
    """LE CAS DU RPi400 : l'ancien garde voyait le commentaire et retirait la route."""
    r, conf = lance(tmp_path, COMMENTAIRE)
    assert r.returncode == 0 and "FIN" in r.stdout, r.stderr
    assert conf.exists()


def test_une_vraie_directive_rend_la_route_inutile_et_la_retire(tmp_path):
    r, conf = lance(tmp_path, "proxy_set_header X-SecuBox-LAN $lan_client;\n")
    assert r.returncode == 0 and not conf.exists()


def test_sans_fichier_geoip_pas_de_route(tmp_path):
    r, conf = lance(tmp_path, COMMENTAIRE, geo=False)
    assert r.returncode == 0 and not conf.exists()


def test_le_garde_n_est_plus_une_recherche_de_chaine():
    assert 'grep -q "X-SecuBox-LAN"' not in POST and "proxy_set_header[[:space:]]+X-SecuBox-LAN" in POST
