# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2743 — le postinst du hub pose la DIRECTIVE `proxy_set_header X-SecuBox-LAN $lan_client;` quand core a été configuré avant lui.

CONSTAT (RPi400, 2026-10-15) : secubox-proxy.conf ne contenait la ligne qu'EN COMMENTAIRE. core ne l'ajoute que si `$lan_client` existe à ce moment-là (le fichier GeoIP vient du
hub) ; sur une image neuve core passe avant hub, la ligne est retirée, et rien ne la remet. Sans l'en-tête, l'API croit tout client « WAN » : le second facteur (facultatif sur le
LAN, #1699) est exigé même depuis 192.168.1.3. Même piège que #1351 : tester la CHAÎNE au lieu de la DIRECTIVE.

On exécute le VRAI bloc du postinst, sous `set -e`, avec un faux nginx."""
import subprocess
from pathlib import Path

import pytest

PKG = Path(__file__).resolve().parents[1]
POST = (PKG / "debian" / "postinst").read_text()
DIRECTIVE = "proxy_set_header   X-SecuBox-LAN     $lan_client;"
COMMENTAIRE = """# Ce snippet est inclus par chaque location d'API.
# POURQUOI. Elle vaut `proxy_set_header X-SecuBox-LAN $lan_client;`, et
# `$lan_client` est defini par conf.d/secubox-lan-geo.conf, livre par secubox-hub.
proxy_set_header   Host              $host;
"""


def bloc():
    d = POST.index("    # VERDICT LAN POUR TOUTE L'API (#2743)")
    f = POST.index("    # `nginx -t` AVANT tout rechargement")
    return POST[d:f]


def lance(tmp_path, snippet=COMMENTAIRE, geo=True, nginx_ok=True, snippet_present=True):
    s = tmp_path / "secubox-proxy.conf"
    if snippet_present:
        s.write_text(snippet)
    g = tmp_path / "secubox-lan-geo.conf"
    if geo:
        g.write_text("geo $lan_client { default 0; }\n")
    faux = tmp_path / "bin"
    faux.mkdir(exist_ok=True)
    (faux / "nginx").write_text("#!/bin/sh\nexit %d\n" % (0 if nginx_ok else 1))
    (faux / "nginx").chmod(0o755)
    script = tmp_path / "bloc.sh"
    script.write_text("set -e\n" + bloc() + "echo FIN\n")
    r = subprocess.run(["bash", str(script)], capture_output=True, text=True,
                       env={"PATH": f"{faux}:/usr/bin:/bin", "SECUBOX_PROXY_SNIPPET": str(s), "SECUBOX_LAN_GEO": str(g)})
    return r, s


def directives(s):
    return [ligne for ligne in s.read_text().splitlines() if ligne.strip().startswith("proxy_set_header") and "X-SecuBox-LAN" in ligne]


def test_un_snippet_ou_la_ligne_n_est_qu_un_commentaire_recoit_la_directive(tmp_path):
    """LE CAS DU RPi400."""
    r, s = lance(tmp_path)
    assert r.returncode == 0 and "FIN" in r.stdout, (r.returncode, r.stderr)
    assert directives(s) == [DIRECTIVE]
    assert not Path(str(s) + ".sbxbak").exists()


def test_idempotent_une_seconde_configuration_n_ajoute_rien(tmp_path):
    r, s = lance(tmp_path)
    r2, _ = lance(tmp_path, snippet=s.read_text())
    assert r2.returncode == 0 and len(directives(s)) == 1


def test_une_directive_deja_posee_meme_indentee_n_est_pas_dupliquee(tmp_path):
    r, s = lance(tmp_path, snippet="    proxy_set_header X-SecuBox-LAN $lan_client;\n")
    assert r.returncode == 0 and len(directives(s)) == 1


def test_si_nginx_refuse_le_snippet_est_restaure_tel_quel(tmp_path):
    """`$lan_client` inconnue casserait TOUTE la configuration nginx : on teste, et on retire."""
    r, s = lance(tmp_path, nginx_ok=False)
    assert r.returncode == 0 and "FIN" in r.stdout
    assert s.read_text() == COMMENTAIRE and not Path(str(s) + ".sbxbak").exists()


def test_sans_le_fichier_geoip_on_n_y_touche_pas(tmp_path):
    r, s = lance(tmp_path, geo=False)
    assert r.returncode == 0 and s.read_text() == COMMENTAIRE


def test_sans_snippet_aucune_erreur_sous_set_e(tmp_path):
    r, _ = lance(tmp_path, snippet_present=False)
    assert r.returncode == 0 and "FIN" in r.stdout


def test_le_bloc_precede_le_test_et_le_rechargement_de_nginx():
    assert POST.index("# VERDICT LAN POUR TOUTE L'API (#2743)") < POST.index("# `nginx -t` AVANT tout rechargement")


def test_le_garde_reconnait_la_directive_et_pas_la_chaine():
    """Régression de #1351 : `grep -q 'X-SecuBox-LAN'` trouvait le COMMENTAIRE."""
    b = bloc()
    assert "proxy_set_header[[:space:]]+X-SecuBox-LAN" in b and "grep -q 'X-SecuBox-LAN'" not in b and 'grep -q "X-SecuBox-LAN"' not in b
