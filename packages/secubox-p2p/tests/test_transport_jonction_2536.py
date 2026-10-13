# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2536 — sbx-mesh-join : HTTP:7331 pour un parent local, HTTPS (certificat vérifié) pour un parent distant ; et l'échec dit POURQUOI.

Essai réel gk1 → gk2 : le script ne parlait qu'en HTTP:7331, injoignable d'une box derrière une Freebox ; et la jonction automatique notait
« RuntimeError » sans le texte de l'exception."""
import re
import subprocess
import sys
from pathlib import Path

import pytest

ICI = Path(__file__).resolve().parents[1]
SCRIPT = (ICI / "scripts" / "sbx-mesh-join").read_text()
sys.path.insert(0, str(ICI))
from api import automesh  # noqa: E402


def _base(hote):
    """Exécute la VRAIE fonction `api_base_pour` extraite du script."""
    m = re.search(r"^es_adresse_locale\(\) \{.*?^\}\n", SCRIPT, re.M | re.S)
    n = re.search(r"^api_base_pour\(\) \{.*?^\}\n", SCRIPT, re.M | re.S)
    assert m and n, "fonctions de choix du transport absentes"
    code = 'API_PORT=7331\n' + m.group(0) + n.group(0) + f'api_base_pour "{hote}"\n'
    return subprocess.run(["bash", "-c", code], capture_output=True, text=True, timeout=10).stdout.strip()


@pytest.mark.parametrize("hote", ["192.168.1.200", "10.10.0.1", "172.16.4.2", "172.31.255.1", "127.0.0.1", "169.254.1.1", "gk2.local", "localhost"])
def test_parent_local_http_sur_le_port_du_module(hote):
    assert _base(hote) == f"http://{hote}:7331"


@pytest.mark.parametrize("hote", ["admin.gk2.secubox.in", "gk2.secubox.in", "82.67.100.75", "172.32.0.1", "172.15.0.1", "192.169.1.1", "exemple.test"])
def test_parent_distant_https_sans_port(hote):
    assert _base(hote) == f"https://{hote}"


def test_le_script_n_utilise_jamais_curl_k():
    assert not re.search(r"curl[^\n]*\s-k\b|--insecure", SCRIPT), "le certificat du parent doit être vérifié"


def test_la_route_debian_passe_par_la_base_choisie():
    assert '"$API_BASE/api/v1/p2p/master-link/join"' in SCRIPT
    assert '"$API_BASE/api/v1/p2p/master-link/status"' in SCRIPT or '"$base/api/v1/p2p/master-link/status"' in SCRIPT


def test_un_parent_distant_ne_tente_pas_les_routes_openwrt_en_clair():
    assert "es_adresse_locale" in SCRIPT and re.search(r"es_adresse_locale \"\$ip\" \|\|", SCRIPT)


def test_l_echec_garde_le_texte_de_l_exception(tmp_path):
    def rejoindre(adresse, jeton):
        raise RuntimeError("jonction refusée ou parent injoignable (code 7)")
    code = tmp_path / "code"
    code.write_text(automesh.encoder("admin.gk2.secubox.in", "a" * 64))
    etat = tmp_path / "etat.json"
    assert automesh.executer(rejoindre, str(code), str(etat)) == "echec"
    import json
    assert "parent injoignable (code 7)" in json.loads(etat.read_text())["message"]


def test_le_jeton_n_est_jamais_dans_le_message(tmp_path):
    jeton = "b" * 64

    def rejoindre(adresse, j):
        raise RuntimeError(f"erreur avec {j}")
    code = tmp_path / "code"
    code.write_text(automesh.encoder("admin.gk2.secubox.in", jeton))
    etat = tmp_path / "etat.json"
    automesh.executer(rejoindre, str(code), str(etat))
    assert jeton not in etat.read_text()
