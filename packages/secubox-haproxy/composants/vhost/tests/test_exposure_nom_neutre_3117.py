# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""#3117 : le filtre d'un vhost est celui que son fichier inclut."""
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[5]
sys.path.insert(0, str(ROOT / "packages" / "secubox-haproxy" / "composants" / "vhost"))
from api import exposure_read as er  # noqa: E402

VHOST = """server {
    listen 9080;
    server_name metablogizer.*;
    # include /etc/nginx/snippets/exposure/commente.conf;
    include /etc/nginx/snippets/exposure/metablogizer.conf;
}
"""


def _cadre(tmp_path):
    sites = tmp_path / "sites"; sites.mkdir()
    snip = tmp_path / "snip"; snip.mkdir()
    (sites / "metablogizer.conf").write_text(VHOST)
    er._index_cache["cle"] = None
    return sites, snip


def test_vhost_neutre_lit_le_filtre_inclus(tmp_path):
    sites, snip = _cadre(tmp_path)
    (snip / "metablogizer.conf").write_text("allow 127.0.0.1;\nallow 192.168.0.0/16;\ndeny all;\n")
    assert er.nom_du_filtre("metablogizer.gk3.secubox.in", [sites]) == "metablogizer"
    assert er.read_exposure("metablogizer.gk3.secubox.in", snippet_dir=snip,
                            sites_dirs=[sites])["reach"] == "lan"


def test_repli_fqdn_sans_include(tmp_path):
    sites, snip = _cadre(tmp_path)
    (sites / "autre.conf").write_text("server {\n server_name autre.example.org;\n}\n")
    (snip / "autre.example.org.conf").write_text("allow 127.0.0.1;\ndeny all;\n")
    assert er.read_exposure("autre.example.org", snippet_dir=snip,
                            sites_dirs=[sites])["reach"] == "localhost"


def test_nom_exact_prime_sur_le_joker(tmp_path):
    sites, snip = _cadre(tmp_path)
    (sites / "exact.conf").write_text(
        "server {\n server_name metablogizer.x.org;\n include /etc/nginx/snippets/exposure/exact.conf;\n}\n")
    er._index_cache["cle"] = None
    assert er.nom_du_filtre("metablogizer.x.org", [sites]) == "exact"
