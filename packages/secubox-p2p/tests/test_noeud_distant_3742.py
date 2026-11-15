# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3742 — nœud distant (hors LAN) : annonce publique déclarative remise aux seuls nœuds distants, avec keepalive ; LAN inchangé."""
import base64
from pathlib import Path

import pytest

from api import main, mesh

CLE = base64.b64encode(b"k" * 32).decode()
CLE_MAITRE = base64.b64encode(b"m" * 32).decode()


def _req(adresse, distant=None):
    return main.JoinRequest(token="t", fingerprint="fp", hostname="gk7", address=adresse, wg_public_key=CLE, wg_port=51822,
                            distant=distant)


@pytest.mark.parametrize("brut,attendu", [
    ("gk2.secubox.in:51822", "gk2.secubox.in:51822"),
    ("GK2.secubox.in:51822", "gk2.secubox.in:51822"),
    ("82.67.100.75:51822", "82.67.100.75:51822"),
    ("[2a01:e0a:dec:c4e0::200]:51822", "[2a01:e0a:dec:c4e0::200]:51822"),
    ("2a01:e0a:dec:c4e0::200:51822", None),          # IPv6 sans crochets : ambiguë
    ("gk2.secubox.in", None), ("gk2.secubox.in:0", None), ("gk2.secubox.in:51822\nPostUp = id", None),
    ("a b:51822", None), ("", None), (None, None),
])
def test_validation_de_l_annonce(brut, attendu):
    assert mesh.public_endpoint_valide(brut) == attendu


def test_champ_lu_dans_p2p_toml(tmp_path):
    p = tmp_path / "p2p.toml"
    p.write_text('[wireguard]\nlisten_port = 51822\npublic_endpoint = "gk2.secubox.in:51822"\n')
    assert mesh.load_p2p_config(p)["public_endpoint"] == "gk2.secubox.in:51822"
    p.write_text('[wireguard]\nlisten_port = 51822\n')
    assert mesh.load_p2p_config(p)["public_endpoint"] is None


def test_un_noeud_distant_n_a_pas_d_endpoint_lan_chez_le_maitre():
    jr = {"address": "192.168.42.17"}
    main._record_wg_identity(jr, _req("192.168.42.17", distant=True))
    assert jr["distant"] is True and "wg_endpoint" not in jr


def test_un_noeud_lan_garde_son_endpoint():
    jr = {"address": "192.168.1.30"}
    main._record_wg_identity(jr, _req("192.168.1.30"))
    assert jr["wg_endpoint"] == "192.168.1.30:51822" and "distant" not in jr


def _offre(monkeypatch, tmp_path, jr, toml):
    p = tmp_path / "p2p.toml"
    p.write_text(toml)
    monkeypatch.setattr(main, "CONFIG_FILE", p)
    monkeypatch.setattr(main, "get_wg_mesh_config", lambda: {"address": "10.10.0.1/24", "listen_port": 51822})
    monkeypatch.setattr(main, "_master_wg_pubkey", lambda st: CLE_MAITRE)
    return main._wg_offer({"wg_public_key": CLE, "mesh_ip": "10.10.0.9", **jr})


ANNONCE = '[wireguard]\npublic_endpoint = "gk2.secubox.in:51822"\n'


def test_offre_au_noeud_distant_porte_l_annonce_et_le_keepalive(monkeypatch, tmp_path):
    o = _offre(monkeypatch, tmp_path, {"distant": True}, ANNONCE)
    assert o["master_endpoint"] == "gk2.secubox.in:51822" and o["persistent_keepalive"] == 25


def test_offre_au_noeud_lan_inchangee(monkeypatch, tmp_path):
    o = _offre(monkeypatch, tmp_path, {}, ANNONCE)
    assert "master_endpoint" not in o and "persistent_keepalive" not in o
    assert set(o) == {"master_public_key", "master_port", "master_mesh_ip", "address", "network"}


def test_sans_annonce_le_noeud_distant_garde_l_adresse_jointe(monkeypatch, tmp_path):
    o = _offre(monkeypatch, tmp_path, {"distant": True}, '[wireguard]\nlisten_port = 51822\n')
    assert "master_endpoint" not in o
    assert mesh.endpoint_vers_maitre(o, "admin.gk2.secubox.in") == "admin.gk2.secubox.in:51822"


def test_le_pair_compose_l_endpoint_depuis_l_annonce():
    assert mesh.endpoint_vers_maitre({"master_port": 51822, "master_endpoint": "gk2.secubox.in:51822"}, "x") == "gk2.secubox.in:51822"
    assert mesh.endpoint_vers_maitre({"master_port": 51822, "master_endpoint": "a\nb:1"}, "192.168.1.1") == "192.168.1.1:51822"


def test_conf_rendue_du_noeud_distant():
    etat = {"private_key": CLE, "address": "10.10.0.9/24", "peers": [
        {"public_key": CLE_MAITRE, "endpoint": "gk2.secubox.in:51822", "allowed_ips": "10.10.0.0/24", "persistent_keepalive": 25}]}
    conf = mesh.render_wg_conf(etat)
    assert "Endpoint = gk2.secubox.in:51822" in conf and "PersistentKeepalive = 25" in conf


def test_le_script_de_jonction_se_declare_distant_hors_lan():
    s = (Path(__file__).resolve().parents[1] / "scripts" / "sbx-mesh-join").read_text()
    assert 'es_adresse_locale "$MASTER_IP" || DISTANT=true' in s and '"distant":$DISTANT' in s
    assert "mesh.endpoint_vers_maitre(wg, master_ip)" in s


def test_postinst_ne_reecrit_jamais_p2p_toml():
    s = (Path(__file__).resolve().parents[1] / "debian" / "postinst").read_text()
    bloc = s[s.index("#3742"):s.index("Create secubox user")]
    assert ">> /etc/secubox/p2p.toml" not in bloc and "> /etc/secubox/p2p.toml" not in bloc and "sed -i" not in bloc
