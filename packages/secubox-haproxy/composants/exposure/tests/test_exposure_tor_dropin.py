# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Les services onion vivent dans /etc/tor/torrc.d/, pas dans /etc/tor/torrc (#2050, écrivains concurrents).

Avant, l'API d'exposition AJOUTAIT ses lignes au fichier /etc/tor/torrc de Debian et en RETIRAIT par une
expression régulière `.*?` en mode DOTALL, que torctl, la macro Tor et le toolbox touchent aussi (par torrc.d).
Un fichier par service, écrit atomiquement : pas de relecture-réécriture d'un fichier partagé, et retirer un
service ne peut plus emporter les lignes d'un autre."""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[5]
sys.path.insert(0, str(ROOT / "common"))
sys.path.insert(0, str(ROOT / "packages" / "secubox-haproxy" / "composants" / "exposure"))

import api.main as m  # noqa: E402


def cadre(monkeypatch, tmp_path):
    torrc = tmp_path / "torrc"
    torrc.write_text("SocksPort 9050\nLog notice file /var/log/tor/notices.log\n%include /etc/tor/torrc.d/*.conf\n")
    monkeypatch.setattr(m, "TOR_CONFIG", torrc)
    monkeypatch.setattr(m, "TOR_DROPIN_DIR", tmp_path / "torrc.d")
    monkeypatch.setattr(m, "TOR_DATA", tmp_path / "hs")
    monkeypatch.setattr(m, "run_cmd", lambda *a, **k: "")
    return torrc


def test_ajouter_ecrit_un_fichier_par_service_et_ne_touche_pas_au_torrc(monkeypatch, tmp_path):
    torrc = cadre(monkeypatch, tmp_path)
    avant = torrc.read_text()
    (tmp_path / "hs" / "webui").mkdir(parents=True)
    (tmp_path / "hs" / "webui" / "hostname").write_text("abc.onion\n")
    r = m._tor_add_sync("webui", local_port=9080, onion_port=80)
    f = tmp_path / "torrc.d" / "70-secubox-hs-webui.conf"
    assert r["onion"] == "abc.onion"
    assert f.read_text().splitlines()[-2:] == [f"HiddenServiceDir {tmp_path / 'hs' / 'webui'}",
                                               "HiddenServicePort 80 127.0.0.1:9080"]
    assert torrc.read_text() == avant, "le torrc de Debian n'est plus réécrit"
    assert not list((tmp_path / "torrc.d").glob("*.tmp")), "écriture atomique"


def test_retirer_supprime_le_fichier_et_laisse_les_autres_services(monkeypatch, tmp_path):
    cadre(monkeypatch, tmp_path)
    for n in ("a", "b"):
        (tmp_path / "hs" / n).mkdir(parents=True)
        m._tor_add_sync(n, local_port=80, onion_port=80)
    m._tor_remove_sync("a")
    assert not (tmp_path / "torrc.d" / "70-secubox-hs-a.conf").exists()
    assert (tmp_path / "torrc.d" / "70-secubox-hs-b.conf").exists()
    assert not (tmp_path / "hs" / "a").exists()


def test_retirer_un_ancien_bloc_du_torrc_n_emporte_que_ce_bloc(monkeypatch, tmp_path):
    """Les services posés avant ce changement sont encore dans le torrc : on les retire proprement, ligne à ligne."""
    torrc = cadre(monkeypatch, tmp_path)
    hs = tmp_path / "hs"
    torrc.write_text(
        "SocksPort 9050\n"
        f"\n# Hidden service: vieux\nHiddenServiceDir {hs / 'vieux'}\nHiddenServicePort 80 127.0.0.1:80\n"
        f"\n# Hidden service: autre\nHiddenServiceDir {hs / 'autre'}\nHiddenServicePort 80 127.0.0.1:81\n"
        "ControlPort 9051\n")
    (hs / "vieux").mkdir(parents=True)
    m._tor_remove_sync("vieux")
    t = torrc.read_text()
    assert "vieux" not in t
    assert "SocksPort 9050" in t and "ControlPort 9051" in t
    assert f"HiddenServiceDir {hs / 'autre'}" in t and "HiddenServicePort 80 127.0.0.1:81" in t


def test_la_presence_se_voit_dans_le_fichier_ou_dans_l_ancien_torrc(monkeypatch, tmp_path):
    torrc = cadre(monkeypatch, tmp_path)
    assert m._torrc_has_stanza("x") is False
    m._tor_add_sync("x", local_port=80, onion_port=80)
    assert m._torrc_has_stanza("x") is True
    torrc.write_text(f"HiddenServiceDir {tmp_path / 'hs' / 'ancien'}\nHiddenServicePort 80 127.0.0.1:80\n")
    assert m._torrc_has_stanza("ancien") is True


def test_la_liste_des_services_lit_le_port_dans_le_fichier(monkeypatch, tmp_path):
    cadre(monkeypatch, tmp_path)
    (tmp_path / "hs" / "webui").mkdir(parents=True)
    (tmp_path / "hs" / "webui" / "hostname").write_text("abc.onion\n")
    m._tor_add_sync("webui", local_port=9080, onion_port=8443)
    s = m.get_tor_services()
    assert s == [{"service": "webui", "onion": "abc.onion", "port": "8443", "backend": "127.0.0.1:9080"}]
