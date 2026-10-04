# SPDX-License-Identifier: LicenseRef-CMSD-1.0
import io
import json
import shutil
import subprocess
from pathlib import Path

import pytest

from dns_lan import cli
from tests.test_appliquer import Faux

RACINE = Path(__file__).resolve().parent.parent


@pytest.fixture
def conf(tmp_path):
    t = (RACINE / "conf" / "dns-lan.toml").read_text()
    t = t.replace('/etc/unbound/unbound.conf.d', str(tmp_path / "u")).replace(
        "/etc/systemd/network/10-netplan-eth2.network.d/50-secubox-ipv6-stable.conf", str(tmp_path / "r" / "50.conf"))
    (tmp_path / "u").mkdir()
    p = tmp_path / "dns-lan.toml"
    p.write_text(t)
    return str(p)


def lancer(args, systeme=None):
    out = io.StringIO()
    code = cli.main(args, systeme=systeme, sortie=out)
    return code, out.getvalue()


def test_generate_puis_check_conforme(conf):
    code, out = lancer(["--config", conf, "generate"], Faux())
    assert code == 0 and json.loads(out)["ok"] is True
    code, out = lancer(["--config", conf, "check"])
    assert code == 0 and json.loads(out) == {"ok": True, "ecart": []}


def test_check_signale_la_derive(conf):
    lancer(["--config", conf, "generate"], Faux())
    f = next(Path(conf).parent.glob("u/96-secubox-lan.conf"))
    f.write_text("server:\n    interface: 1.2.3.4\n")
    code, out = lancer(["--config", conf, "check"])
    assert code == 3 and json.loads(out)["ok"] is False


def test_status_liste_les_fichiers(conf):
    code, out = lancer(["--config", conf, "status"])
    d = json.loads(out)
    assert code == 0 and len(d["fichiers"]) == 5 and d["ecart"] == 5


def test_config_absente_ou_invalide_code_1(tmp_path, capsys):
    assert lancer(["--config", str(tmp_path / "absent.toml"), "generate"])[0] == 1
    mauvais = tmp_path / "x.toml"
    mauvais.write_text('[lan]\ninterface = "pas-une-ip"\nacces = ["10.0.0.0/8"]\n')
    assert lancer(["--config", str(mauvais), "check"])[0] == 1
    assert "secubox-dns-lan" in capsys.readouterr().err


@pytest.mark.skipif(shutil.which("unbound-checkconf") is None, reason="unbound-checkconf absent")
def test_de_bout_en_bout_avec_le_vrai_unbound_checkconf(tmp_path, conf, monkeypatch):
    """Le rendu complet doit être accepté par le vrai unbound-checkconf (un conf minimal qui inclut le dossier généré)."""
    lancer(["--config", conf, "generate"], Faux())
    u = tmp_path / "u"
    racine = tmp_path / "unbound.conf"
    racine.write_text(f'server:\n    directory: "{tmp_path}"\n    chroot: ""\n    username: ""\ninclude: "{u}/*.conf"\n')
    r = subprocess.run(["unbound-checkconf", str(racine)], capture_output=True, text=True)
    assert r.returncode == 0, r.stdout + r.stderr
