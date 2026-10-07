# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""secubox-adblock-sync (D4, #2050) : pose du drop-in `95-secubox-adblock.conf` par la bibliothèque commune.

Avant : écriture NON atomique (`write_text`), restauration par `write_text`, et un repli « systemctl restart unbound » quand le rechargement échouait —
un échec de rechargement pouvait donc couper la résolution de tout le réseau. Désormais : écriture atomique, vérification, rechargement, retour arrière
octet pour octet (et rechargement de l'ancienne vue) ; aucun redémarrage, jamais."""
import importlib.machinery
import importlib.util
import sys
import types
from pathlib import Path

import pytest

ICI = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ICI.parents[1] / "common"))
import secubox_unbound as U  # noqa: E402

SCRIPT = ICI / "sbin" / "secubox-adblock-sync"


@pytest.fixture
def mod(tmp_path, monkeypatch):
    fl = types.ModuleType("secubox_toolbox.filterlists")
    fl.OUT_DNS = tmp_path / "domains.txt"
    fl.OUT_DNS.write_text("ads.example\ntracker.example\n")
    fl.compile_lists = lambda force=False: {"compiled": 2}
    pkg = types.ModuleType("secubox_toolbox")
    pkg.filterlists = fl
    monkeypatch.setitem(sys.modules, "secubox_toolbox", pkg)
    monkeypatch.setitem(sys.modules, "secubox_toolbox.filterlists", fl)
    loader = importlib.machinery.SourceFileLoader("adblock_sync_test", str(SCRIPT))
    spec = importlib.util.spec_from_loader("adblock_sync_test", loader)
    m = importlib.util.module_from_spec(spec)
    loader.exec_module(m)
    m.DROPIN = tmp_path / "unbound.d" / "95-secubox-adblock.conf"
    m.STATUS = tmp_path / "ad-guard" / "sinkhole-status.json"
    m.STATE = tmp_path / "ad-guard" / "sinkhole.enabled"
    m.IP_ALLOWLIST = tmp_path / "ad-guard" / "ip-allowlist.txt"
    m.DOMAIN_ALLOWLIST = tmp_path / "ad-guard" / "domain-allowlist.txt"
    return m


class Faux(U.SystemeUnbound):
    MODULE = "adblock-sync"

    def __init__(self, verif=(True, ""), recharge_ok=True):
        self.verif, self.recharge_ok, self.appels = verif, recharge_ok, []

    def verifier_unbound(self):
        self.appels.append("verifier")
        return self.verif

    def recharger_unbound(self):
        self.appels.append("recharger")
        if not self.recharge_ok:
            raise self.ERREUR("reload a échoué")

    def audit(self, action, detail=""):
        pass


def test_la_synchronisation_pose_verifie_et_recharge(mod):
    s = Faux()
    st = mod.do_sync(systeme=s)
    assert st["ok"] is True and st["blocked"] == 2 and st["reloaded"] is True
    assert "ads.example" in mod.DROPIN.read_text() and s.appels == ["verifier", "recharger"]


def test_une_config_refusee_remet_l_ancienne_octet_pour_octet(mod):
    mod.DROPIN.parent.mkdir(parents=True)
    mod.DROPIN.write_bytes(b"# ancienne vue\n")
    st = mod.do_sync(systeme=Faux(verif=(False, "syntax error")))
    assert st["ok"] is False and "unbound-checkconf" in st["error"]
    assert mod.DROPIN.read_bytes() == b"# ancienne vue\n"


def test_un_rechargement_qui_echoue_restaure_et_ne_redemarre_jamais(mod):
    mod.DROPIN.parent.mkdir(parents=True)
    mod.DROPIN.write_bytes(b"# ancienne vue\n")
    s = Faux(recharge_ok=False)
    st = mod.do_sync(systeme=s)
    assert st["ok"] is False and mod.DROPIN.read_bytes() == b"# ancienne vue\n"
    assert s.appels == ["verifier", "recharger", "recharger"], "l'ancienne vue est rechargée, aucun redémarrage"
    assert not hasattr(mod.Systeme, "redemarrer_unbound")


def test_un_contenu_identique_ne_recharge_rien(mod):
    mod.do_sync(systeme=Faux())
    s = Faux()
    st = mod.do_sync(systeme=s)
    assert st["ok"] is True and st["reloaded"] is False and s.appels == []


def test_desactiver_retire_la_vue_et_recharge(mod):
    mod.do_sync(systeme=Faux())
    s = Faux()
    st = mod.do_disable(systeme=s)
    assert st["ok"] is True and st["enabled"] is False and not mod.DROPIN.exists() and s.appels == ["verifier", "recharger"]


def test_desactiver_sans_vue_ne_recharge_rien(mod):
    s = Faux()
    st = mod.do_disable(systeme=s)
    assert st["ok"] is True and s.appels == []


def test_le_script_ne_contient_plus_de_repli_par_redemarrage():
    src = SCRIPT.read_text()
    assert '"restart"' not in src and "systemctl" not in src
