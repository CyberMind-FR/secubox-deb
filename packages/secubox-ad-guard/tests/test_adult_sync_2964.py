# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""secubox-adguard-adult-sync (#2964, suite de #2962) : exception adulte par
appareil, sans lever le filtrage pubs/trackers.

Contrairement à `ip-allowlist.txt` (bypass complet via une vue Unbound vide),
un appareil exempté ici garde le sinkhole général — sa vue le redéclare
entièrement, minoré des domaines adultes. C'est ce que ces tests prouvent :
un domaine NON adulte reste `always_nxdomain` dans la vue d'exception."""
import importlib.machinery
import importlib.util
import sys
import types
from pathlib import Path

import pytest

ICI = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ICI.parents[1] / "common"))
import secubox_unbound as U  # noqa: E402

SCRIPT = ICI / "sbin" / "secubox-adguard-adult-sync"

HOSTS_ADULTE = (
    "0.0.0.0 cam-adulte.example\n"
    "0.0.0.0 tube-adulte.example\n"
    "# un commentaire\n"
    "127.0.0.1 deja-bloque.example\n"
)


@pytest.fixture
def mod(tmp_path, monkeypatch):
    fl = types.ModuleType("secubox_filterlists")
    fl.OUT_DNS = tmp_path / "dns-domains.txt"
    fl.OUT_DNS.write_text("pub.example\ntracker.example\ndeja-bloque.example\n")
    monkeypatch.setitem(sys.modules, "secubox_filterlists", fl)
    loader = importlib.machinery.SourceFileLoader("adult_sync_test", str(SCRIPT))
    spec = importlib.util.spec_from_loader("adult_sync_test", loader)
    m = importlib.util.module_from_spec(spec)
    loader.exec_module(m)
    m.GENERAL_DNS = fl.OUT_DNS
    m.CACHE = tmp_path / "ad-guard" / "adult-source-cache.txt"
    m.ADULT_DOMAINS = tmp_path / "ad-guard" / "adult-domains.txt"
    m.EXEMPT_IP = tmp_path / "ad-guard" / "adult-exempt-ip.txt"
    m.DROPIN = tmp_path / "unbound.d" / "96-secubox-adult.conf"
    m.STATUS = tmp_path / "ad-guard" / "adult-sinkhole-status.json"
    m.STATE = tmp_path / "ad-guard" / "adult-sinkhole.enabled"
    m._fetch = lambda force=False: HOSTS_ADULTE
    return m


class Faux(U.SystemeUnbound):
    MODULE = "adguard-adult-sync"

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


def test_parse_hosts_lit_le_format_hosts_et_ignore_les_commentaires():
    from importlib.machinery import SourceFileLoader
    import importlib.util as iu
    loader = SourceFileLoader("adult_sync_parse", str(SCRIPT))
    spec = iu.spec_from_loader("adult_sync_parse", loader)
    m = iu.module_from_spec(spec)
    loader.exec_module(m)
    assert m.parse_hosts(HOSTS_ADULTE) == {
        "cam-adulte.example", "tube-adulte.example", "deja-bloque.example",
    }


def test_la_synchronisation_pose_verifie_et_recharge(mod):
    s = Faux()
    st = mod.do_sync(systeme=s)
    assert st["ok"] is True and st["adult"] == 3 and st["reloaded"] is True
    assert "cam-adulte.example" in mod.DROPIN.read_text()
    assert s.appels == ["verifier", "recharger"]


def test_un_domaine_deja_bloque_par_le_general_nest_pas_redeclare(mod):
    # "deja-bloque.example" est dans le sinkhole GÉNÉRAL (fixture) ET dans la
    # source adulte : le déclarer une 2e fois en `local-zone` ferait refuser
    # la config par Unbound (deux `local-zone` pour le même nom).
    mod.do_sync(systeme=Faux())
    texte = mod.DROPIN.read_text()
    assert texte.count('local-zone: "deja-bloque.example."') == 0


def test_sans_appareil_exempte_aucune_vue(mod):
    mod.do_sync(systeme=Faux())
    assert "view:" not in mod.DROPIN.read_text()


def test_appareil_exempte_garde_le_sinkhole_general_hors_adulte(mod):
    mod.EXEMPT_IP.parent.mkdir(parents=True, exist_ok=True)
    mod.EXEMPT_IP.write_text("192.168.1.3\n")
    st = mod.do_sync(systeme=Faux())
    texte = mod.DROPIN.read_text()
    assert st["exempt_ip"] == 1
    assert "access-control-view: 192.168.1.3 sbx-adult-allow" in texte
    assert 'view-first: yes' in texte
    # La vue bloque TOUJOURS les domaines du sinkhole général qui ne sont pas
    # adultes — pubs/trackers restent filtrés pour cet appareil.
    assert 'local-zone: "pub.example." always_nxdomain' in texte
    assert 'local-zone: "tracker.example." always_nxdomain' in texte
    # Mais laisse passer les domaines adultes.
    assert 'local-zone: "cam-adulte.example." always_transparent' in texte
    assert 'local-zone: "tube-adulte.example." always_transparent' in texte


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
    assert not hasattr(mod.Systeme, "redemarrer_unbound")


def test_desactiver_retire_la_vue_et_recharge(mod):
    mod.do_sync(systeme=Faux())
    s = Faux()
    st = mod.do_disable(systeme=s)
    assert st["ok"] is True and st["enabled"] is False and not mod.DROPIN.exists()
    assert s.appels == ["verifier", "recharger"]


def test_source_injoignable_sans_cache_echoue_proprement(mod):
    mod._fetch = lambda force=False: None
    st = mod.do_sync(systeme=Faux())
    assert st["ok"] is False and "unreachable" in st["error"]
