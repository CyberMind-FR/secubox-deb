# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""secubox-adblock-sync : D4 (#2050) puis #3205 — le rendu est DÉPOSÉ comme source de secubox-dns-listes.

D4 avait remplacé une écriture non atomique et un repli « systemctl restart unbound » par la bibliothèque commune (pose,
vérification, rechargement, retour arrière). Depuis #3205, un seul service compile les trois listes (webfilter, adblock,
adult), vérifie, recharge et revient en arrière : le script dépose sa source et ne touche plus ni Unbound ni sa
configuration."""
import importlib.machinery
import importlib.util
import sys
import types
from pathlib import Path

import pytest

ICI = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ICI.parents[1] / "common"))
from secubox_unbound import depot as D  # noqa: E402

SCRIPT = ICI / "sbin" / "secubox-adblock-sync"


@pytest.fixture
def mod(tmp_path, monkeypatch):
    # #2863 : la bibliotheque vit dans secubox_filterlists (secubox-core) ; secubox-toolbox n'est PAS necessaire (profil minimal).
    fl = types.ModuleType("secubox_filterlists")
    fl.OUT_DNS = tmp_path / "domains.txt"
    fl.OUT_DNS.write_text("ads.example\ntracker.example\n")
    fl.compile_lists = lambda force=False: {"compiled": 2}
    monkeypatch.setitem(sys.modules, "secubox_filterlists", fl)
    monkeypatch.setitem(sys.modules, "secubox_toolbox", None)       # None = « import impossible » : le toolbox est absent
    loader = importlib.machinery.SourceFileLoader("adblock_sync_test", str(SCRIPT))
    spec = importlib.util.spec_from_loader("adblock_sync_test", loader)
    m = importlib.util.module_from_spec(spec)
    loader.exec_module(m)
    m.SOURCE = tmp_path / "sources" / "95-secubox-adblock.conf"
    m.STATUS = tmp_path / "ad-guard" / "sinkhole-status.json"
    m.STATE = tmp_path / "ad-guard" / "sinkhole.enabled"
    m.IP_ALLOWLIST = tmp_path / "ad-guard" / "ip-allowlist.txt"
    m.DOMAIN_ALLOWLIST = tmp_path / "ad-guard" / "domain-allowlist.txt"
    return m


def test_la_synchronisation_depose_la_source(mod):
    st = mod.do_sync()
    assert st["ok"] is True and st["blocked"] == 2 and st["source"] == "depose"
    assert '"ads.example." always_nxdomain' in mod.SOURCE.read_text()
    assert st["application"] == "secubox-dns-listes" and "reloaded" not in st      # l'application est asynchrone


def test_un_contenu_identique_n_est_pas_redepose(mod):
    mod.do_sync()
    avant = mod.SOURCE.stat().st_mtime_ns
    st = mod.do_sync()
    assert st["ok"] is True and st["source"] == "inchange" and mod.SOURCE.stat().st_mtime_ns == avant


def test_le_rendu_est_accepte_par_le_compilateur(mod, tmp_path):
    """Allowlist d'IP comprise : la vue sbx-allow fait partie de ce qu'une source peut porter."""
    mod.IP_ALLOWLIST.parent.mkdir(parents=True, exist_ok=True)
    mod.IP_ALLOWLIST.write_text("192.168.1.7\n")
    mod.do_sync()
    texte, stats = D.listes.compiler([mod.SOURCE], [])
    assert stats["emis"] == 2 and '"tracker.example." always_nxdomain' in texte


def test_desactiver_retire_la_source(mod):
    mod.do_sync()
    st = mod.do_disable()
    assert st["ok"] is True and st["enabled"] is False and st["source"] == "retire" and not mod.SOURCE.exists()
    assert mod.STATE.read_text() == "0\n"


def test_desactiver_sans_source(mod):
    st = mod.do_disable()
    assert st["ok"] is True and st["source"] == "absent"


def test_un_depot_refuse_est_annonce(mod, tmp_path):
    mod.SOURCE.parent.mkdir(parents=True)
    mod.SOURCE.symlink_to(tmp_path / "ailleurs")
    st = mod.do_sync()
    assert st["ok"] is False and "lien symbolique" in st["error"] and not (tmp_path / "ailleurs").exists()


def test_le_script_ne_touche_plus_unbound():
    src = SCRIPT.read_text()
    for interdit in ("unbound.conf.d", "unbound-control", "unbound-checkconf", "poser_vue", "retirer_vue", '"restart"', "systemctl"):
        assert interdit not in src, interdit


def test_une_adresse_invalide_de_l_allowlist_est_ignoree(mod):
    """Une seule ligne invalide faisait échouer la compilation des TROIS listes (relecture #3205) : elle est écartée ici."""
    mod.IP_ALLOWLIST.parent.mkdir(parents=True, exist_ok=True)
    mod.IP_ALLOWLIST.write_text("192.168.1.7\npas-une-adresse\n10.0.0.0/33\n# commentaire\n")
    assert mod._ip_allowlist() == ["192.168.1.7"]
    mod.do_sync()
    D.listes.compiler([mod.SOURCE], [])                                   # ne lève pas
