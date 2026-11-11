# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3674 : SBX TV Privacy est toujours actif — activation à chaque configuration du paquet, jamais de réglage par
appareil touché, jamais d'état corrompu écrasé."""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from api import dnstv  # noqa: E402


def _conf(monkeypatch, ajout):
    monkeypatch.setattr(dnstv, "_conf_paquet", lambda: {"adblock_tv": {"ajout_auto_initial": ajout}})


def test_etat_absent_ecrit_actif_avec_ajout_auto(tmp_path, monkeypatch):
    _conf(monkeypatch, True)
    assert dnstv.activer_toujours(tmp_path) is True
    e = dnstv.lire_etat(tmp_path)[0]
    assert e["actif"] is True and e["ajout_auto"] is True and e["mode_defaut"] == "auto"


def test_etat_d_usine_inactif_devient_actif_et_detecte(tmp_path, monkeypatch):
    _conf(monkeypatch, True)
    (tmp_path / "etat.json").write_text(json.dumps({"actif": False, "clients": [], "ajout_auto": False}))
    assert dnstv.activer_toujours(tmp_path) is True
    e = dnstv.lire_etat(tmp_path)[0]
    assert e["actif"] is True and e["ajout_auto"] is True


def test_reglages_par_appareil_jamais_touches(tmp_path, monkeypatch):
    _conf(monkeypatch, True)
    clients = [{"ip": "192.168.1.50", "nom": "TV", "mode": "observe"}]
    (tmp_path / "etat.json").write_text(json.dumps({"actif": False, "clients": clients, "ajout_auto": False}))
    assert dnstv.activer_toujours(tmp_path) is True
    e = dnstv.lire_etat(tmp_path)[0]
    assert e["actif"] is True and e["ajout_auto"] is False and e["clients"][0]["mode"] == "observe"
    assert dnstv.activer_toujours(tmp_path) is False                     # déjà actif : rien n'est réécrit


def test_etat_corrompu_jamais_ecrase(tmp_path, monkeypatch):
    _conf(monkeypatch, True)
    (tmp_path / "etat.json").write_text("{ pas du json")
    assert dnstv.activer_toujours(tmp_path) is False
    assert (tmp_path / "etat.json").read_text() == "{ pas du json"


# --- relecture sécurité #3674 ---------------------------------------------------------------------------------------------

def _charger_auto():
    import importlib.machinery
    import importlib.util
    chemin = Path(__file__).resolve().parents[1] / "sbin" / "secubox-adguard-auto"
    spec = importlib.util.spec_from_loader("adguard_auto_3674", importlib.machinery.SourceFileLoader("adguard_auto_3674", str(chemin)))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


class _R:
    def __init__(self, rc):
        self.returncode, self.stdout, self.stderr = rc, "", ""


def test_amorcage_box_d_image_applique_une_fois_par_demi_heure(tmp_path, monkeypatch):
    m = _charger_auto()
    _conf(monkeypatch, True)
    monkeypatch.setattr(dnstv, "DOSSIER_ETAT", tmp_path)
    monkeypatch.setattr(dnstv, "CONF_UNBOUND", tmp_path / "94-absent.conf")
    monkeypatch.setattr(m, "AMORCE", tmp_path / ".amorce-essai")
    from api import dnstv_regles
    monkeypatch.setattr(dnstv_regles, "verrou", lambda *a, **k: __import__("contextlib").nullcontext())
    appels = []
    assert m.amorcer(10_000, lancer=lambda: appels.append(1) or _R(0)) is True
    assert dnstv.lire_etat(tmp_path)[0]["actif"] is True and appels == [1]
    assert m.amorcer(10_000 + 60, lancer=lambda: appels.append(1) or _R(0)) is False        # pas avant 30 min
    assert m.amorcer(10_000 + 1801, lancer=lambda: appels.append(1) or _R(0)) is True and len(appels) == 2
    (tmp_path / "94-absent.conf").write_text("x")
    assert m.amorcer(10_000 + 9999, lancer=lambda: appels.append(1) or _R(0)) is False       # drop-in présent : rien


def test_disable_n_est_plus_ouvert_au_compte_secubox():
    s = (Path(__file__).resolve().parents[1] / "sudoers.d" / "secubox-adguard-tv").read_text()
    regle = [ligne for ligne in s.splitlines() if ligne.startswith("secubox ")][0]
    assert "secubox-adguard-tv disable" not in regle and "secubox-adguard-tv apply" in regle


def test_postinst_n_applique_que_si_necessaire():
    p = (Path(__file__).resolve().parents[1] / "debian" / "postinst").read_text()
    assert 'if [ "$tv" = 0 ] || { [ "$tv" = 10 ] && { [ ! -f /etc/unbound/unbound.conf.d/94-secubox-adguard-tv.conf ]' in p
    assert 'systemctl enable secubox-ad-guard-dnsfeed.service' in p                          # hors systemd : sans --now
