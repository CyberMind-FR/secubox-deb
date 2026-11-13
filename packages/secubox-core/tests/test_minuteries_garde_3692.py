# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3692 : trois minuteries activées de gk2 restaient arrêtées des jours (dh_installsystemd --no-start les arrête à la
mise à jour du paquet, sans les relancer). Le garde relance toute minuterie SecuBox ACTIVÉE arrêtée, et rien d'autre."""
import importlib.machinery
import importlib.util
import json
import subprocess
from pathlib import Path

import pytest

RACINE = Path(__file__).resolve().parents[3]
SCRIPT = RACINE / "packages/secubox-core/sbin/secubox-minuteries-garde"


class FauxSystemctl:
    """Répond aux appels du garde comme systemd ; note les gestes."""

    def __init__(self, unites, absentes=()):
        self.unites = unites            # nom -> (UnitFileState, ActiveState)
        self.absentes = list(absentes)  # unités not-found en échec
        self.gestes = []

    def __call__(self, *args, delai=60):
        a = list(args)
        if a[0] == "list-unit-files":
            sortie = "".join(f"{n} {f} enabled\n" for n, (f, _) in self.unites.items() if f == "enabled")
        elif a[0] == "show":
            noms = a[a.index("--") + 1:]
            sortie = "\n".join(f"Id={n}\nActiveState={self.unites[n][1]}\nUnitFileState={self.unites[n][0]}\nLoadState=loaded\n"
                               for n in noms)
        elif a[0] == "list-units":
            sortie = "".join(f"{n} not-found failed failed {n}\n" for n in self.absentes)
        else:
            self.gestes.append(a)
            sortie = ""
        return subprocess.CompletedProcess(a, 0, sortie, "")


@pytest.fixture
def g(monkeypatch, tmp_path):
    chargeur = importlib.machinery.SourceFileLoader("garde3692", str(SCRIPT))
    spec = importlib.util.spec_from_loader("garde3692", chargeur)
    mod = importlib.util.module_from_spec(spec)
    chargeur.exec_module(mod)
    (tmp_path / "audit.log").write_text("")
    monkeypatch.setattr(mod, "AUDIT_DOSSIER", str(tmp_path))
    return mod


def test_relance_les_minuteries_activees_arretees_et_audite(g, monkeypatch, tmp_path):
    f = FauxSystemctl({
        "secubox-mail-imap-sync.timer": ("enabled", "inactive"),
        "secubox-sentinel-feeds.timer": ("enabled", "failed"),
        "secubox-dirs-guard.timer": ("enabled", "active"),
    })
    monkeypatch.setattr(g, "systemctl", f)
    assert g.main([]) == 0
    assert ["start", "--", "secubox-mail-imap-sync.timer"] in f.gestes
    assert ["start", "--", "secubox-sentinel-feeds.timer"] in f.gestes
    assert ["start", "--", "secubox-dirs-guard.timer"] not in f.gestes
    lignes = [json.loads(x) for x in (tmp_path / "audit.log").read_text().splitlines()]
    assert {x["unite"] for x in lignes if x["evenement"] == "minuterie_relancee"} == {
        "secubox-mail-imap-sync.timer", "secubox-sentinel-feeds.timer"}


def test_ne_touche_ni_desactivee_ni_etrangere(g, monkeypatch):
    f = FauxSystemctl({
        "secubox-healthbump.timer": ("disabled", "inactive"),
        "apt-daily.timer": ("enabled", "inactive"),
        "secubox-pilotage-garde-abc.timer": ("transient", "inactive"),
    })
    monkeypatch.setattr(g, "systemctl", f)
    assert g.main([]) == 0
    assert not [x for x in f.gestes if x[0] == "start"]


def test_efface_les_restes_d_unites_retirees(g, monkeypatch):
    f = FauxSystemctl({}, absentes=["secubox-dns-listes-contexte.timer", "autre-chose.service"])
    monkeypatch.setattr(g, "systemctl", f)
    assert g.main([]) == 0
    assert ["reset-failed", "--", "secubox-dns-listes-contexte.timer"] in f.gestes
    assert ["reset-failed", "--", "autre-chose.service"] not in f.gestes


def test_verifier_n_agit_pas(g, monkeypatch, capsys):
    f = FauxSystemctl({"secubox-premier-pas-decouverte.timer": ("enabled", "inactive")})
    monkeypatch.setattr(g, "systemctl", f)
    assert g.main(["--verifier"]) == 0
    sortie = json.loads(capsys.readouterr().out)
    assert sortie["ok"] is False and sortie["minuteries_arretees"] == ["secubox-premier-pas-decouverte.timer"]
    assert f.gestes == []


def test_minuterie_du_garde_sur_l_horloge():
    texte = (RACINE / "packages/secubox-core/systemd/secubox-minuteries-garde.timer").read_text()
    assert "OnCalendar=" in texte and "OnUnitActiveSec" not in texte
