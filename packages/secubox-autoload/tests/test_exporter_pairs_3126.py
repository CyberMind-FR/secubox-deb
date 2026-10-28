# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3126 (L1 « Voir », tâche 7) : projection publique des pairs (adresse tunnel → client, lot, série, profil, abonnement), sans aucun secret."""
import importlib.machinery
import importlib.util
import json
import stat
import sys
from pathlib import Path

import pytest

ICI = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ICI))
from autoload import jetons as J, tunnel as T  # noqa: E402

CLE_A, CLE_B, CLE_C = "A" * 43 + "=", "B" * 43 + "=", "C" * 43 + "="


def _charger_ctl():
    ldr = importlib.machinery.SourceFileLoader("autoloadctl_3126", str(ICI / "sbin" / "autoloadctl"))
    spec = importlib.util.spec_from_loader("autoloadctl_3126", ldr)
    m = importlib.util.module_from_spec(spec)
    ldr.exec_module(m)
    return m


@pytest.fixture
def base(tmp_path, monkeypatch):
    var = tmp_path / "var"
    var.mkdir(mode=0o750)
    db = var / "jetons.db"
    monkeypatch.setenv("SECUBOX_AUTOLOAD_DB", str(db))
    monkeypatch.setenv("SECUBOX_AUTOLOAD_AUDIT", str(tmp_path / "audit.log"))
    reg = J.Registre(db, tmp_path / "audit.log")
    pairs = T.Pairs(db)
    e = reg.emettre("lgm", "lite", lot="lot-1", serie="SBX-1")
    reg.reclamer(e.valeur, CLE_A)
    adresse = pairs.attribuer(CLE_A)
    assert adresse == "10.64.0.2"
    return {"var": var, "db": db, "reg": reg, "pairs": pairs, "jeton": e.valeur, "sortie": var / "pairs-publics.json"}


def _lire(b):
    return json.loads(b["sortie"].read_text())


def test_projection_sans_secret(base):
    base["reg"].emettre("autre", "isp")                       # un jeton émis et jamais réclamé n'apparaît pas
    assert _charger_ctl().main(["exporter-pairs"]) == 0
    brut = base["sortie"].read_text()
    for interdit in ("cle_pub", "empreinte", CLE_A, base["jeton"], "gk2_"):
        assert interdit not in brut
    assert set(_lire(base)["pairs"][0]) == {"adresse", "client", "lot", "serie", "profil", "abonnement"}


def test_projection_relie_adresse_et_client(base):
    assert _charger_ctl().main(["exporter-pairs"]) == 0
    assert _lire(base) == {"version": 1, "pairs": [{"adresse": "10.64.0.2", "client": "lgm", "lot": "lot-1", "serie": "SBX-1", "profil": "lite", "abonnement": "actif"}]}
    assert stat.S_IMODE(base["sortie"].stat().st_mode) == 0o644
    base["reg"].fixer_abonnement("lgm", "suspendu")
    _charger_ctl().main(["exporter-pairs"])
    assert _lire(base)["pairs"][0]["abonnement"] == "suspendu"


def test_champs_sans_valeur_sont_null_et_les_pairs_retires_absents(base):
    e = base["reg"].emettre("k2", "lite")                      # ni lot ni série
    base["reg"].reclamer(e.valeur, CLE_B)
    base["pairs"].attribuer(CLE_B)
    e3 = base["reg"].emettre("k3", "lite")
    base["reg"].reclamer(e3.valeur, CLE_C)
    base["pairs"].attribuer(CLE_C)
    base["pairs"].retirer(CLE_C)
    base["pairs"].attribuer(CLE_A)                              # idempotent
    _charger_ctl().main(["exporter-pairs"])
    par = {p["client"]: p for p in _lire(base)["pairs"]}
    assert set(par) == {"lgm", "k2"} and par["k2"]["lot"] is None and par["k2"]["serie"] is None


def test_pair_sans_jeton_reclame_absent(base):
    base["pairs"].attribuer(CLE_B)                              # adresse attribuée, aucun jeton lié à cette clé
    _charger_ctl().main(["exporter-pairs"])
    assert [p["adresse"] for p in _lire(base)["pairs"]] == ["10.64.0.2"]


def test_base_absente_projection_vide_et_base_non_creee(tmp_path, monkeypatch):
    var = tmp_path / "v"
    var.mkdir(mode=0o750)
    monkeypatch.setenv("SECUBOX_AUTOLOAD_DB", str(var / "jetons.db"))
    assert _charger_ctl().main(["exporter-pairs"]) == 0
    assert json.loads((var / "pairs-publics.json").read_text()) == {"version": 1, "pairs": []}
    assert not (var / "jetons.db").exists()


def test_tunnel_sync_exporte(base, monkeypatch):
    ctl = _charger_ctl()
    monkeypatch.setattr(ctl.T, "synchroniser", lambda *a, **k: 1)
    assert ctl.main(["tunnel-sync"]) == 0
    assert base["sortie"].exists() and _lire(base)["pairs"][0]["client"] == "lgm"


def test_echec_export_ne_fait_pas_echouer_tunnel_sync_mais_exporter_pairs_oui(base, monkeypatch, capsys):
    ctl = _charger_ctl()
    monkeypatch.setattr(ctl.T, "synchroniser", lambda *a, **k: 1)
    base["var"].chmod(0o770)                                    # inscriptible par le groupe : refusé
    assert ctl.main(["tunnel-sync"]) == 0
    assert "exporter-pairs" in capsys.readouterr().err and not base["sortie"].exists()
    assert ctl.main(["exporter-pairs"]) != 0


def test_dossier_remplace_par_un_lien_est_refuse(base, tmp_path, monkeypatch):
    cible = tmp_path / "ailleurs"
    cible.mkdir(mode=0o750)
    reel = tmp_path / "var-reel"
    base["var"].rename(reel)
    base["var"].symlink_to(cible)
    monkeypatch.setenv("SECUBOX_AUTOLOAD_DB", str(reel / "jetons.db"))   # la base se lit ailleurs ; seul le dossier de sortie est un lien
    from autoload import projection as P
    with pytest.raises(P.ProjectionErreur):
        P.exporter(reel / "jetons.db", base["var"])
    assert list(cible.iterdir()) == []


def test_un_fichier_de_sortie_lien_est_remplace_pas_suivi(base, tmp_path):
    victime = tmp_path / "victime"
    victime.write_text("intact")
    base["sortie"].symlink_to(victime)
    assert _charger_ctl().main(["exporter-pairs"]) == 0
    assert victime.read_text() == "intact" and not base["sortie"].is_symlink()
    assert _lire(base)["version"] == 1
    assert [p.name for p in base["var"].iterdir() if p.name.startswith(".")] == []
