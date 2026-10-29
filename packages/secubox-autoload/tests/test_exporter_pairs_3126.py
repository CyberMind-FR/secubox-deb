# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3126 (L1 « Voir », tâche 7) : projection publique des pairs (adresse tunnel → client, lot, série, profil, abonnement), sans aucun secret."""
import importlib.machinery
import importlib.util
import json
import os
import stat
import sys
from pathlib import Path

import pytest

ICI = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ICI))
from autoload import jetons as J, tunnel as T  # noqa: E402

T0_PASSE = 1_000_000_000
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
    return {"var": var, "db": db, "reg": reg, "pairs": pairs, "jeton": e.valeur, "public": tmp_path / "autoload-public", "sortie": tmp_path / "autoload-public" / "pairs-publics.json"}


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
    assert json.loads((tmp_path / "autoload-public" / "pairs-publics.json").read_text()) == {"version": 1, "pairs": []}
    assert not (var / "jetons.db").exists()


def test_tunnel_sync_exporte(base, monkeypatch):
    ctl = _charger_ctl()
    monkeypatch.setattr(ctl.T, "synchroniser", lambda *a, **k: 1)
    assert ctl.main(["tunnel-sync"]) == 0
    assert base["sortie"].exists() and _lire(base)["pairs"][0]["client"] == "lgm"


def test_echec_export_ne_fait_pas_echouer_tunnel_sync_mais_exporter_pairs_oui(base, monkeypatch, capsys):
    ctl = _charger_ctl()
    monkeypatch.setattr(ctl.T, "synchroniser", lambda *a, **k: 1)
    base["public"].mkdir(mode=0o755)
    base["public"].chmod(0o777)                                 # inscriptible par tous : refusé
    assert ctl.main(["tunnel-sync"]) == 0
    assert "exporter-pairs" in capsys.readouterr().err and not base["sortie"].exists()
    assert ctl.main(["exporter-pairs"]) != 0


def test_le_dossier_public_est_cree_en_0755(base):
    assert not base["public"].exists()
    assert _charger_ctl().main(["exporter-pairs"]) == 0
    assert stat.S_IMODE(base["public"].stat().st_mode) == 0o755 and base["sortie"].exists()
    assert not (base["var"] / "pairs-publics.json").exists()    # plus rien dans le dossier du service


def test_dossier_public_lien_est_refuse(base, tmp_path):
    cible = tmp_path / "ailleurs"
    cible.mkdir(mode=0o755)
    base["public"].symlink_to(cible)
    from autoload import projection as P
    with pytest.raises(P.ProjectionErreur):
        P.exporter(base["db"], base["public"])
    assert list(cible.iterdir()) == []


def test_racine_lien_est_refusee(base, tmp_path):
    cible = tmp_path / "ailleurs"
    cible.mkdir(mode=0o755)
    lien = tmp_path / "lien"
    lien.symlink_to(cible)
    from autoload import projection as P
    with pytest.raises(P.ProjectionErreur):
        P.exporter(base["db"], lien / "autoload-public")
    assert list(cible.iterdir()) == []


def test_un_fichier_de_sortie_lien_est_remplace_pas_suivi(base, tmp_path):
    base["public"].mkdir(mode=0o755)
    victime = tmp_path / "victime"
    victime.write_text("intact")
    base["sortie"].symlink_to(victime)
    assert _charger_ctl().main(["exporter-pairs"]) == 0
    assert victime.read_text() == "intact" and not base["sortie"].is_symlink()
    assert _lire(base)["version"] == 1
    assert [p.name for p in base["public"].iterdir() if p.name.startswith(".")] == []


def test_abonnement_echu_est_projete_comme_lister(base):
    base["reg"].fixer_abonnement("lgm", "actif", expire_le=T0_PASSE)
    _charger_ctl().main(["exporter-pairs"])
    assert _lire(base)["pairs"][0]["abonnement"] == "echu"
    assert base["reg"].lister()[0]["abonnement"] == "echu"


def test_base_verrouillee_ne_remplace_pas_la_projection(base, monkeypatch, capsys):
    import sqlite3
    from autoload import projection as P
    ctl = _charger_ctl()
    assert ctl.main(["exporter-pairs"]) == 0
    avant = base["sortie"].read_bytes()
    monkeypatch.setattr(P, "DELAI_S", 0.2)
    verrou = sqlite3.connect(base["db"], isolation_level=None)
    verrou.execute("BEGIN EXCLUSIVE")
    try:
        assert ctl.main(["exporter-pairs"]) == 1
        assert "exporter-pairs" in capsys.readouterr().err
        monkeypatch.setattr(ctl.T, "synchroniser", lambda *a, **k: 1)
        assert ctl.main(["tunnel-sync"]) == 0
    finally:
        verrou.rollback()
        verrou.close()
    assert base["sortie"].read_bytes() == avant


def test_base_corrompue_sans_trace(base, capsys):
    ctl = _charger_ctl()
    base["db"].write_bytes(os.urandom(4096))
    assert ctl.main(["exporter-pairs"]) == 1
    err = capsys.readouterr().err
    assert "exporter-pairs" in err and "Traceback" not in err
    import unittest.mock as mock
    with mock.patch.object(ctl.T, "synchroniser", lambda *a, **k: 1):
        assert ctl.main(["tunnel-sync"]) == 0
    assert not base["sortie"].exists()


def test_projection_sans_les_valeurs_reelles_de_la_base(base):
    import sqlite3
    cx = sqlite3.connect(base["db"])
    secrets_ = [v for ligne in cx.execute("SELECT cle_pub, empreinte FROM jetons") for v in ligne if v] + [base["jeton"]]
    cx.close()
    assert len(secrets_) >= 3
    _charger_ctl().main(["exporter-pairs"])
    brut = base["sortie"].read_text()
    assert all(v not in brut for v in secrets_)


def test_temporaire_nettoye_si_le_renommage_echoue(base, monkeypatch):
    from autoload import projection as P
    def casse(*a, **k):
        raise OSError(5, "Input/output error")
    monkeypatch.setattr(P.os, "replace", casse)
    with pytest.raises(P.ProjectionErreur):
        P.exporter(base["db"], base["public"])
    assert list(base["public"].iterdir()) == []


def test_fd_ferme_si_fchmod_echoue(base, monkeypatch):
    from autoload import projection as P
    vus = []
    reel_fchmod = os.fchmod

    def fchmod(fd, mode):
        if mode == 0o644:
            vus.append(fd)
            raise OSError(1, "Operation not permitted")
        return reel_fchmod(fd, mode)
    monkeypatch.setattr(P.os, "fchmod", fchmod)
    with pytest.raises(P.ProjectionErreur):
        P.exporter(base["db"], base["public"])
    assert len(vus) == 1
    with pytest.raises(OSError):
        os.fstat(vus[0])                                        # EBADF : le descripteur du temporaire est fermé
    assert list(base["public"].iterdir()) == []


def test_dossier_public_existant_trop_ferme_est_remis_en_0755(base):
    base["public"].mkdir(mode=0o700)
    base["public"].chmod(0o700)
    assert _charger_ctl().main(["exporter-pairs"]) == 0
    assert stat.S_IMODE(base["public"].stat().st_mode) == 0o755 and base["sortie"].exists()


def test_exporter_rend_le_nombre_de_pairs(base):
    from autoload import projection as P
    chemin, n = P.exporter(base["db"], base["public"])
    assert n == 1 and chemin == base["sortie"]
