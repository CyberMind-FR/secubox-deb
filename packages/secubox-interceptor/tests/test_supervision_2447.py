# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""#2447 — supervision réelle : analyse du journal sbxmitm, niveaux, exclusions, jamais de mesure inventée."""
import json
import sys
import pathlib

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from api import main as m  # noqa: E402

NOW = 1_800_000_000.0


def _l(age_s, unite, msg):
    return json.dumps({"MESSAGE": msg, "_SYSTEMD_UNIT": f"secubox-toolbox-ng-worker@{unite}.service", "__REALTIME_TIMESTAMP": str(int((NOW - age_s) * 1e6))})


def test_journal_compte_hotes_moteurs_et_minutes():
    j = "\n".join([
        _l(10, 1, "2026/10/12 09:42:29 ja4 t2a2a_c21_ah2_sni=Bag.iTunes.apple.com"),
        _l(70, 1, "2026/10/12 09:41:29 ja4 tbaba_c21_ah2_sni=bag.itunes.apple.com"),
        _l(130, 3, "2026/10/12 09:40:29 ja4 t9a9a_c21_ah2_sni=xp.apple.com"),
        _l(99999, 2, "ja4 tzzz_c21_ah2_sni=trop-ancien.test"),               # hors fenêtre
        _l(5, 2, "[csp-debug] rien à voir"),                                  # pas une ligne JA4
        "pas du json",
    ])
    r = m.parse_journal(j, NOW, 60)
    assert r["total"] == 3 and r["hotes_distincts"] == 2 and r["empreintes_distinctes"] == 3
    assert r["top_hotes"][0] == {"hote": "bag.itunes.apple.com", "n": 2}
    assert r["par_moteur"] == {"1": 2, "3": 1} and len(r["serie"]) == 60
    assert r["serie"][-1] == 1 and r["serie"][-2] == 1 and r["serie"][-3] == 1 and sum(r["serie"]) == 3


def test_journal_vide_ou_illisible_ne_leve_pas():
    assert m.parse_journal("", NOW, 60)["total"] == 0 and m.parse_journal("x\n{", NOW, 60)["total"] == 0


def test_parse_ss():
    assert m.parse_ss("LISTEN 0 4096 10.99.1.1:8091 0.0.0.0:*\nLISTEN 0 4096 [::]:9080 [::]:*\nbof") == {"10.99.1.1:8091", "[::]:9080"}


def test_niveaux_et_exclusions_depuis_les_fichiers(tmp_path):
    (tmp_path / "peer-rlevel.json").write_text(json.dumps({"defaults": {"mode": "reel"}, "peers": {"a": {"chosen": "reel"}, "b": {"chosen": "passive"}, "c": {}}}))
    (tmp_path / "cumulative-cache.json").write_text(json.dumps({"level_distribution_7d": {"r3": 2}, "events": {"total_7d": 40}}))
    (tmp_path / "mitm-bypass.conf").write_text("# c\n(.+\\.)?signal\\.org\n\n")
    n = m.niveaux(tmp_path)
    assert n["pairs"] == 3 and n["repartition_pairs"] == {"reel": 1, "passive": 1, "défaut": 1} and n["evenements_7j"] == 40 and n["niveaux_clients"] == {"r3": 2}
    e = m.exclusions(tmp_path)
    assert e["bypass"] == ["(.+\\.)?signal\\.org"] and e["splice"] is None and e["filtres_desactives"] is None     # absent = null, jamais []


def test_sources_absentes_donnent_null_pas_zero(tmp_path):
    n = m.niveaux(tmp_path)
    assert n["pairs"] is None and n["niveaux_clients"] is None and n["evenements_7j"] is None


def test_moteurs_etat_et_port(monkeypatch):
    def faux(cmd, timeout=10):
        if cmd[0] == "ss":
            return "LISTEN 0 4096 10.99.1.1:8091 0.0.0.0:*\n"
        return "active\n" if cmd[-1].endswith("@1") else "inactive\n"
    monkeypatch.setattr(m, "_sh", faux)
    r = {x["nom"]: x for x in m.moteurs()}
    assert r["sbxmitm 1"]["actif"] and r["sbxmitm 1"]["port_ouvert"] is True and not r["sbxmitm 2"]["actif"] and r["sbxmitm 2"]["port_ouvert"] is False


def test_aucune_ecriture_ni_action_dans_l_api():
    posts = [r for r in m.app.routes if getattr(r, "methods", None) and (r.methods & {"POST", "PUT", "DELETE", "PATCH"})]
    assert posts == []
