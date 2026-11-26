# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3969 — activité des campagnes sur 7 jours par tranche de 6 h : agrégat incrémental (octets neufs seulement),
tranche non mesurée = null, campagne comptée depuis qu'elle est connue, aucune adresse rendue, état relu. Adresses de
documentation (RFC 5737)."""
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from api import activite as A  # noqa: E402

T = datetime(2026, 11, 25, 12, 30, 0, tzinfo=timezone.utc).timestamp()
H = 3600
IPV4 = re.compile(r"(?<![\d.])\d{1,3}(?:\.\d{1,3}){3}(?![\d.])")


def ligne(il_y_a, ip="203.0.113.7", **k):
    d = {"timestamp": datetime.fromtimestamp(T - il_y_a, tz=timezone.utc).isoformat(), "client_ip": ip, "host": "x.example.test",
         "category": "sqli", "severity": "high", "action": "banned"}
    d.update(k)
    return json.dumps(d)


@pytest.fixture
def box(tmp_path, monkeypatch):
    A.vider()
    c = {"journal": tmp_path / "waf-threats.log", "etat": tmp_path / "activite.json", "campagnes": tmp_path / "campaigns.json", "vie": tmp_path / "vie.json"}
    monkeypatch.setattr(A, "CHEMINS", c)
    c["campagnes"].write_text(json.dumps({"attaquants": 3, "campagnes": [
        {"signature": "aaaa1111", "attaquants": ["203.0.113.7", "203.0.113.8"]}, {"signature": "bbbb2222", "attaquants": ["198.51.100.4"]}]}))

    class Box:
        ch = c

        def ecrire(self, *lignes):
            with open(c["journal"], "a") as f:
                f.write("".join(x + "\n" for x in lignes))
    return Box()


def test_tranches_alignees_sur_paris():
    k = A.tranche(T)
    assert A.debut(k) <= T < A.debut(k + 1) and A.debut(k + 1) - A.debut(k) == 6 * H
    assert datetime.fromtimestamp(A.debut(k), A._d.PARIS).hour in (0, 6, 12, 18)


def test_compte_par_campagne_null_hors_couverture_et_sans_adresse(box):
    box.ecrire(ligne(30 * H), ligne(30 * H - 60, ip="203.0.113.8"), ligne(2 * H), ligne(2 * H - 120, ip="198.51.100.4"),
               ligne(H, ip="192.0.2.99"), ligne(H - 60, severity="audit"))
    v = A.rafraichir(T, forcer=True)
    assert len(v["debuts"]) == 28 and v["pas_s"] == 6 * H
    a, b = v["campagnes"]["aaaa1111"], v["campagnes"]["bbbb2222"]
    assert sum(x or 0 for x in a) == 3 and sum(x or 0 for x in b) == 1   # l'adresse hors campagne et la ligne d'état ne comptent pas
    assert a[0] is None and v["couverture"][0] is None                      # il y a 7 jours : non mesuré, jamais 0
    assert any(x == 0 for x in b)                                           # tranche couverte sans événement : 0 mesuré
    assert not IPV4.search(json.dumps(v)) and not IPV4.search(box.ch["etat"].read_text())


def test_incremental_et_campagne_connue_ensuite(box):
    box.ecrire(ligne(3 * H))
    A.rafraichir(T - 2 * H)
    taille = box.ch["journal"].stat().st_size
    box.ch["campagnes"].write_text(json.dumps({"campagnes": [{"signature": "aaaa1111", "attaquants": ["203.0.113.7"]},
                                                              {"signature": "cccc3333", "attaquants": ["198.51.100.9"]}]}))
    box.ecrire(ligne(H - 60), ligne(H - 30, ip="198.51.100.9"))
    v = A.rafraichir(T)
    assert A._fond["agregat"].e["curseur"].endswith(":" + str(box.ch["journal"].stat().st_size)) and taille < box.ch["journal"].stat().st_size
    assert sum(x or 0 for x in v["campagnes"]["aaaa1111"]) == 2
    c = v["campagnes"]["cccc3333"]
    assert sum(x or 0 for x in c) == 1 and c[-2] is None                   # avant d'être connue : non mesurée
    assert "bbbb2222" not in v["campagnes"]                                 # sortie de l'instantané : oubliée


def test_etat_relu_par_un_autre_processus(box):
    box.ecrire(ligne(2 * H))
    A.rafraichir(T, forcer=True)
    A.vider()
    v = A.vue(lambda: T + 60)
    assert v["disponible"] and v["age_s"] == 60 and sum(x or 0 for x in v["campagnes"]["aaaa1111"]) == 1
    box.ch["etat"].write_text('{"v": 1}')
    A.vider()
    assert A.vue() == {"disponible": False}


def test_route_lue_en_lecture():
    src = (Path(__file__).resolve().parents[1] / "api" / "main.py").read_text(encoding="utf-8")
    assert '@app.get("/campaigns/activite", dependencies=[Depends(require_lecture_ai)])' in src
    assert "_activite.rafraichir" in src and "return await asyncio.to_thread(_activite.vue)" in src
