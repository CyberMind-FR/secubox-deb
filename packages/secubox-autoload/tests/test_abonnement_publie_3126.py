# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3126 (relecture finale L1, I2/R37) : tout changement d'abonnement ou révocation par l'API relance tunnel-sync, donc l'export de la
projection publique lue par le maître de pilotage ; une minuterie horaire du service la recalcule (échéance → « echu »)."""
import asyncio
import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from secubox_core import auth
from autoload import jetons as J, projection as P, tunnel as T
from api import main as A

ICI = Path(__file__).resolve().parents[1]
CLE_A, CLE_B = "A" * 43 + "=", "B" * 43 + "="
HUB = "H" * 43 + "="
T0 = 1_800_000_000


class Horloge:
    def __init__(self):
        self.t = float(T0)

    def __call__(self):
        return self.t


class Monde:
    """Le service d'enrôlement avec un tunnel-sync factice qui fait ce que fait le vrai pour la projection : l'export."""

    def __init__(self, tmp_path):
        self.h = Horloge()
        self.db = tmp_path / "var" / "jetons.db"
        self.db.parent.mkdir()
        self.public = tmp_path / "autoload-public"
        self.reg = J.Registre(self.db, tmp_path / "audit.log", horloge=self.h)
        self.pairs = T.Pairs(self.db, horloge=self.h)
        self.syncs, self.echec = 0, False
        self.app = A.creer_app(self.reg, self.pairs, HUB, self.appliquer, horloge=self.h)
        self.app.dependency_overrides[auth.require_jwt] = lambda: {"sub": "admin"}
        self.c = TestClient(self.app)

    def appliquer(self):
        if self.echec:
            raise T.TunnelErreur("wg indisponible")
        self.syncs += 1
        P.exporter(self.db, self.public)

    def projection(self):
        return {p["client"]: p["abonnement"] for p in json.loads((self.public / P.NOM).read_text())["pairs"]}

    def enroler(self, client, cle, **kw):
        e = self.reg.emettre(client, "lite", **kw)
        r = self.c.post("/enrol", json={"jeton": e.valeur, "cle_pub": cle}, headers={"X-Forwarded-For": "203.0.113.5"})
        assert r.status_code == 200
        return e


@pytest.fixture
def m(tmp_path):
    return Monde(tmp_path)


@pytest.mark.parametrize("statut", ["revoque", "suspendu"])
def test_changement_d_abonnement_publie_la_projection(m, statut):
    m.enroler("lgm", CLE_A)
    assert m.projection() == {"lgm": "actif"}
    n = m.syncs
    r = m.c.post("/clients/lgm/abonnement", json={"statut": statut})
    assert r.status_code == 200 and r.json()["tunnel_applique"] is True
    assert m.syncs == n + 1 and m.projection() == {"lgm": statut}


def test_abonnement_publie_meme_si_tunnel_sync_echoue_ensuite_rattrape(m):
    m.enroler("lgm", CLE_A)
    m.echec = True
    r = m.c.post("/clients/lgm/abonnement", json={"statut": "revoque"})
    assert r.status_code == 200 and r.json()["tunnel_applique"] is False   # l'état est enregistré ; la minuterie horaire republiera
    assert m.reg.livraison_autorisee(CLE_A) is False


def test_revocation_d_un_jeton_publie_meme_sans_pair_a_retirer(m):
    e = m.reg.emettre("c1", "lite")                       # jamais réclamé : aucun pair
    n = m.syncs
    r = m.c.post(f"/jetons/{e.id}/revoquer", json={"motif": "erreur"})
    assert r.status_code == 200 and r.json()["tunnel_applique"] is True and m.syncs == n + 1


def test_revocation_d_un_lot_publie_meme_sans_pair_a_retirer(m):
    m.reg.emettre("c1", "lite", lot="lot-1")
    n = m.syncs
    r = m.c.post("/lots/lot-1/revoquer", json={"motif": "lot défectueux"})
    assert r.status_code == 200 and r.json()["pairs_retires"] == 0 and r.json()["tunnel_applique"] is True and m.syncs == n + 1


def test_echeance_passee_publiee_echu_par_la_minuterie(m, monkeypatch):
    m.enroler("lgm", CLE_A)
    m.c.post("/clients/lgm/abonnement", json={"statut": "actif", "mois": 1})
    monkeypatch.setattr(P.time, "time", lambda: T0)
    m.appliquer()
    assert m.projection() == {"lgm": "actif"}
    # l'échéance passe sans aucune action d'administration ; seule la minuterie horaire relance tunnel-sync (l'export calcule « echu »)
    monkeypatch.setattr(P.time, "time", lambda: T0 + 40 * 86400)
    appels = []

    async def attente(s):
        appels.append(s)
        if len(appels) >= 2:
            raise asyncio.CancelledError

    async def tourner():
        await T.republier_periodiquement(m.appliquer, attente=attente)
    with pytest.raises(asyncio.CancelledError):
        asyncio.run(tourner())
    assert m.projection() == {"lgm": "echu"}
    assert appels == [T.REPUBLICATION_DELAI_S, T.REPUBLICATION_S] and T.REPUBLICATION_S == 3600


def test_minuterie_survit_a_un_echec_et_reessaie(capsys):
    essais = []

    def appliquer():
        essais.append(1)
        if len(essais) == 1:
            raise T.TunnelErreur("sudo refusé")

    async def tour():
        n = []

        async def attente(s):
            n.append(s)
            if len(n) >= 3:
                raise asyncio.CancelledError
        with pytest.raises(asyncio.CancelledError):
            await T.republier_periodiquement(appliquer, attente=attente)
    asyncio.run(tour())
    assert len(essais) == 2 and "republication" in capsys.readouterr().err


def test_le_lanceur_sert_la_minuterie_sans_nouvelle_unite():
    lanceur = (ICI / "sbin" / "secubox-autoload-api").read_text()
    assert "republier_periodiquement" in lanceur and "publier_par_sudo" in lanceur     # N4 : la minuterie passe par tunnel-sync --sans-reactiver
    assert not list((ICI / "systemd").glob("*.timer")) and not (ICI / "systemd" / "secubox-autoload-sync.service").exists()
