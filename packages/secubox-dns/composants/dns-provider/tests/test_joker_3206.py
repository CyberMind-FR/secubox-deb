# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3206 — joker DNS d'un pair du maillage : « *.<nœud> A <ip publique du relais> » dans la zone gérée.

Vécu sur gk3 puis gk4 (2026-10-27) : le défi DNS-01 du certificat joker crée _acme-challenge.<nœud>, le nœud existe
alors dans la zone et le joker parent (*.secubox.in) ne couvre plus ses noms : 19 noms refusés par le relais jusqu'à la
création à la main de *.gk4 chez Gandi. Le relais l'assure désormais lui-même : idempotent, jamais d'écrasement."""
import asyncio
import sys
from pathlib import Path

import pytest

COMP = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(COMP))

from api import joker  # noqa: E402


class Faux:
    """Adaptateur simulé : domaines gérés, enregistrements par zone, créations notées."""

    def __init__(self, domaines, enregistrements=None, refuse=False):
        self.domaines = domaines
        self.enregistrements = enregistrements or {}
        self.crees = []
        self.refuse = refuse

    async def list_domains(self):
        return [{"name": d, "id": d, "status": "active"} for d in self.domaines]

    async def list_records(self, zone):
        return list(self.enregistrements.get(zone, []))

    async def create_record(self, zone, rec):
        if self.refuse:
            raise RuntimeError("Gandi API 409 : déjà là")
        self.crees.append((zone, rec))
        self.enregistrements.setdefault(zone, []).append({"name": rec[0], "type": "A", "value": rec[1], "ttl": 300})
        return {"success": True}


def fabrique(nom, ip):
    return (nom, ip)


def assurer(fournisseurs, domaine, ip="82.67.100.75"):
    return asyncio.run(joker.assurer(fournisseurs, domaine, ip, fabrique))


GANDI = [{"name": "*", "type": "A", "value": "82.67.100.75"}, {"name": "*.gk3", "type": "A", "value": "82.67.100.75"}]


def test_cree_le_joker_du_noeud():
    g = Faux(["secubox.in", "maegia.tv"], {"secubox.in": list(GANDI)})
    r = assurer([("df97", g)], "gk4.secubox.in")
    assert r == {"etat": "cree", "zone": "secubox.in", "nom": "*.gk4", "ip": "82.67.100.75", "fournisseur": "df97"}
    assert g.crees == [("secubox.in", ("*.gk4", "82.67.100.75"))]


def test_deja_juste_rien_n_est_cree():
    g = Faux(["secubox.in"], {"secubox.in": list(GANDI)})
    r = assurer([("df97", g)], "gk3.secubox.in")
    assert r["etat"] == "inchange" and g.crees == []


def test_jamais_d_ecrasement():
    g = Faux(["secubox.in"], {"secubox.in": [{"name": "*.gk4", "type": "A", "value": "203.0.113.9"}]})
    with pytest.raises(joker.Refus, match="203.0.113.9"):
        assurer([("df97", g)], "gk4.secubox.in")
    assert g.crees == []


@pytest.mark.parametrize("domaine", [
    "secubox.in",                 # la zone elle-même : jamais un joker d'apex
    "a.gk4.secubox.in",           # plusieurs niveaux sous la zone
    "gk4.autre.fr",               # zone non gérée
    "GK4.secubox.in;rm",          # invalide
    "",
])
def test_refus_hors_forme_noeud_zone(domaine):
    g = Faux(["secubox.in"], {"secubox.in": list(GANDI)})
    with pytest.raises(joker.Refus):
        assurer([("df97", g)], domaine)
    assert g.crees == []


@pytest.mark.parametrize("ip", ["192.168.1.200", "10.10.0.1", "127.0.0.1", "pas-une-ip", "2001:db8::1"])
def test_refus_d_une_ip_non_publique(ip):
    g = Faux(["secubox.in"], {"secubox.in": list(GANDI)})
    with pytest.raises(joker.Refus):
        assurer([("df97", g)], "gk4.secubox.in", ip)
    assert g.crees == []


def test_zone_la_plus_longue_l_emporte():
    """gk4.lab.secubox.in sous la zone lab.secubox.in (si gérée) : libellé gk4, pas « gk4.lab »."""
    g = Faux(["secubox.in", "lab.secubox.in"], {})
    r = assurer([("p", g)], "gk4.lab.secubox.in")
    assert (r["zone"], r["nom"]) == ("lab.secubox.in", "*.gk4")


def test_verifie_apres_creation():
    class Muet(Faux):
        async def create_record(self, zone, rec):
            self.crees.append((zone, rec))                     # « succès » sans effet : jamais cru sur parole
            return {"success": True}

    g = Muet(["secubox.in"], {"secubox.in": list(GANDI)})
    with pytest.raises(joker.Echec, match="absent"):
        assurer([("df97", g)], "gk4.secubox.in")
