# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Hôtes locaux (#1670) : seuls les noms exacts du domaine de la box, et joignables."""
import asyncio
import json

import pytest

from api import hotes


def test_candidats_exacts_du_domaine():
    t = ["server_name radio.gk3.secubox.in radio.gk3.net;",
         "  server_name hall.gk2.net hall.gk3.secubox.in hall.* ~^x\\.gk3\\.secubox\\.in$;",
         "server_name admin.gk2.secubox.in;"]
    assert hotes.candidats(t, "gk3.secubox.in") == ["hall.gk3.secubox.in", "radio.gk3.secubox.in"]
    assert hotes.candidats(t, "") == []
    # « mood.* » (#1680) : le service de la box sous son propre domaine.
    assert hotes.candidats(["server_name mood.gk2.secubox.in mood.*;"], "gk3.secubox.in") == ["mood.gk3.secubox.in"]


def test_seuls_les_joignables_sont_locaux(monkeypatch):
    monkeypatch.setattr(hotes, "lire_sites", lambda: ["server_name a.gk3.secubox.in b.gk3.secubox.in;"])

    async def joignable(nom):
        return nom.startswith("a.")
    monkeypatch.setattr(hotes, "_joignable", joignable)
    assert asyncio.run(hotes.recalculer("gk3.secubox.in")) == ["a.gk3.secubox.in"]
    assert hotes.locaux() == ["a.gk3.secubox.in"]


# #1714 : un nom que le frontal ne route pas (421) n'est pas un service servi.
def test_421_n_est_pas_joignable():
    from api import hotes as h
    assert h.repond(200) and h.repond(302) and h.repond(401) and h.repond(404)
    assert not h.repond(421)
    assert not h.repond(502) and not h.repond(504)


def test_classer_cartes_du_hall_d_abord():
    noms = ["aaa.gk2.secubox.in", "bbs.gk2.secubox.in", "zzz.gk2.secubox.in", "radio.gk2.secubox.in", "mmm.gk2.secubox.in"]
    assert hotes.classer(noms, ["radio", "bbs", None, ""]) == [
        "bbs.gk2.secubox.in", "radio.gk2.secubox.in", "aaa.gk2.secubox.in", "mmm.gk2.secubox.in", "zzz.gk2.secubox.in"]
    assert hotes.classer(noms, []) == sorted(noms)


# #3174 : chaque sonde d'un nom non routé laissait une anomalie « host_anomaly:unrouted » dans le journal des menaces du WAF
# (261 en une matinée sur gk2) et faisait de la box elle-même la « dernière attaque » du bandeau. La table de routes du WAF dit
# d'avance qu'un tel nom répondrait 421 : il n'est pas sondé.
def _tables(tmp_path, routes, a_la_demande=None):
    r = tmp_path / "haproxy-routes.json"
    r.write_text(routes if isinstance(routes, str) else json.dumps(routes))
    d = tmp_path / "on-demand-vhosts.json"
    if a_la_demande is not None:
        d.write_text(json.dumps(a_la_demande))
    return r, d


def test_noms_routes_table_du_waf_plus_vhosts_a_la_demande_3174(tmp_path):
    r, d = _tables(tmp_path, {"Hall.gk2.secubox.in": ["10.0.0.1", "80"], "10.55.0.1": ["10.0.0.2", "80"]}, ["Nc.gk2.secubox.in"])
    assert hotes.noms_routes(r, d) == {"hall.gk2.secubox.in", "10.55.0.1", "nc.gk2.secubox.in"}
    seul = tmp_path / "seul"
    seul.mkdir()
    r, d = _tables(seul, {"hall.gk2.secubox.in": ["10.0.0.1", "80"]})
    assert hotes.noms_routes(r, d) == {"hall.gk2.secubox.in"}                       # sans vhosts à la demande : la table seule


@pytest.mark.parametrize("contenu", [None, "{pas du json", "[]"])
def test_sans_table_lisible_du_waf_rien_n_est_exclu_3174(tmp_path, contenu):
    r = tmp_path / "haproxy-routes.json"
    if contenu is not None:
        r.write_text(contenu)
    assert hotes.noms_routes(r, tmp_path / "absent.json") is None


def test_un_nom_non_route_n_est_pas_sonde_3174(monkeypatch, tmp_path):
    r, d = _tables(tmp_path, {"a.gk2.secubox.in": ["10.0.0.1", "80"]}, ["c.gk2.secubox.in"])
    monkeypatch.setattr(hotes, "ROUTES_WAF", r)
    monkeypatch.setattr(hotes, "A_LA_DEMANDE", d)
    monkeypatch.setattr(hotes, "lire_sites", lambda: ["server_name a.gk2.secubox.in b.gk2.secubox.in c.gk2.secubox.in;"])
    sondes = []

    async def joignable(nom):
        sondes.append(nom)
        return True
    monkeypatch.setattr(hotes, "_joignable", joignable)
    assert asyncio.run(hotes.recalculer("gk2.secubox.in")) == ["a.gk2.secubox.in", "c.gk2.secubox.in"]
    assert sorted(sondes) == ["a.gk2.secubox.in", "c.gk2.secubox.in"]               # b : le WAF répondrait 421, aucune requête


def test_sans_table_du_waf_tout_est_sonde_comme_avant_3174(monkeypatch, tmp_path):
    monkeypatch.setattr(hotes, "ROUTES_WAF", tmp_path / "absent.json")
    monkeypatch.setattr(hotes, "lire_sites", lambda: ["server_name a.gk1.secubox.in b.gk1.secubox.in;"])
    sondes = []

    async def joignable(nom):
        sondes.append(nom)
        return nom.startswith("a.")
    monkeypatch.setattr(hotes, "_joignable", joignable)
    assert asyncio.run(hotes.recalculer("gk1.secubox.in")) == ["a.gk1.secubox.in"] and len(sondes) == 2
