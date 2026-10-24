# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3133 — convergence des liens directs entre DEUX pairs (« sonde puis promotion »).

Modèle de réseau minimal, horloge simulée, avec les vrais `pairs_directs.calculer` / `appliquer` et le vrai
`mesh.render_wg_conf` (c'est le rendu qui dit si un pair capte le trafic : une ligne `AllowedIPs = <ip>/32`).

- Une session WireGuard A↔B existe SSI chacun a la clé de l'autre dans ses pairs (sonde ou actif) ET que le
  chemin direct est joignable. Première poignée de main dans les 25 s (PersistentKeepalive), puis toutes les 120 s.
- Chaque pair participant exécute sa logique toutes les 60-70 s (minuterie 1 min + RandomizedDelaySec 10 s), le
  premier passage 120-130 s après son démarrage (OnBootSec=2min).
- « Trou noir » : un pair rend `AllowedIPs = <ip de l'autre>/32` alors qu'aucune session n'existe.
- « Désaccord » : la session existe mais un seul des deux capte : le trafic est perdu dans les deux sens (le
  filtrage par source de WireGuard rejette ce qui revient par le maître). Il dure au plus une période, une fois.
"""
import base64
import random
import re

import pytest

from api import mesh
from api import pairs_directs as pd

DT = 5
PERIODE_MIN, PERIODE_MAX = 60, 70
DELAI = 180
KEEPALIVE = 25
REKEY = 120


def _cle(c):
    return base64.b64encode(c.encode() * 32).decode()


K_MAITRE, K_A, K_B = _cle("M"), _cle("A"), _cle("B")
IP = {"A": "10.10.0.2", "B": "10.10.0.3"}
CLE = {"A": K_A, "B": K_B}
AUTRE = {"A": "B", "B": "A"}
LISTE = [{"name": "noeuda", "public_key": K_A, "mesh_ip": IP["A"], "endpoint": "192.168.1.2:51820"},
         {"name": "noeudb", "public_key": K_B, "mesh_ip": IP["B"], "endpoint": "192.168.1.3:51820"}]


def _etat(n):
    return {"role": "peer", "private_key": "cle-privee-factice", "public_key": CLE[n], "address": IP[n] + "/24",
            "peers": [{"public_key": K_MAITRE, "allowed_ips": "10.10.0.0/24", "mesh_ip": "10.10.0.1",
                       "name": "master", "endpoint": "192.168.1.1:51820"}]}


def _a_la_cle(etat, cle):
    return any(isinstance(p, dict) and p.get("public_key") == cle for p in etat["peers"])


def _capte(etat, cle, ip):
    """Vrai si le RENDU wg-quick donne <ip>/32 au pair de cette clé (c'est ce que WireGuard appliquera)."""
    for bloc in mesh.render_wg_conf(etat).split("[Peer]")[1:]:
        if f"PublicKey = {cle}\n" in bloc:
            return re.search(r"^AllowedIPs = " + re.escape(ip) + r"/32$", bloc, re.M) is not None
    return False


def simuler(debut_b=0.0, b_participe=True, joignable=True, coupure=None, graine=0, duree=6 * 3600):
    """Rend les mesures de la simulation (secondes)."""
    hasard = random.Random(graine)
    etats = {"A": _etat("A"), "B": _etat("B")}
    prochain = {"A": 120 + hasard.random() * 10, "B": debut_b + 120 + hasard.random() * 10}
    session_depuis = None        # début de la session courante
    poignee = None               # dernière poignée de main (horodatage), persiste après la coupure
    m = {"trou_noir_max": 0, "trou_noir_total": 0, "desaccord_max": 0, "a_capte_b": False, "b_capte_a": False,
         "t_cles": None, "t_convergence": None, "t_reconvergence": None, "capte_apres_coupure_fin": None}
    trou = desaccord = 0
    t = 0.0
    while t < duree:
        lien = joignable and (coupure is None or not coupure[0] <= t < coupure[1])
        cles = _a_la_cle(etats["A"], K_B) and _a_la_cle(etats["B"], K_A)
        if cles and m["t_cles"] is None:
            m["t_cles"] = t
        if cles and lien:
            if session_depuis is None:
                session_depuis = t
                poignee_suivante = t + hasard.random() * KEEPALIVE
            if t >= poignee_suivante:
                poignee, poignee_suivante = t, t + REKEY
        else:
            session_depuis = None
        session = session_depuis is not None and poignee is not None and poignee >= session_depuis
        a_capte, b_capte = _capte(etats["A"], K_B, IP["B"]), _capte(etats["B"], K_A, IP["A"])
        m["a_capte_b"] |= a_capte
        m["b_capte_a"] |= b_capte
        if a_capte and b_capte and session and m["t_convergence"] is None:
            m["t_convergence"] = t
        if (coupure is not None and t >= coupure[1] and a_capte and b_capte and session
                and m["t_reconvergence"] is None):
            m["t_reconvergence"] = t
        trou = trou + DT if (a_capte or b_capte) and not session else 0
        desaccord = desaccord + DT if session and a_capte != b_capte else 0
        if (a_capte or b_capte) and not session:
            m["trou_noir_total"] += DT
        m["trou_noir_max"] = max(m["trou_noir_max"], trou)
        m["desaccord_max"] = max(m["desaccord_max"], desaccord)
        for n in "AB":
            if n == "B" and not b_participe:
                continue
            if t >= prochain[n]:
                poignees = {K_MAITRE: t}
                if poignee is not None:
                    poignees[CLE[AUTRE[n]]] = poignee
                calcul = pd.calculer(etats[n], LISTE, poignees, t)
                etats[n] = pd.appliquer(etats[n], calcul, t)
                # idempotence : un second calcul sur l'état appliqué ne propose rien
                assert pd.appliquer(etats[n], pd.calculer(etats[n], LISTE, poignees, t), t) == etats[n]
                prochain[n] = t + PERIODE_MIN + hasard.random() * (PERIODE_MAX - PERIODE_MIN)
        t += DT
    m["capte_apres_coupure_fin"] = _capte(etats["A"], K_B, IP["B"]) or _capte(etats["B"], K_A, IP["A"])
    m["etats"] = etats
    return m


GRAINES = range(6)


@pytest.mark.parametrize("graine", GRAINES)
@pytest.mark.parametrize("debut_b", [0, 20 * 60, 50 * 60, 3 * 3600])
def test_convergence_depart_simultane_ou_decale(debut_b, graine):
    m = simuler(debut_b=debut_b, graine=graine, duree=debut_b + 3 * 3600)
    assert m["t_cles"] is not None and m["t_convergence"] is not None
    # convergence (les deux actifs) en au plus 2 périodes après que chacun a la clé de l'autre
    assert m["t_convergence"] - m["t_cles"] <= 2 * PERIODE_MAX
    assert m["trou_noir_max"] == 0                       # jamais un /32 actif sans session
    assert m["desaccord_max"] <= PERIODE_MAX + DT        # un seul désaccord, au plus une période
    for n in "AB":                                        # les deux finissent actifs, durablement
        d = [p for p in m["etats"][n]["peers"] if p.get("direct") is True]
        assert len(d) == 1 and d[0]["direct_etat"] == "actif" and d[0]["allowed_ips"] == IP[AUTRE[n]] + "/32"


@pytest.mark.parametrize("graine", GRAINES)
def test_pair_non_participant_jamais_capte(graine):
    m = simuler(b_participe=False, graine=graine)
    assert not m["a_capte_b"] and m["trou_noir_total"] == 0
    sondes = [p for p in m["etats"]["A"]["peers"] if p.get("direct") is True]
    assert len(sondes) == 1 and sondes[0]["direct_etat"] == "sonde" and "allowed_ips" not in sondes[0]


@pytest.mark.parametrize("graine", GRAINES)
def test_chemin_direct_injoignable_jamais_capte(graine):
    m = simuler(joignable=False, graine=graine)
    assert not m["a_capte_b"] and not m["b_capte_a"] and m["trou_noir_total"] == 0


@pytest.mark.parametrize("graine", GRAINES)
def test_lien_actif_dont_la_poignee_disparait(graine):
    m = simuler(coupure=(2 * 3600, float("inf")), graine=graine)
    assert m["t_convergence"] is not None and m["t_convergence"] < 2 * 3600
    # Le trou noir n'apparaît qu'à la coupure, une fois : au plus le délai de poignée (180 s, mesuré depuis la
    # dernière poignée, faite au plus REKEY s avant la coupure) plus une période (la rétrogradation n'a lieu qu'au
    # passage suivant de la minuterie).
    assert 0 < m["trou_noir_max"] <= DELAI + PERIODE_MAX + DT
    assert m["trou_noir_total"] == m["trou_noir_max"]
    assert not m["capte_apres_coupure_fin"]               # les deux sont redevenus des sondes
    for n in "AB":
        d = [p for p in m["etats"][n]["peers"] if p.get("direct") is True]
        assert len(d) == 1 and d[0]["direct_etat"] == "sonde" and "allowed_ips" not in d[0]


@pytest.mark.parametrize("graine", GRAINES)
def test_lien_retabli_apres_coupure_reconverge(graine):
    debut, fin = 2 * 3600, 2 * 3600 + 1800
    m = simuler(coupure=(debut, fin), graine=graine, duree=fin + 3600)
    # les sondes restent pendant la coupure : au rétablissement, la session revient d'elle-même et les deux
    # pairs repassent actifs en au plus 2 périodes (+ le premier keepalive)
    assert m["t_reconvergence"] is not None and m["t_reconvergence"] - fin <= 2 * PERIODE_MAX + KEEPALIVE
    assert m["trou_noir_total"] == m["trou_noir_max"] <= DELAI + PERIODE_MAX + DT
    assert m["desaccord_max"] <= PERIODE_MAX + DT
