# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3723, revue finale des phases 4-7, côté gk3 : porte SADE lue par l'exécuteur et refus non définitifs (I2), préfixes
LAN connus (I3), fin réelle d'un ban vivant et clôtures `couvert` (I5), rapprochement sans clé ai-lecture (M6), rule_id
explicite des touches de filtre (F1).

Banc de l'exécuteur (#3723, tâche 7) : gk2 simulé derrière la VRAIE garde, VRAIS modèles de gestes_ia.py.
"""
import json
from datetime import timedelta

import pytest

import test_executeur_3723 as te
from veille import apprentissage, base, decisions, executeur, normaliser, riposte

from test_executeur_3723 import A, B, POLITIQUES, TABLE, ClientGk2, _action, _etat, _maintenant, _prop, _tour
from test_veille_correlation_3721 import T0

banc = te.banc                                                     # fixture du banc de l'exécuteur


def _sade(b, mode):
    """Relevé de /ai/etat gardé dans veille.db (comme `_lire_etat_gk2`), frais."""
    decisions.poser_etat(b.db, "ai_etat", json.dumps({"lu_le": decisions.iso(_maintenant()), "sade_mode": mode,
                                                      "plafonds_par_geste": {}}), _maintenant())
    b.gk2.sade_mode = mode


# ── I2 : porte SADE lue par l'exécuteur ────────────────────────────────
def test_observe_rien_ne_part_pas_meme_un_clic(banc):
    _sade(banc, "observe")
    auto = _prop(banc.db, geste="ban", cible=A)
    clic = _prop(banc.db, geste="ban", cible=B, mode="clic", etat="approuvee")
    _tour(banc)
    assert banc.gk2.appels == []
    assert (_etat(banc.db, auto), _etat(banc.db, clic)) == ("proposee", "approuvee")
    assert _action(banc.db, auto) is None and _action(banc.db, clic) is None


def test_reactive_d_office_limiter_seul_clics_admis(banc):
    _sade(banc, "reactive")
    ban_auto = _prop(banc.db, geste="ban", cible=A)
    limite = _prop(banc.db, geste="limiter", cible=B, duree=3600)
    clic = _prop(banc.db, geste="leurre", cible="45.83.66.1", mode="clic", etat="approuvee", duree=3600)
    _tour(banc)
    assert _etat(banc.db, ban_auto) == "proposee" and _action(banc.db, ban_auto) is None
    assert _etat(banc.db, limite) == "faite" and _etat(banc.db, clic) == "faite"
    corps = {n: c for n, c in banc.gk2.appels}
    assert corps["limiter"]["mode"] == "auto" and corps["leurre"]["mode"] == "clic"


@pytest.mark.parametrize("motif", ["sade_observe", "sade_reactive", "protegee_inconnue"])
def test_refus_non_definitif_proposition_gardee_reessayee_plus_tard(banc, motif):
    _sade(banc, "active")
    pid = _prop(banc.db, geste="limiter", cible=B, duree=3600)
    banc.gk2.forcer.append((409, motif))
    _tour(banc)
    assert _etat(banc.db, pid) == "proposee" and _action(banc.db, pid) is None
    assert banc.db.execute("SELECT reessai_le FROM propositions WHERE id = ?", (pid,)).fetchone()[0]
    assert any(ev == "ai-reponse-gk2" and d["resultat"] == "reessai" and d["motif"] == motif
               for ev, d in banc.lignes)
    _tour(banc)                                                    # trop tôt : rien ne repart
    assert len(banc.gk2.appels) == 1
    plus_tard = _maintenant() + timedelta(seconds=executeur.REESSAI_S + 1)
    _tour(banc, maintenant=plus_tard)
    assert len(banc.gk2.appels) == 2 and _etat(banc.db, pid) == "faite"
    # jamais compté dans la suspension d'elle-même (3 × plafond_*) ni dans les plafonds de gk3
    assert not decisions.suspension(banc.db)["suspendu"]


def test_refus_definitif_reste_refuse(banc):
    pid = _prop(banc.db, geste="limiter", cible=B, duree=3600)
    banc.gk2.forcer.append((409, "protegee"))
    _tour(banc)
    assert _etat(banc.db, pid) == "refusee_gk2"


def test_corps_porte_le_mode_de_chaque_geste(banc):
    _sade(banc, "active")
    for geste, cible in (("limiter", A), ("leurre", B), ("partager", "45.83.66.2")):
        _prop(banc.db, geste=geste, cible=cible, duree=3600, mode="clic", etat="approuvee")
    _tour(banc)
    assert sorted((n, c["mode"]) for n, c in banc.gk2.appels) == [("leurre", "clic"), ("limiter", "clic"),
                                                                  ("partager", "clic")]


# ── I3 : préfixes LAN connus de gk3 ────────────────────────────────────
IF_INET6 = ("2a010e0a000100020000000000000001 02 40 00 80 br-lan\n"     # 2a01:e0a:1:2::1/64, portée globale
            "fe800000000000000000000000000001 02 40 20 80 br-lan\n")    # lien local


def test_prefixes_locaux_ipv6(tmp_path, monkeypatch):
    f = tmp_path / "if_inet6"
    f.write_text(IF_INET6)
    monkeypatch.setattr(riposte, "SOURCE_IF_INET6", str(f))
    n = riposte.prefixes_locaux()
    assert [str(x) for x in n] == ["2a01:e0a:1:2::/64"]


def test_executeur_ne_signe_pas_une_cible_du_lan(banc, tmp_path, monkeypatch):
    f = tmp_path / "if_inet6"
    f.write_text(IF_INET6)
    monkeypatch.setattr(riposte, "SOURCE_IF_INET6", str(f))
    pid = _prop(banc.db, geste="limiter", cible="2a01:e0a:1:2::99", duree=3600)
    _tour(banc)
    assert banc.gk2.appels == [] and _etat(banc.db, pid) == "echec"


def test_riposte_ne_propose_pas_une_cible_du_lan(tmp_path, monkeypatch):
    f = tmp_path / "if_inet6"
    f.write_text(IF_INET6)
    monkeypatch.setattr(riposte, "SOURCE_IF_INET6", str(f))
    assert riposte._protegee(riposte.ipaddress.ip_network("2a01:e0a:1:2::99"), riposte.prefixes_locaux())
    vu = {}
    monkeypatch.setattr(riposte, "_candidats", lambda *a: [("limiter", "2a01:e0a:1:2::99", 3600, "contenir_limiter",
                                                             {}, None)])

    class D:
        id, type, niveau, incidents, evts, etapes = "d", "acteur", "contenir", [], [], []
    monkeypatch.setattr(riposte, "signaux", lambda *a, **k: None)
    monkeypatch.setattr(riposte, "_comptes", lambda *a, **k: [])
    db = base.ouvrir(tmp_path / "v.db")
    try:
        admises = riposte.proposer(db, D(), POLITIQUES, T0, journal_audit=lambda *a: vu.setdefault("audit", a))
        assert admises == []
    finally:
        db.close()


# ── I5 : fin réelle d'un ban vivant, clôtures `couvert` ────────────────
def _ban_et_action(db, ip, maj, duree_s, fin_gk2, pid):
    db.execute("INSERT INTO propositions(id, geste, cible, duree_s, mode, politique, motif, etat, expire_le, cree_le, "
               "maj_le) VALUES (?, 'ban', ?, ?, 'auto', 'gestes.ban', 'm', 'faite', 'z', ?, ?)",
               (pid, ip, duree_s, decisions.iso(maj), decisions.iso(maj)))
    db.execute("INSERT INTO actions(id, proposition_id, geste, cible, mode, etat, jti, cle, envoyee_le, fin_gk2) "
               "VALUES (?, ?, 'ban', ?, 'auto', 'faite', 'j', 'k', ?, ?)",
               (f"a-{pid}", pid, ip, decisions.iso(maj), fin_gk2))


def test_ban_vivant_suit_la_fin_rendue_par_gk2(tmp_path):
    db = base.ouvrir(tmp_path / "v.db")
    try:
        # maj_le + duree_s dit « échu » ; gk2 a rendu une fin plus tardive (rapprochement, horloge) : vivant
        _ban_et_action(db, A, T0 - timedelta(hours=30), 86400, int((T0 + timedelta(hours=2)).timestamp()), "p1")
        v = riposte._ban_vivant(db, A, None, T0)
        assert v is not None and v[0] == "p1" and v[3] == T0 + timedelta(hours=2)
        # maj_le + duree_s dit « vivant » ; la fin de gk2 est passée : plus vivant
        _ban_et_action(db, B, T0 - timedelta(hours=1), 86400, int((T0 - timedelta(minutes=1)).timestamp()), "p2")
        assert riposte._ban_vivant(db, B, None, T0) is None
    finally:
        db.close()


def test_cloture_couvert_reste_comptee_en_recidive_comme_sur_gk2(tmp_path):
    db = base.ouvrir(tmp_path / "v.db")
    try:
        _ban_et_action(db, A, T0 - timedelta(hours=1), 86400, int((T0 + timedelta(hours=20)).timestamp()), "p1")
        db.execute("INSERT INTO propositions(id, geste, cible, duree_s, mode, reference, politique, motif, etat, "
                   "expire_le, cree_le, maj_le) VALUES ('u1', 'unban', ?, 0, 'clic', 'p1', 'gestes.unban', 'm', "
                   "'faite', 'z', 'a', 'a')", (A,))
        db.execute("INSERT INTO actions(id, proposition_id, geste, cible, mode, etat, jti, cle, envoyee_le, motif) "
                   "VALUES ('a-u1', 'u1', 'unban', ?, 'clic', 'faite', 'j', 'k', 'a', 'couvert')", (A,))
        # gk2 (`_CAUSES_SANS_RECIDIVE` = audit, unban) compte encore un ban clos `couvert` : gk3 aussi
        assert riposte._bans_poses(db, "ban", A) == 1
        # mais le ban d'ai-ban est clos : il n'est plus « vivant » (aucune prolongation proposée)
        assert riposte._ban_vivant(db, A, None, T0) is None
        db.execute("UPDATE actions SET motif = 'annule' WHERE id = 'a-u1'")
        assert riposte._bans_poses(db, "ban", A) == 0                  # une vraie levée retire de la récidive
    finally:
        db.close()


# ── M6 : sans clé ai-lecture, le rapprochement passe par la clé ai-ban ─
def test_sans_cle_de_lecture_rapprochement_par_ai_ban(banc):
    client = ClientGk2("http://gk2", "gk2", None, TABLE, transport=banc.transport, cle_ban=banc.ban_prive)
    assert client.peut_agir and not client.peut_lire
    pid = _prop(banc.db, geste="limiter", cible=B, duree=3600)
    banc.transport.couper = "apres"
    _tour(banc, client=client)
    assert _action(banc.db, pid)["etat"] == "envoi"
    banc.transport.couper = None
    _tour(banc, client=client, maintenant=_maintenant() + timedelta(seconds=executeur.DELAI_RAPPROCHEMENT_S + 5))
    assert _action(banc.db, pid)["etat"] == "faite"                     # /ai/etat lu avec la clé ai-ban
    etat = json.loads(decisions.lire_etat(banc.db, "cle_ai_lecture"))
    assert etat["etat"] == "absente" and etat["rapprochement"] == "ai-ban"


def test_sans_cle_de_lecture_get_hors_ai_etat_refuse():
    import asyncio
    from veille.client import ErreurGk2
    client = ClientGk2("http://gk2", "gk2", None, {"bans": ("/waf/bans", "/bans")}, cle_ban=b"x")
    with pytest.raises(ErreurGk2) as e:
        asyncio.run(client.get("bans"))                                  # la collecte exige la clé de lecture
    assert e.value.code is None and e.value.motif == "cle_lecture_absente"


def test_veille_etat_dit_la_cle_de_lecture(tmp_path):
    from api import reponses
    db = base.ouvrir(tmp_path / "v.db")
    try:
        decisions.poser_etat(db, "cle_ai_lecture", json.dumps({"etat": "absente", "rapprochement": "ai-ban"}),
                             _maintenant())
        assert reponses._vue_etat(db)["cle_ai_lecture"] == {"etat": "absente", "rapprochement": "ai-ban"}
    finally:
        db.close()


def test_lanceur_construit_un_client_sans_cle_de_lecture():
    from pathlib import Path
    texte = (Path(__file__).resolve().parents[1] / "sbin" / "secubox-ai-veille").read_text()
    assert "peut_lire" in texte                                          # collecte seulement avec la clé de lecture


# ── F1 : rule_id explicite ─────────────────────────────────────────────
def test_rule_id_range_et_dans_l_empreinte():
    brut = {"timestamp": "2026-11-21T10:00:00Z", "client_ip": A, "category": "ia_filtres_haute",
            "rule_id": "ia-f1", "message": "autre chose"}
    e = normaliser.evenement("menaces", brut)
    assert e.rule_id == "ia-f1" and e.message == "autre chose"
    assert e.ligne()[normaliser.COLONNES.index("rule_id")] == "ia-f1"
    autre = normaliser.evenement("menaces", {**brut, "rule_id": "ia-f2"})
    assert autre.empreinte != e.empreinte and autre.id != e.id
    sans = normaliser.evenement("menaces", {k: v for k, v in brut.items() if k != "rule_id"})
    assert sans.empreinte == normaliser.empreinte("menaces", sans.horodatage, A, sans.famille, None, None)


def test_touches_protegees_par_rule_id_jamais_par_message(tmp_path):
    db = base.ouvrir(tmp_path / "v.db")
    try:
        quand = decisions.iso(T0)
        for i, (rule_id, message) in enumerate((("ia-f1", "x"), (None, "ia-f1"), ("ia-f2", "ia-f1"))):
            db.execute("INSERT INTO evenements(id, source, noeud, horodatage, famille, gravite, ip_src, message, "
                       "rule_id, attributs_json, empreinte, cree_le) VALUES (?, 'menaces', 'gk2', ?, 'ia_filtres_haute',"
                       " 'high', '10.0.0.5', ?, ?, '{}', ?, 'x')", (f"e{i}", quand, message, rule_id, f"e{i}"))
        assert apprentissage.touches_protegees(db, "ia-f1", decisions.iso(T0 - timedelta(hours=1))) == 1
    finally:
        db.close()
