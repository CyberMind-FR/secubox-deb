# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Community Refactor P1 (#1517) : communautés, autorisations, activités,
état de cycle de vie projeté. Chaque test nomme la garantie qu'il protège."""
import sqlite3
import uuid

import pytest

from secubox_core import sbxid as S

NOEUD = "did:plc:" + "a" * 32


@pytest.fixture
def db():
    c = sqlite3.connect(":memory:", isolation_level=None)
    S.initialise(c)
    return c


def personne(db, pseudo, *, status="active", roles=("member",)):
    u = str(uuid.uuid4())
    db.execute("INSERT INTO sbx_users (user_uuid,pseudo,status,home_node,created_at) "
               "VALUES (?,?,?,?,1)", (u, pseudo, status, NOEUD))
    for r in roles:
        db.execute("INSERT INTO sbx_user_roles (user_uuid,role_id) VALUES (?,?)", (u, r))
    return u


# ── schéma ────────────────────────────────────────────────────────────────

def test_migration_additive_et_idempotente(db):
    S.initialise(db)
    S.initialise(db)
    tables = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert {"sbx_communities", "sbx_community_members", "sbx_grants", "sbx_activity"} <= tables


def test_la_table_refuse_une_capacite_systeme_meme_en_sql_direct(db):
    with pytest.raises(sqlite3.IntegrityError):
        db.execute("INSERT INTO sbx_grants VALUES ('g','user','u','sudo.all',NULL,1,NULL)")


# ── état de cycle de vie ─────────────────────────────────────────────────

def test_sans_fiche_invite_ou_demande(db):
    assert S.etat_personne(db, None) == "guest"
    assert S.etat_personne(db, str(uuid.uuid4())) == "guest"
    assert S.etat_personne(db, None, demande_en_attente=True) == "invitation_requested"


def test_les_six_etats_se_deduisent_de_l_existant(db):
    invite = personne(db, "invite", status="invited")
    visiteur = personne(db, "visiteur", roles=("guest",))
    membre = personne(db, "membre")
    admin = personne(db, "gerant", roles=("member", "sbx_operator"))
    assert S.etat_personne(db, invite) == "invited"
    assert S.etat_personne(db, visiteur) == "guest"
    assert S.etat_personne(db, membre) == "member"
    assert S.etat_personne(db, admin) == "node_admin"
    c = S.cree_communaute(db, "Jardin", home_node=NOEUD, created_by=admin)
    S.ajoute_membre(db, c, membre, added_by=admin)
    assert S.etat_personne(db, membre) == "community_assigned"
    # node_admin l'emporte : l'appartenance ne rétrograde pas un gérant.
    S.ajoute_membre(db, c, admin, role="owner", added_by=admin)
    assert S.etat_personne(db, admin) == "node_admin"


def test_une_communaute_archivee_ne_compte_plus(db):
    m = personne(db, "m")
    c = S.cree_communaute(db, "Ancienne", home_node=NOEUD, created_by=m)
    S.ajoute_membre(db, c, m, added_by=m)
    db.execute("UPDATE sbx_communities SET archived_at=1 WHERE community_uuid=?", (c,))
    assert S.etat_personne(db, m) == "member"


def test_suspendu_est_hors_cycle(db):
    s = personne(db, "s", status="suspended")
    assert S.etat_personne(db, s) == "suspended"


# ── communautés ──────────────────────────────────────────────────────────

@pytest.mark.parametrize("nom", ["", "x" * 61, "root", "GK2", "  "])
def test_nom_de_communaute_refuse(db, nom):
    with pytest.raises(S.Refus):
        S.cree_communaute(db, nom, home_node=NOEUD, created_by="x")


def test_nom_unique_sans_casse(db):
    S.cree_communaute(db, "Atelier", home_node=NOEUD, created_by="x")
    with pytest.raises(S.Refus):
        S.cree_communaute(db, "atelier", home_node=NOEUD, created_by="x")


def test_visibilite_inconnue_refusee(db):
    with pytest.raises(S.Refus):
        S.cree_communaute(db, "Club", home_node=NOEUD, created_by="x", visibility="secrete")


def test_seule_une_personne_active_devient_membre(db):
    c = S.cree_communaute(db, "Club", home_node=NOEUD, created_by="x")
    with pytest.raises(S.Refus):
        S.ajoute_membre(db, c, str(uuid.uuid4()), added_by="x")
    with pytest.raises(S.Refus):
        S.ajoute_membre(db, c, personne(db, "susp", status="suspended"), added_by="x")
    with pytest.raises(S.Refus):
        S.ajoute_membre(db, c, personne(db, "ok"), role="roi", added_by="x")


def test_ajout_repete_change_le_role(db):
    c = S.cree_communaute(db, "Club", home_node=NOEUD, created_by="x")
    m = personne(db, "m")
    S.ajoute_membre(db, c, m, added_by="x")
    S.ajoute_membre(db, c, m, role="moderator", added_by="x")
    assert S.membres(db, c) == [{"user_uuid": m, "pseudo": "m", "role": "moderator"}]
    assert S.retire_membre(db, c, m) is True
    assert S.membres(db, c) == []


# ── autorisations User + Community ───────────────────────────────────────

def test_allow_user_et_allow_community(db):
    a = personne(db, "a")
    b = personne(db, "b")
    c = S.cree_communaute(db, "Radio", home_node=NOEUD, created_by="x")
    S.ajoute_membre(db, c, b, added_by="x")
    S.accorde(db, "user", a, "radio.chat", granted_by="x")
    S.accorde(db, "community", c, "bbs.moderate", granted_by="x")
    assert S.capacites_accordees(db, a) == {"radio.chat"}
    assert S.capacites_accordees(db, b) == {"bbs.moderate"}


@pytest.mark.parametrize("cap", ["ssh.login", "sudo.all", "root.shell", "system.reboot"])
def test_aucune_autorisation_ne_touche_au_systeme(db, cap):
    with pytest.raises(S.Refus):
        S.accorde(db, "user", personne(db, "p"), cap, granted_by="x")


def test_capacite_inconnue_refusee(db):
    with pytest.raises(S.Refus):
        S.accorde(db, "user", personne(db, "p"), "bbs.inexistante", granted_by="x")


def test_accorde_est_idempotent_et_revocable(db):
    p = personne(db, "p")
    g1 = S.accorde(db, "user", p, "hall.write", granted_by="x")
    assert S.accorde(db, "user", p, "hall.write", granted_by="x") == g1
    assert S.revoque_autorisation(db, g1) is True
    assert S.capacites_accordees(db, p) == set()


def test_suspendu_ou_communaute_archivee_ne_donnent_rien(db):
    p = personne(db, "p")
    c = S.cree_communaute(db, "Club", home_node=NOEUD, created_by="x")
    S.ajoute_membre(db, c, p, added_by="x")
    S.accorde(db, "community", c, "radio.chat", granted_by="x")
    db.execute("UPDATE sbx_communities SET archived_at=1 WHERE community_uuid=?", (c,))
    assert S.capacites_accordees(db, p) == set()
    q = personne(db, "q")
    S.accorde(db, "user", q, "radio.chat", granted_by="x")
    db.execute("UPDATE sbx_users SET status='suspended' WHERE user_uuid=?", (q,))
    assert S.capacites_accordees(db, q) == set()


# ── activités ────────────────────────────────────────────────────────────

def test_activite_porte_les_cinq_champs(db):
    aid = S.emet_activite(db, "user_joined", author="u1", visibility="node",
                          origin_node=NOEUD, context={"via": "invitation"})
    r = db.execute("SELECT kind,author,context,visibility,origin_node,at FROM sbx_activity "
                   "WHERE activity_uuid=?", (aid,)).fetchone()
    assert r[:5] == ("user_joined", "u1", '{"via":"invitation"}', "node", NOEUD)
    assert r[5] > 0


def test_activite_refus(db):
    with pytest.raises(S.Refus):
        S.emet_activite(db, "piratage", author="u", visibility="node", origin_node=NOEUD)
    with pytest.raises(S.Refus):
        S.emet_activite(db, "bbs_post", author="u", visibility="community", origin_node=NOEUD)
    with pytest.raises(S.Refus):
        S.emet_activite(db, "bbs_post", author="u", visibility="node", origin_node="")
    # Forme canonique : un flottant ne voyagerait pas signé entre boxes (P7).
    with pytest.raises(S.Refus):
        S.emet_activite(db, "mood_changed", author="u", visibility="private",
                        origin_node=NOEUD, context={"confiance": 0.5})
