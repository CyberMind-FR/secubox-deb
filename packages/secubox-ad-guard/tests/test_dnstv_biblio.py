# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""POC « DNS AdBlock TV » (#1943) : listes, classement, état, configuration Unbound, analyseur du journal, compteurs. Sans réseau."""
import json
import sqlite3
import time
from pathlib import Path

import pytest

from api import dnstv

LISTES = Path(__file__).resolve().parents[1] / "lists"

# Lignes REELLES d'Unbound 1.22 (log-queries + log-replies + log-local-actions + log-tag-queryreply), relevées sur le banc local.
BLOQUE = ["[1791027875] unbound[687999:0] info: pub.sbxlab. always_nxdomain 192.168.1.50@59974 ads.pub.sbxlab. A IN",
          "[1791027875] unbound[687999:0] reply: 192.168.1.50 ads.pub.sbxlab. A IN NXDOMAIN 0.000000 1 37"]
AUTORISE = ["[1791027876] unbound[687999:0] reply: 192.168.1.50 example.com. A IN NOERROR 0.021000 0 52"]
ERREUR = ["[1791027877] unbound[687999:0] reply: 192.168.1.50 example.org. A IN SERVFAIL 3.000000 0 31"]


# ── listes ───────────────────────────────────────────────────────────────────
def test_les_listes_livrees_sont_valides_versionnees_et_conformes_au_manifeste():
    assert dnstv.verifier_manifeste(LISTES) == []
    for cat in ("advertising", "tracking", "telemetry", "social"):
        bons, mauvaises, version = dnstv.lire_liste(LISTES / f"{cat}.txt")
        assert bons and not mauvaises and version == "2026.10.03-poc1"


def test_une_liste_modifiee_sans_le_manifeste_est_signalee(tmp_path):
    for f in LISTES.iterdir():
        (tmp_path / f.name).write_bytes(f.read_bytes())
    (tmp_path / "tracking.txt").write_text((LISTES / "tracking.txt").read_text() + "nouveau-tracker.example\n")
    assert any("tracking.txt" in p and "manifeste" in p for p in dnstv.verifier_manifeste(tmp_path))


@pytest.mark.parametrize("brut", ["", "a", "-x.example", "exa mple.com", "ex..com", "http://x.com", "x.com/chemin", "*.x.com", "1.2.3.4",
                                  "a" * 64 + ".com", "x.com\nboom", "x.c"])
def test_un_nom_de_domaine_douteux_est_refuse(brut):
    assert dnstv.valider_domaine(brut) is None


def test_un_nom_valide_est_normalise():
    assert dnstv.valider_domaine("  Ads.Example.COM. ") == "ads.example.com"


def test_le_classeur_trouve_le_domaine_et_ses_parents_pas_les_voisins():
    cl = dnstv.Classifieur(dnstv.charger_listes(LISTES))
    assert cl.classer("x.y.doubleclick.net") == ("advertising", "doubleclick.net")
    assert cl.classer("google-analytics.com")[0] == "tracking"
    assert cl.classer("app-measurement.com")[0] == "telemetry"
    assert cl.classer("example.com") == (None, None) and cl.classer("notdoubleclick.net") == (None, None)


def test_une_ligne_invalide_d_une_liste_est_rapportee_pas_appliquee(tmp_path):
    f = tmp_path / "x.txt"
    f.write_text("# version: 1\ngood.example\n!!mauvais!!\n   \nautre.example # commentaire\n")
    bons, mauvaises, version = dnstv.lire_liste(f)
    assert bons == ["good.example", "autre.example"] and len(mauvaises) == 1 and version == "1"


# ── état : persistance, validation, corruption ───────────────────────────────
def test_l_etat_est_conserve_apres_redemarrage(tmp_path):
    e = {"actif": True, "clients": [{"ip": "192.168.1.50", "nom": "Freebox TV salon", "mode": "block"}]}
    dnstv.ecrire_etat(e, tmp_path)
    relu, erreur = dnstv.lire_etat(tmp_path)                       # « redémarrage » : on relit depuis le disque
    assert erreur is None and relu == e


def test_un_etat_absent_est_inactif_et_un_etat_corrompu_aussi_avec_son_erreur(tmp_path):
    assert dnstv.lire_etat(tmp_path) == ({"actif": False, "clients": []}, None)
    (tmp_path / "etat.json").write_text('{"actif": true, "clients": [{"ip": "pas une ip"}]}')
    etat, erreur = dnstv.lire_etat(tmp_path)
    assert etat == {"actif": False, "clients": []} and "inactif" in erreur
    (tmp_path / "etat.json").write_text("{ pas du json")
    assert dnstv.lire_etat(tmp_path)[1] is not None


@pytest.mark.parametrize("etat", [{"clients": [{"ip": "1.2.3.4", "mode": "tout"}]}, {"clients": [{"ip": "x"}]},
                                  {"clients": [{"ip": "1.2.3.4", "nom": "a;b\nserver:"}]},
                                  {"clients": [{"ip": "1.2.3.4"}, {"ip": "1.2.3.4"}]}, {"clients": "oui"}, "texte",
                                  {"clients": [{"ip": f"10.0.0.{i}"} for i in range(1, 34)]}])
def test_une_configuration_invalide_est_refusee(etat):
    with pytest.raises(dnstv.ErreurTV):
        dnstv.valider_etat(etat)


def test_ecrire_etat_invalide_ne_touche_pas_au_fichier_existant(tmp_path):
    dnstv.ecrire_etat({"actif": True, "clients": [{"ip": "10.0.0.2", "nom": "tv", "mode": "observe"}]}, tmp_path)
    avant = (tmp_path / "etat.json").read_text()
    with pytest.raises(dnstv.ErreurTV):
        dnstv.ecrire_etat({"clients": [{"ip": "n'importe quoi"}]}, tmp_path)
    assert (tmp_path / "etat.json").read_text() == avant


# ── configuration Unbound ────────────────────────────────────────────────────
def test_la_configuration_unbound_a_une_vue_par_mode_et_journalise():
    etat = {"actif": True, "clients": [{"ip": "10.0.0.2", "nom": "tv1", "mode": "observe"}, {"ip": "10.0.0.3", "nom": "tv2", "mode": "block"},
                                       {"ip": "10.0.0.4", "nom": "tv3", "mode": "off"}, {"ip": "fe80::1", "nom": "tv4", "mode": "block"}]}
    c = dnstv.rendre_unbound(etat, {"ads.example.com": "advertising"})
    assert "access-control-view: 10.0.0.2/32 sbx-tv-observe" in c and "access-control-view: 10.0.0.3/32 sbx-tv-block" in c
    assert "access-control-view: fe80::1/128 sbx-tv-block" in c
    assert "10.0.0.4" not in c                                         # off : retiré du périmètre
    assert 'local-zone: "ads.example.com." always_nxdomain' in c
    assert c.count('local-zone: "." transparent') == 2                 # SANS cette zone, une vue ne protège de rien (mesuré)
    for opt in ("log-queries: yes", "log-replies: yes", "log-local-actions: yes", "log-tag-queryreply: yes"):
        assert opt in c


def test_le_mode_observe_ne_contient_aucune_zone_de_blocage():
    c = dnstv.rendre_unbound({"actif": True, "clients": [{"ip": "10.0.0.2", "nom": "t", "mode": "observe"}]}, {"x.example.com": "tracking"})
    observe = c.split('name: "sbx-tv-observe"')[1].split("view:")[0]
    assert "always_nxdomain" not in observe


def test_poc_inactif_ne_declare_aucune_vue():
    c = dnstv.rendre_unbound({"actif": False, "clients": [{"ip": "10.0.0.2", "nom": "t", "mode": "block"}]}, {"x.example.com": "tracking"})
    assert "view:" not in c and "access-control-view" not in c


def test_aucune_valeur_non_validee_n_atteint_la_configuration():
    with pytest.raises(dnstv.ErreurTV):
        dnstv.rendre_unbound({"actif": True, "clients": [{"ip": "10.0.0.2\nserver: do-udp: no", "mode": "block"}]}, {})


# ── analyseur du journal ─────────────────────────────────────────────────────
def test_analyseur_distingue_bloque_autorise_et_erreur_amont():
    an = dnstv.Analyseur()
    evts = [e for ligne in BLOQUE + AUTORISE + ERREUR if (e := an.ligne(ligne))]
    assert [(e.qname, e.decision) for e in evts] == [("ads.pub.sbxlab", "BLOCKED"), ("example.com", "ALLOWED"), ("example.org", "UPSTREAM_ERROR")]
    assert evts[0].client == "192.168.1.50" and evts[0].ts == 1791027875 and evts[0].rcode == "NXDOMAIN"


def test_un_nxdomain_amont_n_est_pas_un_blocage():
    """NXDOMAIN sans action locale = le nom n'existe pas ; ce n'est PAS un blocage."""
    e = dnstv.Analyseur().ligne("[1791027875] unbound[1:0] reply: 192.168.1.50 inexistant.example. A IN NXDOMAIN 0.04 0 40")
    assert e.decision == "ALLOWED" and e.rcode == "NXDOMAIN"


def test_les_lignes_etrangeres_sont_ignorees_et_ne_font_pas_planter():
    an = dnstv.Analyseur()
    for ligne in ["", "garbage", "[1] unbound[1:0] info: start of service (unbound 1.22.0).", "reply: x", "info: a b c d e f IN"]:
        assert an.ligne(ligne) is None


def test_l_analyseur_oublie_les_actions_sans_reponse():
    an = dnstv.Analyseur()
    for i in range(5000):
        an.ligne(f"info: z{i}.example. always_nxdomain 10.0.0.1@5 q{i}.example. A IN")
    assert len(an._actions) <= 4096


# ── magasin : compteurs par domaine et par client ────────────────────────────
def _alimente(m, lignes_par_client):
    an = dnstv.Analyseur()
    cl = dnstv.Classifieur({"ads.pub.sbxlab": "advertising", "track.sbxlab": "tracking"})
    evts = []
    for client, lignes in lignes_par_client.items():
        for ligne in lignes:
            e = an.ligne(ligne.replace("192.168.1.50", client))
            if e:
                evts.append((e, cl.classer(e.qname)[0]))
    return m.ajouter(evts)


def test_compteurs_par_domaine_par_client_et_par_decision(tmp_path):
    m = dnstv.Magasin(tmp_path / "t.db")
    n = _alimente(m, {"192.168.1.50": BLOQUE * 3 + AUTORISE, "192.168.1.51": BLOQUE + AUTORISE * 2})
    assert n == 7
    s = m.statistiques()
    assert s["requetes"] == 7 and s["domaines_uniques"] == 2 and s["par_decision"] == {"BLOCKED": 4, "ALLOWED": 3}
    assert s["par_categorie"] == {"advertising": 4} and s["classes_bloques"] == {"advertising": 4} and s["classes_resolus"] == {}
    assert m.statistiques(client="192.168.1.51")["requetes"] == 3
    assert m.top("BLOCKED")[0] == {"domaine": "ads.pub.sbxlab", "categorie": "advertising", "hits": 4}
    assert {c["client"]: c["requetes"] for c in m.par_client()} == {"192.168.1.50": 4, "192.168.1.51": 3}


def test_en_observe_la_pub_est_comptee_comme_resolue_pas_comme_bloquee(tmp_path):
    """C'est la mesure centrale : « domaines publicitaires résolus » (OBSERVE) contre « bloqués » (BLOCK)."""
    m = dnstv.Magasin(tmp_path / "t.db")
    an = dnstv.Analyseur()
    e = an.ligne("[1791027875] unbound[1:0] reply: 192.168.1.50 ads.pub.sbxlab. A IN NOERROR 0.02 0 40")
    m.ajouter([(e, "advertising")])
    s = m.statistiques()
    assert s["classes_resolus"] == {"advertising": 1} and s["classes_bloques"] == {}


def test_les_compteurs_survivent_a_une_reouverture_et_a_un_arret_brutal(tmp_path):
    chemin = tmp_path / "t.db"
    _alimente(dnstv.Magasin(chemin), {"192.168.1.50": BLOQUE * 2})
    assert dnstv.Magasin(chemin).statistiques()["requetes"] == 2        # nouvelle instance = service redémarré
    _alimente(dnstv.Magasin(chemin), {"192.168.1.50": BLOQUE})
    assert dnstv.Magasin(chemin).statistiques()["requetes"] == 3        # on continue à compter, on ne repart pas de zéro


def test_la_retention_purge_les_vieux_compteurs_et_garde_les_recents(tmp_path):
    m = dnstv.Magasin(tmp_path / "t.db")
    an = dnstv.Analyseur()
    vieux = an.ligne(f"[{int(time.time()) - 40 * 86400}] unbound[1:0] reply: 10.0.0.2 vieux.example. A IN NOERROR 0.1 0 4")
    neuf = an.ligne(f"[{int(time.time())}] unbound[1:0] reply: 10.0.0.2 neuf.example. A IN NOERROR 0.1 0 4")
    m.ajouter([(vieux, None), (neuf, None)])
    assert m.purger(30) == 1
    assert [t["domaine"] for t in m.top("ALLOWED")] == ["neuf.example"]


def test_aucun_contenu_applicatif_n_est_garde(tmp_path):
    """Le schéma ne contient que : jour, client, domaine, catégorie, décision, compteur."""
    m = dnstv.Magasin(tmp_path / "t.db")
    cols = {r[1] for t in ("dnstv_counts", "dnstv_clients") for r in sqlite3.connect(m.chemin).execute(f"PRAGMA table_info({t})")}
    assert cols == {"jour", "client", "domaine", "categorie", "decision", "hits", "premiere_vue", "derniere_vue", "total"}
    assert not any(mot in c for c in cols for mot in ("url", "cookie", "header", "payload", "body"))


def test_la_decision_de_tri_inconnue_est_refusee(tmp_path):
    with pytest.raises(dnstv.ErreurTV):
        dnstv.Magasin(tmp_path / "t.db").top("PEUT-ETRE")


def test_le_resultat_est_serialisable_en_json(tmp_path):
    m = dnstv.Magasin(tmp_path / "t.db")
    _alimente(m, {"192.168.1.50": BLOQUE})
    json.dumps(m.statistiques())
