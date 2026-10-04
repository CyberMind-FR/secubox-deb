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
    assert erreur is None and relu == dict(e, auto_essai=False, mode_defaut="auto", ajout_auto=False, ignores=[])    # #1954/#1959 : champs ajoutés, à leur défaut


def test_un_etat_absent_est_inactif_et_un_etat_corrompu_aussi_avec_son_erreur(tmp_path):
    assert dnstv.lire_etat(tmp_path) == ({"actif": False, "clients": [], "auto_essai": False, "mode_defaut": "auto", "ajout_auto": False, "ignores": []}, None)
    (tmp_path / "etat.json").write_text('{"actif": true, "clients": [{"ip": "pas une ip"}]}')
    etat, erreur = dnstv.lire_etat(tmp_path)
    assert etat == {"actif": False, "clients": [], "auto_essai": False, "mode_defaut": "auto", "ajout_auto": False, "ignores": []} and "inactif" in erreur
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


# ── visualisation : flux récents, séries, services, regroupement par appareil ───────────────────────────────────────────
def _evt(client, nom, decision="ALLOWED", ts=None, rcode="NOERROR"):
    return dnstv.Evenement(ts or int(time.time()), client, nom, "A", rcode, decision)


def test_les_flux_recents_sont_ordonnes_filtres_par_source_et_bornes(tmp_path):
    m = dnstv.Magasin(tmp_path / "t.db")
    now = int(time.time())
    m.ajouter([(_evt("10.0.0.2", "a.example", ts=now - 30), None), (_evt("10.0.0.2", "b.example", "BLOCKED", ts=now - 10), "advertising"),
               (_evt("2a01::5", "c.example", ts=now - 5), None), (_evt("10.0.0.9", "autre.example", ts=now - 1), None)])
    r = m.recents(["10.0.0.2", "2a01::5"], now - 60, 10)                  # une SOURCE = ses deux adresses
    assert [x["domaine"] for x in r] == ["c.example", "b.example", "a.example"]
    assert r[1]["decision"] == "BLOCKED" and r[1]["categorie"] == "advertising"
    assert m.recents(["10.0.0.2"], now - 20, 10)[0]["domaine"] == "b.example"
    assert len(m.recents(None, now - 60, 2)) == 2


def test_la_serie_regroupe_par_tranche_et_compte_les_blocages(tmp_path):
    m = dnstv.Magasin(tmp_path / "t.db")
    base = (int(time.time()) // 300) * 300 - 600
    m.ajouter([(_evt("10.0.0.2", "a.example", ts=base + 10), None), (_evt("10.0.0.2", "b.example", "BLOCKED", ts=base + 20), "tracking"),
               (_evt("10.0.0.2", "c.example", ts=base + 310), None)])
    s = m.serie(["10.0.0.2"], base - 1, 300)
    assert [(p["ts"], p["requetes"], p["bloquees"], p["classees"]) for p in s] == [(base, 2, 1, 1), (base + 300, 1, 0, 0)]


def test_le_flux_par_domaine_donne_requetes_blocages_et_derniere_vue(tmp_path):
    m = dnstv.Magasin(tmp_path / "t.db")
    now = int(time.time())
    m.ajouter([(_evt("10.0.0.2", "x.example", ts=now - 9), None)] * 3 + [(_evt("10.0.0.2", "x.example", "BLOCKED", ts=now - 2), "advertising"),
                                                                           (_evt("10.0.0.2", "y.example", ts=now - 1), None)])
    f = {x["domaine"]: x for x in m.flux(["10.0.0.2"], now - 60)}
    assert f["x.example"]["requetes"] == 4 and f["x.example"]["bloquees"] == 1 and f["x.example"]["categorie"] == "advertising"
    assert f["y.example"]["requetes"] == 1 and f["x.example"]["derniere"] == now - 2


def test_les_flux_recents_sont_bornes_et_purges(tmp_path, monkeypatch):
    monkeypatch.setattr(dnstv, "RECENTS_MAX", 50)
    m = dnstv.Magasin(tmp_path / "t.db")
    now = int(time.time())
    m.ajouter([(_evt("10.0.0.2", f"n{i}.example", ts=now), None) for i in range(120)])
    assert len(m.recents(None, 0, 1000)) <= 50
    m.ajouter([(_evt("10.0.0.2", "vieux.example", ts=now - 3 * 86400), None)])         # plus vieux que la fenêtre : purgé dès l'écriture
    assert all(x["domaine"] != "vieux.example" for x in m.recents(None, 0, 1000))


def test_les_services_donnent_organisation_et_type_sans_rien_inventer():
    cl = dnstv.ClasseurServices(dnstv.charger_services(LISTES / "services.txt"))
    assert cl.classer("7cd77.v.fwmrm.net") == ("FreeWheel", "publicite")
    assert cl.classer("cloudreplay.ftven.fr") == ("France Télévisions", "contenu")
    assert cl.classer("videos-pub.ftv-publicite.fr")[1] == "publicite"             # le plus long suffixe gagne : pas « ftven.fr » pour ftv-publicite
    assert cl.classer("domaine-jamais-vu.example") == ("", "inconnu")
    assert cl.classer("notfwmrm.net") == ("", "inconnu")                           # un suffixe ne s'applique qu'à une frontière de nom


def test_un_fichier_de_services_invalide_est_ignore_ligne_par_ligne(tmp_path):
    f = tmp_path / "s.txt"
    f.write_text("ok.example Orga contenu\nmauvais type_inexistant\nx.example Orga typeinconnu\n!!.example Orga contenu\n")
    assert dnstv.charger_services(f) == [("ok.example", "Orga", "contenu")]


def test_une_source_regroupe_l_ipv4_et_les_ipv6_d_un_meme_appareil():
    voisins = {"192.168.1.95": "38:07:16:93:4e:95", "2a01:e0a::1": "38:07:16:93:4e:95", "fe80::1": "38:07:16:93:4e:95", "192.168.1.3": "d4:93:90:27:a7:dd"}
    g = dnstv.regrouper_sources(["192.168.1.95", "2a01:e0a::1", "192.168.1.3", "10.9.9.9"], voisins)
    assert g == {"38:07:16:93:4e:95": ["192.168.1.95", "2a01:e0a::1"], "d4:93:90:27:a7:dd": ["192.168.1.3"], "10.9.9.9": ["10.9.9.9"]}


def test_la_table_des_voisins_est_lue_en_json_ipv4_et_ipv6():
    class R:
        def __init__(self, s):
            self.stdout = s
    def faux(cmd, **k):
        return R(json.dumps([{"dst": "192.168.1.95", "lladdr": "38:07:16:93:4E:95", "state": ["REACHABLE"]}, {"dst": "192.168.1.9", "state": ["FAILED"]}])
                 if cmd[2] == "-4" else json.dumps([{"dst": "2a01::7", "lladdr": "38:07:16:93:4e:95"}]))
    assert dnstv.lire_voisins(faux) == {"192.168.1.95": "38:07:16:93:4e:95", "2a01::7": "38:07:16:93:4e:95"}


def test_le_manifeste_couvre_aussi_les_services():
    assert dnstv.verifier_manifeste(LISTES) == []
    assert "services.txt" in json.loads((LISTES / "MANIFEST.json").read_text())


# ── #1959 : le journal ignore les requêtes de la box elle-même ───────────────────────────────────────────────────────────────
def test_adresses_locales_lit_toutes_les_adresses_de_la_box():
    sortie = ('[{"ifname":"lo","addr_info":[{"local":"127.0.0.1"},{"local":"::1"}]},'
              '{"ifname":"eth2","addr_info":[{"local":"192.168.1.200"},{"local":"2a01:e0a:dec:c4e0::200"},{"local":"fe80::f2ad:4eff:fe27:889b"}]}]')

    class R:
        stdout = sortie
    loc = dnstv.adresses_locales(executer=lambda *a, **k: R())
    assert {"127.0.0.1", "::1", "192.168.1.200", "2a01:e0a:dec:c4e0::200"} <= loc


def test_les_requetes_de_la_box_ne_sont_pas_journalisees(tmp_path):
    m = dnstv.Magasin(tmp_path / "m.db")
    t = int(time.time())
    evts = [(dnstv.Evenement(t, "192.168.1.200", "a.example.com", "A", "NOERROR", "ALLOWED"), ""),
            (dnstv.Evenement(t, "192.168.1.95", "k7.ftven.fr", "A", "NOERROR", "ALLOWED"), "")]
    assert m.ajouter(evts, exclus={"192.168.1.200"}) == 1
    assert [x["client"] for x in m.recents(depuis=t - 5)] == ["192.168.1.95"]
    assert [c["client"] for c in m.par_client()] == ["192.168.1.95"]


def test_adresses_locales_commande_absente_donne_au_moins_le_bouclage():
    def echec(*a, **k):
        raise OSError("ip absent")
    assert dnstv.adresses_locales(executer=echec) == {"127.0.0.1", "::1"}


def test_le_demon_n_enregistre_pas_les_requetes_de_la_box(tmp_path):
    import importlib.machinery
    import importlib.util
    chemin = Path(__file__).resolve().parents[1] / "sbin" / "secubox-adguard-dnsfeed"
    loader = importlib.machinery.SourceFileLoader("feed_1959", str(chemin))
    spec = importlib.util.spec_from_loader("feed_1959", loader)
    feed = importlib.util.module_from_spec(spec)
    loader.exec_module(feed)
    m = dnstv.Magasin(tmp_path / "m.db")
    ts = int(time.time())
    lignes = [f"[{ts}] unbound[1:0] reply: 192.168.1.200 a.example.com. A IN NOERROR 0.001 0 50",
              f"[{ts}] unbound[1:0] reply: 192.168.1.95 k7.ftven.fr. A IN NOERROR 0.001 0 50"]
    n = feed.suivre(iter(lignes), m, dnstv.Classifieur({}), recharger=lambda: dnstv.Classifieur({}), locales=lambda: {"192.168.1.200"})
    assert n == 1 and [c["client"] for c in m.par_client()] == ["192.168.1.95"]
