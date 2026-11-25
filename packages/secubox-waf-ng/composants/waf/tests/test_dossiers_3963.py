# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3963 — dossiers par site : agrégat horaire incrémental du journal des menaces (rotation, troncature, reprise bornée,
heure non mesurée, plafonds, ligne corrompue, source muette), routes en lecture et phrases en français. Adresses de
test : documentation (RFC 5737)."""
import json
import os
import re
import sys
import types
from datetime import datetime, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from api import dossiers as D  # noqa: E402

try:
    import geoip2  # noqa: F401
except ImportError:                                     # absent de l'environnement de test : un faux module suffit
    _g = types.ModuleType("geoip2")
    _g.database, _g.errors = types.ModuleType("geoip2.database"), types.ModuleType("geoip2.errors")
    _g.errors.AddressNotFoundError = type("AddressNotFoundError", (Exception,), {})
    sys.modules.update({"geoip2": _g, "geoip2.database": _g.database, "geoip2.errors": _g.errors})
from api import main as W  # noqa: E402  (pose les chemins réels, que la fixture remplace ensuite)

T = datetime(2026, 11, 25, 12, 30, 0, tzinfo=timezone.utc).timestamp()
H = 3600
IPV4 = re.compile(r"(?<![\d.])\d{1,3}(?:\.\d{1,3}){3}(?![\d.])")


def ligne(il_y_a=60, host="depot.exemple.test", action="banned", category="sqli", **k):
    d = {"timestamp": datetime.fromtimestamp(T - il_y_a, tz=timezone.utc).isoformat(), "client_ip": "203.0.113.7",
         "host": host, "method": "GET", "path": "/", "category": category, "severity": "high", "rule_id": "x-001",
         "action": action, "reseau_classe": "hebergeur", "asn": 64500}
    d.update(k)
    return json.dumps(d)


@pytest.fixture
def box(tmp_path, monkeypatch):
    D.vider()
    chemins = {n: tmp_path / f"{n}.json" for n in D.CHEMINS}
    chemins["journal"] = tmp_path / "waf-threats.log"
    monkeypatch.setattr(D, "CHEMINS", chemins)
    chemins["routes"].write_text(json.dumps({"depot.exemple.test": ["127.0.0.1", 80], "Www.Exemple.TEST": ["127.0.0.1", 80],
                                             "agenda.exemple.test": ["127.0.0.1", 80], "203.0.113.9": ["127.0.0.1", 80]}))

    class Box:
        c = chemins

        def ecrire(self, *lignes, mode="a"):
            with open(chemins["journal"], mode) as f:
                f.write("".join(x + "\n" for x in lignes))

        def vie(self, t=T):
            chemins["vie"].write_text("{}")
            os.utime(chemins["vie"], (t, t))

        def passe(self, t=T, **k):
            return D.rafraichir(t, **k)

        def site(self, ident="depot.exemple.test", t=T):
            return self.passe(t)["dossiers"][ident]
    yield Box()
    D.vider()


# ── comptes ────────────────────────────────────────────────────────────────────────────────────────────────────────

def test_couches_robots_et_lignes_d_etat(box):
    box.ecrire(ligne(), ligne(action="warning", category="lfi"), ligne(action="detect", category="recon_crawler"),
               ligne(action="robot", category="robots", severity="info"),
               ligne(action="leurre_redirige", category="leurre_redirige", severity="audit", servies=7),
               ligne(action="multipart-tronque", category="multipart-tronque", severity="audit"),
               ligne(action="body-inspect-skipped", category="body-inspect-skipped"),
               ligne(action="detect", category="body-inspect-x"))
    d = box.site()
    assert d["totaux"] == {"arrete": 1, "refuse": 1, "detourne": 7, "passe": 1, "robots": 1}
    assert d["total"] == 10 and d["tenu_pct"] == 90.0
    assert {o["cle"]: o["n"] for o in d["origine"]["lignes"]} == {"hebergeur": 10}        # robots à part
    assert [c["n"] for c in d["chaine"]] == [None, 10, 1, 1, 7, 1]                        # requêtes reçues : jamais inventées


def test_sites_servis_et_noms_inconnus(box):
    box.ecrire(ligne(host="WWW.exemple.test:443"), ligne(host="autre.invalide", category="host_anomaly:unrouted", action="warning"),
               ligne(host="203.0.113.9", category="host_anomaly:ip_literal"), ligne(host="", category="host_anomaly:empty"),
               ligne(host="depot.exemple.test", category="host_anomaly:unrouted"),        # catégorie d'hôte : jamais un site
               ligne(host="sshd", category="auth_ssh:invalid_user", tool="authwatch"))
    v = box.passe()
    assert set(v["dossiers"]) == {"www.exemple.test", D.INCONNUS}
    assert v["dossiers"][D.INCONNUS]["total"] == 4 and v["liste"]["chiffres"]["hors_web"] == 1
    assert v["liste"]["chiffres"]["sites_proteges"] == 3 and v["calmes"] == ["agenda.exemple.test", "depot.exemple.test"]
    inc = v["dossiers"][D.INCONNUS]
    assert "aucun site n’a répondu" in inc["phrase"] and inc["couches"][3]["nom"] == "Noté" and inc["tenu_pct"] is None
    assert not IPV4.search(json.dumps([v["liste"], v["dossiers"]]))


def test_heure_non_mesuree_vaut_null_jamais_zero(box):
    box.ecrire(ligne(5 * H), ligne(60))
    d = box.site()
    assert d["serie"][-6] == 1 and d["serie"][-1] == 1
    assert d["serie"][-5:-1] == [None] * 4 and d["serie"][0] is None                      # aucun signe de vie : pas mesuré
    assert d["heures_mesurees"] == 2 and "Mesure complète sur 0\u00a0heure seulement." in d["phrase"]
    for m in range(0, 76):                                                                # le moteur vit, de minute en minute
        box.vie(T + 2 * H + 60 * m)
        box.passe(T + 2 * H + 60 * m)
    d = box.site(t=T + 2 * H + 4500)
    assert d["serie"][-1] == 0 and d["serie"][-2] is None                                 # 15 h : zéro mesuré ; 14 h : partielle (30 min)


def test_signe_de_vie_discontinu_ne_mesure_pas_un_zero(box):
    box.ecrire()
    box.vie(T - 1500)
    box.passe(T - 1500)
    box.vie()
    v = box.passe()                                                                       # deux signes à 25 min : rien entre les deux
    d = v["dossiers"][D.INCONNUS]
    assert d["serie"][-1] is None and 23 in v["commun"]["partielles"] and d["etat"] == "non_mesure"
    assert d["sous_titre"] == "Non mesuré" and d["total"] is None and ["calme", "v"] not in d["etiquettes"]
    box.ecrire(ligne())
    assert box.site()["serie"][-1] == 1                                                   # un compte reste un minimum lisible


def test_lignes_rapprochees_couvrent_l_heure_lignes_eloignees_non(box):
    box.ecrire(*[ligne(s, host="www.exemple.test") for s in range(5 * H, 2 * H, -300)], *[ligne(s, host="www.exemple.test") for s in range(2 * H, 0, -900)])
    v = box.passe()
    d = v["dossiers"]["www.exemple.test"]
    assert {19, 20, 21} - set(v["commun"]["partielles"]) and v["commun"]["heures_mesurees"] >= 2
    assert 22 in v["commun"]["partielles"] and v["dossiers"][D.INCONNUS]["serie"][20] == 0 and v["dossiers"][D.INCONNUS]["serie"][22] is None
    assert d["serie"][22] == 4


def test_site_calme_dit_les_heures_mesurees_jamais_24h(box):
    box.ecrire(*[ligne(s, host="www.exemple.test") for s in range(5 * H, 0, -300)])
    v = box.passe()
    inc = v["dossiers"][D.INCONNUS]
    assert inc["etat"] == "calme" and inc["sous_titre"].startswith("Rien d’hostile sur ") and "sur les heures mesurées" in inc["phrase"]


def test_signe_de_vie_perime_ou_journal_absent_ne_mesure_rien(box):
    box.vie(T - 2 * H)
    v = box.passe()
    assert v["commun"]["journal"] == "illisible" and not v["commun"]["complet"] and v["commun"]["heures_mesurees"] == 0
    assert v["liste"]["chiffres"]["hostiles"] is None and v["liste"]["chiffres"]["tenu_pct"] is None
    assert v["dossiers"][D.INCONNUS]["phrase"] == "Aucune heure n’est mesurée."
    box.vie()
    assert box.passe()["commun"]["heures_mesurees"] == 0                                  # moteur vivant, journal absent
    box.ecrire()
    assert box.passe()["commun"]["partielles"] == [23]


# ── lecture ────────────────────────────────────────────────────────────────────────────────────────────────────────

def test_lecture_incrementale_sans_doublon_ni_ligne_coupee(box):
    box.ecrire(ligne(), ligne())
    assert box.site()["total"] == 2
    with open(box.c["journal"], "a") as f:
        f.write(ligne()[:40])
    assert box.site()["total"] == 2
    with open(box.c["journal"], "a") as f:
        f.write(ligne()[40:] + "\n")
    assert box.site()["total"] == 3 and box.site()["total"] == 3


def test_rotation_ni_trou_ni_doublon(box):
    box.ecrire(ligne())
    box.passe()
    box.ecrire(ligne(), ligne())                        # écrites après la dernière lecture, avant la rotation
    box.c["journal"].rename(box.c["journal"].with_name("waf-threats.log.1"))
    box.ecrire(ligne())
    v = box.passe()
    assert v["dossiers"]["depot.exemple.test"]["total"] == 4 and v["commun"]["complet"]
    assert D._fond["agregateur"].e["trous"] == 0


def test_double_rotation_ratee_est_un_trou_dit_partiel(box):
    box.ecrire(ligne(3 * H))
    box.passe(T - 3 * H)
    box.c["journal"].rename(box.c["journal"].with_name("waf-threats.log.7"))    # l'inode suivi n'est plus nulle part
    box.ecrire(ligne(90))
    v = box.passe()
    assert v["dossiers"]["depot.exemple.test"]["total"] == 2
    assert D._fond["agregateur"].e["trous"] == 1
    assert v["commun"]["partielles"] == [20, 23]        # heure du dernier relevé, heure de la reprise ; rien entre les deux
    assert v["dossiers"]["depot.exemple.test"]["serie"][21:23] == [None, None]


def test_troncature_sur_place(box):
    box.ecrire(*[ligne(120) for _ in range(5)])
    box.passe()
    box.ecrire(ligne(), mode="w")
    assert box.site()["total"] == 6


def test_journal_reecrit_supprime_ou_recree_sans_double_compte(box):
    j = box.c["journal"]
    box.ecrire(ligne(100), ligne(90))
    box.passe()
    copie = j.read_bytes()
    j.unlink()                                          # supprimé puis recréé (inode souvent réutilisé) avec d'autres lignes
    box.ecrire(ligne(80), ligne(70), ligne(60), ligne(50))
    assert box.site()["total"] == 6
    j.unlink()
    assert box.passe()["commun"]["journal"] == "illisible" and box.passe()["dossiers"]["depot.exemple.test"]["total"] == 6
    j.write_bytes(copie)                                # un fichier déjà compté revient : rien n'est recompté
    assert box.site()["total"] == 6
    box.ecrire(ligne(40))
    assert box.site()["total"] == 7
    tmp = j.with_name("tmp")                            # recopié (autre inode, même contenu) : on continue au même octet
    tmp.write_bytes(j.read_bytes())
    tmp.rename(j)
    box.ecrire(ligne(30))
    assert box.site()["total"] == 8


def test_point_un_deja_lu_n_est_pas_rejoue(box):
    """Le courant disparaît sans être renommé : `.1`, déjà compté, ne doit pas être relu."""
    j = box.c["journal"]
    box.ecrire(ligne(300))
    box.passe()
    j.rename(j.with_name("waf-threats.log.1"))
    box.ecrire(ligne(200))
    assert box.site()["total"] == 2
    j.rename(j.with_name("perdu"))
    box.ecrire(ligne(100))
    assert box.site()["total"] == 3


def test_lot_entier_ou_rien(box, monkeypatch):
    box.ecrire(ligne())
    box.passe()
    avant = json.dumps(D._fond["agregateur"].e)
    box.ecrire(ligne(), ligne())
    vrai = D._veille.lire_flux
    appels = []

    def casse(*a):
        appels.append(1)
        if len(appels) == 2:
            raise OSError("disque")
        return vrai(*a)
    monkeypatch.setattr(D._veille, "lire_flux", casse)
    with pytest.raises(OSError):
        box.passe()                                     # le premier lot avait été ajouté : il n'en reste rien
    assert json.dumps(D._fond["agregateur"].e) == avant
    monkeypatch.setattr(D._veille, "lire_flux", vrai)
    assert box.site()["total"] == 3


def test_ligne_qui_leve_sautee_une_fois(box, monkeypatch):
    vrai = D._categorie
    monkeypatch.setattr(D, "_categorie", lambda c: 1 / 0 if c == "piege" else vrai(c))
    box.ecrire(ligne(), ligne(category="piege"), ligne())
    v = box.passe()
    assert v["dossiers"]["depot.exemple.test"]["total"] == 2 and v["commun"]["illisibles"] == 1
    assert box.passe()["commun"]["illisibles"] == 1     # pas relue


def test_flot_saute_au_plus_recent_et_le_dit(box, monkeypatch):
    box.ecrire(ligne(H))
    box.passe(T - H)
    une = len(ligne()) + 1
    monkeypatch.setattr(D, "PASSE_LIGNES", 10)
    monkeypatch.setattr(D, "PASSE_TOURS", 2)
    monkeypatch.setattr(D, "RETARD_MAX", 60 * une)
    monkeypatch.setattr(D, "SAUT_OCTETS", 8 * une)
    box.ecrire(*[ligne(60) for _ in range(50)])         # 50 lignes à 20 par passe : en retard, sous la borne
    v = box.passe()
    assert v["commun"]["journal"] == "retard" and not v["commun"]["complet"] and v["liste"]["chiffres"]["hostiles"] is None
    assert v["liste"]["chiffres"]["sous_attaque"] is None and v["liste"]["chiffres"]["series"]["ecartees"] is None
    assert v["dossiers"]["depot.exemple.test"]["attaque"] is None
    box.ecrire(*[ligne(30) for _ in range(90)])         # au-delà : saut
    v = box.passe()
    assert v["commun"]["complet"] and v["commun"]["sauts_24h"] == 1 and v["liste"]["chiffres"]["hostiles"] is not None
    assert 21 < v["dossiers"]["depot.exemple.test"]["total"] < 40
    assert D._fond["agregateur"].e["couv"][str(int(T // H) - 1)].bit_count() < 55 and 23 in v["commun"]["partielles"]
    assert box.passe(T + 90000)["commun"]["sauts_24h"] == 0


def test_routes_illisibles_tout_va_dans_inconnus(box):
    for brut in (None, "{", "[]"):
        D.vider()
        box.c["etat"].unlink(missing_ok=True)
        if brut is None:
            box.c["routes"].unlink()
        else:
            box.c["routes"].write_text(brut)
        box.c["journal"].write_text(ligne() + "\n")
        v = box.passe()
        assert set(v["dossiers"]) == {D.INCONNUS} and v["commun"]["routes"] == "illisible" and v["calmes"] == []
        assert "table des sites est illisible" in v["dossiers"][D.INCONNUS]["phrase"] and v["liste"]["chiffres"]["sites_proteges"] is None


def test_redemarrage_reprend_au_curseur(box):
    box.ecrire(ligne(), ligne())
    box.passe(forcer=True)
    D.vider()                                           # nouveau processus
    box.ecrire(ligne())
    assert box.site()["total"] == 3
    assert box.c["etat"].stat().st_mode & 0o777 == 0o640
    assert not list(box.c["etat"].parent.glob(".dossiers-*"))


def test_redemarrage_avec_etat_corrompu_relit_le_journal(box):
    box.ecrire(ligne())
    box.passe(forcer=True)
    for brut in ("{", "[]", json.dumps({"v": 1}), json.dumps({**D._neuf(), "heures": {"x": {}}}),
                 json.dumps({**D._neuf(), "curseur": "../../etc"}), json.dumps({**D._neuf(), "dernier_ts": "x"}),
                 json.dumps({**D._neuf(), "dernier_ts": -1}), json.dumps({**D._neuf(), "dernier_ts": True}),
                 json.dumps({**D._neuf(), "derniers": {"a.test": {"arrete": [1]}}}), json.dumps({**D._neuf(), "derniers": {"203.0.113.1": {}}}),
                 json.dumps({**D._neuf(), "hors_web": {"1": "2"}}), json.dumps({**D._neuf(), "couv": {"1": 1 << 61}}),
                 json.dumps({**D._neuf(), "couv": {"1": -1}}), json.dumps({**D._neuf(), "sauts": ["x"]}), json.dumps({**D._neuf(), "lus": [3]}),
                 json.dumps({**D._neuf(), "tete": "zz"}), json.dumps({**D._neuf(), "illisibles": None}), json.dumps({**D._neuf(), "inconnu": 1}),
                 json.dumps({**D._neuf(), "heures": {"1": {"<b>": {"c": {}, "o": {}}}}}), json.dumps({**D._neuf(), "initial": 1}),
                 json.dumps({**D._neuf(), "heures": {"1": {"a": {"c": {"sqli": [1]}, "o": {}}}}})):
        D.vider()
        box.c["etat"].write_text(brut)
        assert box.site()["total"] == 1, brut


def test_premier_depart_borne_par_la_fin(box, monkeypatch):
    box.ecrire(*[ligne(2 * H) for _ in range(50)])
    box.c["journal"].rename(box.c["journal"].with_name("waf-threats.log.1"))
    box.ecrire(*[ligne(60) for _ in range(10)])
    taille = box.c["journal"].stat().st_size
    monkeypatch.setattr(D, "REPRISE_OCTETS", taille + 3 * len(ligne(60)))
    d = box.site()
    assert 10 < d["total"] < 15
    monkeypatch.setattr(D, "REPRISE_OCTETS", taille // 2)
    D.vider()
    box.c["etat"].unlink()
    assert 0 < box.site()["total"] < 10


def test_rattrapage_etale_sur_plusieurs_passes(box, monkeypatch):
    monkeypatch.setattr(D, "PASSE_LIGNES", 10)
    monkeypatch.setattr(D, "PASSE_TOURS", 2)
    box.ecrire(*[ligne() for _ in range(45)])
    v = box.passe()
    assert v["dossiers"]["depot.exemple.test"]["total"] == 20 and v["commun"]["rattrapage"] and not v["commun"]["complet"]
    box.passe()
    v = box.passe()
    assert v["dossiers"]["depot.exemple.test"]["total"] == 45 and v["commun"]["complet"]


def test_lignes_corrompues_ou_absurdes(box):
    box.ecrire("{pas du json", "[]", "null", '"x"', json.dumps({"timestamp": "hier"}), ligne(-3600),
               '{"timestamp": NaN, "action": "banned"}', '{"timestamp": 1e999, "action": "banned"}',
               ligne(action=["banned"]), ligne(category={"a": 1}), ligne(host={"a": 1}), ligne(reseau_classe=["x"]),
               ligne(action="leurre_redirige", category="leurre_redirige", servies=-5), ligne(category="<b>x</b>"), ligne())
    v = box.passe()
    d = v["dossiers"]["depot.exemple.test"]
    assert d["total"] == 5 and v["commun"]["illisibles"] >= 5
    assert "<b>" not in json.dumps(v["liste"]) + json.dumps(d)
    assert v["dossiers"][D.INCONNUS]["total"] == 1                      # hôte illisible


def test_plafonds(box, monkeypatch):
    monkeypatch.setattr(D, "MAX_SITES", 3)
    monkeypatch.setattr(D, "MAX_CATS", 2)
    box.c["routes"].write_text(json.dumps({f"s{i}.exemple.test": ["x", 1] for i in range(10)}))
    box.ecrire(*[ligne(host=f"s{i}.exemple.test") for i in range(10)],
               *[ligne(host="s0.exemple.test", category=f"cat{i}") for i in range(6)])
    v = box.passe()
    assert len([s for s in v["dossiers"] if s != D.INCONNUS]) == 3 and v["commun"]["hors_plafond"] == 7
    cats = {c["cle"]: c["n"] for c in v["dossiers"]["s0.exemple.test"]["categories"]}
    assert cats == {"sqli": 1, "cat0": 1, "autres": 5}


def test_plafond_global_de_cellules(box, monkeypatch):
    monkeypatch.setattr(D, "MAX_CELLULES", 4)
    box.ecrire(*[ligne(category=f"cat{i}") for i in range(20)])
    box.passe()
    assert D._fond["agregateur"]._cellules <= 5
    assert box.site()["total"] == 20


def test_fenetre_glissante_oublie_les_vieilles_heures(box):
    box.ecrire(ligne(23 * H), ligne(30 * H), ligne(60))
    assert box.site()["total"] == 2
    v = box.passe(T + 10 * H)
    assert v["dossiers"]["depot.exemple.test"]["total"] == 1
    v = box.passe(T + 40 * H)
    assert "depot.exemple.test" in v["calmes"] and not D._fond["agregateur"].e["heures"]
    assert not D._fond["agregateur"].e["derniers"]


# ── sens ───────────────────────────────────────────────────────────────────────────────────────────────────────────

def test_sous_attaque_seulement_contre_un_rythme_mesure(box):
    box.ecrire(*[ligne(60) for _ in range(200)])
    d = box.site()
    assert d["attaque"] is None and "sous attaque" not in json.dumps(d, ensure_ascii=False)   # pas d'historique : on ne sait pas
    assert box.passe()["liste"]["chiffres"]["sous_attaque"] is None
    D.vider()
    box.c["etat"].unlink()
    # 90 minutes depuis le début de l'heure précédente ; deux requêtes toutes les 5 min avant, une toutes les 5 min ensuite
    box.ecrire(*[ligne(s) for s in range(20 * H, 5400, -300) for _ in range(2)], *[ligne(s) for s in range(5400, 0, -300)],
               *[ligne(60) for _ in range(200)], mode="w")
    v = box.passe()
    d = v["dossiers"]["depot.exemple.test"]
    assert d["attaque"] is True and ["sous attaque", "r"] in d["etiquettes"] and d["urgence"] == 80
    m = re.search(r"En ce moment\u00a0: (\d+) en (\d+)\u00a0minutes, (\d+) fois le rythme habituel", d["phrase"])
    assert m and 85 <= int(m[2]) <= 91 and int(m[3]) == 6 and v["liste"]["chiffres"]["sous_attaque"] == 1   # 218 contre 36 à durée égale


def test_fenetre_d_attaque_proratisee_et_heures_partielles_exclues(box):
    a = D.Agregateur()
    h = int(T // H)
    for k in range(2, 12):
        a.e["couv"][str(h - k)] = (1 << 60) - 1
    a.e["couv"][str(h - 1)], a.e["couv"][str(h)] = (1 << 60) - 1, (1 << 31) - 1                       # 91 minutes
    serie = [None] * 12 + [60] * 10 + [60, 40]
    assert D._attaque(a, serie, T, False) == (False, 100, 91, 91.0)
    for k in range(2, 7):
        a.e["couv"][str(h - k)] = 1                                                                 # heures partielles : hors du rythme
    assert D._attaque(a, serie, T, False)[0] is None                                                # cinq complètes : pas d'historique
    a.e["couv"][str(h - 2)] = (1 << 60) - 1
    assert D._attaque(a, serie, T, False)[0] is False
    a.e["couv"][str(h)] = 0b1                                                                       # heure en cours mal couverte
    assert D._attaque(a, serie, T, False)[0] is None
    assert D._attaque(a, serie[:-1] + [900], T, False)[0] is True                                   # un minimum qui dépasse suffit
    assert D._attaque(a, serie[:-1] + [900], T, True)[0] is None                                    # lecture en retard : on ne sait pas
    a.e["couv"][str(h)] = a.e["couv"][str(h - 1)] = 0
    assert D._attaque(a, serie[:-2] + [None, None], T, False)[0] is None


def test_journal_illisible_ni_attaque_ni_chiffre(box):
    box.ecrire(*[ligne(s) for s in range(20 * H, 0, -300)])
    assert box.passe()["liste"]["chiffres"]["sous_attaque"] == 0
    box.c["journal"].rename(box.c["journal"].with_name("ailleurs"))
    c = box.passe()["liste"]["chiffres"]
    assert c["sous_attaque"] is None and c["hostiles"] is None and c["passees"] is None and c["hors_web"] is None


def test_heures_de_paris_et_changement_d_heure():
    def h(*a):
        return int(datetime(*a, tzinfo=timezone.utc).timestamp() // 3600)
    assert D.nom_heure(h(2026, 7, 1, 10)) == "12\u00a0h" and D.nom_heure(h(2026, 12, 1, 10)) == "11\u00a0h"
    assert [D.nom_heure(h(2026, 10, 25, u)) for u in (0, 1, 2)] == ["2\u00a0h (été)", "2\u00a0h (hiver)", "3\u00a0h"]
    assert [D.nom_heure(h(2026, 3, 29, u)) for u in (0, 1)] == ["1\u00a0h", "3\u00a0h"]


def test_phrases_accords_et_nombres(box):
    box.ecrire(ligne())
    d = box.site()
    assert d["phrase"].startswith("1 requête hostile en 24 h, de type « injection SQL ». Le mur l’a écartée.")
    box.ecrire(*[ligne() for _ in range(1233)], *[ligne(action="detect", category="recon_crawler") for _ in range(1)])
    d = box.site()
    assert "1 235 requêtes hostiles en 24 h" in d["phrase"]
    assert "99,9 %" in d["phrase"] and "1 a été vue puis laissée passer" in d["phrase"]   # jamais arrondi à 100 %
    assert d["etiquettes"][-1] == ["1 laissée passer", "o"] and d["geste"]["href"] == "/waf/#modes"
    assert not IPV4.search(d["phrase"])
    assert D.pct(100) == "100 %" and D.pl(0, "adresse", "adresses") == "0 adresse"


def _rotation(box, **k):
    box.c["rotation"].write_text(json.dumps({"genere_le": int(T), "mode": "propose", "campagnes": [
        {"signature": "0a1b2c3d4e", "hote": "depot.exemple.test", "etablie_le": int(T) - 900, "dernier": int(T) - 60, "sources": 640,
         "bannies": 0, "epargnees": 3, "a_bannir": 19, "ecartees": 2}, {"signature": "../x", "hote": "depot.exemple.test"},
        {"signature": "ffffffff", "hote": "203.0.113.4"}], **k}))


def test_decisions_en_attente_et_geste(box):
    _rotation(box)
    box.c["campagnes"].write_text(json.dumps({"genere_le": int(T), "mode": "propose", "candidats": [
        {"ip": "203.0.113.1", "decision": "a_bannir"}, {"ip": "203.0.113.1", "decision": "a_bannir"},
        {"ip": "203.0.113.2", "decision": "banni"}, {"ip": "203.0.113.3", "decision": "ecarte:lan"}, "x"]}))
    box.ecrire(ligne())
    v = box.passe()
    d = v["dossiers"]["depot.exemple.test"]
    assert d["urgence"] == 100 and d["etiquettes"][0] == ["à décider", "r"] and d["geste"]["href"] == "/actor/"
    assert "19 adresses sont proposées au bannissement et attendent ta décision." in d["phrase"]
    assert any(f["preuve"] == "attend ta décision" and "19" in f["texte"] for f in d["faits"])
    dec = v["liste"]["decisions"]
    assert [(c["id"], c["hote"]) for c in dec["rotation"]["campagnes"]] == [("rotation:0a1b2c3d", "depot.exemple.test"), ("rotation:ffffffff", None)]
    assert dec["campagnes"]["a_bannir"] == 1 and dec["campagnes"]["bannis"] == 1 and dec["acteurs"]["a_bannir"] is None
    assert not IPV4.search(json.dumps(v["liste"]))


def test_etat_de_rotation_perime_ou_auto_ne_demande_rien(box):
    box.ecrire(ligne())
    for k in ({"mode": "auto"}, {"genere_le": int(T) - 3600}):
        _rotation(box, **k)
        assert box.site()["etat"] != "a_decider"
    assert box.passe()["liste"]["decisions"]["rotation"]["etat"] == "perime"


def test_population_visant_le_site_devient_un_fait(box):
    box.c["populations"].write_text(json.dumps({"genere_le": int(T), "populations": [
        {"id": "famille:collecte", "famille": "collecte", "nom_cible": "depot.exemple.test", "adresses": 2454, "etat": "observee",
         "actives_24h": 12, "dernier": int(T) - 600}]}))
    box.ecrire(ligne())
    assert box.passe()["liste"]["cibles_servies"] == ["depot.exemple.test"]
    assert any(f["texte"] == "Collecte : 2 454 adresses en sept jours" for f in box.site()["faits"])
    assert len(box.site()["faits"]) <= D.MAX_FAITS


# ── routes ─────────────────────────────────────────────────────────────────────────────────────────────────────────

@pytest.fixture
def waf():
    W.app.dependency_overrides.clear()
    yield W
    W.app.dependency_overrides.clear()


def test_routes_gardees_et_sans_calcul(box, waf, monkeypatch):
    from fastapi.testclient import TestClient
    c = TestClient(waf.app)
    hors_lan = {"X-SecuBox-LAN": "0"}                   # le harnais représente un tableau de bord du réseau local
    for u in ("/dossiers/sites", "/dossiers/sites/depot.exemple.test"):
        assert c.get(u, headers=hors_lan).status_code == 401
    waf.app.dependency_overrides[D.require_lecture] = lambda: {"sub": "lecteur"}
    assert c.get("/dossiers/sites").json() == {"disponible": False, "genere_le": None, "couverture_depuis": None}
    box.ecrire(ligne(8 * H), ligne(), ligne(host="autre.invalide", category="host_anomaly:unrouted"))
    box.passe()
    monkeypatch.setattr(D, "rafraichir", lambda *a, **k: pytest.fail("calcul sur le chemin d'une requête"))
    monkeypatch.setattr(D._veille, "lire_flux", lambda *a, **k: pytest.fail("journal lu sur le chemin d'une requête"))
    j = c.get("/dossiers/sites").json()
    assert j["disponible"] and j["genere_le"] == int(T) and j["couverture_depuis"] == int(T) - 8 * H and j["perime"] in (True, False)
    assert [s["id"] for s in j["sites"]] == ["depot.exemple.test", D.INCONNUS] and j["calmes_total"] == 2 and j["calmes"] == []
    d = c.get("/dossiers/sites/depot.exemple.test").json()
    assert d["couches"][0]["nom"] == "Arrêté" and len(d["couches"][0]["serie"]) == 24 and d["couverture_depuis"]
    assert c.get("/dossiers/sites/agenda.exemple.test").status_code == 404 and "agenda" not in c.get("/dossiers/sites").text    # inventaire : administrateur
    waf.app.dependency_overrides[D._est_admin] = lambda: True
    assert "agenda.exemple.test" in c.get("/dossiers/sites").json()["calmes"]
    calme = c.get("/dossiers/sites/agenda.exemple.test").json()
    assert calme["total"] is None and calme["etat"] == "non_mesure"       # une minute couverte : rien ne dit « calme »
    assert c.get("/dossiers/sites/inconnu.exemple.test").status_code == 404
    assert c.get("/dossiers/sites/<script>").status_code == 422
    assert not IPV4.search(c.get("/dossiers/sites").text + c.get("/dossiers/sites/noms-inconnus").text)


def test_autre_processus_sert_l_etat_ecrit(box, waf):
    """Monté dans l'agrégateur (sans tâche de fond), le module sert les vues du fichier d'état."""
    from fastapi.testclient import TestClient
    waf.app.dependency_overrides[D.require_lecture] = lambda: {"sub": "lecteur"}
    box.ecrire(ligne(), ligne(action="detect"))
    box.passe(forcer=True)
    D.vider()
    j = TestClient(waf.app).get("/dossiers/sites").json()
    assert j["sites"][0]["total"] == 2 and j["genere_le"] == int(T) and j["sites"][0]["totaux"]["passe"] == 1


def test_la_boucle_de_fond_est_branchee(waf):
    import inspect
    src = inspect.getsource(waf._warm_loop)
    assert "asyncio.to_thread(_dossiers.rafraichir)" in src
    assert all(any(d.call is D.require_lecture for d in r.dependant.dependencies)
               for r in D.router.routes)


def test_est_admin_suit_require_jwt(waf, monkeypatch):
    import asyncio
    from types import SimpleNamespace
    req = SimpleNamespace(headers={"authorization": "Bearer x"}, cookies={})

    async def passe(*a):
        return {"sub": "a"}

    async def refuse(*a):
        raise D.HTTPException(403)

    async def casse(*a):
        raise RuntimeError("x")
    monkeypatch.setattr(D, "_validate_token", lambda t: None)
    for garde, attendu in ((passe, True), (refuse, False), (casse, False)):
        monkeypatch.setattr(D, "require_jwt", garde)
        assert asyncio.run(D._est_admin(req)) is attendu
    monkeypatch.setattr(D, "require_jwt", passe)
    monkeypatch.setattr(D, "_validate_token", lambda t: {"sub": "lecteur"})
    monkeypatch.setattr(D, "est_admin_reel", lambda p: False)
    assert asyncio.run(D._est_admin(req)) is False


def test_reconstruction_concurrente_une_seule_fois(box, monkeypatch):
    import threading
    import time
    box.ecrire(ligne())
    box.passe(forcer=True)
    D.vider()
    vrai, appels = D.construire, []

    def lent(*a):
        appels.append(1)
        time.sleep(.1)
        return vrai(*a)
    monkeypatch.setattr(D, "construire", lent)
    fils = [threading.Thread(target=D._vues) for _ in range(6)]
    for f in fils:
        f.start()
    for f in fils:
        f.join()
    assert len(appels) == 1


def test_etats_accessoires_hostiles(box):
    box.c["campagnes"].write_text(json.dumps({"genere_le": int(T), "mode": "propose", "candidats": [{"ip": ["x"], "decision": "a_bannir"}, {"ip": "203.0.113.1", "decision": ["x"]}]}))
    box.c["populations"].write_text(json.dumps({"populations": [{"nom_cible": ["x"], "famille": {}, "actives_24h": 3, "etat": "observee", "dernier": 5}]}))
    box.ecrire(ligne())
    assert box.passe()["liste"]["decisions"]["campagnes"]["a_bannir"] == 0
