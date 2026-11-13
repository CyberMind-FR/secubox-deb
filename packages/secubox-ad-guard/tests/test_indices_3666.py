# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Indices TV Privacy partagés (#3666) : contenu publié et lecture des livraisons."""
import json
import os

from api import dnstv_indices as I


class _Regles:
    """Doublure : seule `.liste()` est lue par `contenu`."""
    def __init__(self, regles):
        self._l = regles

    def liste(self):
        return list(self._l)


class _Taxo:
    def __init__(self, cats=None):
        self.cats = cats or {}

    def classer(self, d, macs=()):
        return {"categorie": self.cats.get(d, "INCONNU")}


def _regle(appareil, domaine, etat="confirme", origine="auto", indice=None):
    r = {"appareil": appareil, "domaine": domaine, "etat": etat, "origine": origine,
         "historique": [{"ts": 1, "de": "essai", "vers": etat, "origine": origine, "motif": ""}]}
    if indice is not None:
        r["indice"] = indice
    return r


def test_contenu_sans_appareil_ni_date():
    c = I.contenu(_Regles([_regle("tv-salon", "ads.ex.com"), _regle("tv-chambre", "ads.ex.com")]), [], _Taxo({"ads.ex.com": "PUBLICITE"}))
    assert c["indices"] == {"ads.ex.com": "PUBLICITE"}
    assert b"tv-salon" not in I.octets(c) and b"tv-chambre" not in I.octets(c)
    assert set(c) == {"format", "jeu", "indices", "legitimes"}


def test_categorie_taxonomie_gardee_si_autorisee():
    """F4 : la catégorie LOCALE décide ; une autre catégorie que pub / pistage / télémétrie n'est jamais publiée."""
    c = I.contenu(_Regles([_regle("tv", "t.ex.com"), _regle("tv", "s.ex.com"), _regle("tv", "m.ex.com")]), [],
                  _Taxo({"t.ex.com": "TRACKING", "s.ex.com": "STREAMING", "m.ex.com": "TELEMETRIE"}))
    assert c["indices"] == {"t.ex.com": "TRACKING", "m.ex.com": "TELEMETRIE"}


def test_pas_d_echo():
    auto = _regle("tv", "a.ex.com", indice=["gk6"])
    assert I.contenu(_Regles([auto]), [], _Taxo())["indices"] == {}
    adm = _regle("tv", "a.ex.com", origine="admin", indice=["gk6"])
    assert "a.ex.com" in I.contenu(_Regles([adm]), [], _Taxo())["indices"]


def test_legitime_l_emporte():
    exc = [{"appareil": "tv", "domaine": "a.ex.com", "type": "autoriser"}]
    c = I.contenu(_Regles([_regle("tv", "a.ex.com")]), exc, _Taxo({"a.ex.com": "PUBLICITE"}))
    assert c["indices"] == {} and c["legitimes"] == ["a.ex.com"]


def test_exceptions_bloquer_et_rejet_admin():
    exc = [{"appareil": "tv", "domaine": "b.ex.com", "type": "bloquer"}]
    regs = [_regle("tv", "r.ex.com", "rejete", "admin"), _regle("tv", "x.ex.com", "retire", "auto")]
    c = I.contenu(_Regles(regs), exc, _Taxo({"b.ex.com": "PUBLICITE"}))
    assert c["indices"] == {"b.ex.com": "PUBLICITE"}
    assert c["legitimes"] == ["r.ex.com"]


def test_octets_deterministes():
    r1 = [_regle("a", "x.com"), _regle("b", "y.com")]
    e1 = [{"appareil": "a", "domaine": "z.com", "type": "autoriser"}, {"appareil": "a", "domaine": "w.com", "type": "autoriser"}]
    c1 = I.contenu(_Regles(r1), e1, _Taxo())
    c2 = I.contenu(_Regles(r1[::-1]), e1[::-1], _Taxo())
    assert I.octets(c1) == I.octets(c2)


def test_ecrire_publication_atomique_0640_et_si_change(tmp_path):
    p = tmp_path / "d" / "pub.json"
    c = {"format": 1, "jeu": "tv-indices", "indices": {}, "legitimes": []}
    assert I.ecrire_publication(True, False, c, p) is True
    assert (p.stat().st_mode & 0o777) == 0o640
    assert json.loads(p.read_text())["contenu"] == c
    assert I.ecrire_publication(True, False, c, p) is False
    assert I.ecrire_publication(True, True, c, p) is True
    assert [f.name for f in p.parent.iterdir()] == ["pub.json"]


DID1, DID2 = "did:plc:" + "a" * 32, "did:plc:" + "b" * 32


def _livraison(dossier, did, contenu, nom="gk2"):
    dossier.mkdir(parents=True, exist_ok=True)
    f = dossier / "index.json"
    idx = json.loads(f.read_text()) if f.exists() else {}
    idx[did] = {"nom": nom, "empreinte": "b2:" + "0" * 64}
    f.write_text(json.dumps(idx))
    (dossier / (did[len("did:plc:"):] + ".json")).write_text(contenu if isinstance(contenu, str) else json.dumps(contenu))


def _c(indices=None, legit=()):
    return {"format": 1, "jeu": "tv-indices", "indices": indices or {}, "legitimes": list(legit)}


def test_charger_valide_et_plafonne(tmp_path):
    d = tmp_path / "liv"
    _livraison(d, DID1, _c({"ads.ex.com": "PUBLICITE", "ADS.Ex.com.": "TRACKING"}), "gk2")
    gros = json.dumps({"format": 1, "jeu": "tv-indices", "indices": {"gros.com": "TRACKING"}, "legitimes": [],
                       "bourrage": "x" * (3 * 1024 * 1024)})
    assert len(gros) > 2 * 1024 * 1024
    _livraison(d, DID2, gros, "gk6")
    tronque = json.dumps(_c({"tronque.com": "TRACKING"}))[:-5]
    _livraison(d, "did:plc:" + "c" * 32, tronque, "gk7")
    _livraison(d, "did:plc:" + "d" * 32, _c({"streaming.com": "STREAMING"}), "gk8")
    ix = I.charger(d)
    for absent in ("gros.com", "tronque.com", "streaming.com"):
        assert absent not in ix.confirmes
    # doublon normalisé : clés triées, "ADS.Ex.com." < "ads.ex.com" -> la première gagne
    assert ix.confirmes == {"ads.ex.com": {"gk2": "TRACKING"}}


def test_charger_plafond_indices(tmp_path):
    d = tmp_path / "liv"
    ok = {f"h{i}.ex.com": "TRACKING" for i in range(I.INDICES_MAX)}
    _livraison(d, DID1, _c(ok), "gk1")
    _livraison(d, DID2, _c({**ok, "de.trop.com": "TRACKING"}), "gk2")
    ix = I.charger(d)
    assert len(ix.confirmes) == I.INDICES_MAX and set(ix.confirmes["h0.ex.com"]) == {"gk1"}


def test_charger_plafond_legitimes(tmp_path):
    d = tmp_path / "liv"
    _livraison(d, DID1, _c(None, [f"l{i}.ex.com" for i in range(I.LEGITIMES_MAX)]), "gk1")
    _livraison(d, DID2, _c(None, [f"l{i}.ex.com" for i in range(I.LEGITIMES_MAX + 1)]), "gk2")
    ix = I.charger(d)
    assert ix.legitime_chez("l0.ex.com") == ["gk1"] and len(ix.legitimes) == I.LEGITIMES_MAX


def test_charger_plafond_producteurs(tmp_path):
    d = tmp_path / "liv"
    for i in range(I.PRODUCTEURS_MAX + 1):
        _livraison(d, "did:plc:" + f"{i:032x}", _c({"a.com": "TRACKING"}), f"gk{i}")
    ix = I.charger(d)
    assert len(ix.confirmes["a.com"]) == I.PRODUCTEURS_MAX and "gk64" not in ix.confirmes["a.com"]


def test_charger_elements_non_chaines(tmp_path):
    d = tmp_path / "liv"
    _livraison(d, DID1, {"format": 1, "jeu": "tv-indices", "indices": {"a.com": "TRACKING"}, "legitimes": [1, None, ["x"], "ok.com"]}, "gk1")
    ix = I.charger(d)
    assert ix.legitime_chez("ok.com") == ["gk1"] and ix.confirmateurs("a.com") == ["gk1"]


def test_charger_producteur_qui_leve_n_affecte_pas_les_suivants(tmp_path, monkeypatch):
    d = tmp_path / "liv"
    _livraison(d, DID1, _c({"boom.com": "TRACKING"}), "gk1")
    _livraison(d, DID2, _c({"b.com": "TRACKING"}), "gk2")
    vrai = I._valider_contenu

    def piege(c):
        if isinstance(c, dict) and "boom.com" in c.get("indices", {}):
            raise RuntimeError("producteur défectueux")
        return vrai(c)
    monkeypatch.setattr(I, "_valider_contenu", piege)
    ix = I.charger(d)
    assert "boom.com" not in ix.confirmes and ix.confirmateurs("b.com") == ["gk2"] and ix.indisponibles == {"gk1"}


def test_charger_refuse_symlink_et_did_ou_nom_invalide(tmp_path):
    d = tmp_path / "liv"
    _livraison(d, DID1, _c({"a.com": "TRACKING"}), "gk2")
    cible = tmp_path / "cible.json"
    cible.write_text(json.dumps(_c({"b.com": "TRACKING"})))
    f2 = d / (DID2[8:] + ".json")
    os.symlink(cible, f2)
    idx = json.loads((d / "index.json").read_text())
    idx[DID2] = {"nom": "gk6", "empreinte": "b2:" + "0" * 64}
    idx["did:plc:XYZ"] = {"nom": "gk9", "empreinte": ""}
    idx["did:plc:" + "e" * 32] = {"nom": "../Mauvais", "empreinte": ""}
    (d / "index.json").write_text(json.dumps(idx))
    ix = I.charger(d)
    assert ix.confirmes == {"a.com": {"gk2": "TRACKING"}}


def test_charger_dossier_absent(tmp_path):
    ix = I.charger(tmp_path / "rien")
    assert ix.confirmes == {} and ix.legitimes == {} and ix.lisible is False


def test_charger_index_illisible_ou_vide(tmp_path):
    d = tmp_path / "liv"
    d.mkdir()
    (d / "index.json").write_text("[1, 2")
    assert I.charger(d).lisible is False
    (d / "index.json").write_text("[]")
    assert I.charger(d).lisible is False
    (d / "index.json").write_text("{}")
    ix = I.charger(d)
    assert ix.lisible is True and ix.indisponibles == set() and ix.confirmes == {}


def test_charger_producteur_illisible_est_indisponible(tmp_path):
    d = tmp_path / "liv"
    _livraison(d, DID1, _c({"a.com": "TRACKING"}), "gk2")
    _livraison(d, DID2, "{tronqué", "gk6")
    ix = I.charger(d)
    assert ix.lisible is True and ix.indisponibles == {"gk6"} and ix.confirmateurs("a.com") == ["gk2"]
    assert I.Index().lisible is True and I.Index().indisponibles == set()


def test_index_confirmateurs_et_legitimes(tmp_path):
    d = tmp_path / "liv"
    _livraison(d, DID1, _c({"a.com": "TRACKING"}), "gk6")
    _livraison(d, DID2, _c({"a.com": "TRACKING"}), "gk2")
    _livraison(d, "did:plc:" + "c" * 32, _c(None, ["a.com"]), "gk1")
    ix = I.charger(d)
    assert ix.confirmateurs("a.com") == ["gk2", "gk6"]
    assert ix.legitime_chez("a.com") == ["gk1"]
    assert ix.categorie("a.com") == "TRACKING"
    assert ix.categorie("zz.com") is None


def test_categorie_la_plus_frequente_puis_alpha():
    ix = I.Index(confirmes={"a.com": {"g1": "TRACKING", "g2": "PUBLICITE"}, "b.com": {"g1": "TRACKING", "g2": "PUBLICITE", "g3": "PUBLICITE"}})
    assert ix.categorie("a.com") == "PUBLICITE"
    assert ix.categorie("b.com") == "PUBLICITE"


# ── correctif final (B1, F2, F4, F5, F6, F18) ──────────────────────────────────────────────────────────────────

def test_f4_jamais_une_autre_categorie_ni_un_inconnu_sans_l_administrateur():
    """F4 (vie privée) : une exception « bloquer » sur un domaine de contrôle parental ou de streaming n'est jamais publiée ; un
    INCONNU n'est publié (étiquette PUBLICITE) que confirmé par l'administrateur ; légitimes : pub / pistage / télémétrie / INCONNU."""
    taxo = _Taxo({"parental.ex.com": "CONTROLE_PARENTAL", "film.ex.com": "STREAMING", "pub.ex.com": "PUBLICITE",
                  "cdn.ex.com": "CDN", "trk.ex.com": "TRACKING"})
    exc = [{"appareil": "tv", "domaine": "parental.ex.com", "type": "bloquer"},
           {"appareil": "tv", "domaine": "film.ex.com", "type": "bloquer"},
           {"appareil": "tv", "domaine": "inconnu-bloque.ex.com", "type": "bloquer"},
           {"appareil": "tv", "domaine": "pub.ex.com", "type": "bloquer"},
           {"appareil": "tv", "domaine": "cdn.ex.com", "type": "autoriser"},
           {"appareil": "tv", "domaine": "inconnu-ok.ex.com", "type": "autoriser"}]
    regs = [_regle("tv", "inconnu-auto.ex.com"), _regle("tv", "inconnu-admin.ex.com", origine="admin"),
            _regle("tv", "film.ex.com", origine="admin"), _regle("tv", "trk.ex.com", "rejete", "admin")]
    c = I.contenu(_Regles(regs), exc, taxo)
    assert c["indices"] == {"pub.ex.com": "PUBLICITE", "inconnu-admin.ex.com": "PUBLICITE"}
    assert c["legitimes"] == ["inconnu-ok.ex.com", "trk.ex.com"]


def test_b1_contenu_invalide_n_est_pas_indisponible(tmp_path):
    """B1 : seule une lecture LOCALE ratée rend un producteur indisponible ; un contenu signé mais invalide (schéma, plafond)
    = aucun indice de ce producteur (un essai né de lui peut donc être oublié)."""
    d = tmp_path / "liv"
    _livraison(d, DID1, {"format": 1, "jeu": "tv-indices", "indices": [], "legitimes": []}, "gk1")
    _livraison(d, DID2, _c({f"h{i}.ex.com": "TRACKING" for i in range(I.INDICES_MAX + 1)}), "gk2")
    _livraison(d, "did:plc:" + "c" * 32, {"format": 2}, "gk3")
    _livraison(d, "did:plc:" + "e" * 32, _c({"a.com": "TRACKING"}), "gk5")
    idx = json.loads((d / "index.json").read_text())
    idx["did:plc:" + "f" * 32] = {"nom": "gk4"}                    # listé, fichier absent ici : lecture ratée
    (d / "index.json").write_text(json.dumps(idx))
    ix = I.charger(d)
    assert ix.lisible is True and ix.indisponibles == {"gk4"}
    assert ix.confirmes == {"a.com": {"gk5": "TRACKING"}}


def test_charger_plafond_indices_n_est_pas_indisponible(tmp_path):
    d = tmp_path / "liv"
    _livraison(d, DID2, _c({f"h{i}.ex.com": "TRACKING" for i in range(I.INDICES_MAX + 1)}), "gk2")
    assert I.charger(d).indisponibles == set()


def test_f2_un_domaine_indice_et_legitime_rejette_le_producteur(tmp_path):
    d = tmp_path / "liv"
    _livraison(d, DID1, _c({"a.com": "TRACKING", "b.com": "PUBLICITE"}, ["A.com."]), "gk1")     # même domaine normalisé
    _livraison(d, DID2, _c({"c.com": "TRACKING"}, ["d.com"]), "gk2")
    ix = I.charger(d)
    assert ix.confirmes == {"c.com": {"gk2": "TRACKING"}} and ix.legitimes == {"d.com": {"gk2"}}
    assert ix.indisponibles == set()


def test_f5_plafond_global_de_domaines(tmp_path, monkeypatch):
    monkeypatch.setattr(I, "DOMAINES_MAX", 5)
    d = tmp_path / "liv"
    _livraison(d, "did:plc:" + "1" * 32, _c({"a.com": "TRACKING", "b.com": "TRACKING"}, ["l.com"]), "gk1")   # 3
    _livraison(d, "did:plc:" + "2" * 32, _c({"c.com": "TRACKING", "e.com": "TRACKING", "f.com": "TRACKING"}), "gk2")  # 6 > 5
    _livraison(d, "did:plc:" + "3" * 32, _c({"g.com": "TRACKING"}), "gk3")      # tiendrait, mais suit un dépassement : ignoré
    ix = I.charger(d)
    assert set(ix.confirmes) == {"a.com", "b.com"} and ix.legitimes == {"l.com": {"gk1"}}
    assert ix.indisponibles == set()
    assert I.DOMAINES_MAX == 5


def test_f5_resume_ecrit_si_change_et_relu(tmp_path):
    d = tmp_path / "liv"
    _livraison(d, DID1, _c({"a.com": "TRACKING", "b.com": "PUBLICITE"}, ["ok.com"]), "gk1")
    _livraison(d, DID2, _c({"a.com": "TRACKING"}), "gk2")
    os.utime(d / "index.json", (1_700_000_000, 1_700_000_000))
    r = I.resume(I.charger(d), d)
    assert r == {"format": 1, "recus": 2, "maj": 1_700_000_000, "producteurs": [
        {"nom": "gk1", "indices": 2, "legitimes": 1}, {"nom": "gk2", "indices": 1, "legitimes": 0}]}
    assert b"a.com" not in json.dumps(r).encode()
    f = tmp_path / "resume.json"
    assert I.ecrire_resume(r, f) is True and I.ecrire_resume(r, f) is False
    assert (f.stat().st_mode & 0o777) == 0o640
    assert I.lire_resume(f) == {"recus": 2, "maj": 1_700_000_000, "producteurs": r["producteurs"]}
    assert I.resume(I.Index(lisible=False), d)["maj"] is None
    assert I.lire_resume(tmp_path / "absent.json") == {"recus": 0, "producteurs": [], "maj": None}
    f.write_text(json.dumps({"recus": "x", "maj": 1, "producteurs": []}))
    assert I.lire_resume(f)["recus"] == 0


def test_f6_lecture_ratee_journalisee(tmp_path, caplog, monkeypatch):
    import logging
    d = tmp_path / "liv"
    d.mkdir()
    (d / "index.json").write_text("[1, 2")
    with caplog.at_level(logging.INFO, logger=I.log.name):
        assert I.charger(d).lisible is False
    assert any("illisible" in r.getMessage() and r.levelno == logging.WARNING for r in caplog.records)
    caplog.clear()

    def boum(c):
        raise RuntimeError("boum")
    monkeypatch.setattr(I, "_lire_json", boum)
    with caplog.at_level(logging.INFO, logger=I.log.name):
        assert I.charger(d).lisible is False
    assert any(r.levelno == logging.ERROR and r.exc_info for r in caplog.records)


def test_f18_mode_retabli_si_contenu_inchange(tmp_path):
    p = tmp_path / "pub.json"
    c = I.contenu_vide()
    assert I.ecrire_publication(True, True, c, p) is True
    os.chmod(p, 0o644)
    assert I.ecrire_publication(True, True, c, p) is False
    assert (p.stat().st_mode & 0o777) == 0o640


def test_f3_drapeaux_seuls_gardent_le_contenu(tmp_path):
    p = tmp_path / "pub.json"
    assert I.ecrire_drapeaux(False, True, p) is True                       # absent : contenu vide
    assert json.loads(p.read_text()) == {"format": 1, "publier": False, "recevoir": True, "contenu": I.contenu_vide()}
    c = _c({"a.com": "TRACKING"})
    I.ecrire_publication(True, True, c, p)
    assert I.ecrire_drapeaux(True, False, p) is True
    assert json.loads(p.read_text()) == {"format": 1, "publier": True, "recevoir": False, "contenu": c}
    assert I.ecrire_drapeaux(True, False, p) is False
