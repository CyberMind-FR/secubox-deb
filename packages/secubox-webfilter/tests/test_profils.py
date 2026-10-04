# SPDX-License-Identifier: LicenseRef-CMSD-1.0
import pytest

from webfilter import profils

CATS = {"adulte", "jeux", "phishing"}


def cfg(**extra):
    base = {"version": 1,
            "profils": {"defaut": {"categories": {"adulte": "observe", "jeux": "observe", "phishing": "observe"}, "autorise": []},
                        "enfants": {"categories": {"adulte": "block", "jeux": "block", "phishing": "block"}, "autorise": []}},
            "appareils": {"aa:bb:cc:dd:ee:01": {"nom": "Tablette", "profil": "enfants", "exceptions": {}}}}
    base.update(extra)
    return base


def test_valide_et_normalise():
    c = profils.valider(cfg(), CATS)
    assert c["profils"]["enfants"]["categories"]["jeux"] == "block" and c["appareils"]["aa:bb:cc:dd:ee:01"]["profil"] == "enfants"


def test_vide_a_un_profil_defaut_en_observe():
    c = profils.vide(CATS)
    assert c["profils"]["defaut"]["categories"] == {"adulte": "observe", "jeux": "observe", "phishing": "observe"} and c["appareils"] == {}


@pytest.mark.parametrize("mod", [
    lambda c: c["profils"].pop("defaut"),                                                  # defaut obligatoire
    lambda c: c["profils"].update({"../x": {"categories": {}, "autorise": []}}),
    lambda c: c["profils"].update({"A B": {"categories": {}, "autorise": []}}),
    lambda c: c["profils"]["enfants"]["categories"].update({"inconnue": "block"}),
    lambda c: c["profils"]["enfants"]["categories"].update({"jeux": "bloque"}),
    lambda c: c["profils"]["enfants"].update({"autorise": ['a.com"; local-zone: "."']}),
    lambda c: c["profils"]["enfants"].update({"autorise": [f"d{i}.example.com" for i in range(201)]}),
    lambda c: c["profils"]["enfants"].update({"extra": 1}),
    lambda c: c["appareils"].update({"AA:BB:CC:DD:EE:02": {"nom": "x", "profil": "enfants", "exceptions": {}}}),
    lambda c: c["appareils"].update({"aa:bb:cc:dd:ee": {"nom": "x", "profil": "enfants", "exceptions": {}}}),
    lambda c: c["appareils"].update({"aa:bb:cc:dd:ee:02": {"nom": "x", "profil": "inexistant", "exceptions": {}}}),
    lambda c: c["appareils"].update({"aa:bb:cc:dd:ee:02": {"nom": "x\ny", "profil": "enfants", "exceptions": {}}}),
    lambda c: c["appareils"].update({"aa:bb:cc:dd:ee:02": {"nom": "x", "profil": "enfants", "exceptions": {"jeux": "autre"}}}),
    lambda c: c["appareils"].update({"aa:bb:cc:dd:ee:02": {"nom": "x", "profil": "enfants", "exceptions": {"inconnue": "block"}}}),
    lambda c: c.update({"version": -1}),
    lambda c: c.update({"inconnu": 1}),
])
def test_refus(mod):
    c = cfg()
    mod(c)
    with pytest.raises(profils.ErreurProfils):
        profils.valider(c, CATS)


def test_limites_de_taille_et_type():
    c = cfg()
    for i in range(257):
        c["appareils"][f"aa:bb:cc:dd:{i // 256:02x}:{i % 256:02x}"] = {"nom": "x", "profil": "defaut", "exceptions": {}}
    with pytest.raises(profils.ErreurProfils):
        profils.valider(c, CATS)
    for brut in ("pas un dict", None, 42, []):
        with pytest.raises(profils.ErreurProfils):
            profils.valider(brut, CATS)


def test_effective_applique_les_exceptions_et_les_autorisations():
    c = profils.valider(cfg(), CATS)
    c["appareils"]["aa:bb:cc:dd:ee:01"]["exceptions"] = {"jeux": "observe"}
    c["profils"]["enfants"]["autorise"] = ["education.example.org"]
    e = profils.effective(c, "aa:bb:cc:dd:ee:01")
    assert e["modes"] == {"adulte": "block", "jeux": "observe", "phishing": "block"} and e["autorise"] == ["education.example.org"]
    assert profils.bloquees(e) == ["adulte", "phishing"]


def test_appareil_inconnu_prend_le_profil_defaut():
    c = profils.valider(cfg(), CATS)
    assert profils.effective(c, "aa:bb:cc:dd:ee:99")["modes"]["jeux"] == "observe"


def test_cle_de_vue_stable_partagee_et_libre():
    c = profils.valider(cfg(), CATS)
    c["appareils"]["aa:bb:cc:dd:ee:02"] = {"nom": "Autre", "profil": "enfants", "exceptions": {}}
    e1, e2 = profils.effective(c, "aa:bb:cc:dd:ee:01"), profils.effective(c, "aa:bb:cc:dd:ee:02")
    assert profils.cle_vue(e1) == profils.cle_vue(e2) and profils.cle_vue(e1).startswith("wf-") and len(profils.cle_vue(e1)) == 11
    assert profils.cle_vue(profils.effective(c, "inconnu")) == "wf-libre"
    c["appareils"]["aa:bb:cc:dd:ee:02"]["exceptions"] = {"jeux": "observe"}
    assert profils.cle_vue(profils.effective(c, "aa:bb:cc:dd:ee:02")) != profils.cle_vue(e1)
    assert profils.cle_vue(e1) == profils.cle_vue(profils.effective(c, "aa:bb:cc:dd:ee:01"))     # stable


def test_domaine_autorise_normalise_doit_deja_l_etre():
    c = cfg()
    c["profils"]["enfants"]["autorise"] = ["Education.Example.org"]
    with pytest.raises(profils.ErreurProfils):
        profils.valider(c, CATS)                                  # la forme canonique est exigée : pas de réécriture silencieuse
