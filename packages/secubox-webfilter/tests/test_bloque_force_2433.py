# SPDX-License-Identifier: LicenseRef-CMSD-1.0
"""#2433 — domaines TOUJOURS bloqués (par profil et par appareil), même quand la catégorie du domaine est en observe pour l'appareil."""
import pytest

from webfilter import generation, profils

CATS = {"adulte", "jeux", "phishing"}
LISTES = {"adulte": ["porn.example.com", "live.exemple.test"], "jeux": ["bet.example.org"], "phishing": []}
MAC = "aa:bb:cc:dd:ee:01"
VOISINS = {MAC: ["192.168.1.50"]}


def cfg(appareil_bloque=None, profil_bloque=None, autorise=None, exceptions=None):
    prof = {"categories": {"adulte": "block", "jeux": "block", "phishing": "block"}, "autorise": autorise or []}
    if profil_bloque is not None:
        prof["bloque"] = profil_bloque
    app = {"nom": "reepost", "profil": "defaut", "exceptions": exceptions if exceptions is not None else {"adulte": "observe"}}
    if appareil_bloque is not None:
        app["bloque"] = appareil_bloque
    return profils.valider({"version": 1, "profils": {"defaut": prof}, "appareils": {MAC: app}}, CATS)


def gen(c):
    return generation.generer(cfg=c, reseaux=["192.168.1.0/24"], voisins=VOISINS, adguard=set(), charger=lambda cat: LISTES[cat], zones_max=1000)


def vue_de_l_appareil(c):
    cle = profils.cle_vue(profils.effective(c, MAC))
    for bloc in gen(c).texte.split("view:\n")[1:]:
        if f'name: "{cle}"' in bloc:
            return bloc
    raise AssertionError("vue absente")


def test_sans_domaine_force_une_categorie_en_observe_ne_bloque_rien():
    v = vue_de_l_appareil(cfg())
    assert "porn.example.com" not in v and "live.exemple.test" not in v      # adulte est en observe pour cet appareil
    assert 'local-zone: "bet.example.org." always_nxdomain' in v             # jeux reste bloqué


def test_un_domaine_force_est_bloque_meme_si_sa_categorie_est_en_observe():
    v = vue_de_l_appareil(cfg(appareil_bloque=["live.exemple.test"]))
    assert 'local-zone: "live.exemple.test." always_nxdomain' in v
    assert "porn.example.com" not in v                                       # le reste de la catégorie reste observé


def test_un_domaine_force_absent_de_toute_liste_est_bloque_aussi():
    v = vue_de_l_appareil(cfg(appareil_bloque=["jamais-liste.exemple.test"]))
    assert 'local-zone: "jamais-liste.exemple.test." always_nxdomain' in v


def test_le_blocage_force_l_emporte_sur_une_autorisation_du_meme_nom():
    v = vue_de_l_appareil(cfg(appareil_bloque=["live.exemple.test"], autorise=["live.exemple.test"]))
    assert 'local-zone: "live.exemple.test." always_nxdomain' in v
    assert 'local-zone: "live.exemple.test." transparent' not in v


def test_une_autorisation_sur_un_parent_ne_debloque_pas_un_sous_domaine_force():
    v = vue_de_l_appareil(cfg(appareil_bloque=["sous.exemple.test"], autorise=["exemple.test"]))
    assert 'local-zone: "exemple.test." transparent' in v and 'local-zone: "sous.exemple.test." always_nxdomain' in v


def test_le_domaine_force_d_un_profil_s_applique_a_tous_ses_appareils():
    c = cfg(profil_bloque=["live.exemple.test"])
    assert profils.effective(c, MAC)["bloque"] == ["live.exemple.test"]
    assert profils.effective(c, "")["bloque"] == ["live.exemple.test"]       # appareil inconnu : profil `defaut`
    assert profils.effective(cfg(appareil_bloque=["a.exemple.test"], profil_bloque=["b.exemple.test"]), MAC)["bloque"] == ["a.exemple.test", "b.exemple.test"]


def test_forme_canonique_exigee_et_limites():
    for mauvais in (["LIVE.exemple.test"], ["http://x.exemple.test"], ["x.exemple.test/chemin"], ["pas un domaine"], [""]):
        with pytest.raises(profils.ErreurProfils):
            cfg(appareil_bloque=mauvais)
    with pytest.raises(profils.ErreurProfils):
        cfg(profil_bloque=[f"d{i}.exemple.test" for i in range(201)])


def test_sans_domaine_force_la_configuration_et_les_vues_sont_inchangees():
    c = cfg()
    assert "bloque" not in c["profils"]["defaut"] and "bloque" not in c["appareils"][MAC]       # rien d'écrit : retour arrière sûr
    assert profils.cle_vue({"modes": {"adulte": "block"}, "autorise": []}) == profils.cle_vue({"modes": {"adulte": "block"}, "autorise": [], "bloque": []})
    assert profils.cle_vue({"modes": {"adulte": "observe"}, "autorise": [], "bloque": ["x.exemple.test"]}) != "wf-libre"


def test_la_cle_de_vue_distingue_deux_appareils_aux_domaines_forces_differents():
    a = profils.cle_vue({"modes": {}, "autorise": [], "bloque": ["a.exemple.test"]})
    b = profils.cle_vue({"modes": {}, "autorise": [], "bloque": ["b.exemple.test"]})
    assert a != b and a.startswith("wf-") and b.startswith("wf-")
