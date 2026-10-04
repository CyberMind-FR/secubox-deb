# SPDX-License-Identifier: LicenseRef-CMSD-1.0
import pytest

from webfilter import generation, profils

CATS = {"adulte", "jeux", "phishing"}
LISTES = {"adulte": ["porn.example.com"], "jeux": ["bet.example.org", "casino.example.net"], "phishing": ["evil.example.io"]}
VOISINS = {"aa:bb:cc:dd:ee:01": ["192.168.1.50", "2a01:db8::50"], "aa:bb:cc:dd:ee:02": ["192.168.1.51"], "aa:bb:cc:dd:ee:03": ["192.168.1.52"]}


def cfg_enfants():
    return profils.valider({"version": 3, "profils": {
        "defaut": {"categories": {"adulte": "observe", "jeux": "observe", "phishing": "observe"}, "autorise": []},
        "enfants": {"categories": {"adulte": "block", "jeux": "block", "phishing": "block"}, "autorise": ["bet.example.org"]}},
        "appareils": {"aa:bb:cc:dd:ee:01": {"nom": "T1", "profil": "enfants", "exceptions": {}},
                      "aa:bb:cc:dd:ee:02": {"nom": "T2", "profil": "enfants", "exceptions": {}},
                      "aa:bb:cc:dd:ee:03": {"nom": "Tel", "profil": "defaut", "exceptions": {"phishing": "block"}}}}, CATS)


def gen(**k):
    args = dict(cfg=cfg_enfants(), reseaux=["192.168.1.0/24", "2a01:db8::/64"], voisins=VOISINS, adguard=set(), charger=lambda c: LISTES[c], zones_max=1000)
    args.update(k)
    return generation.generer(**args)


def vue(texte, nom):
    """Le bloc `view:` de la vue `nom`."""
    for bloc in texte.split("view:\n")[1:]:
        if f'name: "{nom}"' in bloc:
            return bloc
    raise AssertionError(f"vue {nom} absente")


def cle(mac):
    return profils.cle_vue(profils.effective(cfg_enfants(), mac))


def test_une_vue_par_configuration_effective_et_partage():
    t = gen().texte
    assert t.count('name: "wf-') == 3                                    # wf-defaut, la vue des enfants (partagée), la vue de Tel
    assert t.count("access-control-view: 192.168.1.0/24 wf-defaut") == 1 and t.count("access-control-view: 2a01:db8::/64 wf-defaut") == 1
    ve, vt = cle("aa:bb:cc:dd:ee:01"), cle("aa:bb:cc:dd:ee:03")
    assert ve == cle("aa:bb:cc:dd:ee:02") and ve != vt
    for ligne in (f"192.168.1.50/32 {ve}", f"2a01:db8::50/128 {ve}", f"192.168.1.51/32 {ve}", f"192.168.1.52/32 {vt}"):
        assert f"access-control-view: {ligne}" in t


def test_zones_bloquees_et_autorisations_en_transparent():
    v = vue(gen().texte, cle("aa:bb:cc:dd:ee:01"))
    assert 'local-zone: "porn.example.com." always_nxdomain' in v and 'local-zone: "casino.example.net." always_nxdomain' in v
    assert 'local-zone: "evil.example.io." always_nxdomain' in v
    assert 'local-zone: "bet.example.org." transparent' in v              # l'autorisation REMPLACE l'entrée listée du même nom
    assert 'local-zone: "bet.example.org." always_nxdomain' not in v


def test_vue_defaut_vide_si_rien_n_est_bloque():
    v = vue(gen().texte, "wf-defaut")
    assert "local-zone:" not in v and "view-first: yes" in v


def test_un_appareil_de_configuration_defaut_reutilise_wf_defaut():
    c = cfg_enfants()
    c["appareils"]["aa:bb:cc:dd:ee:03"]["exceptions"] = {}
    c["appareils"]["aa:bb:cc:dd:ee:03"]["profil"] = "defaut"
    r = gen(cfg=c)
    assert "access-control-view: 192.168.1.52/32 wf-defaut" in r.texte and r.texte.count('name: "wf-') == 2


def test_exclusion_des_adresses_d_adguard_et_signalement():
    r = gen(adguard={"192.168.1.50", "2a01:db8::50"})
    assert "192.168.1.50/32" not in r.texte and "2a01:db8::50/128" not in r.texte
    assert r.exclus["aa:bb:cc:dd:ee:01"] == "geree par ad-guard"          # toutes ses adresses sont à ad-guard
    r2 = gen(adguard={"192.168.1.50"})
    assert "2a01:db8::50/128" in r2.texte and "aa:bb:cc:dd:ee:01" not in r2.exclus   # une adresse libre : l'appareil reste filtré


def test_adresses_de_la_box_jamais_liees():
    r = gen(adresses_box=frozenset({"192.168.1.51"}))
    assert "192.168.1.51/32" not in r.texte and r.exclus["aa:bb:cc:dd:ee:02"] == "adresse de la box"


def test_appareil_sans_adresse_connue_n_a_pas_d_entree():
    r = gen(voisins={})
    assert "/32 wf-" not in r.texte and "/128 wf-" not in r.texte and r.exclus["aa:bb:cc:dd:ee:01"] == "adresse inconnue"
    assert r.texte.count('name: "wf-') == 1                                # aucune vue inutile : seule wf-defaut


def test_adresse_en_double_liee_une_seule_fois():
    r = gen(voisins={"aa:bb:cc:dd:ee:01": ["192.168.1.50"], "aa:bb:cc:dd:ee:02": ["192.168.1.50"]})
    assert r.texte.count("192.168.1.50/32") == 1


def test_budget_de_zones():
    with pytest.raises(generation.ErreurGeneration) as e:
        gen(zones_max=2)
    assert "budget" in str(e.value)
    assert gen(zones_max=1000).zones > 0


def test_comptes_du_resultat():
    r = gen()
    assert r.vues["wf-defaut"] == 0 and r.vues[cle("aa:bb:cc:dd:ee:01")] == 4 and r.entrees == 6 and r.zones == sum(r.vues.values())


def test_texte_deterministe():
    assert gen().texte == gen().texte
    assert gen(voisins=dict(reversed(list(VOISINS.items())))).texte == gen().texte


def test_en_tete_et_marque():
    t = gen().texte
    assert t.startswith("# SPDX-License-Identifier: LicenseRef-CMSD-1.0\n# GÉNÉRÉ par secubox-webfilter-ctl")


@pytest.mark.parametrize("liste", [['evil.com"; local-zone: "." always_nxdomain'], ["Majuscule.example.com"], ["nodot"], ["a b.example.com"], ["x.example.com\nserver:"]])
def test_valeur_hostile_dans_une_liste_n_atteint_jamais_le_texte(liste):
    with pytest.raises(generation.ErreurGeneration):
        gen(charger=lambda c: liste)


@pytest.mark.parametrize("reseaux", [["192.168.1.0/24\nserver:"], ["pas-un-reseau"], ["192.168.1.0/24%eth0"], ["fe80::/64%x"], [42]])
def test_reseau_hostile_refuse(reseaux):
    with pytest.raises(generation.ErreurGeneration):
        gen(reseaux=reseaux)


def test_adresses_adguard_lues_dans_son_dropin():
    t = ("server:\n    access-control-view: 192.168.1.95/32 sbx-tv-auto-tv-banc\n    access-control-view: 2a01:e0a:dec:c4e0:c147::3429/128 sbx-tv-auto-tv-banc\n"
         "    local-zone-override: x. 1.2.3.4/32 transparent\n    access-control-view: 10.0.0.0/8 reseau\n    access-control-view: pas-une-ip/32 x\n")
    assert generation.adresses_adguard(t) == {"192.168.1.95", "2a01:e0a:dec:c4e0:c147::3429"}
