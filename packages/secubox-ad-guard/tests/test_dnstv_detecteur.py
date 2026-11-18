# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#1959 : détection « TV/streamer probable » par comportement DNS (compteurs par jour, regroupés par MAC)."""
import time

from api import dnstv, dnstv_detecteur as D

SERVICES = dnstv.ClasseurServices([("fwmrm.net", "FreeWheel", "publicite"), ("ftven.fr", "France Télévisions", "contenu"),
                                   ("youboranqs01.com", "NPAW", "qualite_video"), ("example.org", "Exemple", "contenu")])
MAC = "38:07:16:94:fb:5b"
V6 = "2a01:e0a:dec:c4e0:4951:bf00:df87:2c57"
VOISINS = {"192.168.1.128": MAC, V6: MAC, "192.168.1.88": "aa:bb:cc:dd:ee:ff"}
TV = {"7cd77.v.fwmrm.net": 12, "cloudreplay.ftven.fr": 30, "infinity.youboranqs01.com": 8}


def detect(compteurs, exclus=frozenset(), **kw):
    return D.detecter(compteurs, VOISINS, SERVICES, ("fwmrm.net",), set(exclus), **kw)


def test_tv_detectee_avec_sa_preuve():
    d = detect({V6: TV})
    assert len(d) == 1 and d[0].mac == MAC and d[0].adresses == [V6]
    assert "fwmrm.net" in d[0].preuve and "France Télévisions" in d[0].preuve and 0 < d[0].score <= 100


def test_les_deux_adresses_d_un_meme_appareil_se_cumulent():
    moitie = {"7cd77.v.fwmrm.net": 3, "cloudreplay.ftven.fr": 10, "infinity.youboranqs01.com": 4}
    d = detect({"192.168.1.128": moitie, V6: moitie})
    assert len(d) == 1 and sorted(d[0].adresses) == sorted(["192.168.1.128", V6])            # 6 requêtes d'insertion cumulées ≥ 5


def test_un_pic_isole_ne_suffit_pas():
    assert detect({"192.168.1.128": {"7cd77.v.fwmrm.net": 1, "cloudreplay.ftven.fr": 2, "infinity.youboranqs01.com": 1}}) == []


def test_sans_insertion_publicitaire_ou_avec_un_seul_service_pas_de_detection():
    assert detect({"192.168.1.128": {"cloudreplay.ftven.fr": 90, "infinity.youboranqs01.com": 40}}) == []
    assert detect({"192.168.1.128": {"7cd77.v.fwmrm.net": 20, "cloudreplay.ftven.fr": 90}}) == []


def test_adresse_sans_mac_jamais_detectee():
    assert detect({"192.168.1.77": TV}) == []


def test_exclusions_box_et_passerelle():
    assert detect({"192.168.1.128": TV}, exclus={"192.168.1.128"}) == []


def test_noms_hostiles_ne_sont_ni_comptes_ni_recopies():
    c = dict(TV)
    c['x"; reboot.example.org'] = 99
    c["AUTRE.Example.org"] = 99
    d = detect({"192.168.1.128": c})
    assert len(d) == 1 and "reboot" not in d[0].preuve and "Exemple" not in d[0].preuve


def test_deux_appareils_distincts_restent_distincts():
    autre = {"7cd77.v.fwmrm.net": 9, "cloudreplay.ftven.fr": 4, "x.example.org": 3}
    d = detect({V6: TV, "192.168.1.88": autre})
    assert {x.mac for x in d} == {MAC, "aa:bb:cc:dd:ee:ff"}


def test_seuils_configurables():
    assert detect({"192.168.1.128": TV}, min_declencheurs=50) == []
    assert len(detect({"192.168.1.128": TV}, min_services=2, min_declencheurs=5)) == 1


def test_compteurs_clients_toutes_decisions(tmp_path):
    m = dnstv.Magasin(tmp_path / "m.db")
    t = int(time.time())
    m.ajouter([(dnstv.Evenement(t, "192.168.1.128", "k7.ftven.fr", "A", "NOERROR", "ALLOWED"), ""),
               (dnstv.Evenement(t, "192.168.1.128", "k7.ftven.fr", "A", "NXDOMAIN", "BLOCKED"), ""),
               (dnstv.Evenement(t - 5 * 86400, "192.168.1.128", "vieux.example.org", "A", "NOERROR", "ALLOWED"), "")])
    c = m.compteurs_clients(dnstv._jour(t - 86400))
    assert c == {"192.168.1.128": {"k7.ftven.fr": 2}}                           # tous les types de décision, et pas les jours trop anciens


# ── #3771 : seconde voie, le service du système d'une TV connectée ──────────────────────────────────────────────────────────
PLAT = D.PLATEFORMES_TV


def test_freebox_player_en_direct_detecte_sans_freewheel():
    # relevé gk7 du 17/11 : Freebox Pop sur le direct france.tv, trois adresses IPv6 d'une même MAC, aucune requête FreeWheel
    vois = dict(VOISINS, **{"2a01::a": MAC, "2a01::b": MAC})
    c = {"2a01::a": {"androidtvchannels-pa.googleapis.com": 2, "telemetry-prod.svc.freebox.itc.proxad.net": 2, "api.oqee.net": 2},
         "2a01::b": {"telemetry-prod.svc.freebox.itc.proxad.net": 2, "androidtv.prod.cloud.netflix.com": 1}}
    d = D.detecter(c, vois, SERVICES, ("fwmrm.net",), set(), plateformes=PLAT)
    assert len(d) == 1 and d[0].mac == MAC and sorted(d[0].adresses) == ["2a01::a", "2a01::b"]
    assert d[0].preuve.startswith("système TV : 7 requêtes") and "androidtvchannels-pa" in d[0].preuve     # preuve bornée à 120 caractères


def test_tv_lg_et_samsung_detectees():
    for dom in ("snu.lgtvsdp.com", "log-config.samsungacr.com"):
        assert len(detect({V6: {dom: 3}}, plateformes=PLAT)) == 1


def test_sous_le_seuil_ou_voie_desactivee_rien():
    assert detect({V6: {"androidtvchannels-pa.googleapis.com": 2}}, plateformes=PLAT) == []
    assert detect({V6: {"androidtvchannels-pa.googleapis.com": 50}}) == []                         # plateformes vide = voie fermée


def test_telephone_android_pas_detecte():
    # un téléphone Android interroge Google, YouTube, Netflix mobile, jamais l'accueil Android TV
    tel = {"android.googleapis.com": 40, "youtubei.googleapis.com": 30, "android.prod.cloud.netflix.com": 10, "googleads.g.doubleclick.net": 9}
    assert detect({V6: tel}, plateformes=PLAT) == []


def test_un_nom_qui_imite_la_plateforme_ne_compte_pas():
    assert detect({V6: {"androidtvchannels-pa.googleapis.com.evil.example": 9, "xlgtvsdp.com": 9}}, plateformes=PLAT) == []


def test_reglage_toml_plateformes(tmp_path):
    from api import dnstv_auto
    t = tmp_path / "a.toml"
    t.write_text('[adblock_tv_auto]\nplateformes_tv = []\nmin_plateforme = 5\n')
    r = dnstv_auto.reglage_depuis({}, t)
    assert r.plateformes_tv == () and r.min_plateforme == 5
    assert dnstv_auto.reglage_depuis({}, tmp_path / "absent.toml").plateformes_tv == PLAT
