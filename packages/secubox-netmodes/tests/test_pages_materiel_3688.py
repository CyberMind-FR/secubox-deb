# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3688 — panneau Réseau selon le matériel réel, dans un vrai navigateur, API simulée :

- MOCHAbin : six onglets, bandeau du mode routeur, schéma WAN/switch/ports ; le schéma est IDENTIQUE à celui d'une API
  d'avant #3688 (sans champ `materiel`) : rien ne change ;
- Raspberry Pi (eth0 + wlan0 + wg-mesh) : onglets Cartographie, Liens du maillage, Modes (hérité) seulement, ni passerelle
  WAN, ni voisins WAN, ni switch, ni « source en panne » ; interfaces réelles avec état, adresse et route par défaut ;
- mode routeur actif sur une carte sans switch, ou matériel illisible : vue complète, rien n'est masqué ;
- 1400 px et 420 px sans débordement horizontal, aucune erreur JS."""
import copy
import re
from pathlib import Path

import pytest

from test_pages_reseau_3190 import P2P, SUM, WG, _avec_navigateur, _cadre, _page, _sans_debordement  # noqa: F401

WWW = Path(__file__).resolve().parents[1] / "www" / "netmodes"

MAT_MOCHABIN = {"modele": "Globalscale Marvell ARMADA 7040 MOCHAbin board", "switch_dsa": True, "wan_dedie": True, "pont_lan": True,
                "vue_routeur": True, "pannes": [],
                "interfaces": [{"nom": n, "genre": g, "etat": "up", "porteuse": True, "vitesse_mbps": 1000, "adresses": [], "passerelle": None}
                               for n, g in (("eth0", "filaire"), ("eth1", "conduit_switch"), ("eth2", "filaire"), ("lan0", "port_switch"))]}
MAT_RPI = {"modele": "Raspberry Pi 4 Model B Rev 1.1", "switch_dsa": False, "wan_dedie": False, "pont_lan": False, "vue_routeur": False,
           "pannes": [],
           "interfaces": [{"nom": "eth0", "genre": "filaire", "etat": "up", "porteuse": True, "vitesse_mbps": 1000,
                           "adresses": ["192.0.2.128/24", "2001:db8::dea6:32ff:fe64:f596/64"], "passerelle": "192.0.2.254"},
                          {"nom": "wlan0", "genre": "wifi", "etat": "down", "porteuse": None, "vitesse_mbps": None, "adresses": [], "passerelle": None}]}
CARTE_MOCHABIN = {"wan": {"interface": "eth2", "adresse": "192.0.2.200/24", "passerelle": "192.0.2.254",
                          "voisins": [{"ip": "192.0.2.94", "mac": "00:00:5e:00:53:94"}]},
                  "lxc": {"pont": "br-lxc", "actifs": 7}, "tunnels": [{"nom": "wg-mesh", "etat": "up"}, {"nom": "wg-toolbox", "etat": "up"}]}
PORTS_MOCHABIN = [{"nom": "eth2", "role": "wan", "porteuse": True, "vitesse_mbps": 1000, "etat_admin": "up", "maitre": None, "macs": [],
                   "plusieurs_appareils": False, "coupe": False, "isole": None, "reseau_isole": None},
                  {"nom": "eth1", "role": "conduit", "porteuse": True, "vitesse_mbps": 2500, "etat_admin": "up", "maitre": None, "macs": [],
                   "plusieurs_appareils": False, "coupe": False, "isole": None, "reseau_isole": None}] + [
    {"nom": f"lan{i}", "role": "lan", "porteuse": i == 0, "vitesse_mbps": 1000 if i == 0 else None, "etat_admin": "up", "maitre": "br-lan",
     "macs": ["00:00:5e:00:53:c0"] if i == 0 else [], "plusieurs_appareils": False, "coupe": False, "isole": False, "reseau_isole": None}
    for i in range(4)]
ROUTEUR_INACTIF = {"etat": "inactif", "depuis": None, "config": None, "minuteur_actif": False, "echeance": None, "bascule_en_cours": False,
                   "dhcp_actif": True, "adresses_pont": ["198.51.100.1/24"], "ports_coupes": []}
COMMUN = {"p2p/peers": (200, P2P), "wireguard/peers/status": (200, WG), "wireguard/summary": (200, SUM)}


def api_mochabin(materiel=True):
    carte = {"carte": CARTE_MOCHABIN, "pannes": []}
    if materiel:
        carte.update(sans_objet=[], materiel=MAT_MOCHABIN)
    a = {"netmodes/reseau/carte": (200, carte),
         "netmodes/reseau/ports": (200, {"ports": PORTS_MOCHABIN, "pannes": []}),
         "netmodes/reseau/clients": (200, {"clients": [{"mac": "00:00:5e:00:53:c0", "ip": "198.51.100.192", "nom": "pc-demo", "port": "lan0",
                                                        "source": "bail", "expire": None}], "pannes": []}),
         "netmodes/routeur/etat": (200, ROUTEUR_INACTIF), **COMMUN}
    if materiel:
        a["netmodes/reseau/materiel"] = (200, {"materiel": MAT_MOCHABIN})
    return a


def api_rpi(routeur=None, materiel=MAT_RPI):
    """Réponses d'un Raspberry Pi : WAN eth2 et br-lan sans objet, baux non lus, mode routeur inactif sans adresse."""
    carte = {"carte": {"wan": None, "lxc": {"pont": "br-lxc", "actifs": 0}, "tunnels": [{"nom": "wg-mesh", "etat": "up"}]},
             "pannes": [], "sans_objet": ["wan_addr", "voisins_wan"]}
    if materiel is not None:
        carte["materiel"] = materiel
    a = {"netmodes/reseau/carte": (200, carte),
         "netmodes/reseau/ports": (200, {"ports": [], "pannes": [], "sans_objet": ["fdb"]}),
         "netmodes/reseau/clients": (200, {"clients": None, "pannes": [], "sans_objet": ["fdb", "voisins_lan", "baux"]}),
         "netmodes/routeur/etat": (200, routeur or dict(ROUTEUR_INACTIF, dhcp_actif=False, adresses_pont=[])),
         "p2p/peers": (200, P2P), "wireguard/peers/status": (200, WG),
         "wireguard/summary": (200, {"interfaces": [SUM["interfaces"][0]], "totals": {}})}
    a["netmodes/reseau/materiel"] = (200, {"materiel": materiel}) if materiel is not None else (503, {"detail": "absent"})
    return a


def _hote(nav, api, taille=(1400, 900), ancre=""):
    ctx, pg, j = _page(nav, api, taille)
    pg.goto("http://t.test/netmodes/" + ancre)
    pg.wait_for_function("document.getElementById('pastilleRouteur').textContent !== 'LECTURE…'", timeout=8000)
    pg.wait_for_timeout(300)
    cadre = _cadre(pg)
    cadre.wait_for_function("document.getElementById('etatSources').textContent !== 'LECTURE…'", timeout=8000)
    r = {"onglets": pg.evaluate("[...document.querySelectorAll('.onglet')].filter(o => !o.hidden && o.offsetParent).map(o => o.dataset.onglet)"),
         "choisi": pg.evaluate("document.querySelector('[aria-selected=true]').dataset.onglet"),
         "src": pg.get_attribute("#vue", "src"), "bandeau": pg.is_visible("#bandeauLan"),
         "pastille": pg.inner_text("#pastilleRouteur"), "sous": pg.inner_text("#sousTitre"),
         "schema": cadre.evaluate("document.getElementById('schema').textContent"),
         "sources": cadre.evaluate("[...document.querySelectorAll('.src')].map(e => e.textContent)"),
         "etat": cadre.inner_text("#etatSources"), "legendeSR": cadre.is_visible("#legendeSR"),
         "deb": (_sans_debordement(pg), _sans_debordement(cadre))}
    return ctx, pg, j, r


def test_mochabin_rien_ne_change_six_onglets_et_schema_identique_a_l_ancienne_api():
    def scenario(nav):
        sortie = {}
        for nom, api in (("avec", api_mochabin()), ("avant", api_mochabin(materiel=False))):
            ctx, pg, j, r = _hote(nav, api)
            sortie[nom] = (r, j)
            ctx.close()
        return sortie
    s = _avec_navigateur(scenario)
    (r, j), (avant, j2) = s["avec"], s["avant"]
    assert r["onglets"] == ["carte", "switch", "clients", "maillage", "routeur", "modes"] and r["choisi"] == "carte"
    assert r["bandeau"] and r["pastille"] == "LAN TEMPORAIRE" and r["sous"] == "cartographie, switch, clients, maillage et mode routeur"
    for t in ("Passerelle", "Réseau WAN", "WAN eth2", "Switch DSA", "lan0", "Hubs et switchs détectés", "wg-mesh", "br-lxc"):
        assert t in r["schema"], t
    assert len(r["sources"]) == 7 and r["etat"] == "TOUTES LES SOURCES LUES" and not r["legendeSR"]
    # Rien ne change : même schéma, mêmes onglets, mêmes sources qu'avec la réponse d'avant #3688.
    for k in ("onglets", "schema", "sources", "etat", "bandeau", "pastille"):
        assert r[k] == avant[k], k
    assert r["deb"] == (True, True) and j["erreurs"] == j2["erreurs"] == [] and j["natifs"] == []
    assert ("GET", "api/v1/netmodes/reseau/materiel") in j["appels"] and all(m == "GET" for m, _ in j["appels"])


def test_raspberry_pi_vue_sans_routeur_materiel_reel_seulement():
    def scenario(nav):
        ctx, pg, j, r = _hote(nav, api_rpi(), ancre="#routeur")        # lien direct vers un onglet masqué : retour à la carte
        pg.focus("#onglet-carte")
        pg.keyboard.press("ArrowRight")
        r["fleche"] = pg.evaluate("document.querySelector('[aria-selected=true]').dataset.onglet")
        pg.keyboard.press("ArrowLeft")
        pg.keyboard.press("ArrowLeft")
        r["fleche2"] = pg.evaluate("document.querySelector('[aria-selected=true]').dataset.onglet")
        ctx.close()
        return r, j
    r, j = _avec_navigateur(scenario)
    assert r["onglets"] == ["carte", "maillage", "modes"] and r["choisi"] == "carte" and r["src"] == "carte.html?embed=1"
    assert not r["bandeau"] and r["pastille"] == "SANS SWITCH NI WAN DÉDIÉ"
    assert r["fleche"] == "maillage" and r["fleche2"] == "modes"                 # les flèches sautent les onglets masqués
    sch = r["schema"]
    for t in ("eth0", "Ethernet", "lien actif", "192.0.2.128/24", "route par défaut · passerelle 192.0.2.254", "wlan0", "wifi",
              "descendue", "aucune adresse", "Raspberry Pi 4 Model B Rev 1.1", "br-lxc", "wg-mesh", "5 pairs"):
        assert t in sch, t
    for t in ("Passerelle", "Voisins WAN", "Réseau WAN", "WAN eth2", "Switch DSA", "br-lan", "Hubs", "source en panne", "SFP"):
        assert t not in sch, t
    assert not re.search(r"(?<!w)lan[0-3]", sch)                                 # aucun port du switch (wlan0 est le wifi)
    assert r["sources"] == ["Carte réseau · lue", "Pairs p2p · lue", "WireGuard · pairs · lue", "WireGuard · tunnels · lue"]
    assert r["etat"] == "TOUTES LES SOURCES LUES" and r["legendeSR"] and r["deb"] == (True, True)
    assert j["erreurs"] == [] and j["natifs"] == [] and all(m == "GET" for m, _ in j["appels"])


@pytest.mark.parametrize("cas", ["routeur_actif", "routeur_a_confirmer", "materiel_illisible"])
def test_carte_sans_switch_ne_masque_rien_si_le_routeur_est_actif_ou_le_materiel_illisible(cas):
    routeur = {"routeur_actif": dict(ROUTEUR_INACTIF, etat="actif"),
               "routeur_a_confirmer": dict(ROUTEUR_INACTIF, etat="en_attente", echeance="2099-01-01T00:00:00Z")}.get(cas)
    api = api_rpi(routeur=routeur, materiel=None if cas == "materiel_illisible" else MAT_RPI)

    def scenario(nav):
        ctx, pg, j, r = _hote(nav, api)
        ctx.close()
        return r, j
    r, j = _avec_navigateur(scenario)
    assert r["onglets"] == ["carte", "switch", "clients", "maillage", "routeur", "modes"]
    assert "Switch DSA" in r["schema"] and len(r["sources"]) == 7 and not r["legendeSR"]
    assert r["pastille"] != "SANS SWITCH NI WAN DÉDIÉ" and j["erreurs"] == []


def test_materiel_en_panne_partielle_annoncee_sur_la_carte():
    mat = copy.deepcopy(MAT_RPI)
    mat["pannes"] = ["adresses"]
    for i in mat["interfaces"]:
        i["adresses"] = None

    def scenario(nav):
        ctx, pg, j, r = _hote(nav, api_rpi(materiel=mat))
        ctx.close()
        return r, j
    r, j = _avec_navigateur(scenario)
    assert "adresses : source en panne" in r["schema"] and r["etat"] == "LECTURE PARTIELLE"
    assert r["sources"][0] == "Carte réseau · partielle" and j["erreurs"] == []


@pytest.mark.parametrize("page", ["", "carte.html"])
def test_raspberry_pi_420_px_sans_defilement_horizontal(page):
    def scenario(nav):
        ctx, pg, j = _page(nav, api_rpi(), taille=(420, 900))
        pg.goto("http://t.test/netmodes/" + page)
        pg.wait_for_timeout(1200)
        cadre = _cadre(pg) if not page else pg
        r = (_sans_debordement(pg), _sans_debordement(cadre), cadre.evaluate("document.getElementById('schema').classList.contains('etroit')"),
             cadre.evaluate("document.getElementById('schema').textContent"))
        ctx.close()
        return r, j
    (page_ok, cadre_ok, etroit, schema), j = _avec_navigateur(scenario)
    assert page_ok and cadre_ok and etroit and "eth0" in schema and "Switch DSA" not in schema and j["erreurs"] == []


def test_pages_statiques_materiel_par_l_api_jamais_un_nom_de_carte():
    for f in ("index.html", "carte.html"):
        s = (WWW / f).read_text(encoding="utf-8")
        code = "".join(re.findall(r"<script>(.*?)</script>", s, flags=re.S))       # le script, seul juge de la vue
        assert "vue_routeur !== false" in code and "'actif', 'en_attente', 'config_invalide'" in code.replace('"', "'")
        for nom in ("Raspberry", "MOCHAbin", "ESPRESSObin", "gk7", "userAgent", "device-tree"):
            assert nom not in code, (f, nom)
    assert "/reseau/materiel" in (WWW / "index.html").read_text(encoding="utf-8")
