# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""IPv6 Guardian — collecte PASSIVE : voisins et annonces mDNS, regroupés en appareils lisibles. Échantillons réels de gk2."""
from api import collecte as c

NEIGH6 = """\
2a01:e0a:dec:c4e0:21f1:8a9b:306e:a328 dev eth2 lladdr fa:c5:c2:ac:b6:1a STALE
fe80::9c84:10ff:fe78:9d2f dev br-lxc lladdr 9e:84:10:78:9d:2f STALE
fe80::c1f:9d12:9d62:92c4 dev eth2 lladdr fa:c5:c2:ac:b6:1a STALE
2a01:e0a:dec:c4e0:c1da:bcb7:7071:c880 dev eth2 lladdr 78:7b:8a:58:e8:9b REACHABLE
fd0f:ee:b0:0:3a07:16ff:feb7:6b52 dev eth2 lladdr 38:07:16:b7:6b:52 DELAY
fe80::3a07:16ff:fe77:17d3 dev eth2 lladdr 38:07:16:77:17:d3 router STALE
2a01:e0a:dec:c4e0:dead:beef:0:1 dev eth2  FAILED
fc42:5009:ba4b:5ab0::10 dev lxcbr0 lladdr 00:16:3e:aa:bb:cc REACHABLE
"""
NEIGH4 = """\
192.168.1.95 dev eth2 lladdr fa:c5:c2:ac:b6:1a REACHABLE
192.168.1.20 dev eth2 lladdr 78:7b:8a:58:e8:9b STALE
192.168.1.254 dev eth2 lladdr 38:07:16:77:17:d3 REACHABLE
"""
AVAHI = r"""=;eth2;IPv6;lab34;Device Info;local;Android.local;192.168.1.95;123;"model=fbx8am"
=;eth2;IPv6;Salon\032TV;_airplay._tcp;local;Salon-TV.local;2a01:e0a:dec:c4e0:c1da:bcb7:7071:c880;7000;"model=AppleTV"
=;eth2;IPv4;Salon\032TV;_airplay._tcp;local;Salon-TV.local;192.168.1.20;7000;"model=AppleTV"
=;eth2;IPv6;Imprimante\032bureau;_ipp._tcp;local;HP-LaserJet.local;2a01:e0a:dec:c4e0:21f1:8a9b:306e:a328;631;"ty=HP LaserJet"
=;eth2;IPv6;NAS;_ssh._tcp;local;nas.local;2a01:e0a:dec:c4e0:21f1:8a9b:306e:a328;22;
=;eth2;IPv6;NAS;_smb._tcp;local;nas.local;2a01:e0a:dec:c4e0:21f1:8a9b:306e:a328;445;
=;eth2;IPv6;ligne bizarre sans port
+;eth2;IPv6;pas une resolution;_http._tcp;local
"""


# ── types d'adresses ─────────────────────────────────────────────────────────
def test_les_types_d_adresses_ipv6_sont_distingues():
    assert c.type_adresse("2a01:e0a:dec:c4e0::200") == "publique"       # joignable depuis Internet si le pare-feu le permet
    assert c.type_adresse("fd0f:ee:b0:0:3a07:16ff:feb7:6b52") == "privee"
    assert c.type_adresse("fc42:5009:ba4b:5ab0::1") == "privee"
    assert c.type_adresse("fe80::1") == "locale"
    assert c.type_adresse("::1") == "autre" and c.type_adresse("pas-une-adresse") == "autre"


# ── voisins ──────────────────────────────────────────────────────────────────
def test_les_voisins_sans_adresse_mac_sont_ecartes():
    v = c.parse_voisins(NEIGH6)
    assert all(x["mac"] for x in v)
    assert not any(x["adresse"].endswith(":0:1") for x in v)                # l'entrée FAILED


def test_un_voisin_porte_adresse_interface_mac_et_etat():
    v = {x["adresse"]: x for x in c.parse_voisins(NEIGH6)}
    a = v["2a01:e0a:dec:c4e0:c1da:bcb7:7071:c880"]
    assert a == {"adresse": "2a01:e0a:dec:c4e0:c1da:bcb7:7071:c880", "interface": "eth2", "mac": "78:7b:8a:58:e8:9b",
                 "etat": "REACHABLE", "routeur": False}
    assert v["fe80::3a07:16ff:fe77:17d3"]["routeur"] is True


def test_regroupement_par_mac_un_appareil_plusieurs_adresses():
    appareils = c.regrouper(c.parse_voisins(NEIGH6), c.parse_voisins(NEIGH4))
    par_mac = {a["mac"]: a for a in appareils}
    tel = par_mac["fa:c5:c2:ac:b6:1a"]
    assert tel["adresses_publiques"] == ["2a01:e0a:dec:c4e0:21f1:8a9b:306e:a328"]
    assert tel["adresses_locales"] == ["fe80::c1f:9d12:9d62:92c4"]
    assert tel["ipv4"] == ["192.168.1.95"]
    assert len(appareils) == len({a["mac"] for a in appareils})


def test_les_interfaces_internes_des_conteneurs_ne_comptent_pas_comme_reseau_local():
    appareils = c.regrouper(c.parse_voisins(NEIGH6), c.parse_voisins(NEIGH4), interfaces_lan={"eth2"})
    assert all(a["interface"] == "eth2" for a in appareils)


def test_la_box_voit_la_passerelle_comme_routeur():
    appareils = c.regrouper(c.parse_voisins(NEIGH6), c.parse_voisins(NEIGH4), interfaces_lan={"eth2"})
    passerelle = next(a for a in appareils if a["mac"] == "38:07:16:77:17:d3")
    assert passerelle["routeur"] is True


def test_un_appareil_joignable_est_celui_qui_a_une_adresse_publique():
    appareils = c.regrouper(c.parse_voisins(NEIGH6), c.parse_voisins(NEIGH4), interfaces_lan={"eth2"})
    pub = {a["mac"] for a in appareils if a["adresses_publiques"]}
    assert pub == {"fa:c5:c2:ac:b6:1a", "78:7b:8a:58:e8:9b"}


# ── mDNS ─────────────────────────────────────────────────────────────────────
def test_analyse_mdns_ne_garde_que_les_resolutions_valides():
    m = c.parse_mdns(AVAHI)
    assert len(m) == 6                                                      # 6 lignes « = » exploitables (la 7e n'a pas de port)
    airplay = next(x for x in m if x["type"] == "_airplay._tcp" and x["proto"] == "IPv6")
    assert airplay["port"] == 7000 and airplay["hote"] == "Salon-TV.local"
    assert airplay["nom"] == "Salon TV"                                    # \032 = espace


def test_un_texte_mdns_inattendu_ne_plante_pas():
    assert c.parse_mdns("") == [] and c.parse_mdns("n'importe quoi\n=;;;;") == []


def test_les_services_sont_nommes_en_langage_courant():
    assert c.libelle_service("_ipp._tcp")["libelle"] == "Imprimante"
    assert c.libelle_service("_airplay._tcp")["libelle"].startswith("AirPlay")
    assert c.libelle_service("_ssh._tcp")["sensible"] is True
    assert c.libelle_service("_smb._tcp")["sensible"] is True
    inconnu = c.libelle_service("_zzz._tcp")
    assert inconnu["libelle"] == "Service « zzz »" and inconnu["sensible"] is False


def test_les_annonces_techniques_ne_sont_pas_des_services():
    assert c.est_service("_ipp._tcp") and not c.est_service("_device-info._tcp") and not c.est_service("Device Info")
    assert not c.est_service("_workstation._tcp") and not c.est_service("_sleep-proxy._udp")


# ── rapprochement avec les appareils ─────────────────────────────────────────
def test_les_services_et_les_noms_sont_rattaches_aux_appareils_par_adresse():
    appareils = c.regrouper(c.parse_voisins(NEIGH6), c.parse_voisins(NEIGH4), interfaces_lan={"eth2"})
    enrichis = c.rattacher(appareils, c.parse_mdns(AVAHI))
    par_mac = {a["mac"]: a for a in enrichis}
    imprimante = par_mac["fa:c5:c2:ac:b6:1a"]
    types = {s["type"] for s in imprimante["services"]}
    assert types == {"_ipp._tcp", "_ssh._tcp", "_smb._tcp"}
    assert imprimante["nom"] in ("Android", "HP-LaserJet", "nas")      # un nom d appareil, jamais une adresse MAC
    tv = par_mac["78:7b:8a:58:e8:9b"]
    assert tv["nom"] and [s["type"] for s in tv["services"]] == ["_airplay._tcp"]     # IPv4 et IPv6 dédoublonnés


def test_un_appareil_sans_annonce_a_un_nom_lisible_et_stable():
    appareils = c.regrouper(c.parse_voisins(NEIGH6), c.parse_voisins(NEIGH4), interfaces_lan={"eth2"})
    r = c.rattacher(appareils, [])
    nom = next(a for a in r if a["mac"] == "78:7b:8a:58:e8:9b")["nom"]
    assert nom == "Appareil 58:e8:9b"
    assert next(a for a in r if a["mac"] == "78:7b:8a:58:e8:9b")["nom"] == nom


def test_aucune_adresse_mac_complete_n_est_utilisee_comme_nom():
    appareils = c.regrouper(c.parse_voisins(NEIGH6), c.parse_voisins(NEIGH4), interfaces_lan={"eth2"})
    for a in c.rattacher(appareils, []):
        assert a["mac"] not in a["nom"]


# ── noms d'usage et modèles (TXT mDNS) ───────────────────────────────────────
CAST = (r'=;eth2;IPv6;Freebox-Player-POP-29d0;_googlecast._tcp;local;29d0732c-b54f-566f-f341-916aa38461e0.local;'
        r'2a01:e0a:dec:c4e0:807f:8513:79d:bb;8009;"rs=" "fn=Pièce à vivre" "md=Freebox Player POP" "ve=05"' + "\n")
NEIGH6_CAST = "2a01:e0a:dec:c4e0:807f:8513:79d:bb dev eth2 lladdr 38:07:16:93:4e:95 REACHABLE\n"


def test_le_txt_mdns_est_lu_en_dictionnaire():
    m = c.parse_mdns(CAST)[0]
    assert m["txt"]["fn"] == "Pièce à vivre" and m["txt"]["md"] == "Freebox Player POP"


def test_le_nom_d_usage_passe_avant_un_nom_d_hote_illisible():
    appareils = c.regrouper(c.parse_voisins(NEIGH6_CAST), [], interfaces_lan={"eth2"})
    a = c.rattacher(appareils, c.parse_mdns(CAST))[0]
    assert a["nom"] == "Pièce à vivre" and a["modele"] == "Freebox Player POP"


def test_un_identifiant_uuid_n_est_jamais_un_nom():
    sans_fn = CAST.replace('"fn=Pièce à vivre" ', "")
    appareils = c.regrouper(c.parse_voisins(NEIGH6_CAST), [], interfaces_lan={"eth2"})
    a = c.rattacher(appareils, c.parse_mdns(sans_fn))[0]
    assert "29d0732c" not in a["nom"] and a["nom"].startswith("Appareil")
    assert c.est_identifiant("29d0732c-b54f-566f-f341-916aa38461e0") and not c.est_identifiant("Salon-TV")


def test_les_services_de_la_maison_ont_un_nom_clair():
    assert c.libelle_service("_androidtvremote2._tcp")["libelle"] == "Télécommande Android TV"
    assert c.libelle_service("_secubox._tcp")["libelle"] == "Boîte SecuBox"
    assert c.libelle_service("_fbx-api._tcp")["libelle"] == "Interface de la Freebox"
    assert not c.est_service("_googlezone._tcp")


def test_avahi_est_appele_sans_traduction_des_types():
    from api import service
    appels = []
    def faux(argv, delai=5):
        appels.append(list(argv))
        return ""
    g = service.Surveillance(faux, ttl_mdns=300)
    g._mesure_mdns()
    avahi = next(a for a in appels if a[0] == "avahi-browse")
    assert "-k" in avahi
