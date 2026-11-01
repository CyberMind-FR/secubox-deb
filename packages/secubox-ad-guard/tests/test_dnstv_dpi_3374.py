# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Lot 4 (#3374) : fonctions pures du DPI par appareil — rattachement MAC, repli publicitaire, SSAI, constats sans DNS / DNS chiffré /
contournement, couverture, lecture de conntrack et du fichier de sbxdpi."""
import json

import pytest

from api import dnstv_dpi as D
from api import dnstv_taxonomie as T

MAC_TV = "aa:bb:cc:00:00:01"
LISTES = __import__("pathlib").Path(__file__).resolve().parents[1] / "lists"
REF = T.charger_reference(LISTES / "reference-tv.txt")


TAXO = T.Taxonomie.depuis_dossier(LISTES)


def categorie_ref(d):
    return TAXO.classer(d)["categorie"]


# ── rattachement par MAC (IPv6 privacy) ─────────────────────────────────────────────────────────────────────
def test_une_tv_qui_change_d_adresse_ipv6_reste_un_seul_appareil():
    memoire = {}
    m1, memoire = D.rattacher(["2a01:e0a::1111"], {"2a01:e0a::1111": MAC_TV}, memoire, 1000)
    m2, memoire = D.rattacher(["2a01:e0a::2222"], {"2a01:e0a::2222": MAC_TV}, memoire, 2000)
    assert m1 == {"2a01:e0a::1111": MAC_TV} and m2 == {"2a01:e0a::2222": MAC_TV}
    # la première adresse a quitté la table de voisinage : la mémoire la rattache encore
    m3, memoire = D.rattacher(["2a01:e0a::1111"], {}, memoire, 3000)
    assert m3 == {"2a01:e0a::1111": MAC_TV}


def test_adresse_jamais_vue_n_est_jamais_attribuee_au_hasard_et_la_memoire_expire():
    m, memoire = D.rattacher(["192.168.1.77"], {}, {}, 1000)
    assert m == {"192.168.1.77": None}
    _, memoire = D.rattacher(["192.168.1.50"], {"192.168.1.50": MAC_TV}, {}, 1000)
    m, _ = D.rattacher(["192.168.1.50"], {}, memoire, 1000 + D.MEMOIRE_VOISINS_S + 1)
    assert m == {"192.168.1.50": None}


# ── repli publicitaire : cas réel gk2 du 2026-11-01 ─────────────────────────────────────────────────────────
def _evts_gk2(t0=10_000):
    e = [{"ts": t0 - 900, "domaine": "api.oqee.net", "decision": "ALLOWED"},
         {"ts": t0 - 5, "domaine": "replay-03.oqee.net", "decision": "ALLOWED"},
         {"ts": t0, "domaine": "pagead2.googlesyndication.com", "decision": "BLOCKED"},
         {"ts": t0 + 1, "domaine": "googleads.g.doubleclick.net", "decision": "BLOCKED"},
         {"ts": t0 + 3, "domaine": "metaproxy.francetvpub.fr", "decision": "ALLOWED"},
         {"ts": t0 + 4, "domaine": "audiences.free.fr", "decision": "ALLOWED"},
         {"ts": t0 + 6, "domaine": "stats.oqee.net", "decision": "ALLOWED"},
         {"ts": t0 + 7, "domaine": "imasdk.googleapis.com", "decision": "ALLOWED"},
         {"ts": t0 + 9, "domaine": "m.media-amazon.com", "decision": "ALLOWED"},
         {"ts": t0 + 12, "domaine": "firebase-settings.crashlytics.com", "decision": "ALLOWED"},
         {"ts": t0 + 14, "domaine": "license.oqee.net", "decision": "ALLOWED"},
         {"ts": t0 + 80, "domaine": "tardif.example.com", "decision": "ALLOWED"}]
    return e


def test_reference_classe_les_domaines_mesures_sur_gk2():
    assert categorie_ref("metaproxy.francetvpub.fr") == "PUBLICITE"
    assert categorie_ref("audiences.free.fr") == "TRACKING"
    assert categorie_ref("stats.oqee.net") == "TRACKING"
    assert categorie_ref("imasdk.googleapis.com") == "PUBLICITE"
    assert categorie_ref("m.media-amazon.com") == "CDN"


def test_correler_date_chaque_apparition_apres_le_refus():
    dec = {d["domaine"]: d for d in D.correler(_evts_gk2(), categorie_ref)}
    m = dec["metaproxy.francetvpub.fr"]
    assert m["type"] == "repli" and m["refus_domaine"] == "pagead2.googlesyndication.com" and m["delai_s"] == 3
    assert m["raison"] == "apparu 3 s après le blocage de pagead2.googlesyndication.com"
    assert "tardif.example.com" not in dec                       # hors fenêtre de 30 s
    assert "replay-03.oqee.net" not in dec and "api.oqee.net" not in dec   # déjà demandés avant la coupure
    assert "googleads.g.doubleclick.net" not in dec              # refusé lui-même : pas une apparition


def test_aucun_domaine_protege_ne_devient_repli_bloquable():
    dec = {d["domaine"]: d for d in D.correler(_evts_gk2(), categorie_ref)}
    assert dec["license.oqee.net"]["type"] == "repli-protege"          # DRM
    assert dec["m.media-amazon.com"]["type"] == "repli-protege"        # CDN
    assert all(d["type"] == "repli" for k, d in dec.items() if k in (
        "metaproxy.francetvpub.fr", "audiences.free.fr", "stats.oqee.net", "imasdk.googleapis.com"))
    assert not D.candidats_repli(list(dec.values()))  or all(
        c["categorie"] not in T.PROTEGEES for c in D.candidats_repli(list(dec.values())))


def test_confiance_monte_quand_le_meme_repli_revient_sur_deux_coupures():
    e = _evts_gk2(10_000)
    e += [{"ts": 20_000, "domaine": "pagead2.googlesyndication.com", "decision": "BLOCKED"},
          {"ts": 20_004, "domaine": "metaproxy.francetvpub.fr", "decision": "ALLOWED"}]
    dec = {d["domaine"]: d for d in D.correler(e, categorie_ref)}
    assert dec["metaproxy.francetvpub.fr"]["coupures"] == 2
    assert dec["metaproxy.francetvpub.fr"]["confiance"] == 90
    assert dec["audiences.free.fr"]["confiance"] == 70


def test_suffixe_home_est_rattache_au_domaine_reel():
    e = [{"ts": 0, "domaine": "pagead2.googlesyndication.com.home", "decision": "BLOCKED"},
         {"ts": 2, "domaine": "metaproxy.francetvpub.fr.home", "decision": "ALLOWED"}]
    assert [d["domaine"] for d in D.correler(e, categorie_ref)] == ["metaproxy.francetvpub.fr"]


# ── spot de secours (DPI) ───────────────────────────────────────────────────────────────────────────────────
def test_spot_de_secours_meme_hote_meme_volume_apres_deux_coupures():
    refus = [1000, 5000]
    flux = [{"ts": 1010, "hote": "filler.cdn.example", "octets": 4_000_000},
            {"ts": 5020, "hote": "filler.cdn.example", "octets": 4_100_000},
            {"ts": 5030, "hote": "autre.example", "octets": 10}]
    s = D.secours(flux, refus)
    assert [x["hote"] for x in s] == ["filler.cdn.example"] and s[0]["coupures"] == 2
    assert D.secours([{"ts": 1010, "hote": "x.example", "octets": 1_000_000}, {"ts": 5020, "hote": "x.example", "octets": 3_000_000}], refus) == []


# ── SSAI ────────────────────────────────────────────────────────────────────────────────────────────────────
def test_ssai_oqee_replay():
    motifs = D.charger_motifs_ssai(LISTES / "ssai.txt")
    assert D.est_ssai("replay-03.oqee.net", motifs) and D.est_ssai("replay-12.oqee.net.home", motifs)
    assert not D.est_ssai("api.oqee.net", motifs) and not D.est_ssai("replay-03.oqee.net.evil.com", motifs)


# ── constats : sans DNS, DNS chiffré, contournement ─────────────────────────────────────────────────────────
def test_constats_sur_les_flux():
    flux = [{"local": "192.168.1.50", "distant": "151.101.1.9", "port": 443, "proto": "tcp", "appli": "TLS", "hote": ""},
            {"local": "192.168.1.50", "distant": "151.101.1.10", "port": 443, "proto": "tcp", "appli": "TLS", "hote": ""},
            {"local": "192.168.1.50", "distant": "1.1.1.1", "port": 853, "proto": "tcp", "appli": "DoH_DoT", "hote": ""},
            {"local": "192.168.1.50", "distant": "8.8.8.8", "port": 443, "proto": "tcp", "appli": "TLS", "hote": "dns.google"},
            {"local": "192.168.1.50", "distant": "9.9.9.9", "port": 53, "proto": "udp", "appli": "DNS", "hote": ""},
            {"local": "192.168.1.50", "distant": "192.168.1.200", "port": 53, "proto": "udp", "appli": "DNS", "hote": ""},
            {"local": "192.168.1.50", "distant": "17.253.1.1", "port": 123, "proto": "udp", "appli": "NTP", "hote": ""},
            {"local": "192.168.1.50", "distant": "239.255.255.250", "port": 1900, "proto": "udp", "appli": "SSDP", "hote": ""}]
    c = D.constats(flux, resolus={"151.101.1.10"}, box={"192.168.1.200"}, doh={"8.8.8.8"}, doh_noms={"dns.google"})
    par = {(x["type"], x["distant"]) for x in c}
    assert ("sans-dns", "151.101.1.9") in par and ("sans-dns", "151.101.1.10") not in par
    assert ("dns-chiffre", "1.1.1.1") in par and ("dns-chiffre", "8.8.8.8") in par
    assert ("contournement", "9.9.9.9") in par and ("contournement", "192.168.1.200") not in par
    assert not any(x["distant"] in ("17.253.1.1", "239.255.255.250") for x in c)


def test_couverture():
    assert D.couverture(None, 10_000) == "dns"
    assert D.couverture(9_000, 10_000) == "dns+dpi"
    assert D.couverture(10_000 - D.FENETRE_COUVERTURE_S - 1, 10_000) == "dns"


# ── sources ─────────────────────────────────────────────────────────────────────────────────────────────────
def test_lire_conntrack_ne_garde_que_les_adresses_du_perimetre():
    texte = ("ipv4     2 tcp      6 431999 ESTABLISHED src=192.168.1.50 dst=151.101.1.9 sport=51000 dport=443 "
             "src=151.101.1.9 dst=192.168.1.50 sport=443 dport=51000 [ASSURED] mark=0 use=1\n"
             "ipv4     2 udp      17 29 src=192.168.1.99 dst=9.9.9.9 sport=5353 dport=53 src=9.9.9.9 dst=192.168.1.99 sport=53 dport=5353 mark=0 use=1\n"
             "ipv6     10 udp      17 29 src=2a01:e0a::1111 dst=2001:4860:4860::8888 sport=40000 dport=853 "
             "src=2001:4860:4860::8888 dst=2a01:e0a::1111 sport=853 dport=40000 mark=0 use=1\n"
             "n'importe quoi\n")
    f = D.lire_conntrack(texte, {"192.168.1.50", "2a01:e0a::1111"})
    assert f == [{"local": "192.168.1.50", "distant": "151.101.1.9", "port": 443, "proto": "tcp", "appli": "", "hote": ""},
                 {"local": "2a01:e0a::1111", "distant": "2001:4860:4860::8888", "port": 853, "proto": "udp", "appli": "", "hote": ""}]


def test_lire_sbxdpi_valide_et_borne():
    brut = {"version": 1, "genere": 1000, "flux": [
        {"local": "192.168.1.50", "appli": "TLS.Google", "categorie": "Advertisement", "hote": "pagead2.googlesyndication.com",
         "distant": "", "port": 443, "proto": "tcp", "flux": 3, "octets": 12000, "premier": 990, "dernier": 999},
        {"local": "pas une ip", "appli": "x", "port": 1, "proto": "tcp", "flux": 1, "octets": 1, "premier": 1, "dernier": 1},
        {"local": "192.168.1.50", "appli": "<script>", "port": 443, "proto": "tcp", "flux": 1, "octets": 1, "premier": 1, "dernier": 1}]}
    f = D.lire_sbxdpi(json.dumps(brut))
    assert f["genere"] == 1000 and len(f["flux"]) == 1 and f["flux"][0]["hote"] == "pagead2.googlesyndication.com"
    with pytest.raises(D.ErreurDPI):
        D.lire_sbxdpi("{")
