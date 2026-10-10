# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2240 : capteur DNS d'Actor Intelligence. Seuls les domaines MALVEILLANTS (liste de l'opérateur) ou ANORMAUX (DGA, tunnel, dérive d'un domaine
normal) produisent un signal ; une requête ordinaire n'en produit JAMAIS."""
import random
import string
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from api.dnstv_anomalies import (  # noqa: E402
    detecter, deduplique, enveloppe, entropie, registre_du_domaine, ressemble_dga)

NOW = 1_800_000_000
TV = "192.168.1.60"


def ev(domaine, dt=0, client=TV, qtype="A"):
    return {"ts": NOW - dt, "client": client, "domaine": domaine, "qtype": qtype, "decision": "ALLOWED"}


def alea(n, graine):
    r = random.Random(graine)
    return "".join(r.choice(string.ascii_lowercase + string.digits) for _ in range(n))


def test_domaine_enregistre_gere_les_suffixes_a_deux_niveaux():
    assert registre_du_domaine("a.b.exemple.fr") == "exemple.fr"
    assert registre_du_domaine("www.bbc.co.uk") == "bbc.co.uk"
    assert registre_du_domaine("x.y.service.com.au") == "service.com.au"
    assert registre_du_domaine("localhost") == "localhost"


def test_dga_discrimine_les_noms_lisibles_des_noms_aleatoires():
    assert ressemble_dga(alea(16, 1)) and ressemble_dga(alea(20, 2))
    for ok in ("netflix", "francetelevisions", "googleapis", "cloudflare", "wikipedia", "amazonaws"):
        assert not ressemble_dga(ok), ok
    assert entropie("aaaa") < entropie(alea(16, 3))


def test_requetes_ordinaires_ne_produisent_aucun_signal():
    evts = [ev(d, i) for i, d in enumerate(["www.netflix.com", "api.france.tv", "cdn.cloudflare.com", "play.googleapis.com"] * 20)]
    assert detecter(evts, NOW, connus=set(), base={}, noms_connus={}, liste=set()) == []


def test_trois_domaines_dga_inconnus_du_meme_appareil_font_un_signal():
    evts = [ev(alea(16, i) + ".com", i * 10) for i in range(4)]
    f = detecter(evts, NOW, set(), {}, {}, set())
    assert [x["rule"] for x in f] == ["dns.dga"] and f[0]["client"] == TV and f[0]["severity"] >= 55


def test_un_ou_deux_domaines_dga_ne_suffisent_pas():
    evts = [ev(alea(16, i) + ".com", i * 10) for i in range(2)]
    assert detecter(evts, NOW, set(), {}, {}, set()) == []


def test_un_domaine_aleatoire_deja_connu_n_est_pas_dga():
    evts = [ev(alea(16, i) + ".com", i * 10) for i in range(4)]
    connus = {registre_du_domaine(e["domaine"]) for e in evts}
    assert detecter(evts, NOW, connus, {}, {}, set()) == []


def test_tunnel_dns_sur_un_domaine_normal():
    evts = [ev(alea(40, i) + ".exemple.fr", i) for i in range(35)]
    f = detecter(evts, NOW, {"exemple.fr"}, {}, {"exemple.fr": {"www.exemple.fr"}}, set())
    regles = {x["rule"] for x in f}
    assert "dns.tunnel" in regles and all(x["domaine"] == "exemple.fr" for x in f if x["rule"] == "dns.tunnel")


def test_rafale_txt_vers_un_meme_domaine():
    evts = [ev("c2.exemple.fr", i, qtype="TXT") for i in range(25)]
    assert "dns.tunnel" in {x["rule"] for x in detecter(evts, NOW, {"exemple.fr"}, {}, {"exemple.fr": {"c2.exemple.fr"}}, set())}


def test_liste_de_l_operateur_domaine_ou_parent():
    evts = [ev("mal.sous.mauvais.example")]
    f = detecter(evts, NOW, set(), {}, {}, {"mauvais.example"})
    assert [x["rule"] for x in f] == ["dns.listed"] and f[0]["severity"] == 80


def test_derive_d_un_domaine_normal_pic_de_requetes():
    base = {(TV, "exemple.fr"): [40, 35, 50]}                       # hits par jour, 3 jours : ~50 max
    evts = [ev("www.exemple.fr", i) for i in range(900)]            # 900 requêtes en une heure
    f = detecter(evts, NOW, {"exemple.fr"}, base, {"exemple.fr": {"www.exemple.fr"}}, set())
    assert "dns.drift.spike" in {x["rule"] for x in f}


def test_trafic_regulier_d_un_domaine_normal_n_est_pas_une_derive():
    base = {(TV, "exemple.fr"): [900, 800, 950]}
    evts = [ev("www.exemple.fr", i) for i in range(900)]
    assert detecter(evts, NOW, {"exemple.fr"}, base, {"exemple.fr": {"www.exemple.fr"}}, set()) == []


def test_derive_sous_domaines_jamais_vus_sur_un_domaine_normal():
    evts = [ev(alea(18, i) + ".exemple.fr", i) for i in range(30)]
    f = detecter(evts, NOW, {"exemple.fr"}, {(TV, "exemple.fr"): [100]}, {"exemple.fr": {"www.exemple.fr"}}, set())
    assert "dns.drift.subdomains" in {x["rule"] for x in f}


def test_enveloppe_porte_l_appareil_et_le_domaine_enregistre_jamais_les_sous_domaines():
    f = detecter([ev(alea(16, i) + ".com", i * 10) for i in range(4)], NOW, set(), {}, {}, set())[0]
    e = enveloppe(f, NOW)
    assert e["sensor"] == "dns" and e["src_ip"] == TV and e["protocol"] == "dns" and e["action"] == "observe"
    assert e["path_shape"].startswith("dns:") and e["rule_id"] == "dns.dga" and 0 <= e["severity"] <= 100
    assert len(e["event_id"]) >= 16 and "dns_dga" in e["behavior_tags"]
    assert len(e["path_shape"]) <= 256


def test_deduplication_six_heures():
    f = detecter([ev(alea(16, i) + ".com", i * 10) for i in range(4)], NOW, set(), {}, {}, set())
    etat = {}
    assert len(deduplique(f, etat, NOW)) == 1
    assert deduplique(f, etat, NOW + 600) == []
    assert len(deduplique(f, etat, NOW + 7 * 3600)) == 1
