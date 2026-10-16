# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2816 — profil `minimal` : DPI, dns-guard, ad-guard, NAC, Freebox, ipv6guard, webfilter, avec le seul socle d'administration (WebUI admin).
#2845 — plus WireGuard (sortie Internet distante). #2849 — SANS le WAF ni HAProxy : essayes sur l'ESPRESSObin (951 Mo), ils ont fait tomber la carte (swap plein,
charge > 10, deux coupures franches). Le WAF reste en amont, sur l'infrastructure.

Ni WAF, ni ISP, ni Hall, ni metrics (le module « visites ») : le test calcule la FERMETURE des dependances sur les `control` du depot,
car un module requis par un autre fait entrer ce qu'on voulait exclure."""
import re
from pathlib import Path

PAQUETS = Path(__file__).resolve().parents[2]
META = "secubox-minimal"
CONTROL = (PAQUETS / META / "debian" / "control").read_text(encoding="utf8")

REQUIS = {"secubox-dpi", "secubox-dns-guard", "secubox-ad-guard", "secubox-nac", "secubox-freebox", "secubox-ipv6guard", "secubox-webfilter", "secubox-autoload-agent", "secubox-wireguard"}
SOCLE_ADMIN = {"secubox-core", "secubox-aggregator", "secubox-hub", "secubox-portal", "secubox-auth"}
INTERDITS = {"secubox-waf-ng", "secubox-waf", "secubox-haproxy", "secubox-toolbox", "secubox-webos", "secubox-isp", "secubox-lite", "secubox-full",
             "secubox-metrics", "secubox-soc", "secubox-toolbox-ng", "secubox-mediaflow", "secubox-torrent", "secubox-mail"}


def noms(chunk):
    chunk = re.sub(r"^\s*#.*$", "", chunk, flags=re.M)
    return {m.group(1) for a in chunk.replace("\n", " ").split(",") for alt in a.split("|") if (m := re.match(r"\s*(secubox-[a-z0-9.+-]+)", alt))}


def dependances_directes(txt):
    out = {}
    txt = re.sub(r"^#.*\n", "", txt, flags=re.M)      # les commentaires au milieu d'un Depends (comme dans secubox-lite) coupent la continuation
    for blk in re.split(r"\n\n+", txt):
        m = re.search(r"^Package:\s*(\S+)", blk, re.M)
        if m:
            out[m.group(1)] = set().union(*(noms(c) for c in re.findall(r"^(?:Depends|Pre-Depends):((?:.*\n?(?: .*\n?)*))", blk, re.M)), set())
    return out


def toutes():
    d = {}
    for c in PAQUETS.glob("*/debian/control"):
        d.update(dependances_directes(c.read_text(encoding="utf8")))
    return d


def fermeture(racines, d):
    vus, pile = set(), list(racines)
    while pile:
        p = pile.pop()
        if p not in vus:
            vus.add(p)
            pile.extend(d.get(p, ()))
    return vus


def test_le_metapaquet_nomme_les_modules_demandes_et_le_socle_admin():
    directs = dependances_directes(CONTROL)[META]
    assert REQUIS <= directs, REQUIS - directs
    assert SOCLE_ADMIN <= directs, SOCLE_ADMIN - directs


def test_aucun_module_interdit_meme_par_dependance_indirecte():
    d = toutes()
    ferme = fermeture(dependances_directes(CONTROL)[META], d)
    intrus = ferme & INTERDITS
    assert not intrus, {x: [p for p in ferme if x in d.get(p, ())] for x in intrus}


def test_tout_ce_que_le_profil_nomme_existe_dans_le_depot():
    d = toutes()
    inconnus = {p for p in dependances_directes(CONTROL)[META] if p not in d}
    assert not inconnus, inconnus


def test_le_metapaquet_ne_tire_aucun_service_en_recommends():
    """Un Recommends reintroduirait en silence ce que le profil exclut (apt les installe par defaut)."""
    bloc = CONTROL.split(f"Package: {META}", 1)[1]
    assert not re.search(r"^Recommends:\s*\S*secubox-", bloc, re.M)


def test_les_fichiers_de_paquet_sont_la():
    for f in ("control", "changelog", "rules"):
        assert (PAQUETS / META / "debian" / f).is_file(), f


CONTENEURS = {"secubox-nextcloud", "secubox-gitea", "secubox-mail", "secubox-matrix", "secubox-jitsi", "secubox-peertube", "secubox-photoprism",
              "secubox-streamlit", "secubox-torrent", "secubox-ytsas", "secubox-jellyfin", "secubox-lyrion", "secubox-zigbee", "secubox-picobrew"}


def test_aucun_conteneur_lxc_dans_le_profil():
    """ESPRESSObin : AUCUN conteneur LXC, tous « non installes » — ni un module applicatif, ni un installeur de conteneur livre par un paquet du profil.

    Le paquet `lxc` (les outils) peut subsister : secubox-toolbox en depend en dur et ad-guard depend de toolbox. Il ne cree aucun conteneur."""
    ferme = fermeture(dependances_directes(CONTROL)[META], toutes())
    assert not (ferme & CONTENEURS), ferme & CONTENEURS
    for p in ferme:
        racine = PAQUETS / p
        installeurs = [f for f in racine.rglob("install-lxc.sh") if "/debian/" + p not in str(f)] if racine.is_dir() else []
        assert not installeurs, (p, installeurs)


def test_les_modules_exclus_sont_en_conflicts_car_un_recommends_les_ramenait():
    """L'image du 2026-10-16 contenait le Hall : secubox-auth et secubox-freebox le RECOMMANDENT, et apt installe les Recommends par defaut.
    Un Conflicts est le seul moyen, depuis le meta-paquet, de dire a apt de ne pas les ramener."""
    bloc = CONTROL.split(f"Package: {META}", 1)[1]
    m = re.search(r"^Conflicts:((?:.*\n?(?: .*\n?)*))", bloc, re.M)
    assert m, "Conflicts absent"
    conflits = noms(m.group(1))
    assert {"secubox-webos", "secubox-waf-ng", "secubox-metrics", "secubox-toolbox"} <= conflits, conflits


def test_pas_de_postinst_de_leurre_ni_de_binaire_haproxy():
    """Le WAF est retire (#2849) : plus de leurre a armer, plus de haproxy en dependance."""
    assert not (PAQUETS / META / "debian" / "postinst").exists()
    assert "haproxy" not in CONTROL.split(f"Package: {META}", 1)[1].split("Conflicts:")[0]


def test_ndpid_engine_exige_la_version_qui_choisit_son_interface():
    """1.7.1 lance nDPId sur `eth2` (valeur de gk2) : sur l'ESPRESSObin, 61 redemarrages et la carte noyee (#2851). Le choix de l'interface est dans 1.7.2 (#2740)."""
    assert re.search(r"secubox-ndpid-engine \(>= 1\.7\.2\)", CONTROL)


def test_toolbox_et_rlevel_sont_exclus_et_ad_guard_ne_l_exige_plus():
    """#2855 : toolbox (dont le R-level MITM par pair) quitte le profil. ad-guard l'exigeait en dependance dure alors que son code tolere son absence."""
    d = toutes()
    assert "secubox-toolbox" not in d["secubox-ad-guard"], "ad-guard ne doit plus EXIGER toolbox (Recommends seulement)"
    ctl = (PAQUETS / "secubox-ad-guard" / "debian" / "control").read_text(encoding="utf8")
    assert re.search(r"^Recommends:.*secubox-toolbox", ctl, re.M | re.S)
