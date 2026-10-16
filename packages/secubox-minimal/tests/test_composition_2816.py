# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2816 — profil `minimal` : DPI, dns-guard, ad-guard, NAC, Freebox, avec le seul socle d'administration (WebUI admin).

Ni WAF, ni ISP, ni Hall, ni metrics (le module « visites ») : le test calcule la FERMETURE des dependances sur les `control` du depot,
car un module requis par un autre fait entrer ce qu'on voulait exclure."""
import re
from pathlib import Path

PAQUETS = Path(__file__).resolve().parents[2]
META = "secubox-minimal"
CONTROL = (PAQUETS / META / "debian" / "control").read_text(encoding="utf8")

REQUIS = {"secubox-dpi", "secubox-dns-guard", "secubox-ad-guard", "secubox-nac", "secubox-freebox"}
SOCLE_ADMIN = {"secubox-core", "secubox-aggregator", "secubox-hub", "secubox-portal", "secubox-auth"}
INTERDITS = {"secubox-waf-ng", "secubox-waf", "secubox-haproxy", "secubox-webos", "secubox-isp", "secubox-lite", "secubox-full",
             "secubox-metrics", "secubox-soc", "secubox-toolbox-ng", "secubox-mediaflow", "secubox-torrent", "secubox-mail", "secubox-wireguard"}


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
