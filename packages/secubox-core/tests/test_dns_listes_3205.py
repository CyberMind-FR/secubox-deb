# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3205 — listes DNS compilées par étiquettes : mêmes décisions, chaque domaine une fois.

Validé au banc sur gk1 avec la configuration réelle de gk2 (743 → 387 Mo, 145 530 décisions, aucune différence). Ici, une
configuration synthétique reprend chaque piège rencontré, et un simulateur INDÉPENDANT de la sémantique à étiquettes
d'Unbound (dérogation, puis action d'étiquette, puis type ; zones non applicables sautées) compare toutes les décisions."""
import ipaddress
import re
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "common"))
from secubox_unbound import listes as L  # noqa: E402

CONTEXTE = {
    "10-acl.conf": """server:
    access-control: 192.168.0.0/16 allow
    access-control: 10.10.0.0/24 allow
    access-control: 127.0.0.0/8 allow
    access-control: 2001:db8::/64 allow
""",
    "60-noms.conf": """server:
    local-zone: "lan.example." static
    local-data: "box.lan.example. A 192.168.1.1"
""",
    # Vue TV : conservée telle quelle (le compilateur ne la touche pas, mais en tient compte)
    "94-tv.conf": """server:
    access-control-view: 192.168.1.95/32 tv
    local-zone-override: "track.example." 192.168.1.95/32 transparent
view:
    name: "tv"
    view-first: yes
    local-zone: "tvads.example." always_nxdomain
""",
}
SOURCES = {
    "93-secubox-webfilter.conf": """server:
    access-control-view: 192.168.1.0/24 wf-defaut
    access-control-view: 2001:db8::/64 wf-defaut
    access-control-view: 192.168.1.9/32 wf-x
view:
    name: "wf-x"
    view-first: yes
    local-zone: "casino.example." always_nxdomain
    local-zone: "porn.example." always_nxdomain
    local-zone: "chat.example." transparent
view:
    name: "wf-defaut"
    view-first: yes
    local-zone: "casino.example." always_nxdomain
    local-zone: "porn.example." always_nxdomain
""",
    "95-secubox-adblock.conf": """server:
    local-zone: "ads.example." always_nxdomain
    local-zone: "sub.ads.example." always_nxdomain
    local-zone: "cdn.ads.example." always_transparent
    local-zone: "track.example." always_nxdomain
    local-zone: "x.track.example." always_nxdomain
    local-zone: "pub.example." always_nxdomain
    local-zone: "a.pub.example." always_nxdomain
""",
    "96-secubox-adult.conf": """server:
    local-zone: "porn.example." always_nxdomain
    local-zone: "ads.example." always_nxdomain
    local-zone: "chat.example." always_nxdomain
    local-zone-override: "porn.example." 192.168.1.3 always_transparent
    local-zone-override: "ads.example." 192.168.1.3 always_transparent
    local-zone-override: "chat.example." 192.168.1.3 always_transparent
""",
}
CLIENTS = ["192.168.1.50", "192.168.1.9", "192.168.1.3", "192.168.1.95", "192.168.42.10", "10.10.0.5", "127.0.0.1",
           "2001:db8::50", "192.168.77.7"]
NOMS = ["ads.example", "sub.ads.example", "deep.sub.ads.example", "cdn.ads.example", "a.cdn.ads.example",
        "track.example", "x.track.example", "y.x.track.example", "porn.example", "www.porn.example", "casino.example",
        "chat.example", "a.chat.example", "tvads.example", "box.lan.example", "lan.example", "free.example",
        "pub.example", "a.pub.example", "b.a.pub.example", "example", "unlisted.org"]


def _ecrire(dossier, fichiers):
    dossier.mkdir(parents=True, exist_ok=True)
    for nom, texte in fichiers.items():
        (dossier / nom).write_text(texte)
    return dossier


@pytest.fixture
def compile_(tmp_path):
    src = _ecrire(tmp_path / "sources", SOURCES)
    ctx = _ecrire(tmp_path / "conf.d", CONTEXTE)
    texte, stats = L.compiler(sorted(src.glob("*.conf")), sorted(ctx.glob("*.conf")))
    cfg_ancienne = L.lire(sorted(src.glob("*.conf")) + sorted(ctx.glob("*.conf")))
    return texte, stats, cfg_ancienne, ctx


# ── simulateur indépendant de la sémantique à étiquettes d'Unbound ───────────

BLOQ = {"always_nxdomain", "static", "always_refuse", "refuse", "deny", "always_null"}


def _parse_nouveau(textes):
    """Zones globales (type, étiquettes), dérogations, vues et éléments d'ACL (étiquettes, actions) du NOUVEL ensemble."""
    z, zt, ov, vues, acv, acl_tags, acl_act, blocs = {}, {}, {}, {}, {}, {}, {}, set()
    for texte in textes:
        section, vue = None, None
        for ligne in texte.splitlines():
            s = ligne.strip()
            if not s or s.startswith("#"):
                continue
            if re.fullmatch(r"[a-z-]+:", s) and not ligne[:1].isspace():
                section, vue = s[:-1], None
                continue
            if section == "view":
                m = re.match(r'name:\s*"?([^"\s]+)', s)
                if m and vue is None:
                    vue = m.group(1)
                    vues[vue] = {"first": False, "zones": {}}
                elif s.startswith("view-first:"):
                    vues[vue]["first"] = s.endswith("yes")
                elif (m := re.match(r'local-zone:\s*"([^"]+)"\s+(\S+)', s)):
                    vues[vue]["zones"][m.group(1).rstrip(".") or "."] = m.group(2)
                continue
            if (m := re.match(r'local-zone:\s*"([^"]+)"\s+(\S+)', s)):
                z[m.group(1).rstrip(".")] = m.group(2)
            elif (m := re.match(r'local-zone-tag:\s*"([^"]+)"\s+"([^"]+)"', s)):
                zt[m.group(1).rstrip(".")] = set(m.group(2).split())
            elif (m := re.match(r'local-zone-override:\s*"([^"]+)"\s+(\S+)\s+(\S+)', s)):
                ov.setdefault(m.group(1).rstrip("."), {})[str(ipaddress.ip_network(m.group(2), strict=False))] = m.group(3)
            elif (m := re.match(r"access-control-view:\s*(\S+)\s+(\S+)", s)):
                b = str(ipaddress.ip_network(m.group(1), strict=False))
                acv[b] = m.group(2).strip('"')
                blocs.add(b)
            elif (m := re.match(r'access-control-tag:\s*(\S+)\s+"([^"]*)"', s)):
                b = str(ipaddress.ip_network(m.group(1), strict=False))
                acl_tags[b] = set(m.group(2).split())
                blocs.add(b)
            elif (m := re.match(r"access-control-tag-action:\s*(\S+)\s+(\S+)\s+(\S+)", s)):
                b = str(ipaddress.ip_network(m.group(1), strict=False))
                acl_act.setdefault(b, {})[m.group(2)] = m.group(3)
                blocs.add(b)
            elif (m := re.match(r"access-control:\s*(\S+)\s+allow", s)):
                blocs.add(str(ipaddress.ip_network(m.group(1), strict=False)))
    return z, zt, ov, vues, acv, acl_tags, acl_act, blocs


def _plus_specifique(ip, blocs):
    a = ipaddress.ip_address(ip)
    dedans = [ipaddress.ip_network(b) for b in blocs if a in ipaddress.ip_network(b)]
    return str(max(dedans, key=lambda n: n.prefixlen)) if dedans else None


def _ancetres(q):
    p = q.split(".")
    return [".".join(p[i:]) for i in range(len(p))] + ["."]


def simuler_nouveau(etat, q, ip):
    z, zt, ov, vues, acv, acl_tags, acl_act, blocs = etat
    elem = _plus_specifique(ip, blocs)
    tags, actions = acl_tags.get(elem, set()), acl_act.get(elem, {})
    v = acv.get(_plus_specifique(ip, acv)) if _plus_specifique(ip, acv) else None
    if v:
        zv = next((a for a in _ancetres(q) if a in vues[v]["zones"]), None)
        if zv is not None and not (vues[v]["first"] and vues[v]["zones"][zv] in ("transparent", "typetransparent")):
            return vues[v]["zones"][zv] in BLOQ
        if zv is None and not vues[v]["first"]:
            return False
    for a in _ancetres(q):
        if a not in z:
            continue
        if a in zt and not (zt[a] & tags):
            continue                                         # zone étiquetée, client sans l'étiquette : sautée
        b = _plus_specifique(ip, ov.get(a, {})) if a in ov else None
        if b:
            return ov[a][b] in BLOQ                          # 1. dérogation
        commun = [t for t in sorted(zt.get(a, set())) if t in tags and t in actions]
        if commun:
            return actions[commun[0]] in BLOQ                # 2. action d'étiquette
        return z[a] in BLOQ                                  # 3. type de la zone
    return False


# ── tests ────────────────────────────────────────────────────────────────────

def test_memes_decisions_pour_chaque_client_et_chaque_nom(compile_):
    texte, stats, cfg, ctx = compile_
    etat = _parse_nouveau([texte] + [(ctx / n).read_text() for n in CONTEXTE])
    ecarts = [(ip, q, L.decision_ancienne(cfg, q, ip), simuler_nouveau(etat, q, ip))
              for ip in CLIENTS for q in NOMS if L.decision_ancienne(cfg, q, ip) != simuler_nouveau(etat, q, ip)]
    assert ecarts == []


@pytest.mark.parametrize("ip,q,bloque", [
    ("192.168.1.50", "casino.example", True),     # webfilter (vue) pour le LAN
    ("192.168.42.10", "casino.example", False),   # pas de webfilter hors de sa vue
    ("192.168.1.3", "porn.example", True),        # exempté adult, mais webfilter le bloque dans sa vue
    ("192.168.42.10", "porn.example", True),      # adult pour tous les autres
    ("192.168.1.9", "chat.example", True),        # transparent de vue view-first : traversant, adult bloque (banc)
    ("192.168.1.3", "chat.example", False),       # exempté adult : dérogation
    ("192.168.1.95", "track.example", False),     # dérogation TV conservée
    ("192.168.1.95", "x.track.example", True),    # sous-zone propre, non dérogée
    ("192.168.1.50", "cdn.ads.example", False),   # exception sous un parent bloqué
    ("192.168.1.50", "a.cdn.ads.example", False),
    ("192.168.1.95", "tvads.example", True),      # vue TV intacte
])
def test_cas_du_banc(compile_, ip, q, bloque):
    texte, _, cfg, ctx = compile_
    etat = _parse_nouveau([texte] + [(ctx / n).read_text() for n in CONTEXTE])
    assert L.decision_ancienne(cfg, q, ip) is bloque and simuler_nouveau(etat, q, ip) is bloque


def test_chaque_domaine_une_seule_fois_et_sous_domaine_redondant_retire(compile_):
    texte, stats, _, _ = compile_
    zones = re.findall(r'^\s*local-zone: "([^"]+)"', texte, re.M)
    assert len(zones) == len(set(zones))
    assert "pub.example." in zones and "a.pub.example." not in zones          # même réponse pour tous : élagué
    assert "sub.ads.example." in zones        # 192.168.1.3 a une dérogation sur ads.example, pas sur sub : réponses différentes
    assert "x.track.example." in zones                                        # la TV diffère : gardé
    assert "lan.example." not in zones                                        # défini ailleurs : jamais réémis
    assert not re.search(r"^\s*(view:|local-zone-override:|access-control-view:)", texte, re.M)
    assert stats["elagues"] >= 1 and stats["etiquettes"] >= 1


def test_rendu_deterministe(tmp_path):
    src = _ecrire(tmp_path / "s", SOURCES)
    ctx = _ecrire(tmp_path / "c", CONTEXTE)
    a = L.compiler(sorted(src.glob("*.conf")), sorted(ctx.glob("*.conf")))[0]
    b = L.compiler(sorted(src.glob("*.conf"), reverse=True), sorted(ctx.glob("*.conf"), reverse=True))[0]
    assert a == b


def test_directive_inconnue_dans_une_source_refusee(tmp_path):
    """Une source ne doit jamais perdre une directive en silence."""
    src = _ecrire(tmp_path / "s", {"95-secubox-adblock.conf": 'server:\n    local-data: "x.example. A 1.2.3.4"\n'})
    with pytest.raises(L.ErreurListes, match="local-data"):
        L.compiler(sorted(src.glob("*.conf")), [])


def test_blocs_d_adresses_normalises(tmp_path):
    """« 192.168.1.3 » et « 192.168.1.3/32 » sont la même classe (vu au banc : une classe en double)."""
    src = _ecrire(tmp_path / "s", SOURCES)
    ctx = _ecrire(tmp_path / "c", {**CONTEXTE, "11-acl.conf": "server:\n    access-control: 192.168.1.3/32 allow\n"})
    texte, stats, = L.compiler(sorted(src.glob("*.conf")), sorted(ctx.glob("*.conf")))[:2]
    assert len(re.findall(r"^\s*access-control-tag: 192\.168\.1\.3/32 ", texte, re.M)) == 1


def test_sources_vides():
    texte, stats = L.compiler([], [])
    assert stats["emis"] == 0 and "local-zone:" not in texte


# ── empreinte du contexte : ce qui oblige à recompiler ───────────────────────

def _empreinte(tmp_path, textes):
    tmp_path.mkdir()
    fichiers = []
    for i, t in enumerate(textes):
        p = tmp_path / f"{i:02d}-ctx.conf"
        p.write_text(t)
        fichiers.append(p)
    return L.empreinte(fichiers)


def test_empreinte_ignore_ce_que_le_compilateur_ne_lit_pas(tmp_path):
    """60-secubox-noms change plusieurs fois par jour (local-data) : sans effet sur les décisions, il ne doit pas
    relancer deux minutes de compilation."""
    base = 'server:\n    access-control: 10.0.0.0/8 allow\n    local-zone: "lan." static\n'
    bruit = base + '    local-data: "box.lan. A 10.0.0.1"\n    interface: 10.0.0.1\n    # commentaire\n\n'
    assert _empreinte(tmp_path / "a", [base]) == _empreinte(tmp_path / "b", [bruit])


@pytest.mark.parametrize("ajout", ['    access-control: 10.9.0.0/16 allow\n',
                                   '    access-control-view: 10.0.0.9/32 tv\n',
                                   '    local-zone-override: "x.example." 10.0.0.9/32 transparent\n',
                                   '    local-zone: "x.example." transparent\n',
                                   'view:\n    name: "tv"\n    view-first: yes\n    local-zone: "x.example." always_nxdomain\n'])
def test_empreinte_change_avec_ce_qui_decide(tmp_path, ajout):
    base = 'server:\n    access-control: 10.0.0.0/8 allow\n'
    assert _empreinte(tmp_path / "a", [base]) != _empreinte(tmp_path / "b", [base + ajout])


def test_empreinte_distingue_le_fichier_qui_porte_la_ligne(tmp_path):
    """La première zone lue gagne (ordre des fichiers) : la même ligne déplacée d'un fichier à l'autre peut changer une décision."""
    a = 'server:\n    local-zone: "x.example." transparent\n'
    b = 'server:\n    local-zone: "x.example." always_nxdomain\n'
    assert _empreinte(tmp_path / "a", [a, b]) != _empreinte(tmp_path / "b", [b, a])
