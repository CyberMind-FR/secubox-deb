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
    z, zt, ov, vues, acv, acl_tags, acl_act, blocs, actions = {}, {}, {}, {}, {}, {}, {}, set(), {}
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
            elif (m := re.match(r"access-control:\s*(\S+)\s+(\S+)", s)):
                b = str(ipaddress.ip_network(m.group(1), strict=False))
                actions.setdefault(b, m.group(2))                # doublon : le premier gagne, le second est ignoré (avertissement)
                blocs.add(b)
    return z, zt, ov, vues, acv, acl_tags, acl_act, blocs, actions


# Autorisés par Unbound sans déclaration (acl_list_apply_cfg), ignorés s'ils sont déjà déclarés.
DEFAUTS = {"127.0.0.0/8", "::1/128"}


def _noeud(ip, etat):
    """L'élément d'ACL d'Unbound pour un client : le PLUS PRÉCIS de tous (access-control, vue, étiquettes) — sa vue et ses
    étiquettes seulement, rien n'est hérité d'un bloc plus large."""
    return _plus_specifique(ip, etat[7] | DEFAUTS)


def acces(etat, ip):
    """Action d'accès du client : celle de son élément d'ACL ; un élément créé par une vue ou une étiquette est « allow » ;
    aucun élément : refusé."""
    n = _noeud(ip, etat)
    return "refuse" if n is None else etat[8].get(n, "allow")


def _plus_specifique(ip, blocs):
    a = ipaddress.ip_address(ip)
    dedans = [ipaddress.ip_network(b) for b in blocs if a in ipaddress.ip_network(b)]
    return str(max(dedans, key=lambda n: n.prefixlen)) if dedans else None


def _ancetres(q):
    p = q.split(".")
    return [".".join(p[i:]) for i in range(len(p))] + ["."]


def simuler_nouveau(etat, q, ip):
    z, zt, ov, vues, acv, acl_tags, acl_act, blocs, _ = etat
    elem = _noeud(ip, etat)
    tags, actions = acl_tags.get(elem, set()), acl_act.get(elem, {})
    v = acv.get(elem)
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

def _comparer(sources, contexte, clients, noms, tmp_path):
    """Ancienne configuration (sources + contexte) et nouvelle (92 + contexte) passées au MÊME simulateur : mêmes accès,
    mêmes décisions pour chaque client autorisé."""
    src = _ecrire(tmp_path / "sources", sources)
    ctx = _ecrire(tmp_path / "conf.d", contexte)
    texte, _ = L.compiler(sorted(src.glob("*.conf")), sorted(ctx.glob("*.conf")))
    ancien = _parse_nouveau(list(sources.values()) + list(contexte.values()))
    nouveau = _parse_nouveau([texte] + list(contexte.values()))
    ecarts = [(ip, "acces", acces(ancien, ip), acces(nouveau, ip)) for ip in clients if acces(ancien, ip) != acces(nouveau, ip)]
    ecarts += [(ip, q, simuler_nouveau(ancien, q, ip), simuler_nouveau(nouveau, q, ip)) for ip in clients for q in noms
               if acces(ancien, ip).startswith("allow") and simuler_nouveau(ancien, q, ip) != simuler_nouveau(nouveau, q, ip)]
    return texte, ecarts


def test_memes_decisions_pour_chaque_client_et_chaque_nom(compile_, tmp_path):
    texte, stats, cfg, ctx = compile_
    etat = _parse_nouveau([texte] + [(ctx / n).read_text() for n in CONTEXTE])
    ecarts = [(ip, q, L.decision_ancienne(cfg, q, ip), simuler_nouveau(etat, q, ip))
              for ip in CLIENTS for q in NOMS if L.decision_ancienne(cfg, q, ip) != simuler_nouveau(etat, q, ip)]
    assert ecarts == []
    assert _comparer(SOURCES, CONTEXTE, CLIENTS, NOMS, tmp_path / "b")[1] == []


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


def test_les_clients_locaux_par_defaut_sont_une_classe(tmp_path):
    """Unbound autorise 127.0.0.0/8 et ::1 sans qu'aucun fichier ne le dise. Sans ces classes, une zone bloquée pour tous
    SAUF un client exempté ne s'appliquait plus à la box elle-même — et disparaissait quand aucun réseau n'était déclaré."""
    s = tmp_path / "96-secubox-adult.conf"
    s.write_text('server:\n    local-zone: "cam.example." always_nxdomain\n'
                 '    local-zone-override: "cam.example." 192.168.1.3 always_transparent\n')
    texte, stats = L.compiler([s], [])
    assert '"cam.example." always_nxdomain' in texte
    assert re.search(r'access-control-tag: 127\.0\.0\.0/8 "sbx\d+"', texte) and "access-control-tag: ::1/128 " in texte
    assert "access-control: 127.0.0.0/8" not in texte and "access-control: ::1/128" not in texte    # défauts : pas redéclarés


# ── éléments d'ACL : le compilateur n'ouvre rien que l'ancienne configuration n'ouvrait (relecture #3205) ─────────────

ACL_CONTEXTE = {
    "10-acl.conf": """server:
    access-control: 192.168.0.0/16 allow
    access-control: 10.0.0.0/8 allow_snoop
""",
    "94-tv.conf": """server:
    access-control-view: 192.168.1.96/30 tv
view:
    name: "tv"
    view-first: yes
    local-zone: "tvads.example." always_nxdomain
""",
}
ACL_SOURCES = {"96-secubox-adult.conf": """server:
    local-zone: "cam.example." always_nxdomain
    local-zone: "tube.example." always_nxdomain
    local-zone-override: "cam.example." 192.168.1.3 always_transparent
    local-zone-override: "cam.example." 192.168.1.97 always_transparent
    local-zone-override: "cam.example." 203.0.113.7 always_transparent
    local-zone-override: "cam.example." 10.1.2.3 always_transparent
"""}
ACL_CLIENTS = ["192.168.1.3", "192.168.1.50", "192.168.1.97", "192.168.1.98", "203.0.113.7", "10.1.2.3", "10.9.9.9", "8.8.8.8",
               "127.0.0.1"]
ACL_NOMS = ["cam.example", "www.cam.example", "tube.example", "tvads.example", "free.example"]


def test_une_derogation_hors_des_reseaux_autorises_n_ouvre_pas_le_resolveur(tmp_path):
    """Avant : une dérogation ne créait aucun élément d'ACL. Une adresse exemptée hors des réseaux autorisés (ou 0.0.0.0/0)
    ne devient pas un client autorisé : résolveur ouvert sinon."""
    texte, ecarts = _comparer(ACL_SOURCES, ACL_CONTEXTE, ACL_CLIENTS, ACL_NOMS, tmp_path)
    assert ecarts == []
    assert "203.0.113.7" not in texte and "access-control: 192.168.1.3/32 allow\n" in texte


def test_une_derogation_reprend_l_action_du_reseau_qui_la_couvre(tmp_path):
    texte, _ = _comparer(ACL_SOURCES, ACL_CONTEXTE, ACL_CLIENTS, ACL_NOMS, tmp_path)
    assert "access-control: 10.1.2.3/32 allow_snoop\n" in texte


def test_une_derogation_sous_une_vue_tv_garde_la_vue(tmp_path):
    """Unbound ne fait pas hériter la vue d'un bloc plus large : l'élément /32 créé pour l'exempté doit porter la vue TV."""
    texte, ecarts = _comparer(ACL_SOURCES, ACL_CONTEXTE, ACL_CLIENTS, ACL_NOMS, tmp_path)
    assert ecarts == [] and "access-control-view: 192.168.1.97/32 tv\n" in texte


def test_une_derogation_sur_tout_internet_reste_sans_element_d_acl(tmp_path):
    sources = {"96-secubox-adult.conf": ACL_SOURCES["96-secubox-adult.conf"]
               + '    local-zone-override: "tube.example." 0.0.0.0/0 always_transparent\n'}
    texte, ecarts = _comparer(sources, ACL_CONTEXTE, ACL_CLIENTS, ACL_NOMS, tmp_path)
    assert ecarts == [] and "0.0.0.0/0" not in texte


# ── sources : lues sans suivre de lien, erreurs sans recopier le contenu ─────────────────────────────────────────────

def test_une_source_lien_symbolique_est_refusee(tmp_path):
    secret = tmp_path / "secret"
    secret.write_text("server:\n")
    s = tmp_path / "95-secubox-adblock.conf"
    s.symlink_to(secret)
    with pytest.raises(L.ErreurListes, match="lien"):
        L.compiler([s], [])


def test_une_erreur_ne_recopie_pas_la_ligne(tmp_path):
    s = tmp_path / "95-secubox-adblock.conf"
    s.write_text("root:$y$j9T$empreinte-secrete:19000:0:99999:7:::\n")
    with pytest.raises(L.ErreurListes) as e:
        L.compiler([s], [])
    assert "empreinte-secrete" not in str(e.value) and "$y$" not in str(e.value) and "95-secubox-adblock.conf:1" in str(e.value)


@pytest.mark.parametrize("ligne", ['    local-zone: ads.example. always_nxdomain',
                                   '    local-zone: "ads.example." always_nxdomain # commentaire',
                                   '    access-control-view: pas-une-adresse vue'])
def test_une_ligne_permise_mais_illisible_est_refusee(tmp_path, ligne):
    """« Rien ne se perd en silence » : une ligne au préfixe permis que le compilateur ne reconnaît pas lève une erreur."""
    s = tmp_path / "95-secubox-adblock.conf"
    s.write_text("server:\n" + ligne + "\n")
    with pytest.raises(L.ErreurListes, match="95-secubox-adblock.conf:2"):
        L.compiler([s], [])


def test_view_first_suivi_d_une_autre_directive_est_refuse(tmp_path):
    """Seconde relecture #3205 : la grammaire d'Unbound ignore les sauts de ligne ; « view-first: yes include: … » passait
    le contrôle par préfixe, et le mode direct l'aurait recopié tel quel."""
    s = tmp_path / "93-secubox-webfilter.conf"
    s.write_text('server:\nview:\n    name: "v"\n    view-first: yes include: "/etc/x"\n')
    with pytest.raises(L.ErreurListes, match="93-secubox-webfilter.conf:4"):
        L.compiler([s], [])


def test_un_nom_de_zone_inattendu_n_est_pas_recopie(tmp_path):
    s = tmp_path / "95-secubox-adblock.conf"
    s.write_text('server:\n    local-zone: "jeton secret.example." always_nxdomain\n')
    with pytest.raises(L.ErreurListes) as e:
        L.compiler([s], [])
    assert "secret" not in str(e.value)


def test_un_bloc_vu_par_une_source_et_par_le_contexte_prend_la_vue_du_contexte(tmp_path):
    """Une IP de l'allowlist d'adblock (vue sbx-allow) qui est aussi une TV d'ad-guard (vue 94) : dans le nouvel ensemble,
    seule la vue du contexte reste. Le compilateur la prend pour le calcul et compte le conflit."""
    ctx = tmp_path / "94-tv.conf"
    ctx.write_text('server:\n    access-control: 192.168.0.0/16 allow\n    access-control-view: 192.168.1.95/32 tv\n'
                   'view:\n    name: "tv"\n    view-first: yes\n    local-zone: "tvads.example." always_nxdomain\n')
    src = tmp_path / "95-secubox-adblock.conf"
    src.write_text('server:\n    access-control-view: 192.168.1.95 sbx-allow\n    local-zone: "ads.example." always_nxdomain\n'
                   'view:\n    name: "sbx-allow"\n    view-first: yes\n')
    texte, stats = L.compiler([src], [ctx])
    assert stats["conflits_vue"] == 1 and "sbx-allow" not in texte


def test_acl_deny_refuse_non_local_et_ipv6(tmp_path):
    contexte = {"10-acl.conf": """server:
    access-control: 10.0.0.0/8 deny
    access-control: 172.16.0.0/12 refuse_non_local
    access-control: 2001:db8::/64 allow
"""}
    sources = {"96-secubox-adult.conf": """server:
    local-zone: "cam.example." always_nxdomain
    local-zone-override: "cam.example." 10.1.1.1 always_transparent
    local-zone-override: "cam.example." 172.16.1.1 always_transparent
    local-zone-override: "cam.example." 2001:db8::5 always_transparent
"""}
    texte, ecarts = _comparer(sources, contexte, ["10.1.1.1", "172.16.1.1", "172.16.9.9", "2001:db8::5", "2001:db8::9"],
                              ["cam.example", "www.cam.example"], tmp_path)
    assert ecarts == []
    assert "10.1.1.1" not in texte                                            # deny : ni élément ni étiquette
    assert "access-control: 172.16.1.1/32 refuse_non_local\n" in texte      # action reprise telle quelle
    assert "access-control: 2001:db8::5/128 allow\n" in texte
