# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3893 — sources compactes : exemptions adultes une ligne par adresse, zones du filtre web écrites une fois.

Exigence (accord du propriétaire) : AUCUN changement de filtrage, ni compilé ni en mode direct. Preuves, sur un échantillon
des vraies sources de gk2 (`listes_reelles_3893`) rendues par les VRAIS générateurs modifiés :
  - mode direct : la source adulte dépliée est l'ancien rendu octet pour octet ; chaque vue du filtre web dépliée porte
    les mêmes lignes ;
  - lecture : la configuration lue (zones, dérogations, vues, accès) est identique, compacte, dépliée ou ancienne ;
  - décisions : même (client, domaine, décision) pour chaque classe de clients, apex et sous-domaines ;
  - compilé : le 92 est identique octet pour octet.
Vérifié aussi sur un vrai Unbound au banc gk1 (requêtes réelles, ancien/nouveau, direct/compilé)."""
import importlib.machinery
import importlib.util
import ipaddress
import re
import sys
import types
from pathlib import Path

import pytest

ICI = Path(__file__).resolve().parent
RACINE = ICI.parents[2]
sys.path.insert(0, str(RACINE / "common"))
sys.path.insert(0, str(RACINE / "packages" / "secubox-webfilter"))
sys.path.insert(0, str(ICI))
import listes_reelles_3893 as R  # noqa: E402
from secubox_unbound import depot as D  # noqa: E402
from secubox_unbound import listes as L  # noqa: E402
from webfilter import generation as G  # noqa: E402

N93, N95, N96 = L.SOURCES_CONNUES
ACL = """server:
    access-control: 192.168.1.0/24 allow
    access-control: 2001:db8:c4e0::/64 allow
"""
# Toutes les classes de clients de l'échantillon, plus des clients ordinaires de chaque réseau et hors réseau.
CLIENTS = ["192.168.1.3", "192.168.1.9", "192.168.1.77", "127.0.0.1", "10.10.0.5", "2001:db8:c4e0::3",
           "2001:db8:c4e0::e", "2001:db8:c4e0::1", "2001:db8:c4e0::99", "2001:db8:c4e0::13", "::1"]


def _adult_sync(monkeypatch):
    fl = types.ModuleType("secubox_filterlists")
    fl.OUT_DNS = Path("/nonexistent")
    monkeypatch.setitem(sys.modules, "secubox_filterlists", fl)
    script = RACINE / "packages" / "secubox-ad-guard" / "sbin" / "secubox-adguard-adult-sync"
    loader = importlib.machinery.SourceFileLoader("adult_sync_3893", str(script))
    m = importlib.util.module_from_spec(importlib.util.spec_from_loader("adult_sync_3893", loader))
    loader.exec_module(m)
    return m


def _contenu_93(texte):
    """Les vues de l'ancien 93 : {vue: (zones bloquées, autorisations)}, telles que `generation._zones_vue` les rend."""
    contenu, vue = {}, None
    for ligne in texte.splitlines():
        if (m := re.match(r'\s+name: "([^"]+)"', ligne)):
            vue = m.group(1)
            contenu[vue] = ([], [])
        elif vue and (m := re.match(r'\s+local-zone: "([^"]+)\." (\S+)$', ligne)):
            contenu[vue][0 if m.group(2) == "always_nxdomain" else 1].append(m.group(1))
    return contenu


@pytest.fixture
def rendus(monkeypatch, tmp_path):
    """Trois dossiers de sources : l'ancien format (gk2), le nouveau (générateurs modifiés), le nouveau déplié (mode direct)."""
    adult = _adult_sync(monkeypatch)
    monkeypatch.setattr(adult, "_exempt_ips", lambda: list(R.EXEMPTES))
    ancien93 = R.SOURCES[N93]
    tete = ancien93[:ancien93.index("view:\n")]
    neuf = {N93: tete + "".join(G._vues_compactes(_contenu_93(ancien93))), N95: R.SOURCES[N95],
            N96: adult._render(set(R.ADULTE), set(R.GENERAL))}
    dossiers = {}
    for cle, textes in (("ancien", R.SOURCES), ("compact", neuf), ("deplie", {n: L.developper(t) for n, t in neuf.items()})):
        d = tmp_path / cle
        d.mkdir()
        for n, t in textes.items():
            (d / n).write_text(t)
        dossiers[cle] = d
    ctx = tmp_path / "conf.d"
    ctx.mkdir()
    (ctx / "10-acl.conf").write_text(ACL)
    return dossiers, ctx


def _sources(d):
    return [d / n for n in L.SOURCES_CONNUES]


def _resume(cfg):
    return (cfg.zones, cfg.zones_sources, {b: dict(z) for b, z in cfg.ov_par_bloc.items() if z}, cfg.ov_contexte,
            {v: (x["first"], x["zones"], x["fichier"]) for v, x in cfg.vues.items()}, cfg.acv, cfg.acl, cfg.allow)


def _noms():
    """Chaque zone de l'échantillon, son apex, un sous-domaine, et un nom qu'aucune liste ne porte."""
    zones = set()
    for t in R.SOURCES.values():
        zones |= {m.group(1) for m in re.finditer(r'local-zone: "([^"]+)\."', t)}
    noms = set(zones)
    for z in zones:
        noms |= {"www." + z, "x3893." + z, z.split(".", 1)[-1]}
    return sorted(noms | {"libre-3893.example"})


# ── forme de la source ───────────────────────────────────────────────────────

def test_adulte_deplie_donne_l_ancien_rendu_octet_pour_octet(rendus):
    d, _ = rendus
    compact = (d["compact"] / N96).read_text()
    assert "local-zone-override" not in compact and compact.count("secubox-derogation:") == len(R.EXEMPTES)
    assert L.developper(compact) == R.SOURCES[N96]
    assert len(compact.splitlines()) * 5 < len(R.SOURCES[N96].splitlines())


def test_filtre_web_chaque_zone_ecrite_une_fois_et_memes_lignes_par_vue(rendus):
    d, _ = rendus
    compact = (d["compact"] / N93).read_text()
    paires = {(v, z) for v, (b, a) in _contenu_93(R.SOURCES[N93]).items() for z in [(x, "n") for x in b] + [(x, "t") for x in a]}
    distinctes = {z for _, z in paires}
    assert compact.count("local-zone:") == len(distinctes) < len(paires)

    def par_vue(t):
        out, v = {}, None
        for ligne in t.splitlines():
            if (m := re.match(r'\s+name: "([^"]+)"', ligne)):
                v = m.group(1)
            elif v and ligne.strip().startswith(("local-zone:", "view-first:")):
                out.setdefault(v, []).append(ligne.strip())
        return {k: sorted(x) for k, x in out.items()}
    assert par_vue(L.developper(compact)) == par_vue(R.SOURCES[N93])
    assert not L.compacte(L.developper(compact)) and "secubox-ensemble" not in L.developper(compact)


def test_une_seule_vue_aucun_ensemble_texte_de_toujours():
    lignes = G._vues_compactes({"wf-defaut": (["a.example", "b.example"], ["ok.example"])})
    assert "".join(lignes) == ('view:\n    name: "wf-defaut"\n    view-first: yes\n'
                               '    local-zone: "a.example." always_nxdomain\n    local-zone: "b.example." always_nxdomain\n'
                               '    local-zone: "ok.example." transparent\n')


def test_sans_directive_compacte_le_texte_est_rendu_tel_quel():
    t = R.SOURCES[N95]
    assert not L.compacte(t) and L.developper(t) is t


# ── mêmes décisions ──────────────────────────────────────────────────────────

def test_meme_configuration_lue_ancienne_compacte_ou_depliee(rendus):
    d, ctx = rendus
    lu = {k: _resume(L.lire(_sources(d[k]) + [ctx / "10-acl.conf"])) for k in d}
    assert lu["compact"] == lu["ancien"] and lu["deplie"] == lu["ancien"]


def test_memes_decisions_pour_chaque_client_et_chaque_nom(rendus):
    d, ctx = rendus
    cfgs = {k: L.lire(_sources(d[k]) + [ctx / "10-acl.conf"]) for k in d}
    modeles = {k: L._Modele(c, set()) for k, c in cfgs.items()}
    classes = {str(ipaddress.ip_network(b).network_address) for c in cfgs.values() for b in (*c.acv, *c.ov_par_bloc)}
    noms = _noms()
    ordinaire = modeles["ancien"].profil(ipaddress.ip_network("192.168.1.77"))
    ecarts, exemptions = [], 0
    for ip in sorted(set(CLIENTS) | classes):
        profils = {k: m.profil(ipaddress.ip_network(ip)) for k, m in modeles.items()}
        for q in noms:
            vu = {k: m.decision(q, profils[k]) for k, m in modeles.items()}
            if len(set(vu.values())) != 1:
                ecarts.append((ip, q, vu))
            if ip == "192.168.1.3" and not vu["ancien"] and modeles["ancien"].decision(q, ordinaire):
                exemptions += 1
    assert ecarts == []
    assert exemptions > 50                     # l'échantillon exerce bien l'exemption adulte (sinon le test ne prouverait rien)


def test_le_92_compile_est_identique_octet_pour_octet(rendus):
    d, ctx = rendus
    t_ancien, s_ancien = L.compiler(_sources(d["ancien"]), [ctx / "10-acl.conf"])
    t_neuf, s_neuf = L.compiler(_sources(d["compact"]), [ctx / "10-acl.conf"])
    assert t_neuf == t_ancien
    for s in (s_ancien, s_neuf):
        s.pop("duree_s")
    assert s_neuf == s_ancien and s_neuf["etiquettes"] > 0


# ── lecture stricte de la forme compacte ─────────────────────────────────────

@pytest.mark.parametrize("texte, motif", [
    ('view:\n    name: "v"\n    secubox-ensemble: "absent"\n', "ensemble inconnu"),
    ('secubox-ensemble:\n    name: "e"\nsecubox-ensemble:\n    name: "e"\n', "déjà déclaré"),
    ('server:\n    local-zone: "a.example." always_nxdomain\n    secubox-derogation: 192.168.1.3 always_transparent\n'
     '    local-zone: "b.example." always_nxdomain\n', "après une dérogation"),
    ('server:\n    secubox-derogation: 192.168.1.3 always_transparent\n    secubox-derogation-zone: "b.example."\n',
     "après une dérogation"),
    ('server:\n    secubox-derogation: pas-une-adresse always_transparent\n', "bloc d'adresses invalide"),
    ('secubox-ensemble:\n    name: "e"\n    local-data: "x. A 1.2.3.4"\n', "local-data"),
])
def test_une_forme_compacte_douteuse_est_refusee(tmp_path, texte, motif):
    f = tmp_path / N93
    f.write_text(texte)
    with pytest.raises(L.ErreurListes, match=motif):
        L.lire([f], sources=[N93])


def test_une_directive_compacte_hors_d_une_source_n_est_pas_lue(tmp_path):
    """Un fichier de contexte est chargé tel quel par Unbound : le compilateur n'y prête aucun sens SecuBox."""
    f = tmp_path / "50-autre.conf"
    f.write_text('server:\n    local-zone: "a.example." always_nxdomain\n    secubox-derogation: 192.168.1.3 always_transparent\n')
    assert not L.lire([f], sources=[]).ov_par_bloc


# ── dépôt : mode direct ──────────────────────────────────────────────────────

class _Faux(D.SystemeUnbound):
    MODULE = "test"

    def verifier_unbound(self):
        return True, ""

    def recharger_unbound(self):
        pass

    def audit(self, action, detail=""):
        pass


def test_mode_direct_pose_la_source_depliee_et_ne_la_readopte_pas(rendus, tmp_path):
    d, _ = rendus
    conf = tmp_path / "unbound.conf.d"
    conf.mkdir()
    (conf / "10-acl.conf").write_text(ACL)
    lieux = {"sources": tmp_path / "srcs", "conf_d": conf, "etat": tmp_path / "etat.json",
             "reglages": tmp_path / "dns-listes.toml", "verrou": tmp_path / "verrou"}
    for n in (N93, N96):
        D.deposer_source(n, (d["compact"] / n).read_text(), lieux["sources"])
    lieux["reglages"].write_text('mode = "direct"\n')
    assert D.appliquer(systeme=_Faux(), **lieux)["etat"] == "applique"
    assert (conf / N96).read_text() == R.SOURCES[N96]                          # l'ancien rendu, octet pour octet
    assert (conf / N93).read_text() == (d["deplie"] / N93).read_text()
    lieux["reglages"].write_text('mode = "compile"\n')                          # retour au mode compilé
    r = D.appliquer(systeme=_Faux(), **lieux)
    assert r["etat"] == "applique" and r["adoptes"] == []                       # le fichier déplié n'est pas « plus récent »
    assert (lieux["sources"] / N96).read_text() == (d["compact"] / N96).read_text()
