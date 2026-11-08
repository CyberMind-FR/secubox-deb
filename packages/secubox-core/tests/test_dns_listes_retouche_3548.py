# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3548 — une TV qui change d'adresse : les lignes d'adresses du 92 sont reposées sans recompiler, et le fichier obtenu est
IDENTIQUE à celui d'une compilation complète. Tout autre changement du contexte recompile."""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "common"))
from secubox_unbound import depot as D  # noqa: E402
from secubox_unbound import listes as L  # noqa: E402

ADBLOCK = ('server:\n    local-zone: "ads.example." always_nxdomain\n    local-zone: "a.ads.example." always_nxdomain\n'
           '    local-zone: "track.example." always_nxdomain\n')
ADULT = ('server:\n    local-zone: "porn.example." always_nxdomain\n'
         '    local-zone-override: "porn.example." 192.168.1.50/32 transparent\n')
ACL = "server:\n    access-control: 192.168.1.0/24 allow\n    access-control: 2001:db8::/32 allow\n"


def tv(ips_auto, ips_obs, autorise=None):
    lignes = ["server:"]
    lignes += [f"    access-control-view: {ip} sbx-tv-auto-salon" for ip in ips_auto]
    lignes += [f"    access-control-view: {ip} sbx-tv-observe" for ip in ips_obs]
    for ip in (ips_auto if autorise else []):
        lignes.append(f'    local-zone-override: "{autorise}." {ip} transparent')
    lignes += ['view:', '    name: "sbx-tv-observe"', '    local-zone: "." transparent',
               'view:', '    name: "sbx-tv-auto-salon"', '    view-first: yes', '    local-zone: "tvads.example." always_nxdomain']
    return "\n".join(lignes) + "\n"


@pytest.fixture
def lieux(tmp_path):
    src, conf = tmp_path / "src", tmp_path / "conf"
    src.mkdir(), conf.mkdir()
    (src / "95-secubox-adblock.conf").write_text(ADBLOCK)
    (src / "96-secubox-adult.conf").write_text(ADULT)
    (conf / "10-acl.conf").write_text(ACL)
    return src, conf


def _compiler(src, conf):
    return L.compiler(sorted(src.glob("*.conf")), D.fichiers_contexte(conf))


@pytest.mark.parametrize("autorise", [None, "ads.example"])
def test_retouche_identique_a_la_compilation(lieux, autorise):
    src, conf = lieux
    (conf / "94-tv.conf").write_text(tv(["192.168.1.95/32", "2001:db8::a/128"], ["192.168.1.96/32"], autorise))
    texte, stats = _compiler(src, conf)
    meta = stats["retouche"]
    # la TV prend une IPv6 temporaire nouvelle, perd l'ancienne, et l'appareil observé change d'IPv4
    (conf / "94-tv.conf").write_text(tv(["192.168.1.95/32", "2001:db8::b/128", "2001:db8::c/128"], ["192.168.1.97/32"], autorise))
    r = L.retoucher(texte, meta, D.fichiers_contexte(conf))
    assert r is not None and r[1]["retouche"] is True
    attendu, _ = _compiler(src, conf)
    assert r[0] == attendu


def test_une_vue_nouvelle_recompile(lieux):
    src, conf = lieux
    (conf / "94-tv.conf").write_text(tv(["192.168.1.95/32"], []))
    texte, stats = _compiler(src, conf)
    (conf / "94-tv.conf").write_text(tv(["192.168.1.95/32"], []).replace("tvads.example", "autre.example"))
    assert L.retoucher(texte, stats["retouche"], D.fichiers_contexte(conf)) is None


def test_un_profil_jamais_compile_recompile(lieux):
    """Un appareil observé apparaît alors qu'aucun ne l'était : ses étiquettes sont inconnues."""
    src, conf = lieux
    (conf / "94-tv.conf").write_text(tv(["192.168.1.95/32"], []))
    texte, stats = _compiler(src, conf)
    (conf / "94-tv.conf").write_text(tv(["192.168.1.95/32"], ["10.9.9.9/32"]))
    assert L.retoucher(texte, stats["retouche"], D.fichiers_contexte(conf)) is None


def test_meta_absente_ou_illisible(lieux):
    src, conf = lieux
    (conf / "94-tv.conf").write_text(tv(["192.168.1.95/32"], []))
    texte, _ = _compiler(src, conf)
    assert L.retoucher(texte, None, D.fichiers_contexte(conf)) is None
    assert L.retoucher(texte, {"version": 9}, D.fichiers_contexte(conf)) is None


class Faux(D.SystemeUnbound if hasattr(D, "SystemeUnbound") else object):
    MODULE = "test"

    def __init__(self):
        self.appels = []

    def verifier_unbound(self):
        self.appels.append("verifier")
        return True, ""

    def recharger_unbound(self):
        self.appels.append("recharger")

    def audit(self, action, detail=""):
        pass


def test_depot_retouche_sans_compiler(tmp_path, monkeypatch):
    conf = tmp_path / "unbound.conf.d"
    conf.mkdir()
    (conf / "10-acl.conf").write_text(ACL)
    (conf / "94-tv.conf").write_text(tv(["192.168.1.95/32", "2001:db8::a/128"], ["192.168.1.96/32"], "ads.example"))
    lieux = {"sources": tmp_path / "sources", "conf_d": conf, "etat": tmp_path / "etat.json",
             "reglages": tmp_path / "dns-listes.toml", "verrou": tmp_path / "verrou"}
    D.deposer_source("95-secubox-adblock.conf", ADBLOCK, lieux["sources"])
    vrai, appels = L.compiler, []
    monkeypatch.setattr(L, "compiler", lambda *a: appels.append(1) or vrai(*a))
    assert D.appliquer(systeme=Faux(), **lieux)["etat"] == "applique" and len(appels) == 1
    assert (tmp_path / "retouche.json").is_file()
    (conf / "94-tv.conf").write_text(tv(["192.168.1.95/32", "2001:db8::b/128"], ["192.168.1.97/32"], "ads.example"))
    s = Faux()
    r = D.appliquer(systeme=s, **lieux)
    assert r["etat"] == "applique" and len(appels) == 1 and s.appels == ["verifier", "recharger"]
    assert 'access-control-tag: 192.168.1.97/32 "sbx0"' in (conf / "92-secubox-listes.conf").read_text()
    assert "192.168.1.96/32" not in (conf / "92-secubox-listes.conf").read_text()
    D.deposer_source("96-secubox-adult.conf", ADULT, lieux["sources"])   # une source : compilation complète
    D.appliquer(systeme=Faux(), **lieux)
    assert len(appels) == 2


def test_une_adresse_changee_pendant_la_compilation_est_retouchee(tmp_path, monkeypatch):
    """Sur gk2 chargé, une compilation dure plusieurs minutes : une TV change d'adresse pendant. La passe de rattrapage
    repose les adresses, elle ne recompile pas."""
    conf = tmp_path / "unbound.conf.d"
    conf.mkdir()
    (conf / "10-acl.conf").write_text(ACL)
    (conf / "94-tv.conf").write_text(tv(["192.168.1.95/32"], ["192.168.1.96/32"], "ads.example"))
    lieux = {"sources": tmp_path / "sources", "conf_d": conf, "etat": tmp_path / "etat.json",
             "reglages": tmp_path / "dns-listes.toml", "verrou": tmp_path / "verrou"}
    D.deposer_source("95-secubox-adblock.conf", ADBLOCK, lieux["sources"])
    vrai, appels = L.compiler, []

    def compiler(*a):
        appels.append(1)
        r = vrai(*a)
        if len(appels) == 1:                                   # pendant la compilation : l'appareil observé change d'adresse
            (conf / "94-tv.conf").write_text(tv(["192.168.1.95/32"], ["192.168.1.97/32"], "ads.example"))
        return r
    monkeypatch.setattr(L, "compiler", compiler)
    r = D.appliquer(systeme=Faux(), **lieux)
    assert r["etat"] == "applique" and r["passes"] == 2 and len(appels) == 1
    assert 'access-control-tag: 192.168.1.97/32 "sbx0"' in (conf / "92-secubox-listes.conf").read_text()
