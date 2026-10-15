# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2748 — sur une image neuve, un module servi par groupd (ad-guard) doit l'être pour de bon.

CONSTAT (RPi400, 2026-10-15) : ad-guard n'a plus d'unité d'API depuis #1362 (« servi par groupd »), mais aucun paquet ne
déposait sa déclaration dans groupable.d ni ne créait de groupe : 35 modules sur 100 n'étaient servis par personne.
Parade : une unité `secubox-groupe-declares` sert TOUT ce qui s'est déclaré, activée par l'activateur seulement quand
l'opérateur n'a aucun groupe à lui (sur gk2, g1..g6 servent déjà ces modules : deux serveurs sur une socket, c'est un module mort)."""
import os
import subprocess
from pathlib import Path

PKG = Path(__file__).resolve().parents[1]
PAQUETS = PKG.parent
ACTIVATEUR = PKG / "sbin" / "secubox-groupe-declares-activer"
UNITE = PKG / "systemd" / "secubox-groupe-declares.service"


def lance(tmp_path, groupes=(), actif=False):
    gd = tmp_path / "groups.d"
    gd.mkdir()
    for g in groupes:
        (gd / g).write_text("ad-guard\n")
    journal = tmp_path / "systemctl.log"
    faux = tmp_path / "bin"
    faux.mkdir()
    (faux / "systemctl").write_text(
        f"#!/bin/sh\necho \"$*\" >> {journal}\ncase \"$1\" in is-active) {'exit 0' if actif else 'exit 3'};; esac\nexit 0\n")
    (faux / "systemctl").chmod(0o755)
    r = subprocess.run(["sh", str(ACTIVATEUR)], capture_output=True, text=True,
                       env={"PATH": f"{faux}:/usr/bin:/bin", "SECUBOX_GROUPS_D": str(gd)})
    return r, (journal.read_text().splitlines() if journal.exists() else [])


def test_sans_groupe_l_unite_est_activee_et_demarree(tmp_path):
    r, appels = lance(tmp_path)
    assert r.returncode == 0, r.stderr
    assert "enable secubox-groupe-declares.service" in appels and "start --no-block secubox-groupe-declares.service" in appels


def test_une_unite_deja_en_marche_est_relancee_pour_prendre_le_nouveau_module(tmp_path):
    r, appels = lance(tmp_path, actif=True)
    assert r.returncode == 0 and "restart --no-block secubox-groupe-declares.service" in appels
    assert "start --no-block secubox-groupe-declares.service" not in appels


def test_avec_des_groupes_de_l_operateur_on_ne_touche_a_rien(tmp_path):
    r, appels = lance(tmp_path, groupes=("g1.conf", "tout.conf"))
    assert r.returncode == 0 and appels == [], "sur gk2 les groupes servent déjà ces modules"


def test_une_sauvegarde_de_groupe_n_est_pas_un_groupe(tmp_path):
    r, appels = lance(tmp_path, groupes=("tout.conf.avant-rustdesk",))
    assert "enable secubox-groupe-declares.service" in appels


def test_l_activateur_ne_bloque_jamais_dpkg(tmp_path):
    assert subprocess.run(["sh", "-n", str(ACTIVATEUR)]).returncode == 0
    assert "--no-block" in ACTIVATEUR.read_text()


def test_l_unite_sert_les_declarations_avec_le_meme_durcissement_que_les_groupes():
    t = UNITE.read_text()
    assert "secubox-groupd --declarations" in t and "User=secubox" in t and "LimitNOFILE=65536" in t
    assert "RuntimeDirectory" not in t.replace("PAS DE RuntimeDirectory", "")
    assert "WantedBy=multi-user.target" in t


def test_l_agregateur_livre_l_unite_et_l_activateur_et_les_appelle():
    rules = (PKG / "debian" / "rules").read_text()
    assert "secubox-groupe-declares.service" in rules and "secubox-groupe-declares-activer" in rules
    assert "secubox-groupe-declares-activer" in (PKG / "debian" / "postinst").read_text()


def test_ad_guard_se_declare_groupable_et_appelle_l_activateur():
    decl = PAQUETS / "secubox-ad-guard" / "groupable.d" / "ad-guard"
    assert decl.is_file()
    assert "groupable.d" in (PAQUETS / "secubox-ad-guard" / "debian" / "rules").read_text()
    post = (PAQUETS / "secubox-ad-guard" / "debian" / "postinst").read_text()
    assert "secubox-groupe-declares-activer" in post
    assert subprocess.run(["sh", "-n", str(PAQUETS / "secubox-ad-guard" / "debian" / "postinst")]).returncode == 0
    assert "secubox-aggregator" in (PAQUETS / "secubox-ad-guard" / "debian" / "control").read_text()


def test_debhelper_n_active_ni_ne_demarre_l_unite_a_la_place_de_l_activateur():
    """RÉGRESSION gk2 : dh_installsystemd activait et démarrait l'unité (lien créé par dpkg) alors que gk2 a ses groupes -> deux serveurs sur les mêmes sockets.
    Seul l'activateur, qui regarde groups.d, décide."""
    rules = (PKG / "debian" / "rules").read_text()
    assert "override_dh_installsystemd" in rules
    bloc = rules[rules.index("override_dh_installsystemd"):]
    assert "--name=secubox-groupe-declares" in bloc and "--no-enable" in bloc and "--no-start" in bloc
