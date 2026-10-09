# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""#2050 N1 : defaults est absorbé par core, groupd par aggregator ; les anciens deviennent des transitoires vides."""
import re
from pathlib import Path

PAQ = Path(__file__).resolve().parents[2] / "packages"
ANCIENS = {"defaults": ("core", "1.6.0"), "groupd": ("aggregator", "0.4.0")}


def _c(p):
    return (PAQ / p / "debian/control").read_text()


def test_anciens_sont_retires_du_depot():
    for ancien in ANCIENS:
        assert not (PAQ / f"secubox-{ancien}").exists(), f"secubox-{ancien} : transitoire à retirer"


def test_les_absorbants_remplacent_et_cassent_les_anciens():
    assert re.search(r"secubox-defaults \(<< 1\.0\.3~\)", _c("secubox-core"))
    assert re.search(r"secubox-groupd \(<< 0\.3\.1~\)", _c("secubox-aggregator"))
    for fn in ("Replaces", "Breaks"):
        assert re.search(rf"(?m)^{fn}:.*secubox-defaults \(<< 1\.0\.3~\)", _c("secubox-core")), fn
        assert re.search(rf"(?m)^{fn}:.*secubox-groupd \(<< 0\.3\.1~\)", _c("secubox-aggregator")), fn


def test_core_porte_l_identite_de_la_box():
    assert (PAQ / "secubox-core/etc/default/secubox").is_file()
    assert (PAQ / "secubox-core/sbin/secubox-defaults-aligner").is_file()
    assert (PAQ / "secubox-core/tests/test_aligner_1845.py").is_file()
    rules = (PAQ / "secubox-core/debian/rules").read_text()
    assert "secubox-defaults-aligner" in rules and "etc/default/secubox" in rules
    post = (PAQ / "secubox-core/debian/postinst").read_text()
    assert "secubox-defaults-aligner" in post
    # le declencheur ne part QUE si l'alignement a change le fichier (sinon haproxy regenere a chaque montee de core)
    assert re.search(r"cksum|sha256sum|md5sum", post) and "dpkg-trigger secubox-defaults-changed" in post


def test_aggregator_porte_l_hote_de_groupe():
    for f in ("sbin/secubox-groupd", "systemd/secubox-group@.service", "systemd/secubox-group-root@.service"):
        assert (PAQ / f"secubox-aggregator/{f}").is_file(), f
    rules = (PAQ / "secubox-aggregator/debian/rules").read_text()
    for s in ("secubox-groupd", "secubox-group@.service", "secubox-group-root@.service", "groupable.d",
              "groupable-root.d", "groups.d"):
        assert s in rules, s


def test_plus_aucun_paquet_ne_depend_des_anciens():
    motif = re.compile(r"secubox-(defaults|groupd)\b")
    liens = ("Depends", "Pre-Depends", "Recommends", "Suggests", "Enhances")
    for ctrl in PAQ.glob("*/debian/control"):
        nom = ctrl.parts[-3].removeprefix("secubox-")
        if nom in ANCIENS or "/debian/secubox-" in str(ctrl):
            continue
        champ = None
        for ligne in ctrl.read_text().splitlines():
            if ligne and not ligne[0].isspace():
                champ = ligne.split(":", 1)[0]
            if champ in liens and motif.search(ligne):
                raise AssertionError(f"{ctrl} : {ligne.strip()}")


def test_arbre_les_met_hors_arbre():
    arbre = (PAQ / "secubox-meta/arbre.yaml").read_text()
    avant, _, apres = arbre.partition("# ═══ RACINES")
    for s in ANCIENS:
        assert re.search(rf"secubox-{s}\b", avant), s
        assert not re.search(rf"(?m)^\s+- secubox-{s}\b", apres), s
