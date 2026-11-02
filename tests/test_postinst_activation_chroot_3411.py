# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Images : services des modules jamais activés (ref #3411).

Les images (image/build-*.sh) installent les paquets dans un chroot où /run/systemd/system n'existe pas. Un postinst qui ne
fait `systemctl enable` que sous `if [ -d /run/systemd/system ]` saute donc l'activation, et l'unité reste disabled sur la
box flashée (gk7 : secubox-freebox en 502). L'activation doit se faire hors de ce test (deb-systemd-helper enable) ; seul le
démarrage reste conditionné."""
import re
from pathlib import Path

import pytest

RACINE = Path(__file__).resolve().parents[1]

# Exceptions justifiées : chemin relatif -> raison. Vide à ce jour.
LISTE_BLANCHE: dict[str, str] = {}

GARDE = re.compile(r"^(\s*)if .*\[ -d /run/systemd/system \].*; then\s*$")
ACTIVATION = re.compile(r"^\s*systemctl\s+(?:--\S+\s+)*enable\b")


def _postinsts():
    for p in sorted((RACINE / "packages").rglob("*")):
        if not p.is_file():
            continue
        if not (p.name == "postinst" or p.name.endswith(".postinst")):
            continue
        rel = p.relative_to(RACINE).as_posix()
        # Arbres de construction debhelper (debian/<paquet>/...) : copies, pas des sources.
        if re.search(r"/debian/[^/]+/", rel):
            continue
        yield rel, p.read_text(encoding="utf-8", errors="replace")


def activations_sous_garde(texte: str) -> list[int]:
    """Numéros de ligne des `systemctl enable` placés dans un bloc `if [ -d /run/systemd/system ]`."""
    lignes = texte.split("\n")
    fautes, pile = [], []
    for n, ligne in enumerate(lignes, 1):
        m = GARDE.match(ligne)
        if m:
            pile.append(m.group(1))
            continue
        if pile and re.match(r"^" + re.escape(pile[-1]) + r"fi\b", ligne):
            pile.pop()
            continue
        if pile and ACTIVATION.match(ligne):
            fautes.append(n)
    return fautes


def test_le_detecteur_attrape_le_motif_fautif():
    fautif = "if [ -d /run/systemd/system ]; then\n  systemctl daemon-reload\n  systemctl enable --now x.timer || true\nfi\n"
    assert activations_sous_garde(fautif) == [3]
    sain = ("deb-systemd-helper enable x.timer >/dev/null 2>&1 || true\n"
            "if [ -d /run/systemd/system ]; then\n  systemctl start x.timer || true\nfi\n")
    assert activations_sous_garde(sain) == []


def test_aucun_postinst_ne_conditionne_l_activation_a_systemd_en_marche():
    fautes = []
    vus = 0
    for rel, texte in _postinsts():
        vus += 1
        if rel in LISTE_BLANCHE:
            continue
        for n in activations_sous_garde(texte):
            fautes.append(f"{rel}:{n}")
    assert vus > 50, "inventaire des postinst anormalement court"
    assert not fautes, ("`systemctl enable` sous `[ -d /run/systemd/system ]` : sauté dans le chroot des images ; "
                        "activer avec deb-systemd-helper enable hors du test (#3411) :\n  " + "\n  ".join(fautes))


# Activation forcée (sans was-enabled) admise : chemin -> raison.
ENABLE_FORCE = {"packages/secubox-metrics/debian/postinst": "#1368 : API du tableau de bord toujours armée"}

# Jamais activés par un paquet : l'opérateur (ou le contrôleur) décide.
INTERDITS = ("secubox-lan-dhcp", "secubox-authwatch", "sbxdpi", "secubox-toolbox-egress-proxy")

# Postinst corrigés par #3411 : le motif debhelper y est exigé.
CORRIGES = [f"packages/secubox-{m}/debian/postinst" for m in (
    "ipv6guard", "freebox", "ephemeride", "pseudo-routeur", "mesh", "netmodes", "metrics", "pilotage",
    "pilotage-agent", "toolbox", "core", "waf-ng")] + [
    "packages/secubox-annuaire/composants/openpgp/debian/postinst",
    "packages/secubox-auth/composants/sbxid/debian/postinst"]

MOTIF = re.compile(r'if deb-systemd-helper --quiet was-enabled "\$_u"; then\n\s*deb-systemd-helper enable "\$_u" >/dev/null \|\| true\n'
                   r'\s*else\n\s*deb-systemd-helper update-state "\$_u" >/dev/null \|\| true\n\s*fi')


@pytest.mark.parametrize("rel", CORRIGES)
def test_motif_debhelper_respecte_un_disable_manuel(rel):
    texte = (RACINE / rel).read_text(encoding="utf-8")
    assert "deb-systemd-helper" in texte
    if rel in ENABLE_FORCE:
        bloc = texte[texte.rindex('if [ "$1" = "configure" ]; then'):]
        assert "deb-systemd-helper enable secubox-metrics.service" in bloc, "enable forcé hors du bloc configure"
        texte = texte[:texte.rindex('if [ "$1" = "configure" ]; then')]
    nus = [l for l in texte.splitlines() if re.match(r'^\s*deb-systemd-helper enable (?!"\$_u")', l)]
    assert not nus, f"enable sans was-enabled : {nus}"
    assert MOTIF.search(texte)


@pytest.mark.parametrize("rel,texte", list(_postinsts()))
def test_services_jamais_actives_par_un_paquet(rel, texte):
    for l in texte.splitlines():
        if re.search(r"(systemctl|deb-systemd-helper)\s+(?:--\S+\s+)*enable\b", l) or l.strip().startswith("for _u in"):
            for u in INTERDITS:
                assert not re.search(rf"\b{re.escape(u)}(\.service)?\b", l), f"{rel} : {u} activé ({l.strip()})"


def test_relais_pilotage_toujours_derriere_relais_pret():
    texte = (RACINE / "packages/secubox-pilotage-agent/debian/postinst").read_text(encoding="utf-8")
    for n, l in enumerate(texte.splitlines()):
        if "secubox-pilotage-relais.socket" in l and re.search(r"enable|for _u in", l):
            avant = texte.splitlines()[max(0, n - 3):n]
            assert any('if [ "$relais_pret" = 1 ]' in a for a in avant), l


def test_liste_blanche_a_jour():
    for rel in LISTE_BLANCHE:
        assert (RACINE / rel).is_file(), f"exception obsolète : {rel}"


def test_image_rpi_ne_rogne_plus_les_services_par_defaut():
    script = (RACINE / "image" / "build-rpi-usb.sh").read_text(encoding="utf-8")
    assert 'BOOT_MINIMAL="${BOOT_MINIMAL:-0}"' in script
    debut = script.index("KIOSK_WANTS_KEEP=(")
    garde = script.rfind('if [[ "${BOOT_MINIMAL}" -eq 1 ]]; then', 0, debut)
    assert garde != -1, "le rognage de multi-user.target.wants (#442) doit rester opt-in (--boot-minimal)"
    assert script.rfind("\nfi\n", garde, debut) == -1
