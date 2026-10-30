# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Tous les conteneurs LXC en dernière Debian stable (#3285).

Décision du propriétaire (2026-10-30) : un conteneur créé par nos paquets l'est
dans la suite de l'hôte (dernière stable, trixie aujourd'hui), jamais dans une
suite figée. Ce test balaie les scripts qui créent un conteneur Debian
(`lxc-create -t download … debian`, `debootstrap`) et refuse :
  - une suite `bookworm` écrite en dur dans le code (les commentaires ne
    comptent pas) ;
  - un nouveau créateur qui ne serait recensé ni ici, ni en exception.

EXCEPTIONS : conteneurs laissés en bookworm pour une raison VÉRIFIÉE, écrite
dans le script (« EXCEPTION À #3285 ») et figée par un test du paquet.
HORS_CHAMP : fichiers qui ressemblent à un créateur sans en être un, ou dont le
passage en trixie est porté ailleurs.
"""
import ast
import os
import re
import subprocess
from pathlib import Path

import pytest

RACINE = Path(__file__).resolve().parents[2]

# Créateurs de conteneurs Debian : suite de l'hôte + pièges de trixie traités.
CREATEURS_SHELL = [
    "packages/secubox-clamav/lxc/install-lxc.sh",
    "packages/secubox-gitea/sbin/giteactl",
    "packages/secubox-jellyfin/lib/jellyfin/install-lxc.sh",
    "packages/secubox-jitsi/lib/jitsi/install-lxc.sh",
    "packages/secubox-lyrion/lib/lyrion/install-lxc.sh",
    "packages/secubox-metanews/composants/yacy/lib/yacy/install-lxc.sh",
    "packages/secubox-metrics/composants/grafana/lib/grafana/install-lxc.sh",
    "packages/secubox-mqtt/composants/zigbee/lib/zigbee/install-lxc.sh",
    "packages/secubox-mqtt/lib/mqtt/install-lxc.sh",
    "packages/secubox-nextcloud/sbin/nextcloudctl",
    "packages/secubox-peertube/lib/peertube/install-lxc.sh",
    "packages/secubox-photoprism/lib/photoprism/install-lxc.sh",
    "packages/secubox-streamlit/sbin/streamlitctl",
    "packages/secubox-waf-ng/composants/waf/scripts/wafctl",
    "packages/secubox-ytsas/composants/torrent/lxc/install-lxc.sh",
    "packages/secubox-ytsas/lxc/install-lxc.sh",
]
CREATEURS_PYTHON = [
    "packages/secubox-matrix/api/main.py",
    "packages/secubox-vm/api/main.py",
]
EXCEPTIONS = {
    # venv figé sur Python 3.11 : ctranslate2==4.4.0 n'a aucune roue Python 3.13.
    "packages/secubox-voicestudio/lxc/install-lxc.sh": "ctranslate2==4.4.0",
    # picobrew_pico épingle eventlet==0.36.1 ; Python 3.13 seulement à partir de 0.38.0.
    "packages/secubox-picobrew/sbin/picobrewctl": "eventlet==0.36.1",
}
HORS_CHAMP = {
    # Conteneurs mail et roundcube : passage en trixie porté par la PR #3275 (#3274),
    # qui attend la configuration de Dovecot 2.4.
    "packages/secubox-mail/lib/mail/install.sh",
    # La Suite Meet : déjà créée en trixie (pas de bookworm), hors de ce lot.
    "packages/secubox-meet/lib/meet/install-lxc.sh",
    # Image du live netboot, pas un conteneur.
    "packages/secubox-netboot/scripts/build-live-leger.sh",
}

_CREATION = re.compile(
    r"lxc-create\b.*?(--dist|-d)\s+debian|^\s*debootstrap\s|\"lxc-create\"",
    re.S | re.M,
)


def _code_shell(chemin):
    return [ligne for ligne in (RACINE / chemin).read_text(encoding="utf-8").splitlines()
            if not ligne.lstrip().startswith("#")]


def _sources_candidates():
    for f in sorted((RACINE / "packages").rglob("*")):
        rel = f.relative_to(RACINE).as_posix()
        if not f.is_file() or f.suffix in {".md", ".html", ".json", ".toml", ".example"}:
            continue
        parties = rel.split("/")
        if "debian" in parties or "tests" in parties or "test" in parties:
            continue
        try:
            texte = f.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        if _CREATION.search(texte):
            yield rel


def test_tout_createur_de_conteneur_debian_est_recense():
    connus = set(CREATEURS_SHELL) | set(CREATEURS_PYTHON) | set(EXCEPTIONS) | HORS_CHAMP
    inconnus = sorted(set(_sources_candidates()) - connus)
    assert not inconnus, (
        "Nouveau créateur de conteneur Debian (#3285) : suite de l'hôte (suite_debian_hote), "
        f"puis le recenser ici : {inconnus}"
    )


@pytest.mark.parametrize("chemin", CREATEURS_SHELL)
def test_createur_shell_sans_bookworm_en_dur(chemin):
    fautives = [ligne.strip() for ligne in _code_shell(chemin) if "bookworm" in ligne]
    assert not fautives, f"{chemin} : suite bookworm en dur {fautives}"


@pytest.mark.parametrize("chemin", CREATEURS_SHELL)
def test_createur_shell_traite_les_pieges_de_trixie(chemin):
    texte = (RACINE / chemin).read_text(encoding="utf-8")
    code = "\n".join(_code_shell(chemin))
    assert "suite_debian_hote() {" in texte and "suite_debian_hote)" in texte, chemin
    assert re.search(r'^\s+lxc_sans_credentials "\$', texte, re.M), f"{chemin} : ImportCredential= jamais vidé"
    assert not re.search(r"(?<![A-Za-z_])gnupg(?![A-Za-z_])", code), f"{chemin} : gpg, pas gnupg (#3274)"
    assert not re.search(r"php\d\.\d", code), f"{chemin} : PHP sans version en dur"


def _fonction_shell(chemin):
    texte = (RACINE / chemin).read_text(encoding="utf-8")
    return re.search(r"^suite_debian_hote\(\) \{\n.*?^\}\n", texte, re.M | re.S).group(0)


def test_une_seule_definition_de_la_suite_par_defaut():
    """Les copies locales du helper shell sont identiques (même règle partout)."""
    copies = {_fonction_shell(c) for c in CREATEURS_SHELL}
    assert len(copies) == 1, "suite_debian_hote() diverge d'un script à l'autre"


@pytest.mark.parametrize("contenu,attendu", [
    ("ID=debian\nVERSION_CODENAME=trixie\n", "trixie"),
    ('ID=debian\nVERSION_CODENAME="forky"\n', "forky"),
    ("ID=ubuntu\nVERSION_CODENAME=noble\n", "trixie"),
    ("ID=debian\nVERSION_CODENAME='a b'\n", "trixie"),
    (None, "trixie"),
])
def test_suite_shell_lue_dans_os_release(tmp_path, contenu, attendu):
    osr = tmp_path / "os-release"
    if contenu is not None:
        osr.write_text(contenu)
    fonction = _fonction_shell(CREATEURS_SHELL[0])
    sortie = subprocess.run(["bash", "-c", fonction + "suite_debian_hote"], check=True, timeout=10,
                            capture_output=True, text=True,
                            env={"SECUBOX_OS_RELEASE": str(osr), "PATH": "/usr/bin:/bin"})
    assert sortie.stdout.strip() == attendu


@pytest.mark.parametrize("chemin", CREATEURS_PYTHON)
def test_createur_python_suite_de_l_hote(chemin, tmp_path, monkeypatch):
    texte = (RACINE / chemin).read_text(encoding="utf-8")
    assert not re.search(r'(release: str = |"-r", )"bookworm"|debian/ bookworm', texte), chemin
    arbre = ast.parse(texte)
    noeuds = [n for n in arbre.body
              if (isinstance(n, ast.FunctionDef) and n.name == "suite_debian_hote")
              or (isinstance(n, ast.Assign) and any(getattr(c, "id", "") == "SUITE_DEBIAN_REPLI" for c in n.targets))]
    espace = {"os": os, "re": re}
    exec(compile(ast.Module(body=noeuds, type_ignores=[]), chemin, "exec"), espace)
    monkeypatch.delenv("SECUBOX_DEBIAN_SUITE", raising=False)
    osr = tmp_path / "os-release"
    osr.write_text("ID=debian\nVERSION_CODENAME=forky\n")
    assert espace["suite_debian_hote"](str(osr)) == "forky"
    assert espace["suite_debian_hote"](str(tmp_path / "absent")) == "trixie"


@pytest.mark.parametrize("chemin,motif", sorted(EXCEPTIONS.items()))
def test_exceptions_explicites_et_motivees(chemin, motif):
    texte = (RACINE / chemin).read_text(encoding="utf-8")
    assert "EXCEPTION À #3285" in texte and motif in texte, chemin
    code = [ligne for ligne in _code_shell(chemin) if "bookworm" in ligne]
    assert len(code) == 1 and "${SECUBOX_DEBIAN_SUITE:-bookworm}" in code[0], (
        f"{chemin} : bookworm seulement comme défaut surchargeable, une fois : {code}"
    )
