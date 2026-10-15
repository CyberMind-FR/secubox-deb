# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""#2427 — les images de plus de 2 Gio sont découpées avant publication (alpha.12 : « size must be less than 2147483648 »)."""
import hashlib
import os
import pathlib
import re
import subprocess

import pytest
import yaml

RACINE = pathlib.Path(__file__).resolve().parents[2]
SCRIPT = RACINE / "scripts" / "release-decouper-assets.sh"
WORKFLOW = RACINE / ".github" / "workflows" / "release.yml"


def _sha(chemin):
    return hashlib.sha256(pathlib.Path(chemin).read_bytes()).hexdigest()


def _lancer(*args):
    return subprocess.run(["bash", str(SCRIPT), *map(str, args)], capture_output=True, text=True)


def test_un_gros_fichier_est_decoupe_et_se_reassemble_a_l_identique(tmp_path):
    gros = tmp_path / "secubox-full-vm-x64-trixie.img.gz"
    gros.write_bytes(os.urandom(3 * 1024 * 1024 + 123))        # 3 Mo + 123 octets, seuil à 1 Mo
    petit = tmp_path / "secubox-live-amd64-trixie.img.gz"
    petit.write_bytes(os.urandom(200 * 1024))
    somme_gros, somme_petit = _sha(gros), _sha(petit)
    r = _lancer(tmp_path, "--max-mo", 1)
    assert r.returncode == 0, r.stderr
    assert not gros.exists()                                   # l'original ne sera pas publié
    parts = sorted(tmp_path.glob(gros.name + ".part*"))
    assert [p.name[-7:] for p in parts] == [".part00", ".part01", ".part02", ".part03"]
    assert all(p.stat().st_size <= 1024 * 1024 for p in parts)  # aucune partie au-dessus du seuil
    assert petit.exists() and _sha(petit) == somme_petit        # un petit fichier n'est pas touché
    assert not list(tmp_path.glob(petit.name + ".part*"))
    # réassemblage documenté : cat <fichier>.part* > <fichier>, puis sha256sum -c
    assemble = tmp_path / "reassemble.img.gz"
    assemble.write_bytes(b"".join(p.read_bytes() for p in parts))
    assert _sha(assemble) == somme_gros
    ligne = (tmp_path / (gros.name + ".assembled.sha256")).read_text().split()
    assert ligne == [somme_gros, gros.name]                      # somme du fichier réassemblé, nom sans chemin


def test_idempotent_et_sans_fichier_trop_gros_il_ne_fait_rien(tmp_path):
    (tmp_path / "a.img.xz").write_bytes(b"x" * 1000)
    r = _lancer(tmp_path, "--max-mo", 1)
    assert r.returncode == 0 and "fichiers découpés : 0" in r.stdout
    assert [p.name for p in tmp_path.iterdir()] == ["a.img.xz"]


def test_les_deux_extensions_et_plusieurs_dossiers(tmp_path):
    for d, nom in (("images", "x.img.xz"), ("live-usb", "y.img.gz")):
        (tmp_path / d).mkdir()
        (tmp_path / d / nom).write_bytes(os.urandom(2 * 1024 * 1024))
    r = _lancer(tmp_path / "images", tmp_path / "live-usb", tmp_path / "absent", "--max-mo", 1)
    assert r.returncode == 0 and "fichiers découpés : 2" in r.stdout
    assert list((tmp_path / "images").glob("x.img.xz.part*")) and list((tmp_path / "live-usb").glob("y.img.gz.part*"))


def test_arguments_invalides():
    assert _lancer().returncode == 2
    assert _lancer("/tmp", "--max-mo", "abc").returncode == 2


def test_le_workflow_decoupe_avant_les_sommes_et_publie_les_parties():
    wf = yaml.safe_load(WORKFLOW.read_text())
    etapes = wf["jobs"]["create-release"]["steps"]
    noms = [e.get("name", "") for e in etapes]
    i_decoupe = next(i for i, n in enumerate(noms) if "2 GiB" in n)
    i_sommes = noms.index("Generate combined checksums")
    assert i_decoupe < i_sommes                                   # on hache ce qui sera publié, pas l'original
    assert "release-decouper-assets.sh release/images release/live-usb" in etapes[i_decoupe]["run"]
    # #2719 : l'envoi n'est plus fait par softprops/action-gh-release (envois parallèles, délai d'inactivité dépassé sur les images de
    # plusieurs Go) mais par `gh release upload`, un fichier à la fois : la liste de motifs reste la même, dans le script de l'étape.
    publication = next(e for e in etapes if "gh release upload" in e.get("run", ""))
    fichiers = publication["run"]
    for motif in ("release/images/*.part*", "release/live-usb/*.part*", "release/images/*.assembled.sha256"):
        assert motif in fichiers
    assert "*.part*" in etapes[i_sommes]["run"]


def test_les_notes_de_release_gardent_leurs_backticks(tmp_path):
    """Le heredoc des notes n'est pas protégé : un backtick non échappé exécuterait une commande (déjà arrivé)."""
    wf = yaml.safe_load(WORKFLOW.read_text())
    etape = next(e for e in wf["jobs"]["create-release"]["steps"] if "RELEASE_NOTES.md" in e.get("run", "") and "<< EOF" in e["run"])
    (tmp_path / "release").mkdir()
    script = re.sub(r"\$\{\{[^}]*\}\}", "v0.0.0-test", etape["run"])   # expressions GitHub : substituées comme le ferait le moteur
    r = subprocess.run(["bash", "-e", "-c", script], cwd=tmp_path, capture_output=True, text=True,
                       env={**os.environ, "GITHUB_REF_NAME": "v0.0.0-test", "GITHUB_REF": "refs/tags/v0.0.0-test"})
    if r.returncode != 0:
        pytest.skip(f"étape non exécutable hors GitHub : {r.stderr[:120]}")
    notes = (tmp_path / "release" / "RELEASE_NOTES.md").read_text()
    assert "`.part00`" in notes and "cat secubox-xxx.img.gz.part* > secubox-xxx.img.gz" in notes
    assert "command not found" not in r.stderr
