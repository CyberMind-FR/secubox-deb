# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2719 — les releases alpha.16 et alpha.17 sont sorties incomplètes : envoi des images en échec, publication APT en échec muet,
étape eMMC MOCHAbin au-delà de son délai. Ces tests figent les correctifs du workflow Release."""
import re
import subprocess
from pathlib import Path

import pytest
import yaml

RACINE = Path(__file__).resolve().parents[2]
WORKFLOWS = RACINE / ".github" / "workflows"
RELEASE = yaml.safe_load((WORKFLOWS / "release.yml").read_text())
LIVE_USB = yaml.safe_load((WORKFLOWS / "build-all-live-usb.yml").read_text())
ETAPES = RELEASE["jobs"]["create-release"]["steps"]


def _etape_envoi():
    return next(e for e in ETAPES if "gh release upload" in e.get("run", ""))


# ---------- envoi des fichiers ----------

def test_plus_d_envoi_parallele_par_l_action_softprops():
    """softprops/action-gh-release envoie tout en parallèle : « Upload body timed out due to inactivity » sur des images de 1 à 2 Go."""
    assert not [e for e in ETAPES if e.get("uses", "").startswith("softprops/action-gh-release")]


def test_l_envoi_est_sequentiel_avec_reprises_et_ecrasement():
    run = _etape_envoi()["run"]
    assert "gh release upload" in run and "--clobber" in run                 # réécrase un fichier déjà là (relance) sans le supprimer avant
    assert re.search(r"for\s+i\s+in\s+1\s+2\s+3\s+4", run)                    # quatre essais par fichier
    assert "sleep" in run                                                      # attente entre deux essais
    assert "xargs -P" not in run and "&\n" not in run and " & " not in run    # jamais en parallèle


def test_la_release_reste_un_brouillon_tant_que_tout_n_est_pas_envoye():
    run = _etape_envoi()["run"]
    assert "--draft" in run                                                    # créée (ou repassée) en brouillon avant les envois
    i_envoi, i_publi = run.index("gh release upload"), run.rindex("--draft=false")
    assert i_envoi < i_publi                                                   # publiée APRÈS les envois, jamais avant
    assert "exit 1" in run[:i_publi]                                           # un échec définitif arrête avant la publication : elle reste en brouillon


def test_la_publication_verifie_que_chaque_fichier_est_sur_la_release():
    run = _etape_envoi()["run"]
    assert "--json assets" in run and "manquant" in run                       # comparaison des noms locaux et des noms publiés


def test_les_motifs_de_fichiers_publies_n_ont_pas_change():
    run = _etape_envoi()["run"]
    for motif in ("release/images/*.img.gz", "release/images/*.img.xz", "release/images/*.part*", "release/images/*.assembled.sha256",
                  "release/live-usb/*.part*", "release/live-usb/*.assembled.sha256", "release/live-usb/*.img.gz", "release/live-usb/*.img.xz",
                  "release/live-usb/*.sha256", "release/create-qemu-arm64-vm.sh", "release/create-vbox-vm.sh", "release/SHA256SUMS",
                  "release/SHA256SUMS.gpg"):
        assert motif in run, motif
    assert "release/*.deb" not in run and "release/packages" not in run       # PAS DE .deb ici (#1491)


def test_images_avant_live_usb_pour_que_le_dernier_envoye_reste():
    """À nom égal, le DERNIER fichier envoyé reste sur la release (live-usb/ après images/), comme pour SHA256SUMS."""
    run = _etape_envoi()["run"]
    assert run.index("release/images/*.img.gz") < run.index("release/live-usb/*.img.gz")


def test_le_marquage_prerelease_suit_alpha_beta_rc():
    run = _etape_envoi()["run"]
    assert "--prerelease" in run and all(m in run for m in ("*alpha*", "*beta*", "*rc*"))


def test_le_script_d_envoi_est_du_bash_valide_et_sans_backtick():
    run = _etape_envoi()["run"]
    assert "`" not in run                                                      # un backtick dans un run: serait exécuté (déjà arrivé)
    script = re.sub(r"\$\{\{[^}]*\}\}", "v0.0.0-test", run)
    r = subprocess.run(["bash", "-n", "-c", script], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr


def _simuler(tmp_path, echecs_pour=(), toujours=False):
    """Exécute le vrai script d'envoi avec un faux `gh` : journalise les appels, échoue à la demande."""
    (tmp_path / "release" / "images").mkdir(parents=True)
    (tmp_path / "release" / "live-usb").mkdir()
    (tmp_path / "release" / "images" / "a.img.gz").write_text("a")
    (tmp_path / "release" / "images" / "b.img.xz").write_text("b")
    (tmp_path / "release" / "live-usb" / "c.img.gz").write_text("c")
    (tmp_path / "release" / "SHA256SUMS").write_text("s")
    (tmp_path / "release" / "RELEASE_NOTES.md").write_text("notes")
    bin_ = tmp_path / "bin"
    bin_.mkdir()
    (tmp_path / "publies").write_text("")
    (tmp_path / "essais").write_text("")
    (bin_ / "gh").write_text(
        "#!/bin/bash\n"
        f'echo "$@" >> {tmp_path}/appels\n'
        'case "$1 $2" in\n'
        '  "release view") if [ "$3" = "v0.0.0-test" ] && [ "$4" = "--json" ]; then\n'
        f'      cat {tmp_path}/publies; else exit 1; fi ;;\n'
        '  "release create"|"release edit") exit 0 ;;\n'
        '  "release upload")\n'
        '      f="$4"; n=$(basename "$f")\n'
        f'      echo "$n" >> {tmp_path}/essais\n'
        f'      if {"true" if toujours else "false"} && [ "$n" = "b.img.xz" ]; then exit 1; fi\n'
        f'      if [ "$n" = "{echecs_pour[0] if echecs_pour else "-"}" ] && [ "$(grep -c "^$n$" {tmp_path}/essais)" -lt 3 ]; then exit 1; fi\n'
        f'      echo "$n" >> {tmp_path}/publies.txt; exit 0 ;;\n'
        'esac\n')
    (bin_ / "gh").chmod(0o755)
    (bin_ / "sleep").write_text("#!/bin/bash\nexit 0\n")
    (bin_ / "sleep").chmod(0o755)
    return bin_


@pytest.mark.skipif(not __import__("shutil").which("bash"), reason="bash requis")
def test_une_reprise_apres_un_echec_passager_envoie_le_fichier(tmp_path):
    bin_ = _simuler(tmp_path, echecs_pour=("a.img.gz",))
    # `gh release view --json assets` rend ce que le faux gh a « publié » : on le fabrique à la volée
    (bin_ / "gh").write_text((bin_ / "gh").read_text().replace(
        f"cat {tmp_path}/publies; else exit 1; fi ;;",
        f'sort -u {tmp_path}/publies.txt 2>/dev/null; else exit 1; fi ;;'))
    script = re.sub(r"\$\{\{[^}]*\}\}", "v0.0.0-test", _etape_envoi()["run"])
    r = subprocess.run(["bash", "-e", "-c", script], cwd=tmp_path, capture_output=True, text=True,
                       env={"PATH": f"{bin_}:/usr/bin:/bin", "GH_TOKEN": "x", "HOME": str(tmp_path)})
    appels = (tmp_path / "appels").read_text()
    assert (tmp_path / "essais").read_text().splitlines().count("a.img.gz") == 3, r.stderr   # deux échecs, un succès
    assert "release create" in appels or "release edit" in appels
    assert "--draft=false" in appels                                                          # tout est arrivé : publiée


@pytest.mark.skipif(not __import__("shutil").which("bash"), reason="bash requis")
def test_un_fichier_definitivement_en_echec_laisse_la_release_en_brouillon(tmp_path):
    bin_ = _simuler(tmp_path, toujours=True)
    script = re.sub(r"\$\{\{[^}]*\}\}", "v0.0.0-test", _etape_envoi()["run"])
    r = subprocess.run(["bash", "-e", "-c", script], cwd=tmp_path, capture_output=True, text=True,
                       env={"PATH": f"{bin_}:/usr/bin:/bin", "GH_TOKEN": "x", "HOME": str(tmp_path)})
    assert r.returncode != 0
    assert "--draft=false" not in (tmp_path / "appels").read_text()                           # jamais publiée incomplète
    assert (tmp_path / "essais").read_text().splitlines().count("b.img.xz") == 4              # quatre essais puis abandon


# ---------- publication APT ----------

def test_les_secrets_apt_sont_verifies_avant_l_appel_du_workflow_de_publication():
    jobs = RELEASE["jobs"]
    assert "apt-secrets" in jobs
    verif = " ".join(e.get("run", "") for e in jobs["apt-secrets"]["steps"])
    for secret in ("GPG_PRIVATE_KEY", "DEPLOY_SSH_KEY", "DEPLOY_KNOWN_HOSTS"):
        assert secret in " ".join(str(e.get("env", "")) for e in jobs["apt-secrets"]["steps"])
    assert "::warning" in verif and "ok=false" in verif and "ok=true" in verif                 # saut VISIBLE, jamais muet
    assert "apt-secrets" in jobs["publish"]["needs"]
    assert "apt-secrets.outputs.ok == 'true'" in jobs["publish"]["if"]


# ---------- image eMMC MOCHAbin ----------

def test_l_etape_emmc_mochabin_a_un_delai_plus_large():
    etapes = next(j for j in LIVE_USB["jobs"].values() if any("eMMC" in e.get("name", "") for e in j["steps"]))["steps"]
    emmc = next(e for e in etapes if "embedded eMMC" in e.get("name", ""))
    assert emmc["timeout-minutes"] >= 330                                                      # 240 dépassé en alpha.16 et alpha.17
    assert emmc["timeout-minutes"] <= 345                                                      # sous la limite de 360 min d'un job hébergé
