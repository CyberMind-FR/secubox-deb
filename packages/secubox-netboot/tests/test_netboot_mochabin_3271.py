# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3271 — retour terrain MOCHAbin (U-Boot d'usine Marvell, 2026-10-29).

Environnement relevé sur la carte : loadaddr=0x6000000, kernel_addr_r=0x7000000, fdt_addr_r=0x6f00000,
ramdisk_addr_r=- ; aucune variable `scriptaddr`. Les commandes et scripts netboot ne doivent dépendre que de ce qui
existe dans cet environnement, ou de ce qu'ils posent eux-mêmes."""
import re
import subprocess
from pathlib import Path

import pytest

ICI = Path(__file__).resolve().parents[1]
RACINE = ICI.parents[1]
ENV_USINE = {"loadaddr": "0x6000000", "kernel_addr_r": "0x7000000", "fdt_addr_r": "0x6f00000", "ramdisk_addr_r": "-"}
# variables que U-Boot pose lui-même pendant le script (tftpboot/fatload → filesize ; bootargs complété par le script)
POSEES_PAR_UBOOT = {"filesize", "bootargs"}
CARTES = ("mochabin", "espressobin-v7")
BUILDERS = ("build-live-netboot.sh", "build-live-leger.sh")


# ── 1. ${loadaddr} au lieu de ${scriptaddr} ─────────────────────────────────────────────────────────────────────
def test_aucune_commande_netboot_ne_depend_de_scriptaddr():
    fichiers = [*(ICI / "board").glob("*/live.env"), *(ICI / "scripts").glob("*.sh"), ICI / "www" / "netboot" / "index.html",
                *(ICI / "api").glob("*.py"), *(ICI / "installer").iterdir()]
    fautifs = [str(f.relative_to(ICI)) for f in fichiers if f.is_file() and "scriptaddr" in f.read_text(errors="replace")]
    assert fautifs == [], "le U-Boot d'usine Marvell n'a pas de scriptaddr"


@pytest.mark.parametrize("carte", CARTES)
def test_le_script_netboot_se_charge_a_loadaddr(carte):
    r = subprocess.run(["bash", "-c", '. "$0"; charge_live_env "$1" "$2" && printf %s "$LIVE_SCRIPT_ADDR"',
                        str(ICI / "scripts" / "live-env.sh"), carte, str(ICI)], capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stderr
    assert r.stdout == "${loadaddr}"


def _boot_cmd_rendu(builder, carte):
    """Le gabarit boot.cmd du script de construction, rendu avec le live.env réel de la carte."""
    s = (ICI / "scripts" / builder).read_text()
    gabarit = s.split('cat > "$w/boot.cmd" <<EOF\n', 1)[1].split("\nEOF\n", 1)[0] if 'cat > "$w/boot.cmd" <<EOF' in s \
        else s.split('cat > "$w/boot/boot.cmd" <<EOF\n', 1)[1].split("\nEOF\n", 1)[0]
    script = ('. "$0"; charge_live_env "$1" "$2" || exit 9; nom=$LIVE_NOM; srv=192.0.2.10:8099; tftp_ip=192.0.2.10; '
              'v=6.12.0; w=/x; cat <<EOF\n' + gabarit + "\nEOF\n")
    r = subprocess.run(["bash", "-c", script, str(ICI / "scripts" / "live-env.sh"), carte, str(ICI)],
                       capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stderr
    return r.stdout


@pytest.mark.parametrize("builder", BUILDERS)
@pytest.mark.parametrize("carte", CARTES)
def test_le_boot_scr_du_live_pose_ses_adresses_et_rien_d_absent_de_l_usine(builder, carte):
    texte = _boot_cmd_rendu(builder, carte)
    assert "scriptaddr" not in texte
    posees, lignes = set(), [x for x in texte.splitlines() if x.strip() and not x.lstrip().startswith("#")]
    for k in ("kernel_addr_r", "fdt_addr_r", "ramdisk_addr_r"):
        assert re.search(rf"^setenv {k} 0x[0-9a-f]+$", texte, re.M), (carte, k)   # jamais celle de l'usine (ramdisk=-)
    for ligne in lignes:
        for v in re.findall(r"\$\{([a-z_]+)\}", ligne):
            assert v in posees or v in POSEES_PAR_UBOOT, f"{carte}: ${{{v}}} lu avant d'être posé : {ligne}"
        m = re.match(r"setenv (\w+) ", ligne)
        if m:
            posees.add(m.group(1))
    # le commentaire de tête documente la ligne à taper : uniquement des variables de l'environnement d'usine
    for v in re.findall(r"\$\{([a-z_]+)\}", "\n".join(x for x in texte.splitlines() if x.startswith("#   "))):
        assert v in ENV_USINE, (carte, v)


def test_les_adresses_du_live_ne_recouvrent_pas_le_script_charge_a_loadaddr():
    # boot.scr (quelques centaines d'octets) reste lu à loadaddr pendant que noyau, DTB et initrd arrivent
    for carte in CARTES:
        texte = _boot_cmd_rendu("build-live-netboot.sh", carte)
        for k in ("kernel_addr_r", "fdt_addr_r", "ramdisk_addr_r"):
            a = int(re.search(rf"^setenv {k} (0x[0-9a-f]+)$", texte, re.M).group(1), 16)
            assert not a <= int(ENV_USINE["loadaddr"], 16) < a + 0x100000, (carte, k)


# ── 2. Flashage en flux dans le live ─────────────────────────────────────────────────────────────────────────────
NETFLASH = ICI / "installer" / "sbx-netflash"


def _stub(d, nom, corps):
    f = d / nom
    f.write_text("#!/usr/bin/env bash\n" + corps)
    f.chmod(0o755)


@pytest.fixture
def live_simule(tmp_path):
    """Un live simulé : serveur (curl), mount, blockdev, id et secubox-flash-emmc remplacés ; chaque appel est noté."""
    import gzip
    import hashlib
    import os
    srv, bin_, travail, journal = tmp_path / "srv", tmp_path / "bin", tmp_path / "travail", tmp_path / "journal"
    for d in (srv, bin_, travail):
        d.mkdir()
    brut = os.urandom(2 * 1048576)
    gz = gzip.compress(brut)
    (srv / "minimal.img.gz").write_bytes(gz)
    (srv / "minimal.img.gz.sig").write_bytes(b"signature")
    (srv / "images.txt").write_text(f"minimal.img.gz {len(gz)} {hashlib.sha256(gz).hexdigest()} {len(brut)}\n")
    (tmp_path / "cle.pub").write_text("cle publique\n")
    _stub(bin_, "curl", f'''j="{journal}"; o=""; tete=0; url=""
while [ $# -gt 0 ]; do case "$1" in -o) o="$2"; shift 2 ;; -fsSI|-I) tete=1; shift ;; http://*) url="$1"; shift ;; *) shift ;; esac; done
f="{srv}/${{url##*/}}"; [ -f "$f" ] || exit 22
if [ "$tete" = 1 ]; then echo "tete $url" >> "$j"; exit 0; fi
if [ -n "$o" ]; then echo "fichier $url -> $o" >> "$j"; cp "$f" "$o"; else echo "flux $url" >> "$j"; cat "$f"; fi
''')
    _stub(bin_, "mount", f'echo "mount $*" >> "{journal}"; exit 0\n')
    _stub(bin_, "mountpoint", "exit 1\n")
    _stub(bin_, "blockdev", "echo 7818182656\n")
    _stub(bin_, "id", "echo 0\n")
    _stub(bin_, "pv", "cat\n")
    _stub(bin_, "systemctl", f'echo "systemctl $*" >> "{journal}"\n')
    _stub(bin_, "secubox-flash-emmc", f'echo "flash $*" >> "{journal}"; cat > "{tmp_path}/emmc"\n')
    return {"tmp": tmp_path, "bin": bin_, "travail": travail, "journal": journal, "brut": brut, "gz": gz,
            "pub": tmp_path / "cle.pub"}


def _netflash_main(l, *args):
    import os
    script = ('SBX_NETFLASH_SOURCE=1 source "$0"; PUB="$1"; TRAVAIL="$2"; JOURNAL=/dev/null; shift 2; main "$@"')
    return subprocess.run(["bash", "-c", script, str(NETFLASH), str(l["pub"]), str(l["travail"]), *args],
                          capture_output=True, text=True, timeout=60,
                          env={**os.environ, "PATH": f"{l['bin']}:{os.environ['PATH']}", "SBX_EMMC": "/dev/null"})


def test_le_live_ecrit_l_image_en_flux_meme_quand_la_ram_semble_suffire(live_simule):
    """MOCHAbin 8 Go : l'image partait dans un tmpfs à sa taille et le live manquait de mémoire (#3271)."""
    l = live_simule
    r = _netflash_main(l, "--srv", "192.0.2.10:8099", "--image", "minimal.img.gz", "--auto", "--no-reboot")
    journal = l["journal"].read_text()
    assert "tmpfs" not in journal, "aucun système de fichiers en mémoire pour l'image"
    assert "fichier http://192.0.2.10:8099/mochabin-live/minimal.img.gz " not in journal, "l'image ne doit jamais aller dans un fichier"
    assert "flux http://192.0.2.10:8099/mochabin-live/minimal.img.gz" in journal
    assert r.returncode == 0, r.stdout + r.stderr
    flash = next(x for x in journal.splitlines() if x.startswith("flash "))
    assert "--stdin gz" in flash and f"--sha256 {__import__('hashlib').sha256(l['gz']).hexdigest()}" in flash
    assert (l["tmp"] / "emmc").read_bytes() == l["gz"]               # flux compressé intact jusqu'à l'outil
    # rien de la taille de l'image n'est resté dans l'espace de travail du live (/run, tmpfs)
    gros = [p for p in l["travail"].rglob("*") if p.is_file() and p.stat().st_size >= 1048576]
    assert gros == []


def test_le_mode_ram_a_disparu_du_live():
    s = NETFLASH.read_text()
    assert "mount -t tmpfs" not in s and "mode_ecriture" not in s
    assert 'telecharge "$BASE/$image" ' not in s                      # jamais l'image entière vers un fichier
