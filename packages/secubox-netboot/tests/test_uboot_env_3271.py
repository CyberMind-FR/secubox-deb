# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3271 — préparation de l'environnement U-Boot, même forme pour la MOCHAbin et l'ESPRESSObin v7.

Faits du banc (MOCHAbin, U-Boot Marvell 2018.03 d'usine, 2026-10-29) : loadaddr=0x6000000, pas de scriptaddr,
ethact=mvpp2-0 (SFP+) ; WAN cuivre = mvpp2-2 ; adresses sûres #3091 (noyau 0x08000000, fdt 0x0c000000,
ramdisk 0x0c100000) ; séquence qui démarre l'eMMC : setenv ethact mvpp2-2; dhcp; mmc dev 0; fatload mmc 0:1
${loadaddr} boot.scr; source ${loadaddr}, adresses et autoload=no posés avant le dhcp.

Les valeurs attendues sont écrites ici en dur : elles ne sont pas relues du générateur qu'elles vérifient."""
import importlib.machinery
import importlib.util
import json
import os
import re
import struct
import subprocess
import sys
import zlib
from pathlib import Path

import pytest

ICI = Path(__file__).resolve().parents[1]
RACINE = ICI.parents[1]
GEN = ICI / "scripts" / "uboot-env.py"
OUTIL = ICI / "installer" / "sbx-uboot-env"
CARTES = ("mochabin", "espressobin-v7")
ENV_USINE = {"loadaddr", "bootcmd"}           # seules variables d'usine qu'un script peut lire sans les poser

ATTENDU = {
    "mochabin": {
        "titre": "MOCHAbin", "ethact": "mvpp2-2", "nom": "mochabin-live",
        "adresses": {"kernel_addr_r": "0x08000000", "fdt_addr_r": "0x0c000000", "ramdisk_addr_r": "0x0c100000"},
        "bootcmd": "setenv ethact mvpp2-2; dhcp; mmc dev 0; fatload mmc 0:1 ${loadaddr} boot.scr; source ${loadaddr}",
        "usb": "usb start; fatload usb 0:1 ${loadaddr} secubox-uboot-env.scr; source ${loadaddr}",
        "installe": "mmc dev 0; fatload mmc 0:1 ${loadaddr} secubox-uboot-env.scr; source ${loadaddr}",
    },
    "espressobin-v7": {
        "titre": "ESPRESSObin v7", "ethact": "neta@30000", "nom": "espressobin-live",
        "adresses": {"kernel_addr_r": "0x07000000", "fdt_addr_r": "0x06f00000", "ramdisk_addr_r": "0x0b000000"},
        # #2826, validé sur la carte : eMMC (mmc 1) puis la clé USB
        "bootcmd": "mmc dev 1; if load mmc 1:1 ${loadaddr} boot.scr; then source ${loadaddr}; fi; usb start; "
                   "if load usb 0:1 ${loadaddr} boot-usb.scr; then source ${loadaddr}; fi",
        "usb": "usb start; load usb 0:1 ${loadaddr} secubox-uboot-env.scr; source ${loadaddr}",
        "installe": "mmc dev 1; load mmc 1:1 ${loadaddr} secubox-uboot-env.scr; source ${loadaddr}",
    },
}


def netboot_attendu(carte, srv):
    a = ATTENDU[carte]
    ad = a["adresses"]
    return [f"setenv ethact {a['ethact']}; setenv autoload no",
            f"setenv kernel_addr_r {ad['kernel_addr_r']}; setenv fdt_addr_r {ad['fdt_addr_r']}; "
            f"setenv ramdisk_addr_r {ad['ramdisk_addr_r']}",
            f"dhcp; setenv serverip {srv}",
            f"tftpboot ${{loadaddr}} {a['nom']}/boot.scr; source ${{loadaddr}}"]


def reseau_attendu(carte, srv):
    a = ATTENDU[carte]
    return (f"setenv ethact {a['ethact']}; setenv autoload no; dhcp; setenv serverip {srv}; "
            f"tftpboot ${{loadaddr}} {a['nom']}/secubox-uboot-env.scr; source ${{loadaddr}}")


def gen(*args):
    r = subprocess.run([sys.executable, str(GEN), *args], capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stderr
    return r.stdout


def cmd_de(carte):
    return (RACINE / "board" / carte / "secubox-uboot-env.cmd").read_text()


def corps(texte):
    return [x.strip() for x in texte.splitlines() if x.strip() and not x.lstrip().startswith("#")]


def setenv(texte, var):
    m = re.search(rf"^\s*setenv {var} (.*)$", texte, re.M)
    assert m, var
    v = m.group(1)
    return v[1:-1] if v[:1] in "'\"" and v[-1:] == v[:1] else v


# ── 1. Scripts .cmd/.scr de préparation (sources versionnées, générées) ───────────────────────────────────────────
@pytest.mark.parametrize("carte", CARTES)
def test_le_cmd_versionne_est_celui_du_generateur(carte):
    assert gen("cmd", carte) == cmd_de(carte), "board/<carte>/secubox-uboot-env.cmd à régénérer : scripts/uboot-env.py generer"


@pytest.mark.parametrize("carte", CARTES)
def test_le_cmd_pose_adresses_wan_autoload_et_bootcmd_du_support_installe(carte):
    a, t = ATTENDU[carte], cmd_de(carte)
    for k, v in a["adresses"].items():
        assert setenv(t, k) == v, (carte, k)
    assert setenv(t, "ethact") == a["ethact"]
    assert setenv(t, "autoload") == "no"
    assert setenv(t, "bootcmd") == a["bootcmd"]


def test_la_mochabin_pose_adresses_et_autoload_avant_le_dhcp_du_bootcmd():
    t = cmd_de("mochabin")
    lignes = corps(t)
    i_bootcmd = next(i for i, x in enumerate(lignes) if x.startswith("setenv bootcmd '"))
    for k in ("kernel_addr_r", "fdt_addr_r", "ramdisk_addr_r", "ethact", "autoload"):
        assert next(i for i, x in enumerate(lignes) if x.startswith(f"setenv {k} ")) < i_bootcmd, k
    b = setenv(t, "bootcmd")
    assert b.index("setenv ethact mvpp2-2") < b.index("dhcp") < b.index("fatload mmc 0:1")


@pytest.mark.parametrize("carte", CARTES)
def test_l_ancien_bootcmd_est_garde_au_premier_passage_seulement(carte):
    lignes = corps(cmd_de(carte))
    i = lignes.index('if test -z "${bootcmd_avant}"; then')
    assert lignes[i + 1] == 'setenv bootcmd_avant "${bootcmd}"' and lignes[i + 2] == "fi"
    assert i < next(j for j, x in enumerate(lignes) if x.startswith("setenv bootcmd '"))


@pytest.mark.parametrize("carte", CARTES)
def test_bootcmd_de_secours_netboot_pose_et_documente_jamais_lance_seul(carte):
    a, t = ATTENDU[carte], cmd_de(carte)
    assert setenv(t, "bootcmd_netboot") == (f"setenv ethact {a['ethact']}; setenv autoload no; dhcp; "
                                            f"tftpboot ${{loadaddr}} {a['nom']}/boot.scr; source ${{loadaddr}}")
    assert "bootcmd_netboot" not in setenv(t, "bootcmd"), "un DHCP du WAN ne doit pas pouvoir démarrer la box"
    assert "run bootcmd_netboot" in t


@pytest.mark.parametrize("carte", CARTES)
def test_saveenv_en_dernier_et_rien_d_absent_de_l_usine(carte):
    t = cmd_de(carte)
    lignes = [x for x in corps(t) if not x.startswith("echo ")]
    assert lignes[-1] == "saveenv"
    assert "scriptaddr" not in t
    posees = set()
    for x in lignes:
        hors_quotes = re.sub(r"'[^']*'", "", x)                      # '…' : lu au démarrage, pas maintenant
        for v in re.findall(r"\$\{([a-z_]+)\}", hors_quotes):
            assert v in posees or v in ENV_USINE or v == "bootcmd_avant", (carte, v, x)
        m = re.match(r"setenv (\w+) ", x)
        if m:
            posees.add(m.group(1))


def test_les_deux_cartes_ont_la_meme_forme():
    def forme(t):
        return [re.sub(r"^(setenv \w+|echo|if|fi|saveenv).*", r"\1", x) for x in corps(t)]
    assert forme(cmd_de("mochabin")) == forme(cmd_de("espressobin-v7"))


@pytest.mark.parametrize("carte", CARTES)
def test_l_entete_documente_les_trois_lancements_et_mkimage(carte):
    a, t = ATTENDU[carte], cmd_de(carte)
    tete = "\n".join(x for x in t.splitlines() if x.startswith("#"))
    assert a["usb"] in tete and a["installe"] in tete and reseau_attendu(carte, "<IP du maître>") in tete
    assert "reset" in tete
    assert ('mkimage -A arm64 -O linux -T script -C none -n "SecuBox uboot env" -d secubox-uboot-env.cmd '
            'secubox-uboot-env.scr') in tete
    assert "GÉNÉRÉ" in tete and "scripts/uboot-env.py" in tete


@pytest.mark.parametrize("carte", CARTES)
def test_le_scr_est_le_cmd_compile_par_mkimage(carte):
    scr = (RACINE / "board" / carte / "secubox-uboot-env.scr").read_bytes()
    cmd = cmd_de(carte).encode()
    magic, hcrc, _t, taille, _l, _e, dcrc, os_, arch, typ, comp = struct.unpack(">7I4B", scr[:32])
    assert magic == 0x27051956 and (os_, arch, typ, comp) == (5, 22, 6, 0)     # linux, arm64, script, none
    assert scr[32:64].rstrip(b"\0") == b"SecuBox uboot env"
    assert zlib.crc32(scr[:4] + b"\0\0\0\0" + scr[8:64]) == hcrc
    data = scr[64:64 + taille]
    assert zlib.crc32(data) == dcrc
    assert struct.unpack(">II", data[:8]) == (len(cmd), 0) and data[8:] == cmd


@pytest.mark.parametrize("carte", CARTES)
def test_adresses_sures(carte):
    ad = {k: int(v, 16) for k, v in ATTENDU[carte]["adresses"].items()}
    for v in ad.values():
        assert not 0x04000000 <= v < 0x04200000, "zone réservée PSCI/ATF"
        assert not v <= 0x6000000 < v + 0x100000, "le script reste lu à loadaddr"
    assert ad["ramdisk_addr_r"] - ad["kernel_addr_r"] >= 0x3000000, "48 Mo au moins pour le noyau Debian (~37 Mo)"


# ── 2. Blocs à copier-coller : générés, et identiques partout ─────────────────────────────────────────────────────
@pytest.mark.parametrize("carte", CARTES)
def test_bloc_netboot_exact_et_complet(carte):
    assert gen("netboot", carte, "--serveur", "192.0.2.10").splitlines() == netboot_attendu(carte, "192.0.2.10")


@pytest.mark.parametrize("carte", CARTES)
def test_lignes_de_preparation(carte):
    lignes = [x.split("\t") for x in gen("preparation", carte, "--serveur", "192.0.2.10").splitlines()]
    assert lignes == [["reseau", reseau_attendu(carte, "192.0.2.10")], ["installe", ATTENDU[carte]["installe"]]]


@pytest.mark.parametrize("carte", CARTES)
def test_le_boot_cmd_du_live_documente_le_bloc_genere(carte):
    """build-live-netboot.sh : l'en-tête du boot.cmd (lu par l'API, affiché par la page) vient du générateur."""
    s = (ICI / "scripts" / "build-live-netboot.sh").read_text()
    assert 'uboot-env.py" netboot "$carte" --serveur "$tftp_ip" --nom "$nom"' in s
    gabarit = s.split('cat > "$w/boot.cmd" <<EOF\n', 1)[1].split("\nEOF\n", 1)[0]
    script = ('. "$0"; charge_live_env "$1" "$2" || exit 9; HERE="$2"; carte="$1"; nom=$LIVE_NOM; '
              'srv=192.0.2.10:8099; tftp_ip=192.0.2.10; ' + s.split("# ── en-tête du boot.cmd", 1)[1].split("\n", 1)[1]
              .split("\ncat > ", 1)[0] + '\ncat <<EOF\n' + gabarit + "\nEOF\n")
    r = subprocess.run(["bash", "-c", script, str(ICI / "scripts" / "live-env.sh"), carte, str(ICI)],
                       capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stderr
    tete = re.findall(r"^#   (\S.*?)\s*$", r.stdout, re.M)
    assert tete == netboot_attendu(carte, "192.0.2.10")


def test_le_live_publie_le_script_de_preparation_a_cote_du_boot_scr():
    s = (ICI / "scripts" / "build-live-netboot.sh").read_text()
    assert "secubox-uboot-env.scr" in s and "preparation.txt" in s
    assert 'uboot-env.py" preparation "$carte" --serveur "$tftp_ip" --nom "$nom"' in s


def _page_demo():
    page = (ICI / "www" / "netboot" / "index.html").read_text()
    return page.split("function demoData()", 1)[1].split("BOARDS =", 1)[0]


def test_la_page_de_demonstration_affiche_les_blocs_generes():
    demo = _page_demo()
    for carte, srv in (("mochabin", "192.0.2.10"), ("espressobin-v7", "192.0.2.42")):
        assert "commandes: [" + ", ".join(f"'{x}'" for x in netboot_attendu(carte, srv)) + "]" in demo, carte
        for role, cmd in (("reseau", reseau_attendu(carte, srv)), ("installe", ATTENDU[carte]["installe"])):
            assert f"{{ role: '{role}', commande: '{cmd}' }}" in demo, (carte, role)


def test_la_page_n_a_plus_de_commande_ecrite_en_dur_pour_une_carte():
    page = (ICI / "www" / "netboot" / "index.html").read_text()
    code = page.split("function rendreLive(", 1)[1].split("\n        function ", 1)[0]
    assert "uboot-env.scr; source" not in code and "commandes_preparation" in code


DOCS = (ICI / "README.md", RACINE / "board" / "mochabin" / "README.md", RACINE / "board" / "espressobin-v7" / "README.md")


def test_les_blocs_de_la_documentation_sont_ceux_du_generateur():
    """README : chaque bloc précédé de <!-- uboot-env: SOUS-COMMANDE CARTE [SERVEUR|-] [ROLE] --> est exact."""
    doc = "\n".join(f.read_text() for f in DOCS)
    blocs = re.findall(r"<!-- uboot-env: ([^>]*?) -->\s*```\n(.*?)```", doc, re.S)
    vus = {tuple(b[0].split()[:2]) for b in blocs}
    assert {("netboot", c) for c in CARTES} | {("preparation", c) for c in CARTES} <= vus
    for spec, texte in blocs:
        sous, carte, *reste = spec.split()
        args = [sous, carte] + (["--serveur", reste[0]] if reste and reste[0] != "-" else [])
        sortie = gen(*args)
        if sous == "preparation":
            sortie = "".join(x.split("\t", 1)[1] + "\nreset\n" for x in sortie.splitlines()
                             if len(reste) < 2 or x.startswith(reste[1] + "\t"))
        assert texte == sortie, spec
    assert "0x06d00000" not in doc and "Quand l'image ne tient pas en RAM" not in doc


# ── API : lignes de préparation publiées à côté du live ───────────────────────────────────────────────────────────
@pytest.fixture
def api(tmp_path):
    sys.path.insert(0, str(ICI))
    sys.path.insert(0, str(RACINE / "common"))
    from fastapi.testclient import TestClient
    sys.modules.pop("api.lot", None)
    sys.modules.pop("api.main", None)
    main = importlib.import_module("api.main")
    tftp, http = tmp_path / "tftp", tmp_path / "http"
    (tftp / "mochabin-live").mkdir(parents=True)
    (http / "mochabin-live").mkdir(parents=True)
    (tftp / "mochabin-live" / "boot.cmd").write_text("# SecuBox MOCHAbin — live réseau\nsetenv serverip 192.0.2.10\n")
    main.TFTP_ROOT, main.HTTP_ROOT = tftp, http
    main.app.dependency_overrides[main.require_jwt] = lambda: {"sub": "admin"}
    return main, TestClient(main.app), tftp / "mochabin-live"


def test_api_rend_les_lignes_de_preparation_validees(api):
    _, c, d = api
    bon = gen("preparation", "mochabin", "--serveur", "192.0.2.10")
    (d / "preparation.txt").write_text(bon + "installe\tmmc dev 0; fatload mmc 0:1 ${loadaddr} autre.scr; source ${loadaddr}\n"
                                       "inconnu\tusb start; fatload usb 0:1 ${loadaddr} secubox-uboot-env.scr\n"
                                       "usb\t" + "x" * 300 + "secubox-uboot-env.scr\n")
    live = c.get("/live").json()["lives"][0]
    assert live["commandes_preparation"] == [{"role": r, "commande": x} for r, x in
                                             (line.split("\t") for line in bon.splitlines())]


def test_api_sans_preparation_liste_vide(api):
    _, c, _ = api
    assert c.get("/live").json()["lives"][0]["commandes_preparation"] == []


# ── 3. Dans le live : diagnostic seulement (R-3271-1 : pas de MTD sous le noyau Debian, SPI instable au banc) ─────
@pytest.mark.parametrize("carte,mtd", [("mochabin", "u-boot-env"), ("espressobin-v7", "*")])
def test_conf_du_live_commandes_et_script(carte, mtd):
    c = json.loads(gen("live-conf", carte, "--serveur", "192.0.2.10"))
    assert c["carte"] == carte and c["env"]["mtd"] == mtd and c["env"]["spi"] == "0x3f0000"
    assert "include/configs/mvebu_armada-common.h" in c["env"]["source"]
    assert c["commandes"] == [["reseau", reseau_attendu(carte, "192.0.2.10")], ["installe", ATTENDU[carte]["installe"]]]
    assert c["cmd"] == cmd_de(carte)


def test_plus_aucune_ecriture_spi_depuis_linux():
    for f in (OUTIL, ICI / "installer" / "sbx-netflash", GEN, ICI / "scripts" / "build-live-netboot.sh",
              ICI / "scripts" / "build-live-leger.sh"):
        t = f.read_text()
        assert "fw_setenv" not in t and "--ecrire-spi" not in t and "fw_env.config" not in t, f.name
    assert "libubootenv-tool" not in (ICI / "scripts" / "build-live-leger.sh").read_text()


def test_fw_env_config_de_l_image_mochabin_vise_la_partition_u_boot_env():
    lignes = [x.split() for x in (RACINE / "board" / "mochabin" / "etc" / "fw_env.config").read_text().splitlines()
              if x.strip() and not x.startswith("#")]
    assert lignes == [["/dev/mtd2", "0x0", "0x10000", "0x10000"]]


def _conf(tmp_path, carte):
    f = tmp_path / f"{carte}.json"
    f.write_text(gen("live-conf", carte, "--serveur", "192.0.2.10"))
    return f


def _outil(tmp_path, conf_f, proc, *args):
    p = tmp_path / "mtd"
    p.write_text(proc)
    return subprocess.run([sys.executable, str(OUTIL), "--conf", str(conf_f), *args], capture_output=True, text=True,
                          timeout=60, env={**os.environ, "SBX_UBOOT_ENV_PROC_MTD": str(p)})


PROC_VIDE = "dev:    size   erasesize  name\n"
PROC_MOCHABIN = ('dev:    size   erasesize  name\nmtd0: 003e0000 00010000 "firmware"\n'
                 'mtd1: 00010000 00010000 "hw-info"\nmtd2: 00010000 00010000 "u-boot-env"\n')


@pytest.mark.parametrize("carte", CARTES)
def test_spi_non_exposee_dit_le_en_une_ligne_et_code_non_nul(tmp_path, carte):
    r = _outil(tmp_path, _conf(tmp_path, carte), PROC_VIDE, "--afficher")
    assert r.returncode == 5, r.stdout + r.stderr
    assert "la SPI n'est pas exposée sous ce noyau : utilisez secubox-uboot-env.scr depuis U-Boot" in r.stdout
    assert ATTENDU[carte]["installe"] in r.stdout and reseau_attendu(carte, "192.0.2.10") in r.stdout


def test_afficher_montre_les_commandes_et_le_script(tmp_path):
    r = _outil(tmp_path, _conf(tmp_path, "mochabin"), PROC_MOCHABIN, "--afficher")
    assert r.returncode == 0, r.stdout + r.stderr
    assert cmd_de("mochabin") in r.stdout
    assert ATTENDU["mochabin"]["installe"] in r.stdout and "u-boot-env" in r.stdout


def test_commandes_seules_pour_la_fin_du_flash(tmp_path):
    r = _outil(tmp_path, _conf(tmp_path, "mochabin"), PROC_VIDE, "--commandes")
    assert r.returncode == 0
    lignes = r.stdout
    assert lignes.index(reseau_attendu("mochabin", "192.0.2.10")) < lignes.index(ATTENDU["mochabin"]["installe"])
    assert "setenv bootcmd '" not in lignes                       # pas le script entier : les commandes
    assert "reset" in lignes


def test_configuration_malformee_sans_trace(tmp_path):
    f = tmp_path / "casse.json"
    f.write_text(json.dumps({"carte": "mochabin"}))
    r = _outil(tmp_path, f, PROC_VIDE, "--afficher")
    assert r.returncode == 2 and "Traceback" not in r.stderr and "configuration" in r.stdout


def test_le_readme_dit_que_le_bootcmd_mochabin_enchaine_par_point_virgule():
    doc = (ICI / "README.md").read_text()
    assert "enchaîne par `;`" in doc and "validée au banc" in doc


def test_le_readme_explique_l_abandon_de_l_ecriture_depuis_linux():
    doc = (ICI / "README.md").read_text()
    assert "spi-orion" in doc and "/proc/mtd" in doc and "instable" in doc


def test_sous_processus_bornes_dans_le_temps():
    appels = re.findall(r"subprocess\.run\((.*?)\)\n", GEN.read_text(), re.S)
    assert appels and all("timeout=" in a for a in appels)


@pytest.mark.parametrize("carte", CARTES)
def test_procedure_en_trois_lignes_par_carte_au_readme(carte):
    doc = (ICI / "README.md").read_text()
    bloc = doc.split(f"<!-- procedure: {carte} -->", 1)[1].split("<!-- /procedure -->", 1)[0]
    lignes = [x for x in bloc.strip().splitlines() if x.strip()]
    assert len(lignes) == 3, lignes
    assert ATTENDU[carte]["installe"] in bloc and "secubox-uboot-env.scr" in lignes[1]


# ── Image : le script est sur la partition de démarrage (FAT) ───────────────────────────────────────────────────────
def test_l_image_porte_secubox_uboot_env_scr_et_l_alias_fix_bootcmd():
    b = (RACINE / "image" / "build-image.sh").read_text()
    bloc = b.split("# Script USB (#2816, #2824)", 1)[1].split("# Démonter", 1)[0]
    assert 'board/${BOARD}/secubox-uboot-env.scr" "${MNT}/boot/secubox-uboot-env.scr"' in bloc
    assert 'board/${BOARD}/secubox-uboot-env.cmd" "${MNT}/boot/secubox-uboot-env.cmd"' in bloc
    assert '"${MNT}/boot/secubox-uboot-env.scr" "${MNT}/boot/fix-bootcmd.scr"' in bloc     # alias une version (#2826)
    assert bloc.index("secubox-uboot-env.scr") < bloc.index("if command -v mkimage")


def test_le_netboot_depose_le_script_a_cote_de_boot_scr():
    s = (ICI / "scripts" / "build-live-netboot.sh").read_text()
    assert 'cp "$prep" "$w/out/tftp/secubox-uboot-env.scr"' in s and 'cp "$prep" "$w/out/http/secubox-uboot-env.scr"' in s
    assert 'cp "$prep" "$w/boot/secubox-uboot-env.scr"' in (ICI / "scripts" / "build-live-leger.sh").read_text()


# ── sbx-netflash : la préparation est proposée après le flash, écrite seulement sur option ────────────────────────
NETFLASH = ICI / "installer" / "sbx-netflash"


def _termine(tmp_path, *args):
    bin_ = tmp_path / "bin"
    bin_.mkdir()
    j = tmp_path / "j"
    (bin_ / "sbx-uboot-env").write_text(f'#!/bin/sh\necho "sbx-uboot-env $*" >> "{j}"\n')
    (bin_ / "sbx-uboot-env").chmod(0o755)
    script = 'SBX_NETFLASH_SOURCE=1 source "$0"; reboot_demande=0; termine'
    r = subprocess.run(["bash", "-c", script, str(NETFLASH), *args], capture_output=True, text=True, timeout=60,
                       env={**os.environ, "PATH": f"{bin_}:{os.environ['PATH']}"})
    return r, (j.read_text() if j.exists() else "")


def test_netflash_affiche_les_commandes_u_boot_en_fin_de_flash():
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        r, j = _termine(Path(d))
    assert r.returncode == 0, r.stderr
    assert j.strip() == "sbx-uboot-env --commandes"


def test_les_lives_embarquent_l_outil_et_sa_conf():
    for b in ("build-live-netboot.sh", "build-live-leger.sh"):
        s = (ICI / "scripts" / b).read_text()
        assert "installer/sbx-uboot-env" in s and 'uboot-env.py" live-conf "$carte" --serveur' in s, b
        assert "/etc/secubox/uboot-env.json" in s, b


@pytest.mark.parametrize("carte", CARTES)
def test_les_echo_du_script_restent_en_ascii_simple(carte):
    for x in corps(cmd_de(carte)):
        if x.startswith("echo "):
            assert x.isascii() and not set(x) & set("'#<>"), x


# ── M6 / M7 ──────────────────────────────────────────────────────────────────────────────────────────────────────
def test_coupure_pendant_le_flash_dit_emmc_non_amorcable(tmp_path):
    bin_ = tmp_path / "bin"
    bin_.mkdir()
    for nom, corps_ in {"curl": "head -c 1000 /dev/urandom; exit 18\n", "secubox-flash-emmc": "cat >/dev/null; exit 1\n",
                        "pv": "cat\n", "sleep": "exit 0\n"}.items():
        (bin_ / nom).write_text("#!/usr/bin/env bash\n" + corps_)
        (bin_ / nom).chmod(0o755)
    script = ('SBX_NETFLASH_SOURCE=1 source "$0"; fail() { echo "$*"; exit 1; }; log() { echo "$*"; }; '
              'ecrire_flux() { :; }; st=(18 1); verifie_flux_ecrit')
    r = subprocess.run(["bash", "-c", script, str(ICI / "installer" / "sbx-netflash")], capture_output=True, text=True,
                       timeout=60, env={**os.environ, "PATH": f"{bin_}:{os.environ['PATH']}"})
    assert r.returncode == 1
    assert "eMMC non amorçable, relancer sbx-netflash" in r.stdout


def test_live_script_addr_retire():
    fichiers = [*(ICI / "board").glob("*/live.env"), *(ICI / "scripts").glob("*.sh")]
    fautifs = [f.name for f in fichiers if "LIVE_SCRIPT_ADDR" in f.read_text()]
    assert fautifs == []
