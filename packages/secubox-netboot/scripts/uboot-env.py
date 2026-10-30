#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: uboot-env.py (#3271) — préparation de l'environnement U-Boot, même forme pour toutes les cartes.

Une seule source par carte : board/<carte>/live.env (adresses sûres, ethact, nom du live) et board/<carte>/uboot-env.env
(support installé, bootcmd, emplacement de l'environnement en SPI). Les deux sont lus comme des DONNÉES, jamais exécutés.
Tout ce qui se tape ou s'exécute dans U-Boot en sort :

  uboot-env.py cmd CARTE                         secubox-uboot-env.cmd (sortie standard)
  uboot-env.py generer [--mkimage M] [--board D] écrit D/<carte>/secubox-uboot-env.cmd et .scr pour chaque carte
                                                 (D par défaut : board/ à la racine du dépôt, livré dans l'image)
  uboot-env.py netboot CARTE --serveur IP [--nom NOM]       bloc U-Boot du netboot (en-tête du boot.cmd du live)
  uboot-env.py preparation CARTE [--serveur IP] [--nom NOM] « rôle<TAB>commande » : lancer secubox-uboot-env.scr
                                                            depuis le netboot ou la partition installée
  uboot-env.py live-conf CARTE [--serveur IP] [--nom NOM]   JSON du diagnostic sbx-uboot-env (/etc/secubox/uboot-env.json)

mkimage est absent du poste de développement : celui de la chaîne OpenWrt locale convient, par exemple
  uboot-env.py generer --mkimage ~/CyberMindStudio/secubox-openwrt/secubox-tools/openwrt/staging_dir/host/bin/mkimage
SOURCE_DATE_EPOCH est fixé : le .scr ne change que si le .cmd change.
"""
import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path

ICI = Path(__file__).resolve().parents[1]
BOARD_PAQUET = ICI / "board"
BOARD_DEPOT = ICI.parents[1] / "board"
DATE_FIXE = "1793232000"      # 2026-10-30 : en-tête mkimage reproductible
NOM_SCR = "SecuBox uboot env"

_LIGNE = re.compile(r"^((?:LIVE|UBOOT)_[A-Z_]{1,24})=(.*)$")
_ADRESSE = re.compile(r"0x[0-9a-f]{8}")
_COMMANDE = re.compile(r"[ -&(-~]{1,240}")                 # ASCII imprimable, sans « ' » : posée entre '…'
_IP = re.compile(r"(?:[0-9]{1,3}\.){3}[0-9]{1,3}|<IP du maître>")
_NOM = re.compile(r"[a-z0-9-]{1,32}")


class Refus(Exception):
    pass


def _lit(f: Path) -> dict:
    v = {}
    for ligne in f.read_text(encoding="utf-8").splitlines():
        if not ligne.strip() or ligne.startswith("#"):
            continue
        m = _LIGNE.match(ligne)
        if not m:
            raise Refus(f"ligne inattendue dans {f}")
        val = m.group(2)
        if len(val) >= 2 and val[0] == val[-1] and val[0] in "'\"":
            val = val[1:-1]
        v[m.group(1)] = val
    return v


def _exige(cond, motif):
    if not cond:
        raise Refus(motif)


def cartes(board: Path = BOARD_PAQUET):
    return sorted(d.name for d in board.iterdir() if (d / "uboot-env.env").is_file() and (d / "live.env").is_file())


def charge(carte: str, board: Path = BOARD_PAQUET) -> dict:
    _exige(re.fullmatch(r"[a-z0-9-]{1,32}", carte or ""), f"carte invalide : {carte}")
    d = board / carte
    _exige((d / "uboot-env.env").is_file(), f"carte sans préparation U-Boot : {d}/uboot-env.env")
    v = {**_lit(d / "live.env"), **_lit(d / "uboot-env.env")}
    c = {
        "carte": carte, "titre": v.get("LIVE_TITRE", ""), "nom": v.get("LIVE_NOM", ""), "ethact": v.get("LIVE_ETHACT", ""),
        "adresses": {"kernel_addr_r": v.get("LIVE_KERNEL_ADDR", ""), "fdt_addr_r": v.get("LIVE_FDT_ADDR", ""),
                     "ramdisk_addr_r": v.get("LIVE_RAMDISK_ADDR", "")},
        "mmc": v.get("UBOOT_MMC", ""), "charge": v.get("UBOOT_CHARGE", ""), "bootcmd": v.get("UBOOT_BOOTCMD", ""),
        # diagnostic seulement (R-3271-1) : rien n'est écrit depuis Linux
        "env": {"mtd": v.get("UBOOT_ENV_MTD", ""), "spi": v.get("UBOOT_ENV_SPI", ""),
                "taille": v.get("UBOOT_ENV_TAILLE", ""), "source": v.get("UBOOT_ENV_SOURCE", "")},
    }
    _exige(re.fullmatch(r"[A-Za-z0-9 .-]{1,32}", c["titre"]), "LIVE_TITRE invalide")
    _exige(_NOM.fullmatch(c["nom"]), "LIVE_NOM invalide")
    _exige(re.fullmatch(r"[a-z0-9@_-]{1,32}", c["ethact"]), "LIVE_ETHACT invalide")
    for k, a in c["adresses"].items():
        _exige(_ADRESSE.fullmatch(a), f"adresse {k} invalide : {a} (0x suivi de 8 chiffres hexadécimaux)")
    _exige(re.fullmatch(r"[0-9]", c["mmc"]), "UBOOT_MMC invalide")
    _exige(c["charge"] in ("load", "fatload"), "UBOOT_CHARGE : load ou fatload")
    _exige(_COMMANDE.fullmatch(c["bootcmd"]), "UBOOT_BOOTCMD invalide")
    _exige(f"mmc dev {c['mmc']}" in c["bootcmd"] and "boot.scr" in c["bootcmd"], "UBOOT_BOOTCMD ne lit pas le support")
    _exige(re.fullmatch(r"\*|[a-z0-9-]{1,32}", c["env"]["mtd"]), "UBOOT_ENV_MTD invalide")
    for k in ("spi", "taille"):
        _exige(re.fullmatch(r"0x[0-9a-f]{1,8}", c["env"][k]), f"UBOOT_ENV_{k.upper()} invalide")
    return c


def netboot(c: dict, serveur: str, nom: str = "") -> list:
    """Bloc à taper au U-Boot d'usine pour démarrer le live : adresses et autoload AVANT le dhcp ; serverip APRÈS
    (le dhcp le remplacerait par le next-server)."""
    _exige(_IP.fullmatch(serveur), "--serveur : adresse IPv4 attendue")
    nom = nom or c["nom"]
    _exige(_NOM.fullmatch(nom), "--nom invalide")
    a = c["adresses"]
    return [f"setenv ethact {c['ethact']}; setenv autoload no",
            f"setenv kernel_addr_r {a['kernel_addr_r']}; setenv fdt_addr_r {a['fdt_addr_r']}; "
            f"setenv ramdisk_addr_r {a['ramdisk_addr_r']}",
            f"dhcp; setenv serverip {serveur}",
            f"tftpboot ${{loadaddr}} {nom}/boot.scr; source ${{loadaddr}}"]


def lancements(c: dict, serveur: str = "<IP du maître>", nom: str = "") -> list:
    """Trois façons de lancer secubox-uboot-env.scr ; le script pose lui-même ses adresses."""
    _exige(_IP.fullmatch(serveur), "--serveur : adresse IPv4 attendue")
    nom = nom or c["nom"]
    _exige(_NOM.fullmatch(nom), "--nom invalide")
    ch, m = c["charge"], c["mmc"]
    return [("reseau", f"setenv ethact {c['ethact']}; setenv autoload no; dhcp; setenv serverip {serveur}; "
                       f"tftpboot ${{loadaddr}} {nom}/secubox-uboot-env.scr; source ${{loadaddr}}"),
            ("usb", f"usb start; {ch} usb 0:1 ${{loadaddr}} secubox-uboot-env.scr; source ${{loadaddr}}"),
            ("installe", f"mmc dev {m}; {ch} mmc {m}:1 ${{loadaddr}} secubox-uboot-env.scr; source ${{loadaddr}}")]


def preparation(c: dict, serveur: str = "<IP du maître>", nom: str = "") -> list:
    """Les deux commandes affichées (page, fin du flash) : depuis le netboot, depuis la partition installée."""
    return [x for x in lancements(c, serveur, nom) if x[0] != "usb"]


def bootcmd_netboot(c: dict) -> str:
    return (f"setenv ethact {c['ethact']}; setenv autoload no; dhcp; "
            f"tftpboot ${{loadaddr}} {c['nom']}/boot.scr; source ${{loadaddr}}")


def variables(c: dict) -> list:
    """Variables posées, dans l'ordre (bootcmd_avant à part : seulement s'il n'existe pas)."""
    return [*c["adresses"].items(), ("ethact", c["ethact"]), ("autoload", "no"),
            ("bootcmd_netboot", bootcmd_netboot(c)), ("bootcmd", c["bootcmd"])]


def cmd(c: dict) -> str:
    a = c["adresses"]
    lanc = dict(lancements(c))
    t = c["titre"]
    entete = [
        "# SPDX-License-Identifier: LicenseRef-CMSD-1.0",
        "# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>",
        f"# SecuBox U-Boot — préparation de l'environnement, {t} (#3271, modèle #2826).",
        "# FICHIER GÉNÉRÉ par packages/secubox-netboot/scripts/uboot-env.py depuis",
        f"#   packages/secubox-netboot/board/{c['carte']}/live.env et uboot-env.env : ne pas l'éditer à la main.",
        f'# Compile : mkimage -A arm64 -O linux -T script -C none -n "{NOM_SCR}" -d secubox-uboot-env.cmd secubox-uboot-env.scr',
        "#",
        "# Pose, puis enregistre (saveenv) :",
        f"#   - adresses sûres : kernel_addr_r {a['kernel_addr_r']}, fdt_addr_r {a['fdt_addr_r']}, "
        f"ramdisk_addr_r {a['ramdisk_addr_r']} ;",
        f"#   - ethact {c['ethact']} (port WAN) et autoload no (le dhcp ne charge rien) ;",
        f"#   - bootcmd : démarrage depuis le support installé (mmc {c['mmc']}) ;",
        "#   - bootcmd_netboot : secours netboot, JAMAIS lancé seul (un DHCP du WAN ne doit pas pouvoir démarrer la",
        "#     box). À la console : setenv serverip <IP du maître>; run bootcmd_netboot",
        "#     (sans setenv, serverip vient du next-server du DHCP, s'il en donne un) ;",
        "#   - l'ancien bootcmd dans bootcmd_avant, au premier passage seulement.",
        "#",
        "# Lancer, au choix (console série 115200 8N1, compte à rebours interrompu), puis : reset",
        f"#   réseau    : {lanc['reseau']}",
        f"#   clé USB   : {lanc['usb']}",
        f"#   installée : {lanc['installe']}",
        "",
    ]
    # echo : ASCII sans ' # < > (citation du hush des U-Boot d'usine non vérifiée sur ces caractères)
    corps = [
        'echo "============================================"',
        f'echo "SecuBox {t} - preparation environnement U-Boot"',
        'echo "============================================"',
        'echo "bootcmd actuel : ${bootcmd}"',
        "",
        'if test -z "${bootcmd_avant}"; then',
        '    setenv bootcmd_avant "${bootcmd}"',
        "fi",
        *(f"setenv {k} '{v}'" if " " in v else f"setenv {k} {v}" for k, v in variables(c)),
        "saveenv",
        "",
        f'echo "Pose : adresses, ethact {c["ethact"]}, autoload no, bootcmd (mmc {c["mmc"]}), bootcmd_netboot."',
        'echo "Ancien bootcmd garde dans bootcmd_avant."',
        'echo "Secours netboot : setenv serverip IP_DU_MAITRE; run bootcmd_netboot"',
        'echo "Revenir en arriere : setenv bootcmd \\"\\${bootcmd_avant}\\"; saveenv"',
        'echo "Redemarrer : reset"',
    ]
    return "\n".join(entete + corps) + "\n"


def live_conf(c: dict, serveur: str, nom: str = "") -> dict:
    """Pour sbx-uboot-env (diagnostic) : commandes de la carte, script de référence, emplacement attendu."""
    return {"carte": c["carte"], "titre": c["titre"], "env": c["env"],
            "commandes": [list(x) for x in preparation(c, serveur, nom)], "cmd": cmd(c)}


def generer(mkimage: str, board: Path) -> None:
    for carte in cartes():
        c = charge(carte)
        d = board / carte
        d.mkdir(parents=True, exist_ok=True)
        (d / "secubox-uboot-env.cmd").write_text(cmd(c), encoding="utf-8")
        subprocess.run([mkimage, "-A", "arm64", "-O", "linux", "-T", "script", "-C", "none", "-n", NOM_SCR,
                        "-d", str(d / "secubox-uboot-env.cmd"), str(d / "secubox-uboot-env.scr")],
                       check=True, stdout=subprocess.DEVNULL, env={**os.environ, "SOURCE_DATE_EPOCH": DATE_FIXE},
                       timeout=120)
        print(f"{d}/secubox-uboot-env.cmd, secubox-uboot-env.scr")


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="uboot-env.py", description=__doc__.split("\n\n")[0])
    s = p.add_subparsers(dest="action", required=True)
    s.add_parser("cmd").add_argument("carte")
    g = s.add_parser("generer")
    g.add_argument("--mkimage", default=os.environ.get("MKIMAGE", "mkimage"))
    g.add_argument("--board", type=Path, default=BOARD_DEPOT)
    for nom in ("netboot", "preparation"):
        x = s.add_parser(nom)
        x.add_argument("carte")
        x.add_argument("--serveur", required=nom == "netboot", default="<IP du maître>")
        x.add_argument("--nom", default="")
    lc = s.add_parser("live-conf")
    lc.add_argument("carte")
    lc.add_argument("--serveur", default="<IP du maître>")
    lc.add_argument("--nom", default="")
    a = p.parse_args(argv)
    try:
        if a.action == "generer":
            generer(a.mkimage, a.board)
            return 0
        c = charge(a.carte)
        if a.action == "cmd":
            sys.stdout.write(cmd(c))
        elif a.action == "netboot":
            print("\n".join(netboot(c, a.serveur, a.nom)))
        elif a.action == "preparation":
            print("\n".join(f"{r}\t{x}" for r, x in preparation(c, a.serveur, a.nom)))
        else:
            print(json.dumps(live_conf(c, a.serveur, a.nom), ensure_ascii=False, indent=1))
    except Refus as e:
        print(f"uboot-env.py : {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
