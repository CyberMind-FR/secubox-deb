# SPDX-License-Identifier: LicenseRef-CMSD-1.0
"""secubox-dns-lan generate | check | status."""
import argparse
import json
import sys
import tomllib
from pathlib import Path

from . import appliquer, config, rendu

CONFIG = "/etc/secubox/dns-lan.toml"


def _charger(chemin: str, confiner: bool = True) -> dict:
    try:
        brut = tomllib.loads(Path(chemin).read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise config.ErreurConfig(f"{chemin} introuvable") from None
    except (OSError, tomllib.TOMLDecodeError) as e:
        raise config.ErreurConfig(f"{chemin} illisible : {e}") from None
    return config.valider(brut, confiner)


def main(argv=None, systeme=None, sortie=None, confiner: bool = True) -> int:
    out = sortie or sys.stdout
    ap = argparse.ArgumentParser(prog="secubox-dns-lan", description="DNS du LAN : drop-ins Unbound et adresse IPv6 stable, générés depuis le TOML.")
    ap.add_argument("--config", default=CONFIG)
    ap.add_argument("commande", choices=["generate", "check", "status"])
    a = ap.parse_args(argv)
    try:
        cfg = _charger(a.config, confiner)
        if a.commande == "generate":
            r = appliquer.generer(cfg, systeme)
            print(json.dumps({"ok": True, **r}, ensure_ascii=False), file=out)
            return 0
        ecart = appliquer.deriver(cfg)
        if a.commande == "check":
            print(json.dumps({"ok": not ecart, "ecart": ecart}, ensure_ascii=False), file=out)
            return 0 if not ecart else 3
        fichiers = [{"chemin": c, "present": Path(c).exists(), "conforme": c not in ecart} for c in rendu.rendre(cfg)]
        print(json.dumps({"config": a.config, "fichiers": fichiers, "ecart": len(ecart)}, ensure_ascii=False, indent=1), file=out)
        return 0
    except (config.ErreurConfig, appliquer.ErreurApplication, OSError) as e:
        print(f"secubox-dns-lan : {e}", file=sys.stderr)
        return 1
