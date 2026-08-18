# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: meshtastic — CLI secubox-meshtasticctl (webui → ctl pattern)
CyberMind — https://cybermind.fr

Root-only privileged config editor for /etc/secubox/meshtastic.toml, mirroring
secubox-profiles' api/cli.py + actuate_paths.py conventions (see
.claude/MODULE-COMPLIANCE.md → Privileged Operations): the /meshtastic/ panel
runs as User=secubox and delegates every write here via sudo/systemd-run
(sudoers.d/secubox-meshtastic), never edits the config itself.

Each verb: (1) refuses non-root (rc=1, no write), (2) loads the current
config, (3) applies the change to a Config dataclass copy, (4) serializes it
via `_dump` and validates the shadow copy with `config.load` BEFORE the
atomic rename into place (double-buffer / 4R invariant from
.claude/CLAUDE.md — shadow -> validate -> swap), (5) appends a JSON line to
the audit log. `psk_secret` here is only the reference NAME the daemon reads
from the secrets store — this ctl never handles secret bytes.

`apply-egress` renders `gridpolicy.nft_egress_rules(cfg)` into an nftables
drop-in. Own base chain (like secubox-toolbox-wg.nft / secubox-threatmesh.nft)
with `policy accept`, so it only ADDS explicit accept exceptions for enabled
on-grid MQTT brokers. An empty rule list still writes a valid, rule-less chain
— the fail-safe direction: it never OPENS egress without an enabled broker.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

from . import config, gridpolicy
from .config import Config

DEFAULT_ROOT = Path("/etc/secubox")
AUDIT_LOG = Path("/var/log/secubox/audit.log")
EGRESS_DROPIN = Path("/etc/nftables.d/secubox-meshtastic-egress.nft")


def config_path_for(root: Path) -> Path:
    return root / "meshtastic.toml"


def audit_path_for(root: Path) -> Path:
    # Real /var/log/secubox/audit.log only when root is the real system root
    # (mirrors secubox-profiles' api/actuate_paths.py) — any --root used for
    # test isolation gets its own audit.log under that root instead.
    return AUDIT_LOG if root == DEFAULT_ROOT else root / "audit.log"


def egress_path_for(root: Path) -> Path:
    # Same real-vs-test derivation as audit_path_for, for the nft drop-in.
    if root == DEFAULT_ROOT:
        return EGRESS_DROPIN
    return root / "nftables.d" / "secubox-meshtastic-egress.nft"


def _running_as_root() -> bool:
    return os.geteuid() == 0


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _toml_str(s: str) -> str:
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t") + '"'


def _dump(cfg: Config) -> str:
    """Serialize a Config back to TOML text. Must round-trip: `config.load`
    on the output reproduces `cfg`. Deliberately NOT a line/section-preserving
    editor (tomllib is read-only on this Python — see module docstring) — a
    small dedicated writer that only needs to reproduce what `config.load`
    reads, not arbitrary user formatting/comments."""
    lines: list[str] = [
        f"mode = {_toml_str(cfg.mode)}",
        f"region = {_toml_str(cfg.region)}",
        f"serial = {_toml_str(cfg.serial)}",
        "",
    ]
    for ch in cfg.channels:
        grid_list = ", ".join(_toml_str(g) for g in ch.grid)
        lines += [
            "[[channel]]",
            f"name = {_toml_str(ch.name)}",
            f"grid = [{grid_list}]",
            f"psk_secret = {_toml_str(ch.psk_secret)}",
            "",
        ]
    if cfg.shared_grid is not None:
        lines += [
            "[shared_grid]",
            f"broker = {_toml_str(cfg.shared_grid.broker)}",
            f"enabled = {'true' if cfg.shared_grid.enabled else 'false'}",
            "",
        ]
    if cfg.on_grid is not None:
        lines += [
            "[on_grid]",
            f"broker = {_toml_str(cfg.on_grid.broker)}",
            f"enabled = {'true' if cfg.on_grid.enabled else 'false'}",
            "",
        ]
    lines += [
        "[passive]",
        f"role = {_toml_str(cfg.passive.role)}",
        f"packet_log = {_toml_str(cfg.passive.packet_log)}",
        "",
    ]
    return "\n".join(lines)


def _write_config(path: Path, cfg: Config) -> None:
    """Shadow -> validate -> atomic swap (double-buffer / 4R, .claude/CLAUDE.md).
    Never leaves a partially-written or unvalidated file at `path`."""
    text = _dump(cfg)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(dir=str(path.parent), prefix=f".{path.name}.shadow-")
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
        config.load(tmp)  # validate the shadow copy before it becomes live
        mode = path.stat().st_mode & 0o777 if path.exists() else 0o640
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise


def _render_egress(rules: list[str]) -> str:
    lines = [
        "# SecuBox-Deb :: secubox-meshtastic — egress allow-list",
        "# Generated by secubox-meshtasticctl apply-egress — do not edit by hand.",
        "# Allow-list add-on (policy accept base chain). Only ADDS explicit",
        "# accept exceptions for enabled on-grid MQTT brokers. An empty ruleset",
        "# grants no egress exception — fail-safe: it never OPENS egress without",
        "# an enabled broker.",
        "table inet secubox_meshtastic {",
        "    chain egress {",
        "        type filter hook output priority filter; policy accept;",
    ]
    for r in rules:
        lines.append(f"        {r}")
    lines += ["    }", "}", ""]
    return "\n".join(lines)


def _atomic_write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(dir=str(path.parent), prefix=f".{path.name}.")
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
        os.chmod(tmp, 0o644)
        os.replace(tmp, path)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise


def _audit(root: Path, verb: str, args: dict, result: str) -> None:
    entry = {"ts": _now_iso(), "verb": verb, "args": args, "result": result}
    path = audit_path_for(root)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except OSError:
        pass  # best-effort — never fatal to the config change (see profiles/api/audit.py)


def _find_channel(cfg: Config, name: str) -> int | None:
    return next((i for i, c in enumerate(cfg.channels) if c.name == name), None)


def _cmd_set_mode(args) -> int:
    if not _running_as_root():
        print("set-mode doit être lancé en root.", file=sys.stderr)
        return 1
    root = Path(args.root)
    cfg_path = config_path_for(root)
    cfg = config.load(cfg_path)
    _write_config(cfg_path, replace(cfg, mode=args.mode))
    _audit(root, "set-mode", {"mode": args.mode}, "applied")
    print(f"set-mode: {args.mode}")
    return 0


def _cmd_set_region(args) -> int:
    if not _running_as_root():
        print("set-region doit être lancé en root.", file=sys.stderr)
        return 1
    root = Path(args.root)
    cfg_path = config_path_for(root)
    cfg = config.load(cfg_path)
    _write_config(cfg_path, replace(cfg, region=args.region))
    # « written » et non « applied » : cette commande ecrit le fichier, elle ne
    # touche pas au materiel. C'est le daemon qui pose la region sur la carte a
    # son demarrage. Le mot « applied » a longtemps masque le fait que la carte
    # restait en region UNSET — donc muette, le firmware refusant d'emettre.
    _audit(root, "set-region", {"region": args.region}, "written")
    print(f"set-region: {args.region} (ecrit dans la configuration)")
    print("redemarrer secubox-meshtasticd pour le poser sur la carte")
    return 0


def _cmd_set_role(args) -> int:
    if not _running_as_root():
        print("set-role doit être lancé en root.", file=sys.stderr)
        return 1
    root = Path(args.root)
    cfg_path = config_path_for(root)
    cfg = config.load(cfg_path)
    _write_config(cfg_path, replace(cfg, passive=replace(cfg.passive, role=args.role)))
    _audit(root, "set-role", {"role": args.role}, "applied")
    print(f"set-role: {args.role}")
    return 0


def _cmd_set_grid(args) -> int:
    if not _running_as_root():
        print("set-grid doit être lancé en root.", file=sys.stderr)
        return 1
    root = Path(args.root)
    cfg_path = config_path_for(root)
    cfg = config.load(cfg_path)
    grid = tuple(g.strip() for g in args.grid.split(",") if g.strip())
    bad = [g for g in grid if g not in config.GRIDS]
    if bad:
        print(f"refusé: grid inconnu {bad} (attendu {config.GRIDS})", file=sys.stderr)
        return 2
    idx = _find_channel(cfg, args.channel)
    if idx is None:
        print(f"refusé: canal inconnu: {args.channel}", file=sys.stderr)
        return 2
    channels = list(cfg.channels)
    channels[idx] = replace(channels[idx], grid=grid)
    _write_config(cfg_path, replace(cfg, channels=channels))
    _audit(root, "set-grid", {"channel": args.channel, "grid": list(grid)}, "applied")
    print(f"set-grid[{args.channel}]: {list(grid)}")
    return 0


def _cmd_set_psk(args) -> int:
    if not _running_as_root():
        print("set-psk doit être lancé en root.", file=sys.stderr)
        return 1
    root = Path(args.root)
    cfg_path = config_path_for(root)
    cfg = config.load(cfg_path)
    idx = _find_channel(cfg, args.channel)
    if idx is None:
        print(f"refusé: canal inconnu: {args.channel}", file=sys.stderr)
        return 2
    channels = list(cfg.channels)
    channels[idx] = replace(channels[idx], psk_secret=args.secret)
    _write_config(cfg_path, replace(cfg, channels=channels))
    _audit(root, "set-psk", {"channel": args.channel, "secret": args.secret}, "applied")
    print(f"set-psk[{args.channel}]: {args.secret}")
    return 0


def _cmd_apply_egress(args) -> int:
    if not _running_as_root():
        print("apply-egress doit être lancé en root.", file=sys.stderr)
        return 1
    root = Path(args.root)
    cfg = config.load(config_path_for(root))
    rules = gridpolicy.nft_egress_rules(cfg)
    dropin = egress_path_for(root)
    _atomic_write_text(dropin, _render_egress(rules))
    _audit(root, "apply-egress", {"rules": len(rules)}, "applied")
    print(f"apply-egress: {len(rules)} rule(s) -> {dropin}")
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="secubox-meshtasticctl",
        description="Édition privilégiée de la config Meshtastic SecuBox (webui -> ctl).")
    p.add_argument("--root", default=str(DEFAULT_ROOT),
                   help="racine de config (défaut: /etc/secubox)")
    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("set-mode", help="fixe le mode (active-node/passive-listener/both)")
    sp.add_argument("mode", choices=list(config.MODES))
    sp.set_defaults(func=_cmd_set_mode)

    sp = sub.add_parser("set-region", help="fixe la région radio (ex. EU_868)")
    sp.add_argument("region")
    sp.set_defaults(func=_cmd_set_region)

    sp = sub.add_parser("set-role", help="fixe le rôle passif (ex. CLIENT_MUTE)")
    sp.add_argument("role", choices=list(config.ROLES))
    sp.set_defaults(func=_cmd_set_role)

    sp = sub.add_parser("set-grid", help="fixe le routage grille d'un canal")
    sp.add_argument("channel")
    sp.add_argument("--grid", required=True,
                    help="liste séparée par virgules, ex. off,shared")
    sp.set_defaults(func=_cmd_set_grid)

    sp = sub.add_parser("set-psk", help="fixe le NOM de référence du secret PSK d'un canal")
    sp.add_argument("channel")
    sp.add_argument("--secret", required=True, help="nom de référence (pas les octets du secret)")
    sp.set_defaults(func=_cmd_set_psk)

    sp = sub.add_parser("apply-egress",
                        help="régénère le drop-in nftables d'egress depuis la config")
    sp.set_defaults(func=_cmd_apply_egress)

    args = p.parse_args(argv)
    try:
        return args.func(args)
    except config.ConfigError as exc:
        print(f"erreur: {exc}", file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"erreur: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
