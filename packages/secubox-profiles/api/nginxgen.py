# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: profiles — câblage nginx du splash phase-2 (réveil-sur-boot)
CyberMind — https://cybermind.fr

Généralise le splash phase-2 à TOUS les vhosts on-demand : chacun reçoit UNE
ligne `include snippets/secubox-waking.conf;` dans son bloc server {}, juste
après SA ligne `server_name <domaine>;`. Le snippet (livré par le paquet) fait
tout le reste (proxy_intercept_errors + error_page 502/503/504 -> splash), donc
le câblage par-vhost se réduit à cette unique ligne.

Contraintes : idempotent (marqueur = présence du nom du snippet), ne touche QUE
le bloc du domaine visé (insertion après SA ligne server_name, robuste aux
fichiers multi-server), écriture atomique, JAMAIS de `.bak` dans le répertoire
nginx (nginx charge tout ce qui traîne — un backup y définirait un server
fantôme). La sûreté transactionnelle (nginx -t + rollback) est orchestrée par
`sync_and_reload`, qui garde le contenu original EN MÉMOIRE et le réécrit si
`nginx -t` échoue.
"""
from __future__ import annotations

import os
import tempfile
from pathlib import Path

from .wafsync import ondemand_vhosts

MARKER = "secubox-waking.conf"
_INCLUDE = "    include snippets/secubox-waking.conf;  # secubox phase-2 wake splash (nginx-sync)"


def _is_server_name_line(line: str, domain: str) -> bool:
    s = line.split("#", 1)[0].strip()
    if not s.startswith("server_name"):
        return False
    toks = s[len("server_name"):].rstrip(";").split()
    return domain in toks


def find_config(domain: str, sites_dir: Path) -> Path | None:
    """Le fichier de conf nginx dont un `server_name` contient `domain`, ou None.
    On lit les fichiers de `sites_dir` triés (déterminisme) ; on ignore les
    `.bak`/`.dpkg-*` (résidus non chargés par nginx, jamais la cible)."""
    for p in sorted(Path(sites_dir).iterdir()):
        if not p.is_file() or any(x in p.name for x in (".bak", ".dpkg", ".pre-", "~")):
            continue
        try:
            lines = p.read_text(encoding="utf-8").splitlines()
        except (OSError, UnicodeDecodeError):
            continue
        if any(_is_server_name_line(ln, domain) for ln in lines):
            return p
    return None


def wire(path: Path, domain: str) -> bool:
    """Ajoute l'include phase-2 dans le bloc server de `domain`, après sa ligne
    `server_name`. Idempotent (no-op si le marqueur est déjà là). Retourne True
    si le fichier a changé, False s'il était déjà câblé ou si aucune ligne
    server_name du domaine n'a été trouvée (on ne touche alors à rien)."""
    path = Path(path)
    text = path.read_text(encoding="utf-8")
    if MARKER in text:
        return False
    out: list[str] = []
    done = False
    for line in text.splitlines():
        out.append(line)
        if not done and _is_server_name_line(line, domain):
            out.append(_INCLUDE)
            done = True
    if not done:
        return False
    _write_atomic(path, "\n".join(out) + "\n")
    return True


def unwire(path: Path) -> bool:
    """Retire la/les ligne(s) d'include phase-2 (marqueur). Réversibilité sans
    `.bak`. Retourne True si le fichier a changé."""
    path = Path(path)
    text = path.read_text(encoding="utf-8")
    if MARKER not in text:
        return False
    kept = [ln for ln in text.splitlines() if MARKER not in ln]
    _write_atomic(path, "\n".join(kept) + "\n")
    return True


def _write_atomic(path: Path, text: str) -> None:
    path = Path(path)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
        raise


def sync_and_reload(*, manifests, sites_dir: Path, run) -> dict:
    """Câble l'include phase-2 dans chaque vhost on-demand, valide via
    `nginx -t`, puis recharge nginx — transactionnel : si `nginx -t` échoue,
    restaure tous les fichiers touchés depuis leur contenu original (gardé en
    mémoire, pas de `.bak`) et NE recharge pas.

    `run(argv) -> (rc, out)` est injecté (nginx -t / reload), testable.
    Retourne {wired, already, no_config, reloaded, rolled_back}."""
    sites_dir = Path(sites_dir)
    domains = ondemand_vhosts(manifests)
    originals: dict[Path, str] = {}
    wired: list[str] = []
    already: list[str] = []
    no_config: list[str] = []
    for dom in domains:
        cfg = find_config(dom, sites_dir)
        if cfg is None:
            no_config.append(dom)
            continue
        orig = cfg.read_text(encoding="utf-8")
        if wire(cfg, dom):
            originals.setdefault(cfg, orig)
            wired.append(dom)
        else:
            already.append(dom)

    report = {"wired": wired, "already": already, "no_config": no_config,
              "reloaded": False, "rolled_back": False}
    if not wired:
        return report
    rc, _ = run(["nginx", "-t"])
    if rc != 0:
        for p, orig in originals.items():
            _write_atomic(p, orig)
        report["rolled_back"] = True
        return report
    run(["systemctl", "reload", "nginx"])
    report["reloaded"] = True
    return report
