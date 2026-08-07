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

# PIEGE NGINX : un `error_page` declare dans un bloc REMPLACE ceux herites du
# serveur, il ne s'y ajoute pas. Or tout vhost protege par `auth_request`
# declare `error_page 401 = @sbx_auth_login;` dans son `location /` — et
# annulait donc silencieusement le `error_page 502 503 504` pose au niveau
# serveur par l'include. Le fragment ne pouvait pas fonctionner sur ces
# vhosts, c'est-a-dire la majorite d'entre eux : l'include etait present, la
# page d'attente n'apparaissait jamais, et rien ne le signalait.
#
# On redeclare donc la regle 5xx la ou le 401 est declare.
_LOC_MARKER = "secubox phase-2 wake (location)"
_LOC_LINE = ("        error_page 502 503 504 = @sbx_wake;"
             "  # " + _LOC_MARKER)


def _declares_401(line: str) -> bool:
    s = line.split("#", 1)[0].strip()
    return s.startswith("error_page") and "401" in s.split("=")[0]


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
    """Ajoute l'include phase-2 juste APRÈS la ligne `server_name` DE CE domaine.
    Idempotence PAR BLOC (pas fichier-large) : si la ligne suivant le server_name
    du domaine est déjà l'include, on ne touche à rien — ainsi un fichier
    contenant plusieurs blocs server on-demand voit CHACUN câblé (le check
    fichier-large sautait à tort tous les blocs après le premier). Retourne True
    si le fichier a changé, False s'il était déjà câblé pour ce domaine ou si
    aucune ligne server_name du domaine n'existe."""
    path = Path(path)
    lines = path.read_text(encoding="utf-8").splitlines()
    out: list[str] = []
    done = False
    for idx, line in enumerate(lines):
        out.append(line)
        if not done and _is_server_name_line(line, domain):
            nxt = lines[idx + 1] if idx + 1 < len(lines) else ""
            if MARKER in nxt:
                return False        # ce bloc a déjà l'include
            out.append(_INCLUDE)
            done = True
    if not done:
        return False

    # Deuxieme passe : redeclarer la regle 5xx dans les blocs qui declarent un
    # error_page 401 (cf. _LOC_MARKER). Sans elle, l'include ci-dessus est
    # inerte sur tout vhost protege par auth_request.
    #
    # BORNEE AU BLOC `server` QUI VIENT D'ETRE CABLE. Un fichier peut contenir
    # plusieurs blocs server, et `@sbx_wake` n'est defini que dans celui qui
    # porte l'include : ajouter la regle ailleurs produit une reference a une
    # location inexistante, et `nginx -t` echoue. Constate sur la board — la
    # synchronisation a du tout annuler.
    final: list[str] = []
    depth = 0
    inside = False
    for idx, line in enumerate(out):
        final.append(line)
        if line is _INCLUDE or (not inside and _INCLUDE in line):
            inside, depth = True, 1   # on entre dans le bloc cable
            continue
        if inside:
            depth += line.count("{") - line.count("}")
            if depth <= 0:
                inside = False
                continue
            if _declares_401(line):
                nxt = out[idx + 1] if idx + 1 < len(out) else ""
                if _LOC_MARKER not in nxt:
                    final.append(_LOC_LINE)

    _write_atomic(path, "\n".join(final) + "\n")
    return True


def unwire(path: Path) -> bool:  # noqa: D401 — retire include ET regles de bloc
    """Retire la/les ligne(s) d'include phase-2 (marqueur). Réversibilité sans
    `.bak`. Retourne True si le fichier a changé."""
    path = Path(path)
    text = path.read_text(encoding="utf-8")
    if MARKER not in text and _LOC_MARKER not in text:
        return False
    # Les DEUX marqueurs : retirer seulement l'include laisserait derriere lui
    # des regles de bloc pointant vers un @sbx_wake qui n'existe plus — nginx
    # refuserait alors de recharger.
    kept = [ln for ln in text.splitlines()
            if MARKER not in ln and _LOC_MARKER not in ln]
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


def proxying_domains(sites_dir: Path) -> list[str]:
    """Domaines de TOUS les vhosts qui relaient vers un backend.

    Le mode par defaut ne cable que les modules « a la demande ». Tous les
    autres vhosts gardent donc la page BRUTE de nginx sur un 502 — ce que
    l'utilisateur voit. Or le waker rend desormais une page soignee meme pour
    un vhost non declare : rien ne justifie de les en priver.

    Les vhosts de pure REDIRECTION sont ignores (pas de `proxy_pass`) : ils
    n'ont aucun backend qui puisse tomber, la regle y serait sans effet.
    """
    doms: list[str] = []
    for p in sorted(Path(sites_dir).iterdir()):
        if not p.is_file() or any(x in p.name for x in (".bak", ".dpkg", ".pre-", "~")):
            continue
        try:
            text = p.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        if "proxy_pass" not in text:
            continue
        for line in text.splitlines():
            st = line.split("#", 1)[0].strip()
            if not st.startswith("server_name"):
                continue
            for tok in st[len("server_name"):].rstrip(";").split():
                if tok not in ("_", "localhost") and "." in tok and tok not in doms:
                    doms.append(tok)
    return doms


def sync_and_reload(*, manifests, sites_dir: Path, run, all_vhosts: bool = False) -> dict:
    """Câble l'include phase-2 dans chaque vhost on-demand, valide via
    `nginx -t`, puis recharge nginx — transactionnel : si `nginx -t` échoue,
    restaure tous les fichiers touchés depuis leur contenu original (gardé en
    mémoire, pas de `.bak`) et NE recharge pas.

    `run(argv) -> (rc, out)` est injecté (nginx -t / reload), testable.
    Retourne {wired, already, no_config, reloaded, rolled_back}."""
    sites_dir = Path(sites_dir)
    domains = proxying_domains(sites_dir) if all_vhosts else ondemand_vhosts(manifests)
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
