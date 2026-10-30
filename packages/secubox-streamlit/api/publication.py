#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: secubox-streamlit — port, publication et environnement d'une appli (#3247).

DEUX USAGES, UN SEUL CODE
  * EN ROOT, par streamlitctl (`python3 -I /usr/lib/secubox/streamlit/api/publication.py …`) : c'est lui qui écrit
    streamlit.toml, le vhost nginx, la route sbxwaf, le journal d'audit. `-I` écarte PYTHONPATH, le dossier courant
    et celui du script : la bibliothèque standard seule est importée (vérifié par les tests).
  * importé par l'API (compte secubox) pour VALIDER un nom avant sudo et LIRE les publications. Jamais d'écriture.

LA CHAÎNE PUBLIÉE — celle posée à la main pour couture.gk2.secubox.in le 2026-10-28, rendue générable :
    HAProxy  vhost déclaré (`haproxyctl vhost add <d> nginx_vhosts true` → use_backend sbxwaf_inspector)
    → sbxwaf route <d> → <adresse>:9080, posée par l'outil commun `secubox-waf-route`
    → nginx :9080, server_name <d> (/etc/nginx/sites-available/streamlit-<nom public>.conf, lien dans sites-enabled)
    → conteneur <ip>:<port>, WebSocket compris (Upgrade/Connection, proxy_read_timeout 86400s)
    + la déclaration dans streamlit.toml : [instances.<nom public>] et [apps.<dossier>].
  JAMAIS de contournement du WAF : la route sbxwaf vise nginx, jamais le conteneur ; jamais de waf_bypass.

TOUT RETRAIT VÉRIFIE QUE CE QU'IL RETIRE EST À NOUS : une route re-pointée ailleurs, un fichier nginx qui sert un
autre nom ne sont pas touchés (avertissement). Une table de routes illisible fait ABANDONNER, jamais repartir de
zéro (même prudence que secubox-waf-route). Chaque changement est écrit dans /var/log/secubox/audit.log ; un journal
inaccessible fait abandonner AVANT tout changement.

Codes de retour : 0 fait, 1 échec d'écriture, 2 appli inconnue, 3 état (pas publiée, aucun port, domaine inconnu…),
4 conflit (port ou nom pris, nom réservé), 5 aucun port libre, 64 argument invalide, 75 conteneur indisponible.
"""
from __future__ import annotations

import argparse
import collections
import contextlib
import errno
import fcntl
import ipaddress
import json
import os
import pwd
import re
import secrets
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import zipfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

try:
    import tomllib
except ModuleNotFoundError:  # Python < 3.11 : la validation du résultat est alors sautée
    tomllib = None

OK, ECHEC, INCONNUE, ETAT, CONFLIT, EPUISE, DEPENDANCES, ARGUMENT, INDISPONIBLE = 0, 1, 2, 3, 4, 5, 6, 64, 75

# Libellé DNS strict : minuscules, chiffres, tirets, 1 à 63, ni tiret en tête ni en fin. Le soulignement est refusé
# (pas un nom d'hôte valide) et le point aussi : un nom public est UNE étiquette sous le domaine de la box.
LABEL_RE = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
NOM_APPLI_RE = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}")
ACTEUR_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.@-]{0,63}")
CLE_ENV_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,63}")
DOMAINE_RE = re.compile(r"(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+")

# Noms de service de la box : jamais attribués à une appli, même libres aujourd'hui (un service installé demain les
# réclamerait). Les noms DÉJÀ servis sont refusés en plus par la table de routes, haproxy.toml et nginx.
NOMS_RESERVES = frozenset({
    "admin", "api", "apt", "auth", "autoconfig", "autodiscover", "console", "dns", "ftp", "git", "gitea", "hall",
    "haproxy", "imap", "localhost", "login", "mail", "mesh", "mx", "ns", "ns1", "ns2", "pop", "pop3", "portal",
    "smtp", "sso", "status", "streamforge", "streamlit", "vault", "vpn", "waf", "webmail", "wg", "www",
})
# Variables qui détourneraient l'exécution de l'appli (chargeur, interpréteur, recherche des commandes).
CLES_ENV_INTERDITES = frozenset({"PATH", "HOME", "SHELL", "BASH_ENV", "ENV", "IFS", "STREAMLIT_DATA_DIR"})
PREFIXES_ENV_INTERDITS = ("LD_", "PYTHON")

PORT_NGINX = 9080            # nginx d'hôte derrière sbxwaf (jamais 80/443 : HAProxy les tient)
PORT_MIN, PORT_MAX = 8501, 8600
CONTENEUR = "streamlit"
ENV_CONTENEUR = "/etc/streamlit/env"          # dans le conteneur, root 0600, hors des applis, jamais servi
MARQUE_NGINX = "# secubox-streamlit:"
_EXCLUS = {"__pycache__", "pages"}
# Verrou dans un dossier root 0700 À NOUS (jamais /run/lock, partagé et inscriptible par tous).
VERROU_DEFAUT = "/run/secubox-streamlit/publication.lock"
TAILLE_PORT_MAX = 64 * 1024        # un fichier de port est une poignée de lignes
ENV_MAX = 64 * 1024                # environnement d'une appli : au-delà, refus (jamais tronqué)
ZIP_MAX_OCTETS = 1 << 30           # archive et contenu décompressé : 1 Gio
ZIP_MAX_ENTREES = 10000
PIP_DELAI_S = 240                  # la requête de dépôt doit répondre avant les 300 s de lecture de nginx
PIP_DELAI_CONTENEUR_S = 230        # `timeout` DANS le conteneur : pip s'arrête avant que lxc-attach ne soit coupé
MARGE_DISQUE = 64 * 1024 * 1024    # place laissée libre après un dépôt (gk2 a peu d'espace racine)


class Refus(Exception):
    def __init__(self, code: int, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


def _env(nom: str, defaut: str) -> str:
    return os.environ.get(nom) or defaut


def chemin_routes() -> Path:
    return Path(_env("SECUBOX_STREAMLIT_ROUTES", "/etc/secubox/waf/haproxy-routes.json"))


def chemin_haproxy() -> Path:
    return Path(_env("SECUBOX_HAPROXY_TOML", "/etc/secubox/haproxy.toml"))


def chemin_audit() -> Path:
    return Path(_env("SECUBOX_STREAMLIT_AUDIT", "/var/log/secubox/audit.log"))


def chemin_verrou() -> Path:
    return Path(_env("SECUBOX_STREAMLIT_VERROU", VERROU_DEFAUT))


def dossier_nginx() -> Path:
    return Path(_env("SECUBOX_NGINX_DIR", "/etc/nginx"))


# ─── Validation (partagée avec l'API) ─────────────────────────────────────

def erreur_label(label) -> str | None:
    if not isinstance(label, str) or not label:
        return "nom public vide"
    if not LABEL_RE.fullmatch(label):
        return (f"nom public invalide « {label[:80]} » : minuscules, chiffres et tirets, 1 à 63 caractères, "
                "sans tiret en tête ni en fin")
    return None


def label_reserve(label: str) -> bool:
    return label in NOMS_RESERVES


def label_par_defaut(appli: str) -> str:
    """Le nom public proposé pour un dossier : minuscules, tout le reste en tirets. "" si rien d'utilisable."""
    s = re.sub(r"[^a-z0-9]+", "-", str(appli).lower()).strip("-")[:63].strip("-")
    return s if s and erreur_label(s) is None else ""


def erreur_cle_env(cle) -> str | None:
    if not isinstance(cle, str) or not CLE_ENV_RE.fullmatch(cle):
        return f"nom de variable invalide « {str(cle)[:64]} » (lettres, chiffres, _ ; pas de chiffre en tête)"
    if cle.upper() in CLES_ENV_INTERDITES or cle.upper().startswith(PREFIXES_ENV_INTERDITS):
        return f"variable réservée « {cle} » : elle détournerait l'exécution de l'appli"
    return None


def erreur_valeur_env(valeur) -> str | None:
    if not isinstance(valeur, str):
        return "valeur non textuelle"
    if len(valeur) > 4096:
        return "valeur trop longue (4096 caractères au plus)"
    if any(c in valeur for c in "\n\r\0'"):
        return "valeur refusée : ni saut de ligne, ni caractère nul, ni apostrophe"
    return None


# ─── streamlit.toml, lu ligne à ligne comme le fait streamlitctl ──────────

_ENTETE = re.compile(r"^\s*\[([^\[\]]+)\]\s*(?:#.*)?$")
_CLE = re.compile(r"^\s*([A-Za-z0-9_-]+)\s*=\s*(.*?)\s*$")


def _valeur(brut: str):
    if brut.startswith('"'):
        m = re.match(r'"((?:[^"\\]|\\.)*)"', brut)
        return m.group(1).replace('\\"', '"').replace("\\\\", "\\") if m else brut
    brut = brut.split("#", 1)[0].strip()
    if brut in ("true", "false"):
        return brut == "true"
    if re.fullmatch(r"-?\d+", brut):
        return int(brut)
    return brut


def sections(texte: str) -> list[tuple[str, int, int, dict]]:
    """[(en-tête, ligne d'en-tête, fin exclusive, valeurs)] — clés simples seulement, la première l'emporte."""
    lignes = texte.splitlines(keepends=True)
    res, courant = [], None
    for i, ligne in enumerate(lignes):
        m = _ENTETE.match(ligne)
        if m:
            if courant:
                courant[2] = i
                res.append(tuple(courant))
            courant = [m.group(1).strip(), i, len(lignes), {}]
            continue
        c = _CLE.match(ligne)
        if courant and c and not ligne.lstrip().startswith("#"):
            courant[3].setdefault(c.group(1), _valeur(c.group(2)))
    if courant:
        res.append(tuple(courant))
    return res


def _port(v) -> int | None:
    try:
        p = int(v)
    except (TypeError, ValueError):
        return None
    return p if 1 <= p <= 65535 else None


def instances(texte: str) -> list[dict]:
    out = []
    for entete, _d, _f, v in sections(texte):
        if entete.startswith("instances.") and len(entete) > len("instances."):
            ident = entete[len("instances."):]
            out.append({"id": ident, "app": str(v.get("app") or ident), "port": _port(v.get("port")),
                        "domain": str(v.get("domain") or ""), "enabled": v.get("enabled", True) is not False,
                        "valeurs": v})
    return out


def applis_declarees(texte: str) -> dict[str, dict]:
    return {e[len("apps."):]: v for e, _d, _f, v in sections(texte) if e.startswith("apps.") and len(e) > 5}


def reglages(texte: str) -> dict:
    par = {e: v for e, _d, _f, v in sections(texte)}
    pub, ports = par.get("publication", {}), par.get("ports", {})
    pmin, pmax = _port(ports.get("min")) or PORT_MIN, _port(ports.get("max")) or PORT_MAX
    if pmax < pmin:
        pmin, pmax = PORT_MIN, PORT_MAX
    return {"auto": pub.get("auto") is True, "autostart": pub.get("autostart", True) is not False,
            "ip_conteneur": str(pub.get("ip_conteneur") or ""), "port_min": pmin, "port_max": pmax}


def domaine_de(inst: dict, dom_box: str) -> str:
    return inst["domain"] or (f"{inst['id']}.{dom_box}" if dom_box else "")


def publications(texte: str, dom_box: str) -> dict[str, list[dict]]:
    """{appli: [{nom_public, domaine, port, enabled}]} — lu par l'API (GET /publications)."""
    res: dict[str, list[dict]] = {}
    for inst in instances(texte):
        if not inst["enabled"]:
            continue
        res.setdefault(inst["app"], []).append({"nom_public": inst["id"], "domaine": domaine_de(inst, dom_box),
                                                "port": inst["port"], "enabled": inst["enabled"],
                                                "geree": inst["valeurs"].get("publication_geree") is True})
    return res


def _fmt(v) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, int):
        return str(v)
    return '"' + str(v).replace("\\", "\\\\").replace('"', '\\"') + '"'


def poser_cles(texte: str, entete: str, champs: dict) -> str:
    """Pose `champs` dans [entete] (section créée en fin de fichier si absente) ; les autres lignes restent."""
    lignes = texte.splitlines(keepends=True)
    if lignes and not lignes[-1].endswith("\n"):
        lignes[-1] += "\n"
    sec = next((s for s in sections("".join(lignes)) if s[0] == entete), None)
    if sec is None:
        bloc = (["\n"] if lignes and lignes[-1].strip() else []) + [f"[{entete}]\n"]
        return "".join(lignes + bloc + [f"{k} = {_fmt(v)}\n" for k, v in champs.items()])
    _e, debut, fin, _v = sec
    restants, corps = dict(champs), []
    for ligne in lignes[debut + 1:fin]:
        c = _CLE.match(ligne)
        if c and not ligne.lstrip().startswith("#") and c.group(1) in champs:
            if c.group(1) in restants:
                corps.append(f"{c.group(1)} = {_fmt(restants.pop(c.group(1)))}\n")
            continue
        corps.append(ligne)
    k = len(corps)
    while k and not corps[k - 1].strip():
        k -= 1
    corps[k:k] = [f"{c} = {_fmt(v)}\n" for c, v in restants.items()]
    return "".join(lignes[:debut + 1] + corps + lignes[fin:])


def retirer_cles(texte: str, entete: str, cles: set) -> str:
    lignes = texte.splitlines(keepends=True)
    sec = next((s for s in sections(texte) if s[0] == entete), None)
    if sec is None:
        return texte
    _e, debut, fin, _v = sec
    garde = [ligne for ligne in lignes[debut + 1:fin]
             if not ((c := _CLE.match(ligne)) and not ligne.lstrip().startswith("#") and c.group(1) in cles)]
    return "".join(lignes[:debut + 1] + garde + lignes[fin:])


def retirer_section(texte: str, entete: str) -> str:
    lignes = texte.splitlines(keepends=True)
    sec = next((s for s in sections(texte) if s[0] == entete), None)
    if sec is None:
        return texte
    _e, debut, fin, _v = sec
    while debut and not lignes[debut - 1].strip():       # la ligne vide qui la séparait part avec elle
        debut -= 1
    return "".join(lignes[:debut] + lignes[fin:])


def _valider_toml(ancien: str, nouveau: str) -> None:
    """Double tampon : le résultat doit se relire. Un fichier DÉJÀ invalide avant nous ne bloque pas l'écriture."""
    if tomllib is None:
        return
    try:
        tomllib.loads(ancien)
    except tomllib.TOMLDecodeError:
        return
    try:
        tomllib.loads(nouveau)
    except tomllib.TOMLDecodeError as e:
        raise Refus(ECHEC, f"streamlit.toml : le résultat ne serait pas du TOML valide ({e}) — rien n'est écrit")


# ─── Fichiers, commandes, verrou, audit ───────────────────────────────────

def ecrire_atomique(chemin: Path, data: str, mode_defaut: int = 0o644) -> None:
    """Temporaire VOISIN + rename(2). Mode et propriétaire repris d'un fichier ORDINAIRE remplacé seulement : une
    cible qui est un lien (ou une FIFO, un périphérique) est refusée, jamais suivie ni imitée."""
    try:
        st = os.stat(chemin, follow_symlinks=False)
    except FileNotFoundError:
        st = None
    if st is not None and not stat.S_ISREG(st.st_mode):
        raise Refus(ETAT, f"{chemin} : lien symbolique ou fichier spécial — refusé, rien n'est écrit")
    fd, tmp = tempfile.mkstemp(dir=chemin.parent, prefix=f".{chemin.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(data)
            if st is not None:
                os.fchmod(f.fileno(), st.st_mode & 0o7777)
                with contextlib.suppress(PermissionError):
                    os.fchown(f.fileno(), st.st_uid, st.st_gid)
            else:
                os.fchmod(f.fileno(), mode_defaut)
        os.replace(tmp, chemin)
    except BaseException:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmp)
        raise


def _lstat_dans(dfd: int, nom: str):
    try:
        return os.stat(nom, dir_fd=dfd, follow_symlinks=False)
    except FileNotFoundError:
        return None


def _lire_dans(dfd: int, nom: str, limite: int = TAILLE_PORT_MAX) -> str | None:
    """Contenu d'un fichier ORDINAIRE du dossier `dfd`, None s'il n'existe pas. Jamais à travers un lien
    (O_NOFOLLOW), jamais bloqué par une FIFO (refusée avant ouverture, O_NONBLOCK en ceinture), taille plafonnée.
    Les dossiers d'applis sont inscriptibles par le conteneur : ce que root y lit ne se suit pas."""
    st = _lstat_dans(dfd, nom)
    if st is None:
        return None
    if not stat.S_ISREG(st.st_mode):
        raise Refus(ETAT, f"{nom} : lien symbolique, FIFO ou périphérique — refusé")
    try:
        fd = os.open(nom, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=dfd)
    except FileNotFoundError:
        return None
    except OSError as e:
        raise Refus(ETAT, f"{nom} : {'lien symbolique refusé' if e.errno == errno.ELOOP else e.strerror}")
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise Refus(ETAT, f"{nom} : n'est plus un fichier ordinaire — refusé")
        morceaux, total = [], 0
        while True:
            m = os.read(fd, 65536)
            if not m:
                break
            total += len(m)
            if total > limite:
                raise Refus(ETAT, f"{nom} : trop gros (plus de {limite} octets) — refusé")
            morceaux.append(m)
        return b"".join(morceaux).decode("utf-8", errors="replace")
    finally:
        os.close(fd)


def _ecrire_dans(dfd: int, nom: str, texte: str, mode: int = 0o644) -> None:
    """Écrit `nom` dans le dossier `dfd` : temporaire créé O_EXCL|O_NOFOLLOW, mode FIXE (jamais hérité), root
    propriétaire quand on l'est, puis renameat — la cible, si elle existe, doit être un fichier ordinaire."""
    st = _lstat_dans(dfd, nom)
    if st is not None and not stat.S_ISREG(st.st_mode):
        raise Refus(ETAT, f"{nom} : lien symbolique, FIFO ou périphérique — refusé, rien n'est écrit")
    tmp = f".{nom}.{secrets.token_hex(6)}.tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=dfd)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(texte)
            os.fchmod(f.fileno(), mode)
            if os.geteuid() == 0:
                os.fchown(f.fileno(), 0, 0)
        os.replace(tmp, nom, src_dir_fd=dfd, dst_dir_fd=dfd)
    except BaseException:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmp, dir_fd=dfd)
        raise


def _cmd(argv: list[str], timeout: int = 60, entree: str | None = None, env: dict | None = None) -> tuple[int, str]:
    """(code, sortie utile) ; jamais d'exception : l'appelant décide si l'échec est fatal."""
    try:
        if entree is None:
            r = subprocess.run(argv, check=True, timeout=timeout, capture_output=True, text=True, env=env,
                               stdin=subprocess.DEVNULL)
        else:
            r = subprocess.run(argv, check=True, timeout=timeout, capture_output=True, text=True, env=env,
                               input=entree)
        return 0, (r.stdout or "") + (r.stderr or "")
    except subprocess.CalledProcessError as e:
        return e.returncode or 1, ((e.stderr or "") + (e.stdout or "")).strip()
    except subprocess.TimeoutExpired:
        return 124, f"{argv[0]} : délai de {timeout} s dépassé"
    except OSError as e:
        return 127, f"{argv[0]} : {e.strerror or e}"


def _court(texte: str) -> str:
    lignes = [x.strip() for x in str(texte).splitlines() if x.strip()]
    return " ; ".join(lignes[-3:])[:300]


@contextlib.contextmanager
def verrou(delai: float = 20.0):
    """Verrou exclusif dans un dossier à nous, 0700, sans lien (jamais /run/lock, inscriptible par tous)."""
    chemin = chemin_verrou()
    dossier = chemin.parent
    with contextlib.suppress(FileExistsError):
        os.mkdir(dossier, 0o700)
    try:
        st = os.stat(dossier, follow_symlinks=False)
    except OSError as e:
        raise Refus(ECHEC, f"dossier du verrou {dossier} inaccessible ({e.strerror})")
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != os.geteuid() or st.st_mode & 0o077:
        raise Refus(ECHEC, f"dossier du verrou {dossier} non protégé (attendu : dossier à nous, 0700, sans lien)")
    try:
        fd = os.open(chemin, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    except OSError as e:
        raise Refus(ECHEC, f"verrou {chemin} inaccessible ({e.strerror})")
    try:
        fin = time.monotonic() + delai
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() > fin:
                    raise Refus(INDISPONIBLE, "une autre publication est en cours — réessayez dans un instant")
                time.sleep(0.2)
        yield
    finally:
        os.close(fd)


class Journal:
    """Journal d'audit, ouvert AVANT tout changement : inaccessible = rien n'est modifié."""

    def __init__(self, par: str):
        chemin = chemin_audit()
        try:
            self.fd = os.open(chemin, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o640)
        except OSError as e:
            raise Refus(ECHEC, f"journal d'audit inaccessible ({chemin} : {e.strerror}) — rien n'est modifié")
        self.par = par or "inconnu"

    def ecrire(self, **champs) -> None:
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        ligne = {"ts": ts, "module": "streamlit", **champs, "par": self.par}
        os.write(self.fd, (json.dumps(ligne, ensure_ascii=False) + "\n").encode("utf-8"))

    def fermer(self) -> None:
        os.close(self.fd)


def domaine_box() -> str:
    force = os.environ.get("SECUBOX_DOMAINE", "").strip().lstrip(".").lower()
    if force:
        return force if DOMAINE_RE.fullmatch(force) else ""
    rc, sortie = _cmd([_env("SECUBOX_DOMAINE_BIN", "secubox-domaine")], timeout=15)
    dom = sortie.strip().lower() if rc == 0 else ""
    return dom if DOMAINE_RE.fullmatch(dom) else ""


# ─── Applis et ports ──────────────────────────────────────────────────────













def _proprietaires_admis() -> tuple[set, set]:
    """(uids, gids) admis pour le dossier des applis : root, secubox, et nous-mêmes."""
    uids, gids = {0, os.geteuid()}, {0, os.getegid()}
    try:
        compte = pwd.getpwnam("secubox")
        uids.add(compte.pw_uid)
        gids.add(compte.pw_gid)
    except KeyError:
        pass
    return uids, gids


def _fd_apps(apps: Path) -> int:
    """Le dossier des applis, ouvert SANS suivre de lien : son parent (/srv/streamlit) est monté en écriture dans le
    conteneur, qui pourrait remplacer `apps` par un lien. Propriétaire root, secubox ou nous ; jamais inscriptible
    par tous ; inscriptible par le groupe seulement si ce groupe est root, secubox ou le nôtre. Refus : code 3."""
    apps = Path(os.path.abspath(apps))
    try:
        pfd = os.open(apps.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    except OSError as e:
        raise Refus(ECHEC, f"dossier {apps.parent} inaccessible ({e.strerror})")
    try:
        fd = os.open(apps.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=pfd)
    except OSError as e:
        if e.errno in (errno.ELOOP, errno.ENOTDIR):
            raise Refus(ETAT, f"dossier des applis {apps} : lien symbolique (ou pas un dossier) — refusé")
        raise Refus(ECHEC, f"dossier des applis {apps} inaccessible ({e.strerror})")
    finally:
        os.close(pfd)
    st = os.fstat(fd)
    uids, gids = _proprietaires_admis()
    if (st.st_mode & 0o002 or (st.st_mode & 0o020 and st.st_gid not in gids) or st.st_uid not in uids):
        os.close(fd)
        raise Refus(ETAT, f"dossier des applis {apps} : propriétaire ou mode inattendu (attendu root ou secubox, "
                          f"jamais inscriptible par tous ; vu uid {st.st_uid}, gid {st.st_gid}, "
                          f"{oct(st.st_mode & 0o777)})")
    return fd


def forme_appli(apps: Path, appli: str) -> str | None:
    """'dossier' | 'script' | None (inconnue). Une entrée qui est un LIEN est refusée (code 3), jamais suivie :
    un lien vers /etc ferait lire ou écrire root ailleurs que dans le dossier de l'appli."""
    afd = _fd_apps(apps)
    try:
        for nom, forme in ((appli, "dossier"), (f"{appli}.py", "script")):
            st = _lstat_dans(afd, nom)
            if st is None:
                continue
            if stat.S_ISLNK(st.st_mode):
                raise Refus(ETAT, f"« {nom} » sous {apps} est un lien symbolique — refusé")
            if forme == "dossier" and stat.S_ISDIR(st.st_mode):
                return "dossier"
            if forme == "script" and stat.S_ISREG(st.st_mode):
                return "script"
        return None
    finally:
        os.close(afd)


def appli_existe(apps: Path, appli: str) -> bool:
    return forme_appli(apps, appli) is not None


@contextlib.contextmanager
def _dossier_port(apps: Path, appli: str):
    """(descripteur du dossier qui porte le fichier de port, nom du fichier) — même règle que _app_port_file du
    ctl : DANS le dossier de l'appli, ou `.streamlit-<appli>.toml` voisin d'un script à plat. Ouvert O_NOFOLLOW."""
    forme = forme_appli(apps, appli)
    if forme is None:
        raise Refus(INCONNUE, f"appli inconnue : {appli}")
    afd = _fd_apps(apps)
    try:
        if forme == "dossier":
            try:
                dfd = os.open(appli, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=afd)
            except OSError as e:
                raise Refus(ETAT, f"dossier de l'appli « {appli} » : {e.strerror} (lien refusé)")
            try:
                yield dfd, ".streamlit.toml"
            finally:
                os.close(dfd)
        else:
            yield afd, f".streamlit-{appli}.toml"
    finally:
        os.close(afd)


def lire_port_appli(apps: Path, appli: str, strict: bool = True) -> int | None:
    """Port persisté de l'appli. strict=False (ports des AUTRES applis) : un lien, une FIFO… comptent pour rien."""
    try:
        with _dossier_port(apps, appli) as (dfd, nom):
            texte = _lire_dans(dfd, nom)
    except Refus:
        if strict:
            raise
        return None
    m = re.search(r'^port[ \t]*=[ \t]*"?(\d+)', texte or "", re.M)
    return _port(m.group(1)) if m else None


def _poser_ligne(texte: str, cle: str, valeur: str) -> str:
    if re.search(rf"^{cle}[ \t]*=", texte, re.M):
        return re.sub(rf"^{cle}[ \t]*=.*$", f"{cle} = {valeur}", texte, count=1, flags=re.M)
    return (texte if not texte or texte.endswith("\n") else texte + "\n") + f"{cle} = {valeur}\n"


def ecrire_port_appli(apps: Path, appli: str, port: int | None = None, entrypoint: str | None = None,
                      sauvegarde: str | None = None) -> bool:
    """Pose `port` et/ou `entrypoint` dans le fichier de port de l'appli, en 0644 root, sans jamais suivre un lien
    ni hériter d'un mode. Rend True si le fichier a changé."""
    with _dossier_port(apps, appli) as (dfd, nom):
        ancien = _lire_dans(dfd, nom) or ""
        texte = ancien
        if port is not None:
            texte = _poser_ligne(texte, "port", str(port))
        if entrypoint is not None:
            texte = _poser_ligne(texte, "entrypoint", f'"{entrypoint}"')
        if texte == ancien:
            return False
        if sauvegarde and ancien:
            _ecrire_dans(dfd, f"{nom}.bak.{sauvegarde}", ancien)
        _ecrire_dans(dfd, nom, texte)
        return True


def _entrees_applis(apps: Path):
    """Les applis du dossier : dossiers et scripts .py ORDINAIRES ; les liens sont ignorés, jamais suivis."""
    afd = _fd_apps(apps)
    try:
        with os.scandir(afd) as it:
            entrees = sorted(it, key=lambda e: e.name)
    except OSError:
        return
    finally:
        os.close(afd)
    for e in entrees:
        if e.name.startswith(".") or e.name in _EXCLUS:
            continue
        try:
            if e.is_dir(follow_symlinks=False):
                yield e.name
            elif e.name.endswith(".py") and e.is_file(follow_symlinks=False):
                yield e.name[:-3]
        except OSError:
            continue


def routes_lisibles() -> dict:
    """La table des routes sbxwaf, ou {} si absente ou illisible (lecture seule : choix d'un port, API)."""
    try:
        d = json.loads(chemin_routes().read_text(encoding="utf-8"))
        return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def lire_routes() -> dict:
    chemin = chemin_routes()
    try:
        brut = chemin.read_text(encoding="utf-8")
    except FileNotFoundError:
        raise Refus(ETAT, f"table des routes sbxwaf absente ({chemin}) : le WAF n'est pas installé, "
                          "publication impossible")
    except OSError as e:
        raise Refus(ECHEC, f"table des routes sbxwaf illisible ({e.strerror}) — rien n'est écrit")
    try:
        d = json.loads(brut)
    except ValueError:
        d = None
    if not isinstance(d, dict):
        raise Refus(ECHEC, "table des routes sbxwaf illisible (JSON invalide) — ABANDON : on ne réécrit pas ce "
                           "qu'on n'a pas su lire")
    return d


def _ipv4(x) -> str | None:
    try:
        ip = ipaddress.IPv4Address(str(x).strip())
    except ValueError:
        return None
    return None if ip.is_loopback or ip.is_unspecified or ip.is_multicast else str(ip)


def reseaux_pont(lxc_config: str | None) -> list | None:
    """Sous-réseaux du conteneur : ses adresses déclarées (lxc.net.N.ipv4.address) et celles de son pont
    (lxc.net.N.link, lues par `ip -j`). None : aucune configuration fournie, donc pas de restriction (usage hors
    ctl) ; [] : configuration fournie mais aucun sous-réseau trouvé — seule l'adresse réglée passe alors."""
    if not lxc_config:
        return None
    texte = _lire(Path(lxc_config)) or ""
    reseaux, ponts = [], []
    for ligne in texte.splitlines():
        m = re.match(r"^\s*lxc\.net\.\d+\.ipv4\.address\s*=\s*([\d.]+/\d{1,2})\s*$", ligne)
        if m:
            with contextlib.suppress(ValueError):
                reseaux.append(ipaddress.IPv4Interface(m.group(1)).network)
        m = re.match(r"^\s*lxc\.net\.\d+\.link\s*=\s*([A-Za-z0-9_.-]{1,15})\s*$", ligne)
        if m:
            ponts.append(m.group(1))
    for pont in ponts:
        rc, sortie = _cmd(["ip", "-j", "-4", "addr", "show", "dev", pont], timeout=10)
        if rc:
            continue
        with contextlib.suppress(ValueError, TypeError, KeyError):
            for lien in json.loads(sortie or "[]"):
                for adr in lien.get("addr_info", []):
                    reseaux.append(ipaddress.IPv4Interface(f"{adr['local']}/{adr['prefixlen']}").network)
    return reseaux


def _dans(ip: str | None, reseaux: list | None) -> bool:
    if ip is None:
        return False
    return reseaux is None or any(ipaddress.IPv4Address(ip) in r for r in reseaux)


def ip_conteneur(texte: str, routes: dict, ip_vive: str | None,
                 reseaux: list | None = None) -> tuple[str | None, str, str]:
    """(adresse, origine, motif d'un rejet) pour proxy_pass : réglage `[publication] ip_conteneur` (choix de
    l'opérateur), sinon l'adresse vive, sinon celle des publications existantes — ces deux-là SEULEMENT dans le
    sous-réseau du pont du conteneur : une adresse posée par le conteneur lui-même ne doit jamais faire viser à
    nginx un autre hôte."""
    cfg = _ipv4(reglages(texte)["ip_conteneur"])
    if cfg:
        return cfg, "reglage", ""
    rejet = ""
    vive = _ipv4(ip_vive) if ip_vive else None
    if vive and _dans(vive, reseaux):
        return vive, "vive", ""
    if vive:
        rejet = f"adresse vive {vive} hors du sous-réseau du pont du conteneur"
    compte: collections.Counter = collections.Counter()
    for inst in instances(texte):
        c = routes.get(inst["domain"]) if inst["domain"] else None
        if isinstance(c, list) and len(c) == 2 and _port(c[1]) not in (None, PORT_NGINX) and _ipv4(c[0]):
            compte[_ipv4(c[0])] += 1
    for _appli, ip, _p in vhosts_generes():
        compte[ip] += 1
    for ip, _n in compte.most_common():
        if _dans(ip, reseaux):
            return ip, "voisine", ""
    if reseaux is not None and not reseaux and not rejet:
        rejet = "sous-réseau du pont du conteneur introuvable"
    return None, "", rejet


def vhosts_generes() -> list[tuple[str, str, int]]:
    """(appli, ip, port) des vhosts nginx que NOUS avons générés (marque en tête de fichier)."""
    out = []
    for f in sorted((dossier_nginx() / "sites-available").glob("streamlit-*.conf")):
        texte = _lire(f) if not f.is_symlink() else None
        if not texte or not texte.startswith(MARQUE_NGINX):
            continue
        m_app = re.match(rf"{re.escape(MARQUE_NGINX)} appli=(\S+)", texte)
        m_pp = re.search(r"proxy_pass\s+http://([\d.]+):(\d+)", texte)
        if m_app and m_pp and _ipv4(m_pp.group(1)) and _port(m_pp.group(2)):
            out.append((m_app.group(1), _ipv4(m_pp.group(1)), _port(m_pp.group(2))))
    return out


def ports_pris(appli: str, texte: str, apps: Path, routes: dict, ecoute: set, processus: dict,
               ip: str | None) -> dict[int, str]:
    """{port: raison} — tout ce qui appartient déjà à une AUTRE appli, ou écoute déjà dans le conteneur."""
    pris: dict[int, str] = {}
    for nom, v in applis_declarees(texte).items():
        if nom != appli and _port(v.get("port")):
            pris.setdefault(_port(v.get("port")), f"déjà déclaré pour l'appli « {nom} »")
    for inst in instances(texte):
        if inst["app"] != appli and inst["port"]:
            pris.setdefault(inst["port"], f"déjà publié pour l'appli « {inst['app']} » ({inst['id']})")
    for nom in _entrees_applis(apps):
        if nom != appli:
            p = lire_port_appli(apps, nom, strict=False)
            if p:
                pris.setdefault(p, f"déjà attribué à l'appli « {nom} »")
    for nom, _ip, p in vhosts_generes():
        if nom != appli:
            pris.setdefault(p, f"déjà publié par nginx pour l'appli « {nom} »")
    for nom, p in processus.items():
        if nom != appli:
            pris.setdefault(p, f"utilisé par l'appli « {nom} » en cours")
    for p in ecoute:
        if processus.get(appli) != p:
            pris.setdefault(p, "déjà en écoute dans le conteneur")
    miens = {domaine_de(i, "") for i in instances(texte) if i["app"] == appli}
    for dom, c in routes.items():
        if dom in miens or not (isinstance(c, list) and len(c) == 2):
            continue
        p = _port(c[1])
        if p and p != PORT_NGINX and (ip is None or _ipv4(c[0]) == ip):
            pris.setdefault(p, f"déjà routé pour {dom}")
    return pris


def port_actuel(appli: str, texte: str, apps: Path) -> tuple[int | None, str]:
    p = lire_port_appli(apps, appli, strict=True)
    if p:
        return p, "fichier"
    p = _port(applis_declarees(texte).get(appli, {}).get("port"))
    if p:
        return p, "declare"
    miennes = [i for i in instances(texte) if i["app"] == appli and i["port"]]
    if len(miennes) == 1:
        return miennes[0]["port"], "instance"
    return None, ""


def choisir_port(appli: str, demande: int | None, texte: str, apps: Path, ecoute: set, processus: dict,
                 ip_vive: str | None) -> tuple[int, str, list[str]]:
    routes = routes_lisibles()
    ip, _o, _r = ip_conteneur(texte, routes, ip_vive)
    pris = ports_pris(appli, texte, apps, routes, ecoute, processus, ip)
    avert: list[str] = []
    if demande is not None:
        if not 1024 <= demande <= 65535:
            raise Refus(ARGUMENT, f"port {demande} hors limites (1024 à 65535)")
        if demande in pris:
            raise Refus(CONFLIT, f"port {demande} {pris[demande]} : choisissez-en un autre, ou laissez le champ "
                                 "vide pour un port automatique")
        return demande, "demande", avert
    actuel, origine = port_actuel(appli, texte, apps)
    if actuel:
        if actuel in pris:
            avert.append(f"le port actuel {actuel} est aussi {pris[actuel]}")
        return actuel, origine, avert
    r = reglages(texte)
    for p in range(r["port_min"], r["port_max"] + 1):
        if p not in pris and p not in ecoute:
            return p, "auto", avert
    raise Refus(EPUISE, f"aucun port libre entre {r['port_min']} et {r['port_max']} : élargissez [ports] min/max "
                        "dans /etc/secubox/streamlit.toml")


# ─── Les maillons de la publication ───────────────────────────────────────

def cle_vhost(domaine: str) -> str:
    return re.sub(r"[.-]", "_", domaine)          # même dérivation que `haproxyctl vhost add`


def adresse_nginx_waf(routes: dict) -> str:
    """L'adresse que secubox-waf-route posera pour :9080 (celle des voisins du même port, sinon 127.0.0.1)."""
    for v in routes.values():
        if isinstance(v, list) and len(v) == 2 and v[1] == PORT_NGINX:
            return str(v[0])
    return "127.0.0.1"


def vhost_nginx(appli: str, label: str, domaine: str, ip: str, port: int) -> str:
    return f"""{MARQUE_NGINX} appli={appli} nom={label}
# Généré par streamlitctl (app publish, #3247) — NE PAS ÉDITER : réécrit à chaque publication, retiré au renommage.
# Chaîne : HAProxy → sbxwaf → nginx :{PORT_NGINX} (ici) → conteneur Streamlit {ip}:{port}.
server {{
    listen {PORT_NGINX};
    server_name {domaine};

    # Téléversements Streamlit : même plafond que server.maxUploadSize (200 Mo par défaut).
    client_max_body_size 200m;

    location / {{
        proxy_pass http://{ip}:{port};
        proxy_http_version 1.1;
        # WebSocket : Streamlit ne peint rien sans lui.
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_buffering off;
        proxy_read_timeout 86400s;
        proxy_send_timeout 86400s;
    }}
}}
"""


def _fichiers_nginx(label: str) -> tuple[Path, Path]:
    # Un identifiant d'instance LU dans streamlit.toml devient un nom de fichier écrit en root : jamais un « / »,
    # jamais un point en tête.
    if not NOM_APPLI_RE.fullmatch(label or ""):
        raise Refus(ETAT, f"nom de publication inutilisable comme fichier nginx : « {str(label)[:80]} »")
    nom = f"streamlit-{label}.conf"
    return dossier_nginx() / "sites-available" / nom, dossier_nginx() / "sites-enabled" / nom


def _lire(f: Path) -> str | None:
    try:
        return f.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return None


def _sert(texte: str | None, domaine: str) -> bool:
    return bool(texte) and re.search(rf"^\s*server_name\s+([^;]*\s)?{re.escape(domaine)}(\s[^;]*)?;", texte,
                                     re.M) is not None


def nginx_etat(label: str, domaine: str, attendu: str) -> str:
    """'absent' | 'conforme' | 'a_nous' (même nom servi, contenu différent) | 'autre' (sert autre chose)."""
    dispo, actif = _fichiers_nginx(label)
    if not actif.exists() and not actif.is_symlink() and not dispo.exists():
        return "absent"
    texte_actif = _lire(actif)
    if (actif.is_symlink() and os.readlink(actif) == str(dispo) and _lire(dispo) == attendu):
        return "conforme"
    for t in (texte_actif, _lire(dispo)):
        if t is not None and not _sert(t, domaine):
            return "autre"
    return "a_nous"


def nginx_sert_ailleurs(domaine: str, sauf: set) -> str | None:
    """Un AUTRE fichier de sites-enabled sert-il déjà ce nom ? Rend son nom."""
    for f in sorted((dossier_nginx() / "sites-enabled").glob("*")):
        if f.name in sauf:
            continue
        if _sert(_lire(f), domaine):
            return f.name
    return None


def _nginx_tester_recharger() -> str | None:
    rc, sortie = _cmd(["nginx", "-t"], timeout=60)
    if rc:
        ligne = next((x for x in sortie.splitlines() if "emerg" in x or "[error]" in x), _court(sortie))
        return f"nginx -t : {ligne}"[:300]
    rc, sortie = _cmd(["systemctl", "reload", "nginx"], timeout=60)
    if rc:
        return f"systemctl reload nginx : {_court(sortie)}"
    return None


def _instantane(f: Path):
    if f.is_symlink():
        return ("lien", os.readlink(f))
    if f.exists():
        return ("fichier", f.read_bytes())
    return None


def _restaurer(f: Path, etat) -> None:
    with contextlib.suppress(FileNotFoundError):
        f.unlink()
    if etat is None:
        return
    if etat[0] == "lien":
        os.symlink(etat[1], f)
    else:
        f.write_bytes(etat[1])


def nginx_poser(label: str, contenu: str) -> tuple:
    """Pose sites-available/streamlit-<nom>.conf et son lien dans sites-enabled, teste, recharge. Rend l'état
    d'avant (pour `nginx_restaurer`) ; `nginx -t` en échec : l'état d'avant revient, rien n'est publié."""
    dispo, actif = _fichiers_nginx(label)
    avant = (_instantane(dispo), _instantane(actif))
    if actif.exists() and not actif.is_symlink():
        # Fichier posé à la main (référence de couture.gk2) : copié HORS de sites-enabled (jamais chargé en double).
        shutil.copy2(actif, dispo.with_name(dispo.name + ".avant-secubox"))
    ecrire_atomique(dispo, contenu)
    tmp = actif.with_name(f".{actif.name}.lien")
    with contextlib.suppress(FileNotFoundError):
        tmp.unlink()
    os.symlink(str(dispo), tmp)
    os.replace(tmp, actif)
    erreur = _nginx_tester_recharger()
    if erreur:
        echec = nginx_restaurer(label, avant)
        raise Refus(ECHEC, f"{erreur} — vhost retiré, rien n'est publié"
                    + (f" — retour arrière incomplet : {echec}" if echec else ""))
    return avant


def nginx_restaurer(label: str, avant: tuple) -> str | None:
    """Remet l'état d'avant ; rend la cause si ce retour arrière lui-même échoue (jamais tu)."""
    dispo, actif = _fichiers_nginx(label)
    try:
        _restaurer(dispo, avant[0])
        _restaurer(actif, avant[1])
    except OSError as e:
        return f"nginx : {actif.name} non restauré ({e.strerror})"
    erreur = _nginx_tester_recharger()
    return f"nginx après restauration : {erreur}" if erreur else None


def nginx_retirer(label: str, domaine: str, avert: list[str]) -> str:
    """'retire' | 'absent' | 'laisse' (sert un autre nom) | 'annule' (nginx -t refuse le retrait)."""
    dispo, actif = _fichiers_nginx(label)
    if nginx_etat(label, domaine, "") == "autre":
        avert.append(f"nginx : {actif.name} sert un autre nom — laissé en place")
        return "laisse"
    avant = (_instantane(dispo), _instantane(actif))
    if avant == (None, None):
        return "absent"
    # Un fichier posé à la main (référence couture.gk2) n'est jamais perdu : copié hors de sites-enabled d'abord.
    for f, etat in ((actif, avant[1]), (dispo, avant[0])):
        if etat and etat[0] == "fichier" and not etat[1].decode("utf-8", "replace").startswith(MARQUE_NGINX):
            ecrire_atomique(dispo.with_name(f.name + ".avant-secubox"), etat[1].decode("utf-8", "replace"))
            break
    for f in (actif, dispo):
        with contextlib.suppress(FileNotFoundError):
            f.unlink()
    erreur = _nginx_tester_recharger()
    if erreur:
        echec = nginx_restaurer(label, avant)
        avert.append(f"nginx : retrait de {actif.name} annulé ({erreur})" + (f" ; {echec}" if echec else ""))
        return "annule"
    return "retire"


def route_poser(domaine: str) -> None:
    """Par l'outil commun : même fusion, même prudence, même adresse que tous les paquets (#3247)."""
    env = dict(os.environ, SBX_WAF_ROUTES=str(chemin_routes()))
    rc, sortie = _cmd([_env("SECUBOX_WAF_ROUTE", "secubox-waf-route"), domaine, str(PORT_NGINX)], timeout=30,
                      env=env)
    if rc:
        raise Refus(ECHEC, f"secubox-waf-route : {_court(sortie) or f'code {rc}'}")


def route_retirer(domaine: str, ports_admis: set, avert: list[str]) -> str:
    """Retire la route SEULEMENT si elle vise un port à nous (nginx :9080, ou l'ancien port direct de l'appli).
    'retiree' | 'absente' | 'laissee' (re-pointée ailleurs)."""
    routes = lire_routes()
    cible = routes.get(domaine)
    if cible is None:
        return "absente"
    if not (isinstance(cible, list) and len(cible) == 2 and _port(cible[1]) in ports_admis):
        avert.append(f"route sbxwaf de {domaine} re-pointée ailleurs ({cible}) — laissée en place")
        return "laissee"
    del routes[domaine]
    ecrire_atomique(chemin_routes(), json.dumps(routes, indent=2, sort_keys=True) + "\n")
    return "retiree"


def haproxy_table(domaine: str) -> tuple[str, str] | None:
    """(clé de la table [vhosts.<clé>], backend) du vhost qui porte ce domaine, ou None."""
    for entete, _d, _f, v in sections(_lire(chemin_haproxy()) or ""):
        if entete.startswith("vhosts.") and v.get("domain") == domaine:
            return entete[len("vhosts."):], str(v.get("backend") or "")
    return None


def haproxy_declare(domaine: str) -> bool | None:
    texte = _lire(chemin_haproxy())
    if texte is None:
        return None
    return re.search(rf'^\s*domain\s*=\s*"{re.escape(domaine)}"\s*$', texte, re.M) is not None


def _haproxyctl() -> str | None:
    b = _env("SECUBOX_HAPROXYCTL", "haproxyctl")
    return b if (os.path.isabs(b) and os.access(b, os.X_OK)) or shutil.which(b) else None


def haproxy_poser(domaine: str, avert: list[str]) -> None:
    """Déclaratif (haproxy.toml) puis génération. JAMAIS fatal : sans ACL dédiée, HAProxy envoie déjà tout hôte
    inconnu à sbxwaf_inspector (default_backend) ; un garde de dérive qui refuse de générer est rapporté tel quel."""
    b = _haproxyctl()
    if b is None:
        avert.append("haproxyctl absent : vhost HAProxy non déclaré (le trafic atteint sbxwaf par défaut)")
        return
    rc, sortie = _cmd([b, "vhost", "add", domaine, "nginx_vhosts", "true"], timeout=120)
    if rc:
        avert.append(f"HAProxy : {_court(sortie) or f'code {rc}'} (le trafic atteint sbxwaf par défaut)")
        return
    rc, sortie = _cmd([b, "reload"], timeout=60)
    if rc:
        avert.append(f"HAProxy : rechargement en échec ({_court(sortie)})")


def haproxy_retirer(domaine: str, avert: list[str]) -> str:
    """'retire' | 'absent' | 'laisse' (autre backend) | 'haproxyctl-absent' | 'regeneration-refusee' (table retirée,
    génération refusée) | 'echec' (table toujours là) | 'rechargement-refuse'."""
    table = haproxy_table(domaine)
    if table is None:
        return "absent"
    cle, backend = table
    if backend != "nginx_vhosts":
        # Pas la forme que nous posons : un autre service déclare ce nom. On ne retire pas ce qu'on n'a pas posé.
        avert.append(f"HAProxy : {domaine} déclaré avec backend « {backend} » — laissé en place")
        return "laisse"
    b = _haproxyctl()
    if b is None:
        avert.append(f"haproxyctl absent : vhost {domaine} laissé dans haproxy.toml")
        return "haproxyctl-absent"
    rc, sortie = _cmd([b, "vhost", "remove", cle], timeout=120)
    if rc:
        # Typiquement le garde de dérive : la table est retirée, la régénération refusée. On ne force JAMAIS
        # --allow-shrink : il effacerait aussi les vhosts tenus hors de haproxy.toml.
        if haproxy_table(domaine) is None:
            avert.append(f"HAProxy : {domaine} retiré de haproxy.toml, régénération refusée ({_court(sortie)}) — "
                         "à régénérer par l'opérateur")
            return "regeneration-refusee"
        avert.append(f"HAProxy : retrait de {domaine} en échec ({_court(sortie) or f'code {rc}'})")
        return "echec"
    rc, sortie = _cmd([b, "reload"], timeout=60)
    if rc:
        avert.append(f"HAProxy : {domaine} retiré, rechargement en échec ({_court(sortie)})")
        return "rechargement-refuse"
    return "retire"


_RETRAITS_ACQUIS = {"route": {"retiree", "absente"}, "nginx": {"retire", "absent"}, "haproxy": {"retire", "absent"}}


def _resultat(etats: dict) -> str:
    """'applique' seulement si chaque maillon est réellement retiré (ou n'existait pas) ; sinon 'partiel'."""
    return "applique" if all(v in _RETRAITS_ACQUIS[k] for k, v in etats.items()) else "partiel"


def conteneur_systemctl(verbe: str, appli: str, avert: list[str]) -> None:
    rc, sortie = _cmd(["lxc-attach", "-n", CONTENEUR, "--", "systemctl", verbe, f"streamlit-app@{appli}.service"],
                      timeout=30)
    if rc:
        avert.append(f"conteneur : systemctl {verbe} streamlit-app@{appli} non appliqué ({_court(sortie)}) — "
                     "repris au prochain démarrage du conteneur")


# ─── Verbes ───────────────────────────────────────────────────────────────

def _lire_conf(conf: Path) -> str:
    try:
        return conf.read_text(encoding="utf-8")
    except FileNotFoundError:
        return ""
    except (OSError, UnicodeDecodeError) as e:
        raise Refus(ECHEC, f"{conf} illisible ({e})")


def _ecrire_conf(conf: Path, ancien: str, nouveau: str) -> None:
    if nouveau == ancien:
        return
    _valider_toml(ancien, nouveau)
    try:
        st = os.stat(conf, follow_symlinks=False)
    except FileNotFoundError:
        st = None
    if st is not None:
        if not stat.S_ISREG(st.st_mode):
            raise Refus(ETAT, f"{conf} : lien symbolique ou fichier spécial — refusé, rien n'est écrit")
        ecrire_atomique(conf.with_name(conf.name + ".avant-publication"), ancien, 0o640)
    ecrire_atomique(conf, nouveau, 0o640)


def _declarer_appli(texte: str, appli: str, port: int) -> str:
    champs = {"port": port}
    if "enabled" not in applis_declarees(texte).get(appli, {}):
        champs = {"enabled": True, **champs}
    return poser_cles(texte, f"apps.{appli}", champs)


def verbe_port(a, conf: Path, apps: Path) -> dict:
    if not appli_existe(apps, a.appli):
        raise Refus(INCONNUE, f"appli inconnue : {a.appli}")
    ecoute = {p for p in (_port(x) for x in (a.ecoute or "").split()) if p}
    processus = {}
    for paire in (a.processus or "").split():
        nom, _s, p = paire.rpartition(":")
        if NOM_APPLI_RE.fullmatch(nom or "") and _port(p):
            processus[nom] = _port(p)
    with verrou() if a.apply else contextlib.nullcontext():
        texte = _lire_conf(conf)
        port, source, avert = choisir_port(a.appli, a.demande, texte, apps, ecoute, processus, a.ip_vive)
        if a.apply:
            ecrire_port_appli(apps, a.appli, port=port)
            _ecrire_conf(conf, texte, _declarer_appli(texte, a.appli, port))
    return {"ok": True, "appli": a.appli, "port": port, "source": source, "applique": bool(a.apply),
            "avertissements": avert}


def verbe_publier(a, conf: Path, apps: Path) -> dict:
    if not appli_existe(apps, a.appli):
        raise Refus(INCONNUE, f"appli inconnue : {a.appli}")
    if a.nom is not None and (err := erreur_label(a.nom)):
        raise Refus(ARGUMENT, err)
    with verrou() if a.apply else contextlib.nullcontext():
        return _publier(a, conf, apps)


def conflit_nom(label: str, domaine: str, appli: str, texte: str, routes: dict) -> str | None:
    """Le nom est-il déjà à quelqu'un d'autre ? Autre appli, route sbxwaf, vhost nginx, vhost HAProxy, nom réservé.
    Lecture seule : l'API l'appelle avant tout geste (réponse rapide), le ctl avant d'écrire (autorité)."""
    if label_reserve(label):
        return f"nom public « {label} » réservé aux services de la box"
    for inst in instances(texte):
        if inst["app"] != appli and (inst["id"] == label or inst["domain"] == domaine):
            return f"nom pris : « {label} » est déjà publié pour l'appli « {inst['app']} »"
    if domaine in routes:
        return f"nom pris : {domaine} est déjà routé par sbxwaf ({routes[domaine]})"
    if nginx_etat(label, domaine, "") == "autre":
        return f"nom pris : /etc/nginx/sites-enabled/streamlit-{label}.conf sert un autre nom"
    if (ailleurs := nginx_sert_ailleurs(domaine, {f"streamlit-{label}.conf"})):
        return f"nom pris : {domaine} est déjà servi par nginx ({ailleurs})"
    if haproxy_declare(domaine):
        return f"nom pris : {domaine} est déjà un vhost HAProxy (haproxy.toml)"
    return None


def _publier(a, conf: Path, apps: Path) -> dict:
    texte = _lire_conf(conf)
    if applis_declarees(texte).get(a.appli, {}).get("archived") is True:
        raise Refus(ETAT, f"appli archivée : {a.appli} — désarchivez-la avant de la publier")
    miennes = [i for i in instances(texte) if i["app"] == a.appli and i["enabled"]]
    if len(miennes) > 1:
        raise Refus(ETAT, "plusieurs instances publient cette appli (" + ", ".join(i["id"] for i in miennes)
                    + ") : retirez la publication puis republiez-la sous un seul nom")
    ancienne = miennes[0] if miennes else None
    garde_nom = a.nom is None or (ancienne is not None and a.nom == ancienne["id"])
    if garde_nom:
        if ancienne is None:
            raise Refus(ETAT, f"l'appli « {a.appli} » n'est pas publiée : donnez-lui un nom public")
        label, renommage = ancienne["id"], False
        dom_box = "" if ancienne["domain"] else domaine_box()
        domaine = domaine_de(ancienne, dom_box)
    else:
        dom_box = domaine_box()
        if not dom_box:
            raise Refus(ETAT, "domaine de la box inconnu ([global] domain dans secubox.conf) : publication impossible")
        label, domaine, renommage = a.nom, f"{a.nom}.{dom_box}", ancienne is not None
    if not DOMAINE_RE.fullmatch(domaine or ""):
        raise Refus(ETAT, f"domaine de publication invalide ou inconnu : « {domaine} »")
    port = a.port or (ancienne["port"] if ancienne else None)
    if not port:
        raise Refus(ETAT, f"aucun port attribué à « {a.appli} » : démarrez-la ou attribuez-lui un port d'abord")

    routes = lire_routes()
    avert: list[str] = []
    ip, origine, rejet = ip_conteneur(texte, routes, a.ip_vive, reseaux_pont(a.lxc_config))
    if ip is None:
        raise Refus(INDISPONIBLE, "adresse du conteneur Streamlit inconnue" + (f" ({rejet})" if rejet else "")
                    + " : réveillez-le, ou fixez [publication] ip_conteneur dans streamlit.toml (le sous-réseau du "
                      "pont du conteneur est la seule cible admise autrement)")
    if origine != "vive" and _ipv4(a.ip_vive) and _ipv4(a.ip_vive) != ip:
        avert.append(f"adresse vive du conteneur {a.ip_vive} différente de celle retenue ({ip}, {origine})")
    if garde_nom:
        # Même nom : seuls comptent un AUTRE fichier nginx qui servirait déjà ce domaine (doublon de server_name,
        # que nginx -t laisse passer en avertissement) ou le nôtre détourné vers un autre nom.
        if nginx_etat(label, domaine, "") == "autre":
            raise Refus(CONFLIT, f"/etc/nginx/sites-enabled/streamlit-{label}.conf sert un autre nom")
        if (ailleurs := nginx_sert_ailleurs(domaine, {f"streamlit-{label}.conf"})):
            raise Refus(CONFLIT, f"{domaine} est déjà servi par nginx ({ailleurs}) : retirez ce vhost d'abord")
    elif (conflit := conflit_nom(label, domaine, a.appli, texte, routes)):
        raise Refus(CONFLIT, conflit)

    # Déclaration voulue : [instances.<nom>] (forme de la référence couture.gk2) et [apps.<dossier>].
    # `publication_geree` : posée par streamlitctl. Seule une publication gérée suit d'elle-même le port de l'appli
    # à son démarrage ; une publication posée à la main n'est reprise que par un geste (Publier, Renommer).
    champs_inst = {"app": a.appli, "port": port, "domain": domaine, "enabled": True, "emancipated": True,
                   "waf_enabled": True, "publication_geree": True}
    nouveau = texte
    if renommage:
        report = {k: v for k, v in ancienne["valeurs"].items() if k not in champs_inst}
        nouveau = poser_cles(retirer_section(nouveau, f"instances.{ancienne['id']}"), f"instances.{label}",
                             {**champs_inst, **report})
    else:
        nouveau = poser_cles(nouveau, f"instances.{label}", champs_inst)
    nouveau = _declarer_appli(nouveau, a.appli, port)
    toujours = reglages(texte)["autostart"]
    if toujours and applis_declarees(nouveau).get(a.appli, {}).get("autostart") is not True:
        # Publiée = toujours active : rien ne réveille aujourd'hui une appli par son vhost (#746). Marquée, pour
        # que le retrait de la publication rende la veille, et seulement elle.
        nouveau = poser_cles(nouveau, f"apps.{a.appli}", {"autostart": True, "autostart_publication": True})

    contenu = vhost_nginx(a.appli, label, domaine, ip, port)
    etat_nginx = nginx_etat(label, domaine, contenu)
    route_voulue = [adresse_nginx_waf(routes), PORT_NGINX]
    ancien_dom = domaine_de(ancienne, dom_box) if renommage else ""
    a_faire = (nouveau != texte or etat_nginx != "conforme" or routes.get(domaine) != route_voulue
               or haproxy_declare(domaine) is False
               or (renommage and (ancien_dom in routes or nginx_etat(ancienne["id"], ancien_dom, "") != "absent")))
    evenement = "inchange"
    if a_faire:
        evenement = "renommage" if renommage else ("mise-a-jour" if ancienne else "publication")
    sortie = {"ok": True, "appli": a.appli, "nom_public": label, "domaine": domaine, "port": port,
              "cible": f"{ip}:{port}", "evenement": evenement, "applique": False, "avertissements": avert,
              "ancien": {"nom_public": ancienne["id"], "domaine": ancien_dom} if renommage else None}
    if not a.apply or evenement == "inchange":
        return sortie
    _valider_toml(texte, nouveau)                    # la déclaration finale se relit AVANT le premier geste

    journal = Journal(a.par)
    try:
        route_avant = routes.get(domaine)
        avant_nginx = nginx_poser(label, contenu) if etat_nginx != "conforme" else None
        try:
            if routes.get(domaine) != route_voulue:
                route_poser(domaine)
            _ecrire_conf(conf, texte, nouveau)
        except (Refus, OSError) as e:
            echecs = [x for x in (_defaire_route(domaine, route_avant),
                                  nginx_restaurer(label, avant_nginx) if avant_nginx is not None else None) if x]
            if echecs:
                cause = e.message if isinstance(e, Refus) else f"{e.filename or ''} : {e.strerror or e}"
                raise Refus(e.code if isinstance(e, Refus) else ECHEC,
                            f"{cause} — retour arrière incomplet : {' ; '.join(echecs)}") from e
            raise
        # HAProxy : l'ancien d'abord, le nouveau ensuite — la génération suivante garde alors le même nombre de
        # vhosts et le garde de dérive l'accepte ; son refus du retrait seul n'est rapporté que s'il persiste.
        retrait_ha: list[str] = []
        anciens = {}
        if renommage:
            anciens["haproxy"] = haproxy_retirer(ancien_dom, retrait_ha)
        n = len(avert)
        if haproxy_declare(domaine) is not True:
            haproxy_poser(domaine, avert)
        if len(avert) > n:
            avert.extend(retrait_ha)
        if renommage:
            anciens["route"] = route_retirer(ancien_dom, {PORT_NGINX, ancienne["port"] or port}, avert)
            anciens["nginx"] = nginx_retirer(ancienne["id"], ancien_dom, avert) if NOM_APPLI_RE.fullmatch(
                ancienne["id"]) else "laisse"
        if toujours:
            conteneur_systemctl("enable", a.appli, avert)
        journal.ecrire(evenement=evenement, appli=a.appli, nom_public=label, domaine=domaine,
                       cible=f"{ip}:{port}", ancien_nom_public=ancienne["id"] if renommage else None,
                       ancien_domaine=ancien_dom or None,
                       **({f"ancien_{k}": v for k, v in anciens.items()}),
                       resultat=_resultat(anciens) if anciens else "applique")
    finally:
        journal.fermer()
    sortie["applique"] = True
    return sortie


def _defaire_route(domaine: str, avant) -> str | None:
    """Remet la route d'avant ; rend la cause si ce retour arrière échoue (jamais tu)."""
    try:
        routes = lire_routes()
        if routes.get(domaine) == avant:
            return None
        if avant is None:
            routes.pop(domaine, None)
        else:
            routes[domaine] = avant
        ecrire_atomique(chemin_routes(), json.dumps(routes, indent=2, sort_keys=True) + "\n")
    except Refus as e:
        return f"route sbxwaf de {domaine} non restaurée : {e.message}"
    except OSError as e:
        return f"route sbxwaf de {domaine} non restaurée : {e.strerror or e}"
    return None


def verbe_depublier(a, conf: Path, apps: Path) -> dict:
    with verrou() if a.apply else contextlib.nullcontext():
        texte = _lire_conf(conf)
        miennes = [i for i in instances(texte) if i["app"] == a.appli]
        sortie = {"ok": True, "appli": a.appli, "retires": [], "applique": False, "avertissements": []}
        if not miennes:
            sortie["evenement"] = "inchange"
            return sortie
        dom_box = domaine_box() if any(not i["domain"] for i in miennes) else ""
        for inst in miennes:
            sortie["retires"].append({"nom_public": inst["id"], "domaine": domaine_de(inst, dom_box)})
        par_publication = applis_declarees(texte).get(a.appli, {}).get("autostart_publication") is True

        def declaration(acquises: list) -> str:
            """Déclaration finale pour les instances RÉELLEMENT retirées ; la veille ne revient que si toutes le sont."""
            nouveau = texte
            for inst in acquises:
                nouveau = retirer_section(nouveau, f"instances.{inst['id']}")
            if par_publication and len(acquises) == len(miennes):
                nouveau = retirer_cles(poser_cles(nouveau, f"apps.{a.appli}", {"autostart": False}),
                                       f"apps.{a.appli}", {"autostart_publication"})
            return nouveau
        sortie["evenement"] = "depublication"
        if not a.apply:
            return sortie
        avert = sortie["avertissements"]
        lire_routes()                     # table illisible : on s'arrête AVANT de toucher quoi que ce soit
        _valider_toml(texte, declaration(miennes))   # la déclaration finale se relit AVANT le premier geste
        journal = Journal(a.par)
        acquises = []
        try:
            # La chaîne d'abord : si un retrait échoue, la déclaration dit encore la vérité (toujours publiée) —
            # une instance au retrait « partiel » reste déclarée, un second passage reprendra le reliquat.
            # Une ligne d'audit par entrée, juste après son retrait, avec l'état RÉEL de chaque maillon.
            for inst, r in zip(miennes, sortie["retires"]):
                dom = r["domaine"]
                etats = {"route": "absente", "nginx": "absent", "haproxy": "absent"}
                if dom:
                    etats["route"] = route_retirer(dom, {PORT_NGINX} | ({inst["port"]} if inst["port"] else set()),
                                                   avert)
                    etats["nginx"] = nginx_retirer(inst["id"], dom, avert) if NOM_APPLI_RE.fullmatch(
                        inst["id"]) else "laisse"
                    etats["haproxy"] = haproxy_retirer(dom, avert)
                r.update(etats, resultat=_resultat(etats))
                if r["resultat"] == "applique":
                    acquises.append(inst)
                journal.ecrire(evenement="depublication", appli=a.appli, nom_public=inst["id"], domaine=dom,
                               **etats, resultat=r["resultat"])
            _ecrire_declaration(journal, conf, texte, declaration(acquises), a.appli, "depublication")
            if par_publication and len(acquises) == len(miennes):
                conteneur_systemctl("disable", a.appli, avert)
        finally:
            journal.fermer()
        sortie["applique"] = True
        sortie["partiel"] = len(acquises) < len(miennes)
        sortie["reliquat"] = [i["id"] for i in miennes if i not in acquises]
        return sortie


def _ecrire_declaration(journal, conf: Path, texte: str, nouveau: str, appli: str, evenement: str) -> None:
    """Écrit la déclaration finale (déjà validée) ; un échec est audité avant d'être rendu."""
    try:
        _ecrire_conf(conf, texte, nouveau)
    except (Refus, OSError) as e:
        cause = e.message if isinstance(e, Refus) else (e.strerror or str(e))
        journal.ecrire(evenement=evenement, appli=appli, resultat="echec-declaration", erreur=cause[:300])
        raise


def _dans_le_pont(ip, reseaux: list | None) -> bool:
    """Strict : sans sous-réseau connu, aucune adresse n'est « dans le pont »."""
    ip = _ipv4(ip)
    return bool(ip and reseaux and any(ipaddress.IPv4Address(ip) in r for r in reseaux))


def _chaine_en_place(nom: str, domaine: str) -> bool:
    """La forme générée (ou la référence couture posée à la main) : sites-enabled/streamlit-<nom>.conf sert ce nom."""
    if not NOM_APPLI_RE.fullmatch(nom):
        return False
    actif = dossier_nginx() / "sites-enabled" / f"streamlit-{nom}.conf"
    return _sert(_lire(actif), domaine)


def verbe_depublier_anciennes(a, conf: Path, apps: Path) -> dict:
    """Retire PROPREMENT les publications historiques cassées (décision du propriétaire, #3247) : toute entrée
    `[instances.*]` ou `[apps.*]` qui porte un `domain` sans la chaîne générée. GARDÉES, jamais touchées :
    une publication gérée active, une entrée dont la chaîne est en place (sites-enabled/streamlit-<nom>.conf sert
    ce nom — couture.gk2), toute entrée dont le domaine est aussi porté par une entrée gardée, et tout nom qu'un
    AUTRE fichier de sites-enabled sert (route :9080 + vhost nginx_vhosts est la forme de tout vhost nginx de la
    box : ce serait un autre service). Pour les autres : route sbxwaf retirée si elle vise :9080, ou le port de
    l'entrée à une adresse DU PONT ; vhost HAProxy seulement si backend nginx_vhosts ; streamlit-<nom>.conf.
    La déclaration finale est calculée et validée AVANT le premier geste ; une ligne d'audit par entrée, juste
    après son retrait, avec l'état réel de chaque maillon ; l'entrée est marquée non publiée (enabled = false
    pour une instance, domain → domaine_retire) ; l'appli reste déposée."""
    with verrou() if a.apply else contextlib.nullcontext():
        texte = _lire_conf(conf)
        routes = lire_routes()
        reseaux = reseaux_pont(a.lxc_config)
        candidats = [("instance", i["id"], i["app"], i["domain"], i["port"], i["valeurs"])
                     for i in instances(texte) if i["domain"]]
        candidats += [("appli", nom, nom, v["domain"], _port(v.get("port")), v)
                      for nom, v in applis_declarees(texte).items() if isinstance(v.get("domain"), str)
                      and v.get("domain")]

        def raison_de_garder(typ, nom, v, dom):
            if v.get("publication_geree") is True and v.get("enabled", True) is not False:
                return "publication gérée par streamlitctl"
            if _chaine_en_place(nom, dom):
                return f"chaîne en place (sites-enabled/streamlit-{nom}.conf)"
            return None

        domaines_gardes: dict[str, str] = {}
        for typ, nom, _appli, dom, _port_e, v in candidats:
            if (raison := raison_de_garder(typ, nom, v, dom)):
                domaines_gardes.setdefault(dom, f"{nom} : {raison}")

        retires, gardes, avert = [], [], []
        for typ, nom, appli, dom, port, v in candidats:
            raison = raison_de_garder(typ, nom, v, dom)
            if raison is None and dom in domaines_gardes:
                raison = f"domaine aussi porté par une entrée gardée ({domaines_gardes[dom]})"
            if raison is None and (ailleurs := nginx_sert_ailleurs(dom, {f"streamlit-{nom}.conf"})):
                raison = f"servi par un autre fichier nginx ({ailleurs}) : un autre service, pas une publication cassée"
            if raison is None and not DOMAINE_RE.fullmatch(dom):
                raison = "domaine illisible — laissé à l'opérateur"
            if raison:
                gardes.append({"type": typ, "nom": nom, "domaine": dom, "raison": raison})
                continue
            cible = routes.get(dom)
            if cible is None:
                route = "absente"
            elif isinstance(cible, list) and len(cible) == 2 and (
                    _port(cible[1]) == PORT_NGINX
                    or (port and _port(cible[1]) == port and _dans_le_pont(cible[0], reseaux))):
                route = "a_retirer"
            else:
                route = "laissee"
            table = haproxy_table(dom)
            retires.append({"type": typ, "nom": nom, "appli": appli, "domaine": dom, "route": route,
                            "haproxy": "absent" if table is None else (
                                "a_retirer" if table[1] == "nginx_vhosts" else "laisse")})
        sortie = {"ok": True, "applique": False, "retires": retires, "gardes": gardes, "avertissements": avert}
        if not a.apply or not retires:
            return sortie

        horodatage = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        def declaration(acquis: list) -> str:
            """Marque non publiées les seules entrées RÉELLEMENT retirées : un reliquat (« partiel ») garde son
            `domain`, pour qu'un second passage le reprenne."""
            nouveau = texte
            for r in acquis:
                entete = f"instances.{r['nom']}" if r["type"] == "instance" else f"apps.{r['nom']}"
                champs = {"domaine_retire": r["domaine"], "depubliee": horodatage}
                if r["type"] == "instance":
                    champs = {"enabled": False, **champs}
                nouveau = poser_cles(retirer_cles(nouveau, entete, {"domain"}), entete, champs)
            return nouveau
        _valider_toml(texte, declaration(retires))          # calculée et validée AVANT le premier geste

        journal = Journal(a.par)
        try:
            for r in retires:
                dom = r["domaine"]
                etats = {"route": "absente", "nginx": "absent", "haproxy": "absent"}
                if r["route"] == "a_retirer":
                    etats["route"] = route_retirer(dom, {PORT_NGINX, _port(routes[dom][1])}, avert)
                elif r["route"] == "laissee":
                    etats["route"] = "laissee"
                    avert.append(f"route sbxwaf de {dom} vise autre chose ({routes.get(dom)}) — laissée en place")
                # Un nom inutilisable comme fichier nginx n'est pas vérifiable : « laisse », jamais « absent ».
                etats["nginx"] = nginx_retirer(r["nom"], dom, avert) if NOM_APPLI_RE.fullmatch(r["nom"]) else "laisse"
                if r["haproxy"] != "absent":
                    etats["haproxy"] = haproxy_retirer(dom, avert)
                r.update(etats, resultat=_resultat(etats))
                journal.ecrire(evenement="depublication-ancienne", appli=r["appli"], nom_public=r["nom"], domaine=dom,
                               **etats, resultat=r["resultat"])
            acquis = [r for r in retires if r["resultat"] == "applique"]
            _ecrire_declaration(journal, conf, texte, declaration(acquis), "*", "depublication-ancienne")
        finally:
            journal.fermer()
        sortie["applique"] = True
        sortie["partiel"] = len(acquis) < len(retires)
        sortie["reliquat"] = [r["nom"] for r in retires if r["resultat"] != "applique"]
        return sortie


def verbe_etat(a, conf: Path, apps: Path) -> dict:
    texte = _lire_conf(conf)
    dom_box = domaine_box() if any(not i["domain"] for i in instances(texte) if i["app"] == a.appli) else ""
    return {"ok": True, "appli": a.appli, "publications": publications(texte, dom_box).get(a.appli, []),
            "reglages": reglages(texte)}


# ─── Environnement de l'appli (dans le conteneur) ─────────────────────────

def _env_chemin(appli: str) -> str:
    return f"{ENV_CONTENEUR}/{appli}.env"


def _env_lire(appli: str) -> dict[str, str]:
    racine = os.environ.get("SECUBOX_STREAMLIT_CT_RACINE")      # bancs d'essai seulement
    if racine:
        texte = _lire(Path(racine + _env_chemin(appli))) or ""
    else:
        rc, texte = _cmd(["lxc-attach", "-n", CONTENEUR, "--", "sh", "-c", 'cat -- "$1" 2>/dev/null || true',
                          "sh", _env_chemin(appli)], timeout=30)
        if rc:
            raise Refus(INDISPONIBLE, f"conteneur Streamlit injoignable : {_court(texte)}")
    vals: dict[str, str] = {}
    for ligne in texte.splitlines():
        m = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)=(.*)$", ligne.strip())
        if m:
            v = m.group(2)
            vals[m.group(1)] = v[1:-1] if len(v) >= 2 and v[0] == v[-1] and v[0] in "'\"" else v
    return vals


def _env_ecrire(appli: str, vals: dict[str, str]) -> None:
    texte = "# Variables de l'appli — streamlitctl app env (#3247). Root 0600, jamais servi.\n" + "".join(
        f"{k}='{v}'\n" for k, v in sorted(vals.items()))
    racine = os.environ.get("SECUBOX_STREAMLIT_CT_RACINE")
    if racine:
        f = Path(racine + _env_chemin(appli))
        f.parent.mkdir(parents=True, exist_ok=True)
        ecrire_atomique(f, texte, 0o600)
        return
    script = ('umask 077; mkdir -p -- "$(dirname -- "$1")" && cat > "$1.tmp" && chmod 600 "$1.tmp" '
              '&& mv -f -- "$1.tmp" "$1"')
    rc, sortie = _cmd(["lxc-attach", "-n", CONTENEUR, "--", "sh", "-c", script, "sh", _env_chemin(appli)],
                      timeout=30, entree=texte)
    if rc:
        raise Refus(INDISPONIBLE, f"écriture de l'environnement dans le conteneur impossible : {_court(sortie)}")


def verbe_env(a, conf: Path, apps: Path, entree: str) -> dict:
    if not appli_existe(apps, a.appli):
        raise Refus(INCONNUE, f"appli inconnue : {a.appli}")
    if a.lister:
        return {"ok": True, "appli": a.appli, "cles": sorted(_env_lire(a.appli)), "fichier": _env_chemin(a.appli)}
    if len(entree.encode("utf-8")) > ENV_MAX:
        raise Refus(ARGUMENT, f"environnement trop long (plus de {ENV_MAX} octets) : refusé, rien n'est écrit")
    definir: dict[str, str] = {}
    for ligne in entree.splitlines():
        if not ligne.strip():
            continue
        cle, egal, valeur = ligne.partition("=")
        if not egal:
            raise Refus(ARGUMENT, "entrée attendue : une ligne CLE=valeur par variable")
        if (err := erreur_cle_env(cle) or erreur_valeur_env(valeur)):
            raise Refus(ARGUMENT, err)
        definir[cle] = valeur
    for cle in a.retirer or []:
        if (err := erreur_cle_env(cle)):
            raise Refus(ARGUMENT, err)
    with verrou() if a.apply else contextlib.nullcontext():
        vals = _env_lire(a.appli)
        nouvelles = {k: v for k, v in vals.items() if k not in set(a.retirer or [])}
        nouvelles.update(definir)
        change = nouvelles != vals
        if a.apply and change:
            journal = Journal(a.par)
            try:
                _env_ecrire(a.appli, nouvelles)
                journal.ecrire(evenement="environnement", appli=a.appli, cles_definies=sorted(definir),
                               cles_retirees=sorted(set(a.retirer or []) & set(vals)), resultat="applique")
            finally:
                journal.fermer()
    return {"ok": True, "appli": a.appli, "cles": sorted(nouvelles), "applique": bool(a.apply and change),
            "redemarrage_requis": bool(change), "fichier": _env_chemin(a.appli)}


# ─── Fichier de port écrit pour le ctl (app start, app repair) ────────────

def verbe_ecrire_port(a, conf: Path, apps: Path) -> dict:
    if a.entrypoint is not None:
        # Chemin RELATIF au dossier des applis, en .py, sans « .. » ; ni guillemet, ni barre oblique inverse, ni
        # saut de ligne (il est écrit entre guillemets dans le fichier que lit streamlit-launch).
        e = a.entrypoint
        if (not e or len(e) > 255 or e.startswith(("/", "-")) or ".." in e.split("/") or not e.endswith(".py")
                or any(c in e for c in '"\\\n\r\x00')):
            raise Refus(ARGUMENT, f"point d'entrée invalide : {e[:120]}")
    if a.sauvegarde is not None and not re.fullmatch(r"[0-9A-Za-z_.-]{1,40}", a.sauvegarde):
        raise Refus(ARGUMENT, "suffixe de sauvegarde invalide")
    if a.port is not None and not _port(a.port):
        raise Refus(ARGUMENT, f"port invalide : {a.port}")
    if not appli_existe(apps, a.appli):
        raise Refus(INCONNUE, f"appli inconnue : {a.appli}")
    change = False
    if a.apply:
        # Un seul fichier, écrit par renameat : pas de verrou (rien d'autre n'est modifié).
        change = ecrire_port_appli(apps, a.appli, a.port, a.entrypoint, a.sauvegarde)
    return {"ok": True, "appli": a.appli, "port": a.port, "entrypoint": a.entrypoint, "applique": change}


# ─── Dépôt d'une archive : extraction PAR ROOT, rien ne sort du dossier ─────

def _ouvrir_zip(chemin: str) -> int:
    """Descripteur de l'archive à déposer. Chemin absolu en .zip, sans « .. », fichier ordinaire (jamais un lien),
    taille plafonnée ; appelé par sudo, l'archive doit appartenir à l'appelant (SUDO_UID) : root ne lit pas pour
    lui un fichier qu'il ne pourrait pas lire."""
    pp = PurePosixPath(chemin)
    if not pp.is_absolute() or ".." in pp.parts or pp.suffix != ".zip":
        raise Refus(ARGUMENT, "archive refusée : chemin absolu en .zip attendu, sans « .. »")
    try:
        fd = os.open(chemin, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except OSError as e:
        raise Refus(ARGUMENT, f"archive refusée : {'lien symbolique' if e.errno == errno.ELOOP else e.strerror}")
    st = os.fstat(fd)
    appelant = os.environ.get("SUDO_UID", "")
    if not stat.S_ISREG(st.st_mode) or st.st_size > ZIP_MAX_OCTETS or (
            appelant.isdigit() and st.st_uid != int(appelant)):
        os.close(fd)
        raise Refus(ARGUMENT, "archive refusée : fichier ordinaire de l'appelant, 1 Gio au plus")
    return fd


def _entrees_zip(z: zipfile.ZipFile) -> list[tuple]:
    """[(info, parties, est_dossier)] — tout est refusé avant la moindre écriture : chemin absolu ou « .. »,
    lien symbolique, FIFO, périphérique, trop d'entrées, contenu trop gros."""
    infos = z.infolist()
    if len(infos) > ZIP_MAX_ENTREES:
        raise Refus(ARGUMENT, f"archive refusée : plus de {ZIP_MAX_ENTREES} entrées")
    out, total = [], 0
    for info in infos:
        nom = info.filename
        if "\\" in nom or "\x00" in nom or nom.startswith("/") or re.match(r"^[A-Za-z]:", nom):
            raise Refus(ARGUMENT, f"archive refusée : chemin hors du dossier de l'appli ({nom[:120]})")
        parties = [x for x in nom.split("/") if x not in ("", ".")]
        if ".." in parties:
            raise Refus(ARGUMENT, f"archive refusée : chemin hors du dossier de l'appli ({nom[:120]})")
        if not parties:
            continue
        type_ = stat.S_IFMT((info.external_attr >> 16) & 0xFFFF)
        if type_ not in (0, stat.S_IFREG, stat.S_IFDIR):
            raise Refus(ARGUMENT, f"archive refusée : lien symbolique, FIFO ou périphérique ({nom[:120]})")
        total += info.file_size
        if total > ZIP_MAX_OCTETS:
            raise Refus(ARGUMENT, "archive refusée : plus de 1 Gio une fois décompressée")
        out.append((info, parties, info.is_dir() or type_ == stat.S_IFDIR))
    # Une seule racine qui est un dossier (« monappli/… ») : son contenu devient l'appli (comportement historique).
    tetes = {p[0] for _i, p, _d in out}
    if len(tetes) == 1 and all(len(p) > 1 or d for _i, p, d in out) and any(len(p) > 1 for _i, p, _d in out):
        out = [(i, p[1:], d) for i, p, d in out if len(p) > 1]
    return out


def _descendre(racine_fd: int, parties: list[str]) -> int:
    """Descripteur du sous-dossier `parties` sous `racine_fd`, créé au besoin, jamais à travers un lien."""
    fd = os.dup(racine_fd)
    for partie in parties:
        with contextlib.suppress(FileExistsError):
            os.mkdir(partie, 0o755, dir_fd=fd)
        try:
            nfd = os.open(partie, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
        finally:
            os.close(fd)
        fd = nfd
    return fd


def _extraire(z: zipfile.ZipFile, entrees: list[tuple], racine_fd: int) -> int:
    ecrits, n = 0, 0
    for info, parties, est_dossier in entrees:
        dfd = _descendre(racine_fd, parties if est_dossier else parties[:-1])
        try:
            if est_dossier:
                continue
            try:
                fd = os.open(parties[-1], os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                             0o644, dir_fd=dfd)
            except FileExistsError:
                raise Refus(ARGUMENT, f"archive refusée : entrée en double ({info.filename[:120]})")
            with z.open(info) as src, os.fdopen(fd, "wb") as dst:
                os.fchmod(dst.fileno(), 0o644)
                while True:
                    bloc = src.read(1 << 16)
                    if not bloc:
                        break
                    ecrits += len(bloc)
                    if ecrits > ZIP_MAX_OCTETS:
                        raise Refus(ARGUMENT, "archive refusée : plus de 1 Gio une fois décompressée")
                    dst.write(bloc)
            n += 1
        finally:
            os.close(dfd)
    return n


def verbe_deposer(a, conf: Path, apps: Path) -> dict:
    """Dépose une appli depuis un ZIP : validé ENTIÈREMENT, extrait dans un brouillon sous le dossier des applis
    (mkdtemp, rien de prévisible), puis mis en place par renommage ; les dépendances (requirements.txt) sont
    installées DANS le conteneur, et leur échec est rendu (code 6), jamais masqué."""
    try:
        return _deposer(a, apps)
    except zipfile.BadZipFile as e:
        raise Refus(ARGUMENT, f"archive ZIP illisible ou corrompue ({e})")


def _deposer(a, apps: Path) -> dict:
    fd = _ouvrir_zip(a.archive)
    with os.fdopen(fd, "rb") as fh, zipfile.ZipFile(fh) as z:
        entrees = _entrees_zip(z)
        if not any(not d for _i, _p, d in entrees):
            raise Refus(ARGUMENT, "archive vide")
        afd = _fd_apps(apps)
        try:
            st = _lstat_dans(afd, a.appli)
            if st is not None and stat.S_ISLNK(st.st_mode):
                raise Refus(ETAT, f"« {a.appli} » sous {apps} est un lien symbolique — refusé, rien n'est déposé")
            if st is not None and not stat.S_ISDIR(st.st_mode):
                raise Refus(ETAT, f"« {a.appli} » sous {apps} n'est pas un dossier — refusé")
            req = any(p == ["requirements.txt"] and not d for _i, p, d in entrees)
            sortie = {"ok": True, "success": True, "name": a.appli, "path": str(apps / a.appli),
                      "fichiers": sum(1 for _i, _p, d in entrees if not d),
                      "requirements": {"present": req, "installe": False}, "applique": False,
                      "avertissements": []}
            if not a.apply:
                return sortie
            sv = os.fstatvfs(afd)
            besoin = sum(i.file_size for i, _p, d in entrees if not d) + MARGE_DISQUE
            if sv.f_bavail * sv.f_frsize < besoin:
                raise Refus(ETAT, f"espace disque insuffisant sous {apps} : {sv.f_bavail * sv.f_frsize // 1048576} Mio "
                                  f"libres, {besoin // 1048576} Mio nécessaires (contenu + marge) — rien n'est déposé")
            with verrou():
                brouillon = f".depot-{a.appli}-{secrets.token_hex(6)}"
                os.mkdir(brouillon, 0o755, dir_fd=afd)
                try:
                    bfd = os.open(brouillon, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=afd)
                    try:
                        _extraire(z, entrees, bfd)
                    finally:
                        os.close(bfd)
                    ancien = None
                    if st is not None:
                        ancien = f".ancien-{a.appli}-{secrets.token_hex(6)}"
                        os.rename(a.appli, ancien, src_dir_fd=afd, dst_dir_fd=afd)
                    os.rename(brouillon, a.appli, src_dir_fd=afd, dst_dir_fd=afd)
                    brouillon = None
                    if ancien:
                        try:
                            shutil.rmtree(ancien, dir_fd=afd)
                        except OSError as e:
                            msg = f"ancienne version {apps}/{ancien} non supprimée ({e.strerror}) — à retirer à la main"
                            sortie["avertissements"].append(msg)
                            print(msg, file=sys.stderr)
                finally:
                    if brouillon:
                        try:
                            shutil.rmtree(brouillon, dir_fd=afd)
                        except OSError as e:
                            print(f"brouillon {apps}/{brouillon} non supprimé ({e.strerror}) — à retirer à la main",
                                  file=sys.stderr)
        finally:
            os.close(afd)
    sortie["applique"] = True
    if req:
        chemin = f"{apps}/{a.appli}/requirements.txt"          # même chemin dans le conteneur (montage identité)
        rc, out = _cmd(["lxc-attach", "-n", CONTENEUR, "--", "timeout", str(PIP_DELAI_CONTENEUR_S), "pip3", "install",
                        "--break-system-packages", "-r", chemin], timeout=PIP_DELAI_S)
        if rc:
            raise Refus(DEPENDANCES, f"appli déposée, mais dépendances non installées (pip, code {rc}) : "
                                     f"{_court(out) or 'sans message'} — corrigez requirements.txt puis redéposez")
        sortie["requirements"]["installe"] = True
    return sortie


# ─── Frontaux web permanents (#3294) ──────────────────────────────────────
# Un « frontal » est un service web hébergé dans le conteneur qui n'est PAS une appli Streamlit (couture.gk2 :
# frontal FastAPI d'Atelier Partagé). Déclaré dans [frontaux.<nom>] de streamlit.toml : `boot` démarre le conteneur
# puis son unité ; son vhost nginx :9080 est produit ici, avec les pages d'erreur SecuBox. La route sbxwaf et le
# vhost HAProxy du domaine ne sont JAMAIS touchés : le frontal se branche derrière la chaîne existante.

NOM_FRONTAL_RE = re.compile(r"[a-z0-9-]{1,40}", re.ASCII)
UNITE_RE = re.compile(r"[a-z0-9@._-]{1,64}\.service", re.ASCII)
SANTE_RE = re.compile(r"/[A-Za-z0-9._~/-]{0,127}", re.ASCII)
FICHIER_NGINX_RE = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}\.conf", re.ASCII)
BACKENDS_NGINX = frozenset({"nginx_vhosts", ""})   # backends HAProxy qui mènent à sbxwaf → nginx :9080


def ip_du_conteneur(lxc_config: str | None) -> str | None:
    """L'adresse déclarée du conteneur streamlit (première lxc.net.N.ipv4.address de SA config) : seule cible
    admise d'un frontal — ni le pont (l'hôte), ni un autre conteneur, ni le réseau ou la diffusion."""
    for ligne in (_lire(Path(lxc_config)) or "").splitlines() if lxc_config else []:
        m = re.match(r"^\s*lxc\.net\.[0-9]+\.ipv4\.address\s*=\s*([0-9.]+)/([0-9]{1,2})\s*$", ligne, re.ASCII)
        if m:
            with contextlib.suppress(ValueError):
                itf = ipaddress.IPv4Interface(f"{m.group(1)}/{m.group(2)}")
                if itf.ip not in (itf.network.network_address, itf.network.broadcast_address):
                    return str(itf.ip)
    return None


def erreur_frontal(nom, domaine, cible, unite, sante, dom_box: str, ip_ct: str | None) -> str | None:
    """Validation stricte d'une déclaration ; rend la cause d'un refus (partagée par `set` et par `boot`)."""
    if not isinstance(nom, str) or not NOM_FRONTAL_RE.fullmatch(nom):
        return "nom de frontal invalide (^[a-z0-9-]{1,40}$)"
    if not isinstance(domaine, str) or not DOMAINE_RE.fullmatch(domaine):
        return f"domaine invalide : « {str(domaine)[:80]} »"
    if not dom_box or not domaine.endswith("." + dom_box) or "." in domaine[:-len(dom_box) - 1]:
        return f"domaine hors de la zone de la box ({dom_box or 'inconnue'}) : {domaine}"
    if label_reserve(domaine.split(".", 1)[0]):
        return f"nom réservé à un service de la box : {domaine}"
    m = re.fullmatch(r"([0-9]{1,3}(?:\.[0-9]{1,3}){3}):([0-9]{1,5})", cible, re.ASCII) if isinstance(cible, str) else None
    if not m or not _ipv4(m.group(1)) or _ipv4(m.group(1)) != m.group(1):
        return f"cible invalide (attendu : adresse IPv4:port) : « {str(cible)[:80]} »"
    if not 1024 <= int(m.group(2)) <= 65535:
        return f"port hors de 1024..65535 : {m.group(2)}"
    if not ip_ct or m.group(1) != ip_ct:
        return f"cible {m.group(1)} refusée : seule l'adresse du conteneur streamlit ({ip_ct or 'inconnue'}) est admise"
    if not isinstance(unite, str) or not UNITE_RE.fullmatch(unite) or unite.startswith(("-", ".")):
        return "unité invalide (^[a-z0-9@._-]{1,64}\\.service$)"
    if sante is not None and sante != "" and (not isinstance(sante, str) or not SANTE_RE.fullmatch(sante)
                                              or ".." in sante or "//" in sante):
        return "chemin de santé invalide (absolu, sans « .. »)"
    return None


def frontaux(texte: str) -> dict[str, dict]:
    out = {}
    for e, _d, _f, v in sections(texte):
        if e.startswith("frontaux.") and len(e) > len("frontaux."):
            nom = e[len("frontaux."):]
            out[nom] = {"nom": nom, "domaine": str(v.get("domain") or ""), "cible": str(v.get("cible") or ""),
                        "unite": str(v.get("unite") or ""), "sante": str(v.get("sante") or ""),
                        "enabled": v.get("enabled", True) is not False}
    return out


def _label_frontal(nom: str) -> str:
    return f"frontal-{nom}"


def vhost_frontal(nom: str, domaine: str, cible: str) -> str:
    return f"""{MARQUE_NGINX} frontal={nom}
# Généré par streamlitctl (frontal set, #3294) — NE PAS ÉDITER : réécrit à chaque déclaration.
# Chaîne : HAProxy → sbxwaf → nginx :{PORT_NGINX} (ici) → frontal {nom} dans le conteneur Streamlit ({cible}).
server {{
    # Frontal arrêté ou conteneur endormi : page SecuBox, jamais la 502 brute de nginx.
    include snippets/secubox-errorpages.conf;
    listen {PORT_NGINX};
    server_name {domaine};

    # Frontal léger (formulaires) : aucun téléversement volumineux attendu.
    client_max_body_size 1m;

    location / {{
        proxy_pass http://{cible};
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header X-Forwarded-Host $host;
        proxy_connect_timeout 5s;
        proxy_read_timeout 60s;
    }}
}}
"""


def _reprise(fichier: str | None, domaine: str, label: str, sauf: set | None = None) -> list[Path]:
    """Fichiers nginx à reprendre (posés à la main) ; sans --reprendre, un autre fichier qui sert déjà le domaine
    est un conflit nommé."""
    nom_gere = f"streamlit-{label}.conf"
    sauf = set(sauf or ())
    if fichier is None:
        if (ailleurs := nginx_sert_ailleurs(domaine, {nom_gere} | sauf)):
            raise Refus(CONFLIT, f"{domaine} est déjà servi par nginx ({ailleurs}) : relancez avec "
                                 f"--reprendre {ailleurs} pour le remplacer (sauvegarde horodatée)")
        return []
    if not FICHIER_NGINX_RE.fullmatch(fichier) or fichier == nom_gere:
        raise Refus(ARGUMENT, f"fichier à reprendre invalide : « {fichier[:80]} »")
    fichiers = [dossier_nginx() / d / fichier for d in ("sites-enabled", "sites-available")]
    presents = [f for f in fichiers if f.exists() or f.is_symlink()]
    if not presents:
        raise Refus(INCONNUE, f"fichier à reprendre introuvable : {fichier}")
    for f in presents:
        if f.is_symlink() and f.parent.name == "sites-available":
            raise Refus(ETAT, f"{f} : lien symbolique — refusé")
        t = _lire(f)
        if not _sert(t, domaine):
            raise Refus(ETAT, f"{fichier} ne sert pas {domaine} — refusé, rien n'est modifié")
        if t.startswith(MARQUE_NGINX):
            raise Refus(ETAT, f"{fichier} est un vhost généré par streamlitctl — pas une reprise")
        noms = [n for ligne in re.findall(r"^\s*server_name\s+([^;]*);", t, re.M) for n in ligne.split()]
        if len(re.findall(r"^\s*server\s*\{", t, re.M)) != 1 or noms != [domaine]:
            raise Refus(ETAT, f"{fichier} porte plus d'un bloc server ou d'un nom — reprise refusée, rien n'est modifié")
    if (ailleurs := nginx_sert_ailleurs(domaine, {nom_gere, fichier} | sauf)):
        raise Refus(CONFLIT, f"{domaine} est aussi servi par {ailleurs} : un seul fichier peut être repris")
    return fichiers


def _poser_frontal_nginx(label: str, contenu: str, repris: list[Path], horodatage: str) -> tuple:
    """Remplacement en UN rechargement : la sauvegarde horodatée est écrite, le fichier repris retiré et le nôtre
    posé, puis nginx -t + reload. Échec : tout revient (fichier repris compris) et nginx est rechargé."""
    dispo, actif = _fichiers_nginx(label)
    cibles = [dispo, actif, *repris]
    avant = [(f, _instantane(f)) for f in cibles]
    sauvegarde = None
    vus = set()
    for f in repris:                    # une sauvegarde horodatée par fichier repris (lien suivi une seule fois)
        texte_repris = _lire(f)
        if texte_repris is None or f.name in vus:
            continue
        vus.add(f.name)
        s = dossier_nginx() / "sites-available" / f"{f.name}.avant-frontal-{horodatage}"
        ecrire_atomique(s, texte_repris, 0o644)
        sauvegarde = sauvegarde or s
    try:
        for f in repris:
            with contextlib.suppress(FileNotFoundError):
                f.unlink()
        ecrire_atomique(dispo, contenu)
        tmp = actif.with_name(f".{actif.name}.lien")
        with contextlib.suppress(FileNotFoundError):
            tmp.unlink()
        os.symlink(str(dispo), tmp)
        os.replace(tmp, actif)
        erreur = _nginx_tester_recharger()
    except OSError as e:
        erreur = f"{e.filename or ''} : {e.strerror or e}"
    if erreur:
        echec = _restaurer_frontal_nginx(avant)
        raise Refus(ECHEC, f"{erreur} — état d'avant rétabli, rien n'est déclaré"
                    + (f" — retour arrière incomplet : {echec}" if echec else ""))
    return avant, sauvegarde


def _restaurer_frontal_nginx(avant: list) -> str | None:
    try:
        for f, etat in avant:
            _restaurer(f, etat)
    except OSError as e:
        return f"nginx : {e.filename or ''} non restauré ({e.strerror})"
    erreur = _nginx_tester_recharger()
    return f"nginx après restauration : {erreur}" if erreur else None


def verbe_frontal_lister(a, conf: Path, apps: Path) -> dict:
    res = []
    for f in frontaux(_lire_conf(conf)).values():
        etat = "invalide"
        if NOM_FRONTAL_RE.fullmatch(f["nom"]) and DOMAINE_RE.fullmatch(f["domaine"]):
            etat = nginx_etat(_label_frontal(f["nom"]), f["domaine"], vhost_frontal(f["nom"], f["domaine"], f["cible"]))
        res.append({**f, "vhost": etat})
    return {"ok": True, "frontaux": res}


def frontal_unites(conf: Path) -> list[str]:
    """Unités à démarrer au boot : frontaux actifs et bien formés seulement (le TOML n'est pas une commande)."""
    out = []
    for f in frontaux(_lire_conf(conf)).values():
        if f["enabled"] and NOM_FRONTAL_RE.fullmatch(f["nom"]) and UNITE_RE.fullmatch(f["unite"]) \
                and not f["unite"].startswith(("-", ".")):
            out.append(f["unite"])
    return sorted(set(out))


def verbe_frontal_poser(a, conf: Path, apps: Path) -> dict:
    dom_box = domaine_box()
    if (err := erreur_frontal(a.nom, a.domaine, a.cible, a.unite, a.sante, dom_box, ip_du_conteneur(a.lxc_config))):
        raise Refus(ARGUMENT, err)
    with verrou():
        texte = _lire_conf(conf)
        label = _label_frontal(a.nom)
        for autre in frontaux(texte).values():
            if autre["nom"] != a.nom and autre["domaine"] == a.domaine:
                raise Refus(CONFLIT, f"{a.domaine} est déjà déclaré par le frontal « {autre['nom']} »")
        reprises = [i for i in instances(texte) if i["enabled"] and i["domain"] == a.domaine]
        if a.reprendre_publication is None:
            if reprises:
                raise Refus(CONFLIT, f"{a.domaine} est publié par l'appli « {reprises[0]['app']} » : relancez avec "
                                     f"--reprendre-publication {reprises[0]['app']} (HAProxy et sbxwaf gardés)")
        else:
            # Reprise d'une publication Streamlit pour le MÊME domaine : la chaîne HAProxy → sbxwaf → nginx :9080
            # est gardée telle quelle ; seuls le vhost nginx et la déclaration changent.
            if not NOM_APPLI_RE.fullmatch(a.reprendre_publication):
                raise Refus(ARGUMENT, "nom d'appli invalide pour --reprendre-publication")
            if not reprises:
                vise = [i["domain"] for i in instances(texte) if i["enabled"] and i["app"] == a.reprendre_publication]
                raise Refus(ETAT, f"l'appli « {a.reprendre_publication} » ne publie pas {a.domaine}"
                            + (f" (elle publie : {', '.join(vise)})" if vise else ""))
            if any(i["app"] != a.reprendre_publication for i in reprises):
                raise Refus(CONFLIT, f"{a.domaine} est publié par une autre appli que « {a.reprendre_publication} »")
            r0 = lire_routes().get(a.domaine)
            if not (isinstance(r0, list) and len(r0) == 2 and r0[1] == PORT_NGINX):
                raise Refus(CONFLIT, f"route sbxwaf de {a.domaine} absente ou hors nginx :{PORT_NGINX} ({r0}) — refusé")
            ha0 = haproxy_table(a.domaine)
            if ha0 is None or ha0[1] != "nginx_vhosts":
                raise Refus(CONFLIT, f"HAProxy ne sert pas {a.domaine} par nginx_vhosts ({ha0}) — refusé")
        if nginx_etat(label, a.domaine, "") == "autre":
            raise Refus(CONFLIT, f"sites-enabled/streamlit-{label}.conf sert un autre nom")
        routes = lire_routes()
        route = routes.get(a.domaine)
        if route is not None and not (isinstance(route, list) and len(route) == 2 and route[1] == PORT_NGINX):
            raise Refus(CONFLIT, f"{a.domaine} a une route sbxwaf vers autre chose que le nginx local :{PORT_NGINX} "
                                 f"({route}) — refusé")
        ha = haproxy_table(a.domaine)
        if ha is not None and ha[1] not in BACKENDS_NGINX:
            raise Refus(CONFLIT, f"{a.domaine} est servi par HAProxy vers le backend « {ha[1]} » — refusé")
        sauf = set()
        for i in reprises if a.reprendre_publication else []:
            if NOM_APPLI_RE.fullmatch(i["id"]):
                sauf.add(f"streamlit-{i['id']}.conf")
        repris = _reprise(a.reprendre, a.domaine, label, sauf)
        for nom_pub in sorted(sauf):                       # vhost généré de la publication reprise
            for d in ("sites-enabled", "sites-available"):
                f = dossier_nginx() / d / nom_pub
                if (f.exists() or f.is_symlink()) and f not in repris:
                    repris.append(f)
        contenu = vhost_frontal(a.nom, a.domaine, a.cible)
        champs = {"domain": a.domaine, "cible": a.cible, "unite": a.unite, "sante": a.sante or "",
                  "enabled": not a.inactif}
        nouveau = poser_cles(texte, f"frontaux.{a.nom}", champs)
        for i in reprises if a.reprendre_publication else []:
            # La publication s'efface pour ce domaine ; l'appli et son code restent.
            nouveau = retirer_cles(nouveau, f"instances.{i['id']}", {"domain"})
            nouveau = poser_cles(nouveau, f"instances.{i['id']}", {"enabled": False, "autostart": False})
            if applis_declarees(nouveau).get(i["app"], {}).get("autostart_publication") is True:
                nouveau = retirer_cles(nouveau, f"apps.{i['app']}", {"autostart_publication"})
                nouveau = poser_cles(nouveau, f"apps.{i['app']}", {"autostart": False})
        etat_nginx = nginx_etat(label, a.domaine, contenu)
        avert = []
        if route is None:
            avert.append(f"aucune route sbxwaf pour {a.domaine} : déclarez-la avec secubox-waf-route (non modifiée ici)")
        a_faire = nouveau != texte or etat_nginx != "conforme" or bool(repris)
        sortie = {"ok": True, "frontal": a.nom, "domaine": a.domaine, "cible": a.cible, "unite": a.unite,
                  "evenement": "frontal-pose" if a_faire else "inchange", "applique": False,
                  "reprise": a.reprendre, "avertissements": avert}
        if not a.apply or not a_faire:
            return sortie
        _valider_toml(texte, nouveau)
        journal = Journal(a.par)
        try:
            avant, sauvegarde = (None, None)
            if etat_nginx != "conforme" or repris:
                try:
                    avant, sauvegarde = _poser_frontal_nginx(label, contenu, repris,
                                                             datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ"))
                except Refus as e:
                    journal.ecrire(evenement="frontal-pose", frontal=a.nom, domaine=a.domaine,
                                   resultat="echec-nginx", erreur=e.message[:300])
                    raise
            try:
                _ecrire_conf(conf, texte, nouveau)
            except (Refus, OSError) as e:
                echec = _restaurer_frontal_nginx(avant) if avant is not None else None
                cause = e.message if isinstance(e, Refus) else (e.strerror or str(e))
                journal.ecrire(evenement="frontal-pose", frontal=a.nom, resultat="echec-declaration",
                               erreur=(cause + (f" ; {echec}" if echec else ""))[:300])
                raise
            journal.ecrire(evenement="frontal-pose", frontal=a.nom, domaine=a.domaine, cible=a.cible,
                           unite=a.unite, enabled=not a.inactif, repris=a.reprendre,
                           sauvegarde=sauvegarde.name if sauvegarde else None,
                           publication_reprise=a.reprendre_publication,
                           instances_reprises=[i["id"] for i in reprises] if a.reprendre_publication else None,
                           resultat="applique")
        finally:
            journal.fermer()
        sortie["applique"] = True
        sortie["sauvegarde"] = str(sauvegarde) if sauvegarde else None
        return sortie


def verbe_frontal_boot(a, conf: Path, apps: Path) -> dict:
    """Trace d'audit d'un démarrage de frontal par `boot` (le résultat vient du ctl, l'unité est revalidée)."""
    if a.unite not in frontal_unites(conf):
        raise Refus(ARGUMENT, "unité non déclarée")
    journal = Journal("boot")
    try:
        journal.ecrire(evenement="frontal-boot", unite=a.unite, resultat=a.resultat)
    finally:
        journal.fermer()
    return {"ok": True}


def verbe_frontal_retirer(a, conf: Path, apps: Path) -> dict:
    if not NOM_FRONTAL_RE.fullmatch(a.nom or ""):
        raise Refus(ARGUMENT, "nom de frontal invalide (^[a-z0-9-]{1,40}$)")
    with verrou():
        texte = _lire_conf(conf)
        f = frontaux(texte).get(a.nom)
        if f is None:
            raise Refus(INCONNUE, f"frontal inconnu : {a.nom}")
        nouveau = retirer_section(texte, f"frontaux.{a.nom}")
        sortie = {"ok": True, "frontal": a.nom, "domaine": f["domaine"], "evenement": "frontal-retire",
                  "applique": False, "avertissements": []}
        if not a.apply:
            return sortie
        _valider_toml(texte, nouveau)
        journal = Journal(a.par)
        try:
            etat = nginx_retirer(_label_frontal(a.nom), f["domaine"], sortie["avertissements"]) \
                if DOMAINE_RE.fullmatch(f["domaine"]) else "laisse"
            _ecrire_declaration(journal, conf, texte, nouveau, a.nom, "frontal-retire")
            journal.ecrire(evenement="frontal-retire", frontal=a.nom, domaine=f["domaine"], nginx=etat,
                           resultat="applique")
        finally:
            journal.fermer()
        sortie["applique"] = True
        return sortie


# ─── Ligne de commande ────────────────────────────────────────────────────

class _Parseur(argparse.ArgumentParser):
    def error(self, message):
        raise Refus(ARGUMENT, f"argument refusé : {message}")


def _type_appli(v: str) -> str:
    if not NOM_APPLI_RE.fullmatch(v):
        raise argparse.ArgumentTypeError(f"nom d'appli invalide : {v[:80]}")
    return v


def _type_acteur(v: str) -> str:
    return v if ACTEUR_RE.fullmatch(v) else "inconnu"


def _parseur() -> _Parseur:
    p = _Parseur(prog="publication.py")
    p.add_argument("--conf", default="/etc/secubox/streamlit.toml")
    p.add_argument("--apps", default="/srv/streamlit/apps")
    sub = p.add_subparsers(dest="verbe", required=True, parser_class=_Parseur)
    s = sub.add_parser("port")
    s.add_argument("appli", type=_type_appli)
    s.add_argument("--demande", type=int)
    s.add_argument("--ecoute", default="")
    s.add_argument("--processus", default="")
    s.add_argument("--ip-vive", dest="ip_vive")
    s.add_argument("--apply", action="store_true")
    s = sub.add_parser("publier")
    s.add_argument("appli", type=_type_appli)
    s.add_argument("--nom")
    s.add_argument("--port", type=int)
    s.add_argument("--ip-vive", dest="ip_vive")
    s.add_argument("--lxc-config", dest="lxc_config")
    s.add_argument("--par", type=_type_acteur, default="inconnu")
    s.add_argument("--apply", action="store_true")
    s = sub.add_parser("depublier")
    s.add_argument("appli", type=_type_appli)
    s.add_argument("--par", type=_type_acteur, default="inconnu")
    s.add_argument("--apply", action="store_true")
    s = sub.add_parser("etat")
    s.add_argument("appli", type=_type_appli)
    s = sub.add_parser("ecrire-port")
    s.add_argument("appli", type=_type_appli)
    s.add_argument("--port", type=int)
    s.add_argument("--entrypoint")
    s.add_argument("--sauvegarde")
    s.add_argument("--apply", action="store_true")
    s = sub.add_parser("deposer")
    s.add_argument("archive")
    s.add_argument("appli", type=_type_appli)
    s.add_argument("--apply", action="store_true")
    s = sub.add_parser("depublier-anciennes")
    s.add_argument("--par", type=_type_acteur, default="inconnu")
    s.add_argument("--lxc-config", dest="lxc_config")
    s.add_argument("--apply", action="store_true")
    s = sub.add_parser("env")
    s.add_argument("appli", type=_type_appli)
    s.add_argument("--lister", action="store_true")
    s.add_argument("--retirer", action="append")
    s.add_argument("--par", type=_type_acteur, default="inconnu")
    s.add_argument("--apply", action="store_true")
    s = sub.add_parser("frontal-lister")
    s = sub.add_parser("frontal-unites")
    s = sub.add_parser("frontal-poser")
    s.add_argument("nom")
    s.add_argument("--domaine", required=True)
    s.add_argument("--cible", required=True)
    s.add_argument("--unite", required=True)
    s.add_argument("--sante", default="")
    s.add_argument("--reprendre")
    s.add_argument("--reprendre-publication", dest="reprendre_publication")
    s.add_argument("--inactif", action="store_true")
    s.add_argument("--lxc-config", dest="lxc_config")
    s.add_argument("--par", type=_type_acteur, default="inconnu")
    s.add_argument("--apply", action="store_true")
    s = sub.add_parser("frontal-boot")
    s.add_argument("--unite", required=True)
    s.add_argument("--resultat", required=True, choices=["actif", "deja-actif", "echec", "conteneur-indisponible"])
    s = sub.add_parser("frontal-retirer")
    s.add_argument("nom")
    s.add_argument("--par", type=_type_acteur, default="inconnu")
    s.add_argument("--apply", action="store_true")
    return p


def main(argv: list[str] | None = None, entree: str | None = None) -> int:
    try:
        a = _parseur().parse_args(argv)
        conf, apps = Path(a.conf), Path(a.apps)
        if a.verbe == "port":
            r = verbe_port(a, conf, apps)
        elif a.verbe == "publier":
            r = verbe_publier(a, conf, apps)
        elif a.verbe == "depublier":
            r = verbe_depublier(a, conf, apps)
        elif a.verbe == "etat":
            r = verbe_etat(a, conf, apps)
        elif a.verbe == "ecrire-port":
            r = verbe_ecrire_port(a, conf, apps)
        elif a.verbe == "deposer":
            r = verbe_deposer(a, conf, apps)
        elif a.verbe == "frontal-unites":
            # Une unité par ligne (lue par `streamlitctl boot`), déjà validée : jamais du JSON à découper en shell.
            for u in frontal_unites(conf):
                print(u)
            return OK
        elif a.verbe == "frontal-lister":
            r = verbe_frontal_lister(a, conf, apps)
        elif a.verbe == "frontal-poser":
            r = verbe_frontal_poser(a, conf, apps)
        elif a.verbe == "frontal-boot":
            r = verbe_frontal_boot(a, conf, apps)
        elif a.verbe == "frontal-retirer":
            r = verbe_frontal_retirer(a, conf, apps)
        elif a.verbe == "depublier-anciennes":
            r = verbe_depublier_anciennes(a, conf, apps)
        else:
            # Tout l'entrée standard jusqu'à la limite + 1 : au-delà, refus (jamais une coupe silencieuse).
            r = verbe_env(a, conf, apps, entree if entree is not None else
                          ("" if a.lister or sys.stdin is None or sys.stdin.isatty() else sys.stdin.read(ENV_MAX + 1)))
    except OSError as e:
        e = Refus(ECHEC, f"écriture impossible : {e.filename or ''} : {e.strerror or e}".replace(" :  :", " :"))
        print(json.dumps({"ok": False, "error": e.message, "code": e.code}, ensure_ascii=False))
        print(e.message, file=sys.stderr)
        return e.code
    except Refus as e:
        print(json.dumps({"ok": False, "error": e.message, "code": e.code}, ensure_ascii=False))
        print(e.message, file=sys.stderr)
        return e.code
    print(json.dumps(r, ensure_ascii=False))
    return OK


if __name__ == "__main__":
    sys.exit(main())
