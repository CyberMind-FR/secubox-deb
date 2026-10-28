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
import fcntl
import ipaddress
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # Python < 3.11 : la validation du résultat est alors sautée
    tomllib = None

OK, ECHEC, INCONNUE, ETAT, CONFLIT, EPUISE, ARGUMENT, INDISPONIBLE = 0, 1, 2, 3, 4, 5, 64, 75

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
    return Path(_env("SECUBOX_STREAMLIT_VERROU", "/run/lock/secubox-streamlit-publication.lock"))


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
        res.setdefault(inst["app"], []).append({"nom_public": inst["id"], "domaine": domaine_de(inst, dom_box),
                                                "port": inst["port"], "enabled": inst["enabled"]})
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
    """Temporaire VOISIN + rename(2) ; mode et propriétaire du fichier remplacé conservés."""
    try:
        st = os.stat(chemin, follow_symlinks=False)
    except FileNotFoundError:
        st = None
    fd, tmp = tempfile.mkstemp(dir=chemin.parent, prefix=f".{chemin.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(data)
        if st is not None:
            os.chmod(tmp, st.st_mode & 0o7777)
            with contextlib.suppress(PermissionError):
                os.chown(tmp, st.st_uid, st.st_gid)
        else:
            os.chmod(tmp, mode_defaut)
        os.replace(tmp, chemin)
    except BaseException:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmp)
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
    chemin = chemin_verrou()
    try:
        fd = os.open(chemin, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
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

def appli_existe(apps: Path, appli: str) -> bool:
    return (apps / appli).is_dir() or (apps / f"{appli}.py").is_file()


def fichier_port(apps: Path, appli: str) -> Path:
    return apps / appli / ".streamlit.toml" if (apps / appli).is_dir() else apps / f".streamlit-{appli}.toml"


def lire_port_fichier(f: Path) -> int | None:
    try:
        m = re.search(r'^port[ \t]*=[ \t]*"?(\d+)', f.read_text(encoding="utf-8"), re.M)
    except (OSError, UnicodeDecodeError):
        return None
    return _port(m.group(1)) if m else None


def ecrire_port_fichier(f: Path, port: int) -> None:
    try:
        texte = f.read_text(encoding="utf-8")
    except FileNotFoundError:
        texte = ""
    if re.search(r"^port[ \t]*=", texte, re.M):
        texte = re.sub(r"^port[ \t]*=.*$", f"port = {port}", texte, count=1, flags=re.M)
    else:
        texte = (texte if not texte or texte.endswith("\n") else texte + "\n") + f"port = {port}\n"
    ecrire_atomique(f, texte)


def _entrees_applis(apps: Path):
    try:
        entrees = sorted(apps.iterdir())
    except OSError:
        return
    for e in entrees:
        if e.name.startswith(".") or e.name in _EXCLUS:
            continue
        if e.is_dir():
            yield e.name
        elif e.suffix == ".py" and e.is_file():
            yield e.stem


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


def ip_conteneur(texte: str, routes: dict, ip_vive: str | None) -> tuple[str | None, str]:
    """(adresse, origine) du conteneur pour proxy_pass : réglage > adresse vive > voisines (anciennes routes
    directes des instances, vhosts streamlit déjà générés)."""
    cfg = _ipv4(reglages(texte)["ip_conteneur"])
    if cfg:
        return cfg, "reglage"
    vive = _ipv4(ip_vive) if ip_vive else None
    if vive:
        return vive, "vive"
    compte: collections.Counter = collections.Counter()
    for inst in instances(texte):
        c = routes.get(inst["domain"]) if inst["domain"] else None
        if isinstance(c, list) and len(c) == 2 and _port(c[1]) not in (None, PORT_NGINX) and _ipv4(c[0]):
            compte[_ipv4(c[0])] += 1
    for f in sorted((dossier_nginx() / "sites-available").glob("streamlit-*.conf")):
        with contextlib.suppress(OSError, UnicodeDecodeError):
            m = re.search(r"proxy_pass\s+http://([\d.]+):\d+", f.read_text(encoding="utf-8"))
            if m and _ipv4(m.group(1)):
                compte[_ipv4(m.group(1))] += 1
    if compte:
        return compte.most_common(1)[0][0], "voisine"
    return None, ""


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
            p = lire_port_fichier(fichier_port(apps, nom))
            if p:
                pris.setdefault(p, f"déjà attribué à l'appli « {nom} »")
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
    p = lire_port_fichier(fichier_port(apps, appli))
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
    ip, _o = ip_conteneur(texte, routes, ip_vive)
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
        nginx_restaurer(label, avant)
        raise Refus(ECHEC, f"{erreur} — vhost retiré, rien n'est publié")
    return avant


def nginx_restaurer(label: str, avant: tuple) -> None:
    dispo, actif = _fichiers_nginx(label)
    _restaurer(dispo, avant[0])
    _restaurer(actif, avant[1])
    _nginx_tester_recharger()


def nginx_retirer(label: str, domaine: str, avert: list[str]) -> bool:
    dispo, actif = _fichiers_nginx(label)
    if nginx_etat(label, domaine, "") == "autre":
        avert.append(f"nginx : {actif.name} sert un autre nom — laissé en place")
        return False
    avant = (_instantane(dispo), _instantane(actif))
    if avant == (None, None):
        return False
    for f in (actif, dispo):
        with contextlib.suppress(FileNotFoundError):
            f.unlink()
    erreur = _nginx_tester_recharger()
    if erreur:
        nginx_restaurer(label, avant)
        avert.append(f"nginx : retrait de {actif.name} annulé ({erreur})")
        return False
    return True


def route_poser(domaine: str) -> None:
    """Par l'outil commun : même fusion, même prudence, même adresse que tous les paquets (#3247)."""
    env = dict(os.environ, SBX_WAF_ROUTES=str(chemin_routes()))
    rc, sortie = _cmd([_env("SECUBOX_WAF_ROUTE", "secubox-waf-route"), domaine, str(PORT_NGINX)], timeout=30,
                      env=env)
    if rc:
        raise Refus(ECHEC, f"secubox-waf-route : {_court(sortie) or f'code {rc}'}")


def route_retirer(domaine: str, ports_admis: set, avert: list[str]) -> bool:
    """Retire la route SEULEMENT si elle vise un port à nous (nginx :9080, ou l'ancien port direct de l'appli)."""
    routes = lire_routes()
    cible = routes.get(domaine)
    if cible is None:
        return False
    if not (isinstance(cible, list) and len(cible) == 2 and _port(cible[1]) in ports_admis):
        avert.append(f"route sbxwaf de {domaine} re-pointée ailleurs ({cible}) — laissée en place")
        return False
    del routes[domaine]
    ecrire_atomique(chemin_routes(), json.dumps(routes, indent=2, sort_keys=True) + "\n")
    return True


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


def haproxy_retirer(domaine: str, avert: list[str]) -> None:
    if not haproxy_declare(domaine):
        return
    b = _haproxyctl()
    if b is None:
        avert.append(f"haproxyctl absent : vhost {domaine} laissé dans haproxy.toml")
        return
    rc, sortie = _cmd([b, "vhost", "remove", cle_vhost(domaine)], timeout=120)
    if rc:
        # Typiquement le garde de dérive : la table est retirée, la régénération refusée. On ne force JAMAIS
        # --allow-shrink : il effacerait aussi les vhosts tenus hors de haproxy.toml.
        avert.append(f"HAProxy : {domaine} retiré de haproxy.toml, régénération refusée ({_court(sortie)}) — "
                     "à régénérer par l'opérateur")
        return
    _cmd([b, "reload"], timeout=60)


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
    if conf.exists():
        shutil.copy2(conf, conf.with_name(conf.name + ".avant-publication"))
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
            f = fichier_port(apps, a.appli)
            if lire_port_fichier(f) != port:
                ecrire_port_fichier(f, port)
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
    miennes = [i for i in instances(texte) if i["app"] == a.appli]
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
    ip, origine = ip_conteneur(texte, routes, a.ip_vive)
    if ip is None:
        raise Refus(INDISPONIBLE, "adresse du conteneur Streamlit inconnue : réveillez-le, ou fixez "
                                  "[publication] ip_conteneur dans streamlit.toml")
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
    champs_inst = {"app": a.appli, "port": port, "domain": domaine, "enabled": True, "emancipated": True,
                   "waf_enabled": True}
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

    journal = Journal(a.par)
    try:
        route_avant = routes.get(domaine)
        avant_nginx = nginx_poser(label, contenu) if etat_nginx != "conforme" else None
        try:
            if routes.get(domaine) != route_voulue:
                route_poser(domaine)
            _ecrire_conf(conf, texte, nouveau)
        except (Refus, OSError):
            _defaire_route(domaine, route_avant)
            if avant_nginx is not None:
                nginx_restaurer(label, avant_nginx)
            raise
        # HAProxy : l'ancien d'abord, le nouveau ensuite — la génération suivante garde alors le même nombre de
        # vhosts et le garde de dérive l'accepte ; son refus du retrait seul n'est rapporté que s'il persiste.
        retrait_ha: list[str] = []
        if renommage:
            haproxy_retirer(ancien_dom, retrait_ha)
        n = len(avert)
        if haproxy_declare(domaine) is not True:
            haproxy_poser(domaine, avert)
        if len(avert) > n:
            avert.extend(retrait_ha)
        if renommage:
            route_retirer(ancien_dom, {PORT_NGINX, ancienne["port"] or port}, avert)
            nginx_retirer(ancienne["id"], ancien_dom, avert)
        if toujours:
            conteneur_systemctl("enable", a.appli, avert)
        journal.ecrire(evenement=evenement, appli=a.appli, nom_public=label, domaine=domaine,
                       cible=f"{ip}:{port}", ancien_nom_public=ancienne["id"] if renommage else None,
                       ancien_domaine=ancien_dom or None, resultat="applique")
    finally:
        journal.fermer()
    sortie["applique"] = True
    return sortie


def _defaire_route(domaine: str, avant) -> None:
    with contextlib.suppress(Refus, OSError):
        routes = lire_routes()
        if avant is None:
            routes.pop(domaine, None)
        else:
            routes[domaine] = avant
        ecrire_atomique(chemin_routes(), json.dumps(routes, indent=2, sort_keys=True) + "\n")


def verbe_depublier(a, conf: Path, apps: Path) -> dict:
    with verrou() if a.apply else contextlib.nullcontext():
        texte = _lire_conf(conf)
        miennes = [i for i in instances(texte) if i["app"] == a.appli]
        sortie = {"ok": True, "appli": a.appli, "retires": [], "applique": False, "avertissements": []}
        if not miennes:
            sortie["evenement"] = "inchange"
            return sortie
        dom_box = domaine_box() if any(not i["domain"] for i in miennes) else ""
        nouveau = texte
        for inst in miennes:
            nouveau = retirer_section(nouveau, f"instances.{inst['id']}")
            sortie["retires"].append({"nom_public": inst["id"], "domaine": domaine_de(inst, dom_box)})
        decl = applis_declarees(nouveau).get(a.appli, {})
        par_publication = decl.get("autostart_publication") is True
        if par_publication:
            nouveau = retirer_cles(poser_cles(nouveau, f"apps.{a.appli}", {"autostart": False}),
                                   f"apps.{a.appli}", {"autostart_publication"})
        sortie["evenement"] = "depublication"
        if not a.apply:
            return sortie
        avert = sortie["avertissements"]
        journal = Journal(a.par)
        try:
            _ecrire_conf(conf, texte, nouveau)
            for inst, r in zip(miennes, sortie["retires"]):
                dom = r["domaine"]
                if dom:
                    haproxy_retirer(dom, avert)
                    r["route_retiree"] = route_retirer(dom, {PORT_NGINX} | ({inst["port"]} if inst["port"] else
                                                                           set()), avert)
                    r["nginx_retire"] = nginx_retirer(inst["id"], dom, avert)
                journal.ecrire(evenement="depublication", appli=a.appli, nom_public=inst["id"], domaine=dom,
                               resultat="applique")
            if par_publication:
                conteneur_systemctl("disable", a.appli, avert)
        finally:
            journal.fermer()
        sortie["applique"] = True
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
    s.add_argument("--par", type=_type_acteur, default="inconnu")
    s.add_argument("--apply", action="store_true")
    s = sub.add_parser("depublier")
    s.add_argument("appli", type=_type_appli)
    s.add_argument("--par", type=_type_acteur, default="inconnu")
    s.add_argument("--apply", action="store_true")
    s = sub.add_parser("etat")
    s.add_argument("appli", type=_type_appli)
    s = sub.add_parser("env")
    s.add_argument("appli", type=_type_appli)
    s.add_argument("--lister", action="store_true")
    s.add_argument("--retirer", action="append")
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
        else:
            r = verbe_env(a, conf, apps, entree if entree is not None else
                          ("" if a.lister or sys.stdin is None or sys.stdin.isatty() else sys.stdin.read(65536)))
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
