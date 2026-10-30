# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: pilotage :: vhost `admin.<box>.secubox.in` d'une box légère (#3126, L5 tâche 5)

Une box légère (inventaire : `Device.X_SECUBOX_Pilotage.Interface = "distante"`) n'a pas d'interface d'administration à
elle : le maître la sert sous une ORIGINE À ELLE, `admin.<box>.secubox.in`, par la chaîne normale HAProxy TLS 1.3 → sbxwaf →
nginx (vhost déclaré par `haproxyctl`, route par `secubox-waf-route` ; jamais de contournement du WAF).

  /                 pages `www/` des versions que la box déclare (Device.X_SECUBOX_Packages), extraites par
                    secubox-pilotage-www sous /var/lib/secubox-pilotage-pages/www/<paquet>/<version>/<module>/ ;
                    CSP stricte, nosniff, X-Frame-Options, fichiers en point refusés, liens seulement de même propriétaire
  /api/v1/auth/     connexion avec les identifiants DU MAÎTRE, par le contrôleur (`/vhost/auth/…`) : le jeton du maître ne
                    quitte jamais le contrôleur ; la page reçoit un jeton À PORTÉE (`scope = pilotage-vhost`,
                    `pilotage_vhost = <box>`), refusé par toutes les gardes du maître (`_is_scope_token`), reconnu ici seul
  /api/v1/<module>/ → /run/secubox/pilotage.sock `/relais/<box>/api/v1/<module>/…`, avec `X-SecuBox-Version-Page:
                    <paquet>=<version>` posé par nginx (409 si la box a changé de version depuis)

Ce module est PUR (aucune E/S hors `ecrire_plan`) : il est importé par le service et par le ctl root
`secubox-pilotage-vhost`, qui rend le gabarit nginx.
"""
from __future__ import annotations

import json
import os
import re
import tempfile
import time
from pathlib import Path
from typing import Callable, Iterable, Optional

RE_BOX = re.compile(r"[a-z0-9-]{1,40}")
RE_PAQUET = re.compile(r"secubox-[a-z0-9-]{1,60}")            # mêmes motifs que secubox-pilotage-www
RE_VERSION = re.compile(r"[0-9][A-Za-z0-9.+~:-]{0,62}")
RE_MODULE = re.compile(r"[a-z0-9][a-z0-9_-]{0,63}")
ZONE = "secubox.in"
PORT_NGINX = 9080                     # port des vhosts nginx derrière sbxwaf (le même que les voisins de la table des routes)
RACINE_PAGES = "/var/lib/secubox-pilotage-pages/www"
SOCKET = "/run/secubox/pilotage.sock"
INTERFACE = "Device.X_SECUBOX_Pilotage.Interface"
MAINS = "Device.X_SECUBOX_Pilotage.MainsLiees"
_RE_PAQUETS = re.compile(r"Device\.X_SECUBOX_Packages\.([0-9]{1,5})\.(Name|Version)")
BOXES_MAX = 64                        # vhosts au plus (plan du service, borné aussi par le ctl)
PAGES_MAX = 256                       # paquets par box
ENTETE_VERSION = "X-SecuBox-Version-Page"
ENTETE_BOX = "X-SecuBox-Pilotage-Box"
SCOPE = "pilotage-vhost"
RECLAMATION = "pilotage_vhost"
SESSION_MAX_S = 4 * 3600              # le jeton à portée vit au plus 4 h (et jamais plus que la session du maître)
CORPS_MAX = 4 << 20                   # comme le relais et le canal (R-L5-19)
DEBIT_PAR_MINUTE = 300                # requêtes relayées par (administrateur, box) et par minute

# CSP : rien d'autre que l'origine du vhost (les pages portées sont en fichiers .js/.css, sans script en ligne).
CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; "
       "manifest-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")


def domaine(box: str) -> str:
    if not isinstance(box, str) or not RE_BOX.fullmatch(box):
        raise ValueError("nom de box invalide")
    return f"admin.{box}.{ZONE}"


def _texte(v) -> str:
    return v.strip() if isinstance(v, str) else ""


def interface_distante(valeurs: dict) -> bool:
    return _texte(valeurs.get(INTERFACE)) == "distante"


def mains_liees(valeurs: dict) -> Optional[bool]:
    """Vrai, faux, ou None si inconnu (le contrôleur traite alors la box en lecture seule)."""
    v = valeurs.get(MAINS)
    if isinstance(v, bool):
        return v
    t = _texte(v).lower()
    return True if t in ("true", "1") else False if t in ("false", "0") else None


def pages_declarees(valeurs: dict) -> dict:
    """{paquet: version} des paquets SecuBox déclarés (Device.X_SECUBOX_Packages.{i}.Name/Version) ; une entrée hors motif
    ou incomplète est ignorée, un paquet déclaré deux fois avec deux versions aussi (aucune version n'est devinée)."""
    par_i: dict = {}
    for chemin, v in valeurs.items():
        m = _RE_PAQUETS.fullmatch(chemin) if isinstance(chemin, str) else None
        if m:
            par_i.setdefault(m.group(1), {})[m.group(2)] = _texte(v)
    res: dict = {}
    doubles: set = set()
    for e in par_i.values():
        p, v = e.get("Name", ""), e.get("Version", "")
        if not (RE_PAQUET.fullmatch(p) and RE_VERSION.fullmatch(v)):
            continue
        if p in res and res[p] != v:
            doubles.add(p)
        res[p] = v
    for p in doubles:
        res.pop(p, None)
    return dict(sorted(res.items())[:PAGES_MAX])


def plan(boites: Iterable[tuple]) -> dict:
    """Plan lu par le ctl root : `boites` = [(nom, valeurs d'inventaire)]. Seules les box « distante » de nom valide et
    unique y entrent (un nom porté par deux box n'a pas de vhost : on ne choisit pas)."""
    vus: dict = {}
    for nom, valeurs in boites:
        if isinstance(nom, str) and RE_BOX.fullmatch(nom):
            vus.setdefault(nom, []).append(valeurs)
    sortie = []
    for nom in sorted(vus):
        if len(vus[nom]) != 1 or not interface_distante(vus[nom][0]):
            continue
        sortie.append({"box": nom, "pages": [{"paquet": p, "version": v} for p, v in pages_declarees(vus[nom][0]).items()]})
    return {"boxes": sortie[:BOXES_MAX]}


def ecrire_plan(chemin: Path, contenu: dict) -> bool:
    """Écrit le plan (atomique, 0640) seulement s'il change ; rend vrai s'il a été écrit. Le ctl root le relit à chemin FIXE,
    sans suivre de lien, borné et validé en entier."""
    donnees = (json.dumps(contenu, ensure_ascii=True, sort_keys=True) + "\n").encode("ascii")
    try:
        if chemin.read_bytes() == donnees:
            return False
    except OSError:
        pass
    fd, tmp = tempfile.mkstemp(dir=str(chemin.parent), prefix=".vhosts-", suffix=".tmp")
    try:
        os.fchmod(fd, 0o640)
        os.write(fd, donnees)
        os.fsync(fd)
        os.close(fd)
        os.replace(tmp, chemin)
    except BaseException:
        try:
            os.close(fd)
        except OSError:
            pass
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise
    return True


# --- gabarit nginx (rendu par le ctl root, qui a listé les modules lui-même) ----------------------------------------

def _q(s: str) -> str:
    """Valeur nginx entre guillemets : seuls des caractères des motifs ci-dessus y arrivent (vérifié par l'appelant)."""
    if not re.fullmatch(r"[A-Za-z0-9.+~:=_/@ -]*", s):
        raise ValueError("valeur nginx refusée")
    return f'"{s}"'


def rendre_nginx(box: str, pages: list, racine: str = RACINE_PAGES, socket: str = SOCKET) -> str:
    """`pages` : [{"paquet", "version", "modules": [module…]}]. Un module servi par deux paquets est refusé (ValueError)."""
    dom = domaine(box)
    vus: dict = {}
    for p in pages:
        if not (RE_PAQUET.fullmatch(p["paquet"]) and RE_VERSION.fullmatch(p["version"])):
            raise ValueError("paquet ou version invalide")
        for m in p["modules"]:
            if not RE_MODULE.fullmatch(m) or m in ("api", "auth"):
                raise ValueError(f"module invalide : {m}")
            if m in vus:
                raise ValueError(f"module servi par deux paquets : {m}")
            vus[m] = p
    L = [
        "# Généré par secubox-pilotage-vhost (#3126, L5 tâche 5) — ne pas éditer : réécrit à chaque synchronisation.",
        f"# Box légère {box} : pages de SES versions, API relayée par le contrôleur du pilotage. Derrière HAProxy → sbxwaf.",
        "server {",
        f"    listen 0.0.0.0:{PORT_NGINX};",
        f"    server_name {dom};",
        "    server_tokens off;",
        "    client_max_body_size 4m;",
        "    charset utf-8;",
        # liens : seulement de même propriétaire (root), à partir de la racine de chaque alias — l'extracteur refuse déjà
        # tout lien absolu ou contenant « .. »
        "    disable_symlinks if_not_owner from=$document_root;",
        "    autoindex off;",
        f"    add_header Content-Security-Policy {_q_csp()} always;",
        "    add_header X-Content-Type-Options \"nosniff\" always;",
        "    add_header X-Frame-Options \"DENY\" always;",
        "    add_header Referrer-Policy \"no-referrer\" always;",
        "    add_header Cache-Control \"no-store\" always;",
        "",
        "    # Fichiers et dossiers en point (manifestes .<version>.json, .vu.json, résidus .tmp-/.old-) : jamais servis.",
        "    location ~ /\\. { return 404; }",
        "",
        "    # Connexion : identifiants du maître, jeton à portée de CE vhost rendu par le contrôleur.",
        "    location ^~ /api/v1/auth/ {",
        f"        proxy_pass http://unix:{socket}:/vhost/auth/;",
    ]
    L += _entetes_proxy(box, None)
    L += ["    }", ""]
    for m in sorted(vus):
        p = vus[m]
        L += [f"    location ^~ /api/v1/{m}/ {{",
              f"        proxy_pass http://unix:{socket}:/relais/{box}/api/v1/{m}/;"]
        L += _entetes_proxy(box, f"{p['paquet']}={p['version']}")
        L += ["    }",
              f"    location ^~ /{m}/ {{",
              f"        alias {racine}/{p['paquet']}/{p['version']}/{m}/;",
              "        index index.html;",
              # « ^~ » coupe la recherche des regex du serveur : la garde des fichiers en point est répétée ici
              "        location ~ /\\. { return 404; }",
              "    }"]
    L += ["", "    location ^~ /api/ { return 404; }",
          "    location / { return 404; }",
          "}", ""]
    return "\n".join(L)


def _q_csp() -> str:
    return '"' + CSP + '"'


def _entetes_proxy(box: str, version_page: Optional[str]) -> list:
    """Pas le snippet secubox-proxy.conf : il ajoute `Access-Control-Allow-Origin *`. En-têtes du client effacés : cookie (le
    maître n'en lit aucun ici), marques X-SecuBox-* (LAN, relais, tunnel), puis les nôtres posés."""
    L = ["        proxy_http_version 1.1;",
         "        proxy_set_header Host $host;",
         "        proxy_set_header X-Real-IP $remote_addr;",
         "        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;",
         "        proxy_set_header X-Forwarded-Proto https;",
         "        proxy_set_header Connection \"\";",
         "        proxy_set_header Cookie \"\";",
         "        proxy_set_header X-SecuBox-LAN \"\";",
         "        proxy_set_header X-SecuBox-Maillage \"\";",
         "        proxy_set_header X-SecuBox-Pilotage-Tunnel \"\";",
         "        proxy_set_header X-SecuBox-Pilotage-Relais \"\";",
         f"        proxy_set_header {ENTETE_BOX} {_q(box)};",
         f"        proxy_set_header {ENTETE_VERSION} {_q(version_page) if version_page else chr(34) * 2};",
         "        proxy_hide_header Set-Cookie;",
         "        proxy_buffering off;",
         "        proxy_read_timeout 60s;"]
    return L


# --- jeton à portée du vhost ----------------------------------------------------------------------------------------

def frapper_jeton(payload_maitre: dict, box: str, secret: str, horloge: Callable[[], float] = time.time) -> tuple:
    """Jeton de la page de `box`, tiré d'une session du maître DÉJÀ VÉRIFIÉE : même `sub`, même `jti` (la déconnexion ou la
    révocation de la session du maître le tue aussi), `exp` ≤ celle du maître et ≤ 4 h. `scope` le rend inutilisable par
    toutes les gardes du maître (`_is_scope_token`). Rend (jeton, expires_in)."""
    import jwt
    domaine(box)
    maintenant = int(horloge())
    exp = min(int(payload_maitre["exp"]), maintenant + SESSION_MAX_S)
    corps = {"sub": payload_maitre["sub"], "jti": payload_maitre["jti"], "iat": maintenant, "exp": exp, "scope": SCOPE,
             RECLAMATION: box}
    return jwt.encode(corps, secret, algorithm="HS256"), max(0, exp - maintenant)


def lire_jeton(jeton: str, box: str, secret: str) -> Optional[dict]:
    """Signature, échéance, portée et box ; None sinon. La session (`jti`) et le rôle sont vérifiés par l'appelant."""
    import jwt
    try:
        p = jwt.decode(jeton, secret, algorithms=["HS256"], options={"require": ["exp", "sub", "jti"]})
    except Exception:  # noqa: BLE001 — tout échec de décodage : pas de session
        return None
    if p.get("scope") != SCOPE or p.get(RECLAMATION) != box or not isinstance(p.get("sub"), str):
        return None
    return p


class Debit:
    """Fenêtre glissante d'une minute par clé (administrateur, box)."""

    def __init__(self, par_minute: int = DEBIT_PAR_MINUTE, horloge: Callable[[], float] = time.monotonic) -> None:
        self.par_minute, self.horloge = par_minute, horloge
        self._vus: dict = {}

    def autoriser(self, cle) -> bool:
        t = self.horloge()
        q = [x for x in self._vus.get(cle, ()) if t - x < 60.0]
        if len(q) >= self.par_minute:
            self._vus[cle] = q
            return False
        q.append(t)
        self._vus[cle] = q
        if len(self._vus) > 4096:   # clés mortes
            self._vus = {k: v for k, v in self._vus.items() if v and t - v[-1] < 60.0}
        return True
