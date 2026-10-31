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
  /pilotage-connexion/   page statique du paquet (aucun champ d'identifiants) : reçoit en fragment un CODE à usage unique émis
                    par l'administration du MAÎTRE (où l'administrateur s'est authentifié, 2FA comprise) et l'échange
  /api/v1/auth/echanger  code (≤ 60 s, lié à la box, à l'administrateur et à sa session) → jeton À PORTÉE du vhost (clé dérivée,
                    `aud = admin.<box>`, `iss` propre), refusé par toutes les gardes du maître (R-L5-25 C1c, M7)
  /api/v1/<module>/ → /run/secubox/pilotage.sock `/relais/<box>/api/v1/<module>/…`, avec `X-SecuBox-Version-Page:
                    <paquet>=<version>` posé par nginx (409 si la box a changé de version depuis)

Ce module est PUR (aucune E/S hors `ecrire_plan`) : il est importé par le service et par le ctl root
`secubox-pilotage-vhost`, qui rend le gabarit nginx.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
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
EMETTEUR = "secubox-pilotage-vhost"
CODE_TTL_S = 60
CODES_MAX = 1024
RACINE_CONNEXION = "/usr/share/secubox/pilotage/vhost-www/pilotage-connexion/"
RE_RETOUR = re.compile(r"/[a-z0-9][a-z0-9_-]{0,63}/")
CSP_API = "sandbox; default-src 'none'"
SESSION_MAX_S = 4 * 3600              # le jeton à portée vit au plus 4 h (et jamais plus que la session du maître)
CORPS_MAX = 4 << 20                   # comme le relais et le canal (R-L5-19)
DEBIT_PAR_MINUTE = 300                # requêtes relayées par (administrateur, box) et par minute



def csp_pages(box: str, modules: Iterable[str]) -> str:
    """CSP des pages (R-L5-25 C1b) : scripts et styles limités aux chemins des pages servies (`/<module>/`, `/pilotage-connexion/`),
    jamais `/api/` (une réponse de la box ne peut pas devenir un script de cette origine)."""
    base = f"https://{domaine(box)}"
    srcs = " ".join(f"{base}/{m}/" for m in [*sorted(modules), "pilotage-connexion"])
    return (f"default-src 'none'; script-src {srcs}; style-src {srcs}; img-src 'self' data:; font-src 'self'; connect-src 'self'; "
            "manifest-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")


RE_EMPREINTE = re.compile(r"'sha256-[A-Za-z0-9+/]{43}='")
RE_SCRIPT_INTEGRE = re.compile(r"<script(?![^>]*\bsrc\s*=)[^>]*>(.*?)</script\s*>", re.S | re.I)


def empreintes_scripts(html: str) -> list:
    """#3302 : empreintes CSP des scripts intégrés (sans `src`) d'une page, telles que le navigateur les calcule (contenu exact)."""
    import base64
    import hashlib
    return sorted({"'sha256-" + base64.b64encode(hashlib.sha256(c.encode("utf-8")).digest()).decode() + "'"
                   for c in RE_SCRIPT_INTEGRE.findall(html)})


def csp_module(box: str, chemins: Iterable[str], empreintes: Iterable[str]) -> str:
    """#3302 (banc gk4) : CSP d'UNE page : scripts de son chemin, de /shared/ et de /luci-static/, plus les seuls scripts intégrés
    dont l'empreinte a été calculée à l'extraction (jamais 'unsafe-inline' pour les scripts, jamais /api/) ; styles intégrés
    permis (attributs style= des pages portées)."""
    base = f"https://{domaine(box)}"
    emp = sorted(e for e in empreintes if RE_EMPREINTE.fullmatch(e))
    srcs = " ".join(f"{base}{c}" for c in [*chemins, "/shared/", "/luci-static/"])
    return (f"default-src 'none'; script-src {' '.join([srcs, *emp])}; style-src {srcs} 'unsafe-inline'; img-src 'self' data:; "
            "font-src 'self'; connect-src 'self'; manifest-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")


def _entetes_page(csp: str) -> list:
    """add_header dans une location annule l'héritage du server : tout le jeu est reposé."""
    return [f'        add_header Content-Security-Policy "{csp}" always;',
            '        add_header X-Content-Type-Options "nosniff" always;',
            '        add_header X-Frame-Options "DENY" always;',
            '        add_header Referrer-Policy "no-referrer" always;',
            '        add_header Cache-Control "no-store" always;']


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


# Ressources statiques que plusieurs paquets livrent chacun en partie (jamais une page de module : pas d'API relayée).
PARTAGES = frozenset({"luci-static"})


CSP_MORCEAU = 2000   # nginx refuse un paramètre de plus de 4 Ko (« too long parameter ») : la CSP est découpée en variables


def _csp_nginx(csp: str) -> list:
    """`set $sbx_csp_N "…";` (morceaux coupés sur une espace) puis `add_header` qui les réassemble : même politique (#3302)."""
    if len(csp) <= CSP_MORCEAU:
        return [f'    add_header Content-Security-Policy "{csp}" always;']
    morceaux, reste = [], csp
    while len(reste) > CSP_MORCEAU:
        i = reste.rfind(" ", 0, CSP_MORCEAU)
        i = CSP_MORCEAU if i <= 0 else i
        morceaux.append(reste[:i])
        reste = reste[i:]
    morceaux.append(reste)
    L = [f'    set $sbx_csp_{i} "{m}";' for i, m in enumerate(morceaux)]
    return L + ['    add_header Content-Security-Policy "' + "".join(f"$sbx_csp_{i}" for i in range(len(morceaux))) + '" always;']


def rendre_nginx(box: str, pages: list, racine: str = RACINE_PAGES, socket: str = SOCKET) -> str:
    """`pages` : [{"paquet", "version", "modules": [module…]}]. Un module servi par deux paquets est refusé (ValueError)."""
    dom = domaine(box)
    vus: dict = {}
    partages: dict = {}
    for p in pages:
        if not (RE_PAQUET.fullmatch(p["paquet"]) and RE_VERSION.fullmatch(p["version"])):
            raise ValueError("paquet ou version invalide")
        for m in p["modules"]:
            if not RE_MODULE.fullmatch(m) or m in ("api", "auth"):
                raise ValueError(f"module invalide : {m}")
            if m in PARTAGES:
                partages.setdefault(m, []).append(p)
                continue
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
        *_csp_nginx(csp_pages(box, [*vus, *partages])),
        "    add_header X-Content-Type-Options \"nosniff\" always;",
        "    add_header X-Frame-Options \"DENY\" always;",
        "    add_header Referrer-Policy \"no-referrer\" always;",
        "    add_header Cache-Control \"no-store\" always;",
        "",
        "    # Fichiers et dossiers en point (manifestes .<version>.json, .vu.json, résidus .tmp-/.old-) : jamais servis.",
        "    location ~ /\\. { return 404; }",
        "",
        "    # Connexion : AUCUNE saisie d'identifiants ici ; un code émis par l'administration du maître est échangé (R-L5-25 C1c).",
        "    location ^~ /pilotage-connexion/ {",
        f"        alias {RACINE_CONNEXION};",
        "        index index.html;",
        "        location ~ /\\. { return 404; }",
        "    }",
        "    location = /api/v1/auth/echanger {",
        f"        proxy_pass http://unix:{socket}:/vhost/auth/echanger;",
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
              *_entetes_page(csp_module(box, [f"/{m}/"], (p.get("empreintes") or {}).get(m, []))),
              # « ^~ » coupe la recherche des regex du serveur : la garde des fichiers en point est répétée ici
              "        location ~ /\\. { return 404; }",
              "    }"]
    for m in sorted(partages):
        # ressources statiques livrées en parties par plusieurs paquets (#3302) : composées par try_files en chaîne, dans
        # l'ordre des noms de paquets ; aucune route d'API. `root` (et non `alias`) : l'URI /<m>/… est le chemin sous la version.
        chaine = sorted(partages[m], key=lambda p: (p["paquet"], p["version"]))
        for i, p in enumerate(chaine):
            suite = f"@{m}-{i + 1}" if i + 1 < len(chaine) else "=404"
            tete = f"    location ^~ /{m}/ {{" if i == 0 else f"    location @{m}-{i} {{"
            L += [tete, f"        root {racine}/{p['paquet']}/{p['version']};", f"        try_files $uri {suite};"]
            if i == 0:
                L += ["        location ~ /\\. { return 404; }"]
            L += ["    }"]
    accueil = [p for p in pages if p.get("accueil")]
    if accueil:
        # page d'accueil (index.html à la racine du paquet hub) et pages .html de premier niveau du même paquet (#3302)
        p = accueil[0]
        emp = (p.get("empreintes") or {}).get("", [])
        L += ["    location = / {", f"        root {racine}/{p['paquet']}/{p['version']};", "        try_files /index.html =404;",
              *_entetes_page(csp_module(box, ["/"], emp)), "    }",
              "    location ~ ^/[a-z0-9][a-z0-9_-]{0,63}\\.html$ {", f"        root {racine}/{p['paquet']}/{p['version']};",
              "        try_files $uri =404;", *_entetes_page(csp_module(box, ["/"], emp)), "    }"]
    L += ["", "    location ^~ /api/ { return 404; }",
          "    location / { return 404; }",
          "}", ""]
    return "\n".join(L)


def _entetes_proxy(box: str, version_page: Optional[str]) -> list:
    """Pas le snippet secubox-proxy.conf : il ajoute `Access-Control-Allow-Origin *`. En-têtes du client effacés : cookie (le
    maître n'en lit aucun ici), marques X-SecuBox-* (LAN, relais, tunnel), puis les nôtres posés."""
    L = ["        proxy_http_version 1.1;",
         "        proxy_set_header Host $host;",
         "        proxy_set_header X-Real-IP $remote_addr;",
         "        proxy_set_header X-Forwarded-For $remote_addr;",   # I3 : jamais la chaîne fournie par le client
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
         # M3 (R-L5-26) : Content-Disposition N'EST PAS masqué : le contrôleur pose « attachment » sur toute réponse non JSON
         # (celui de la box est déjà filtré par lui)
         # C1a : sous /api/, rien n'est jamais exécutable ni affichable comme document de cette origine
         f"        add_header Content-Security-Policy \"{CSP_API}\" always;",
         "        add_header X-Content-Type-Options \"nosniff\" always;",
         "        add_header X-Frame-Options \"DENY\" always;",
         "        add_header Referrer-Policy \"no-referrer\" always;",
         "        add_header Cache-Control \"no-store\" always;",
         "        proxy_buffering off;",
         "        proxy_read_timeout 60s;"]
    return L


# --- jeton à portée du vhost ----------------------------------------------------------------------------------------

def cle_vhost(secret: str) -> str:
    """Clé PROPRE aux jetons des vhosts (M7), dérivée de la clé du maître : un jeton du vhost n'est jamais une signature valide pour
    les gardes du maître, et inversement."""
    return hmac.new(secret.encode("utf-8"), b"secubox-pilotage/vhost/v1", hashlib.sha256).hexdigest()


def frapper_jeton(payload_maitre: dict, box: str, secret: str, horloge: Callable[[], float] = time.time) -> tuple:
    """Jeton de la page de `box`, tiré d'une session du maître DÉJÀ VÉRIFIÉE : même `sub`, même `jti` (la déconnexion ou la
    révocation de la session du maître le tue aussi), `exp` ≤ celle du maître et ≤ 4 h ; clé dérivée, `aud = admin.<box>`,
    `iss` propre, `scope` en plus. Rend (jeton, expires_in)."""
    import jwt
    dom = domaine(box)
    maintenant = int(horloge())
    exp = min(int(payload_maitre["exp"]), maintenant + SESSION_MAX_S)
    corps = {"sub": payload_maitre["sub"], "jti": payload_maitre["jti"], "iat": maintenant, "exp": exp, "scope": SCOPE,
             RECLAMATION: box, "aud": dom, "iss": EMETTEUR}
    return jwt.encode(corps, cle_vhost(secret), algorithm="HS256"), max(0, exp - maintenant)


def lire_jeton(jeton: str, box: str, secret: str) -> Optional[dict]:
    """Signature (clé dérivée), échéance, audience, émetteur, portée et box ; None sinon. La session (`jti`) et le rôle sont
    vérifiés par l'appelant."""
    import jwt
    try:
        p = jwt.decode(jeton, cle_vhost(secret), algorithms=["HS256"], audience=domaine(box), issuer=EMETTEUR,
                       options={"require": ["exp", "sub", "jti", "aud", "iss"]})
    except Exception:  # noqa: BLE001 — tout échec de décodage : pas de session
        return None
    if p.get("scope") != SCOPE or p.get(RECLAMATION) != box or not isinstance(p.get("sub"), str):
        return None
    return p


class Codes:
    """Codes à usage unique de connexion au vhost (R-L5-25 C1c), en mémoire du contrôleur : ≤ 60 s, liés à la box, à
    l'administrateur et à sa session (`jti`), consommés à la PREMIÈRE présentation (même refusée)."""

    def __init__(self, horloge: Callable[[], float] = time.time, ttl_s: float = CODE_TTL_S) -> None:
        self.horloge, self.ttl_s = horloge, ttl_s
        self._codes: dict = {}

    def emettre(self, box: str, session: dict) -> str:
        t = self.horloge()
        self._codes = {k: v for k, v in self._codes.items() if t - v["cree"] < self.ttl_s}
        if len(self._codes) >= CODES_MAX:
            raise OverflowError("trop de codes en attente")
        code = secrets.token_urlsafe(32)
        self._codes[code] = {"box": box, "sub": session["sub"], "jti": session["jti"], "exp": session["exp"], "cree": t}
        return code

    def consommer(self, code, box: str) -> Optional[dict]:
        e = self._codes.pop(code, None) if isinstance(code, str) else None
        if e is None or e["box"] != box or self.horloge() - e["cree"] >= self.ttl_s:
            return None
        return e


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
