# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""secubox_unbound.listes — les listes DNS de webfilter, adblock et adult compilées en UN fichier à étiquettes (#3205).

POURQUOI. Chaque générateur posait sa propre configuration : webfilter recopiait toute sa liste dans CHAQUE vue (399 194
zones deux fois sur gk2 pour une seule dérogation), adult écrivait une dérogation par zone et par client exempté (383 980
lignes pour 5 clients), et 416 000 domaines figuraient dans deux listes. Unbound chargeait 1,9 million d'entrées (743 Mo)
quand 734 000 suffisent (387 Mo), mesuré au banc sur gk1 avec la configuration réelle de gk2, à décisions IDENTIQUES sur
145 530 questions et 27 classes de clients.

COMMENT. Une classe de clients = un bloc d'adresses qui porte une politique (`access-control`, `access-control-view`,
cible d'une dérogation). Pour chaque domaine, on calcule l'ensemble des classes qui le voient bloqué selon la sémantique
ACTUELLE d'Unbound, mesurée au banc :
  - la vue d'abord ; dans une vue `view-first`, une zone `transparent` ne tranche pas (Unbound continue vers le global) ;
  - sinon la zone globale la plus spécifique, avec sa dérogation `local-zone-override` pour ce client.
Les domaines de même ensemble partagent une étiquette ; un domaine bloqué pour toutes les classes n'en porte aucune. Une
exception sous un parent bloqué devient `access-control-tag-action … always_transparent`. Un sous-domaine n'est retiré
que si, pour chaque classe, son plus proche parent applicable donne la même réponse.

Les vues et fichiers qui ne sont pas des sources (TV d'ad-guard, dns-lan, routeur…) restent tels quels : ils ne servent
qu'au calcul. STDLIB SEULEMENT, aucun effet de bord : appelé par un service root sous AppArmor."""
from __future__ import annotations

import hashlib
import io
import ipaddress
import os
import re
import stat
import sys
import time
from collections import defaultdict
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

SOURCES_CONNUES = ("93-secubox-webfilter.conf", "95-secubox-adblock.conf", "96-secubox-adult.conf")
SORTIE = "92-secubox-listes.conf"
BLOQUANTS = {"always_nxdomain", "static", "always_refuse", "refuse", "deny", "always_null"}
TRAVERSANTS = {"transparent", "typetransparent"}       # dans une vue view-first : ne tranchent pas (banc)
# Autorisés par Unbound sans qu'aucun fichier ne le dise (acl_list_apply_cfg) : des classes comme les autres, jamais redéclarées.
DEFAUTS_UNBOUND = ("127.0.0.0/8", "::1/128", "::ffff:7f00:1/128")

_LZ = re.compile(r'local-zone:\s*"([^"]+)"\s+([a-z_]+)$')
_OV = re.compile(r'local-zone-override:\s*"([^"]+)"\s+(\S+)\s+([a-z_]+)$')
_ACV = re.compile(r'access-control-view:\s*(\S+)\s+"?([A-Za-z0-9_.-]+)"?$')
_AC = re.compile(r"access-control:\s*(\S+)\s+([a-z_]+)$")
_NAME = re.compile(r'name:\s*"?([^"\s]+)"?$')
_NOM_ZONE = re.compile(r"[a-z0-9_.-]{1,253}|\.")
# Ce qu'une SOURCE peut contenir. Toute autre directive est refusée : rien ne se perd en silence.
_PERMIS_SOURCE = ("local-zone:", "local-zone-override:", "access-control-view:", "name:", "view-first:")
_DIRECTIVE = re.compile(r"[a-z-]{1,40}")              # ce qu'un message d'erreur cite d'une ligne : jamais le reste (relecture #3205)
MAX_SOURCE = 512 * 1024 * 1024                        # 42 Mo pour webfilter sur gk2
_ACTIONS_FERMEES = ("deny", "refuse")                 # le client n'est pas servi : ses étiquettes ne servent à rien


class ErreurListes(ValueError):
    """Une source illisible ou porteuse d'une directive que le compilateur ne sait pas reprendre."""


def bloc(b: str) -> str:
    """Forme canonique d'un bloc d'adresses (« 192.168.1.3 » et « 192.168.1.3/32 » sont la même classe)."""
    return str(ipaddress.ip_network(b, strict=False))


def _nom(z: str) -> str:
    """Nom de zone canonique, PARTAGÉ (sys.intern) : le même domaine dans deux listes et deux vues n'occupe qu'une
    chaîne (mesuré : 963 Mo de pic sur la configuration de gk2 sans partage)."""
    z = z.strip().lower().rstrip(".")
    return sys.intern(z or ".")


def _parents(d: str):
    if d == ".":
        return
    p = d.split(".")
    for i in range(1, len(p)):
        yield ".".join(p[i:])
    yield "."


class Config:
    """Ce qu'Unbound charge de ces fichiers, et d'où vient chaque zone."""

    def __init__(self):
        self.zones: Dict[str, str] = {}                       # zone globale -> type (la première lue gagne, comme Unbound)
        self.zones_sources: set = set()                       # zones globales venues d'une SOURCE (les autres : contexte)
        self.ov_par_bloc: Dict[str, Dict[str, str]] = defaultdict(dict)   # bloc -> zone -> type (dérogations)
        self.ov_contexte: set = set()                         # zones dérogées par un fichier de CONTEXTE (TV) : jamais retirées
        self.vues: Dict[str, dict] = {}                       # nom -> {first, zones, fichier}
        self.acv: Dict[str, Tuple[str, str]] = {}             # bloc -> (vue, fichier)
        self.acl: Dict[str, str] = {}                         # bloc -> action d'access-control (le premier gagne, comme Unbound)
        self.allow: List[str] = []


def _directive(s: str) -> str:
    m = _DIRECTIVE.match(s)
    return m.group(0) if m else "?"


def _ouvrir_source(f: Path):
    """Une source est lue SANS suivre de lien, doit être un fichier ordinaire du compte qui compile, et plafonnée : un lien
    vers /etc/shadow ne devient ni une « source » ni un message d'erreur (relecture #3205)."""
    try:
        fd = os.open(f, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError as e:
        raise ErreurListes(f"{f.name} : illisible ou lien symbolique ({e.strerror})") from None
    st = os.fstat(fd)
    if not stat.S_ISREG(st.st_mode) or st.st_uid != os.geteuid() or st.st_size > MAX_SOURCE:
        os.close(fd)
        raise ErreurListes(f"{f.name} : pas un fichier ordinaire du service, ou trop gros")
    return os.fdopen(fd, encoding="utf-8", errors="replace")


def _bloc_lu(b: str, ou: str) -> str:
    try:
        return bloc(b)
    except ValueError:
        raise ErreurListes(f"{ou} : bloc d'adresses invalide") from None


def lire(fichiers: Iterable[Path], sources: Iterable[str] = SOURCES_CONNUES) -> Config:
    """Lit les fichiers EN FLUX (les listes pèsent ~40 Mo chacune). Les fichiers dont le nom est une source sont
    contrôlés : une directive hors de `_PERMIS_SOURCE` lève ErreurListes."""
    cfg, sources = Config(), set(sources)
    for f in sorted(fichiers, key=lambda p: Path(p).name):
        f = Path(f)
        est_source = f.name in sources
        section, vue = None, None
        with (_ouvrir_source(f) if est_source else f.open(encoding="utf-8", errors="replace")) as fh:
            for n, ligne in enumerate(fh, 1):
                s = ligne.strip()
                if not s or s.startswith("#"):
                    continue
                ou = f"{f.name}:{n}"
                if not ligne[:1].isspace() and s.endswith(":") and re.fullmatch(r"[a-z-]+:", s):
                    section, vue = s[:-1], None
                    if est_source and section not in ("server", "view"):
                        raise ErreurListes(f"{ou} : section « {_directive(section)} » non reprise par le compilateur")
                    continue
                if est_source and not s.startswith(_PERMIS_SOURCE):
                    raise ErreurListes(f"{ou} : directive non reprise par le compilateur : {_directive(s)}")
                reconnue = True
                if section == "view":
                    m = _NAME.match(s)
                    if m and vue is None:
                        vue = m.group(1)
                        cfg.vues[vue] = {"first": False, "zones": {}, "fichier": f.name}
                    elif s.startswith("view-first:") and vue:
                        cfg.vues[vue]["first"] = s.split(":", 1)[1].strip() == "yes"
                    elif (m := _LZ.match(s)) and vue:
                        cfg.vues[vue]["zones"].setdefault(_nom(m.group(1)), sys.intern(m.group(2)))
                    else:
                        reconnue = False
                elif section != "server":
                    reconnue = False
                elif (m := _OV.match(s)):
                    z = _nom(m.group(1))
                    cfg.ov_par_bloc[sys.intern(_bloc_lu(m.group(2), ou))][z] = sys.intern(m.group(3))
                    if not est_source:
                        cfg.ov_contexte.add(z)
                elif (m := _LZ.match(s)):
                    z = _nom(m.group(1))
                    if z not in cfg.zones:
                        cfg.zones[z] = sys.intern(m.group(2))
                        if est_source:
                            cfg.zones_sources.add(z)
                elif (m := _ACV.match(s)):
                    cfg.acv[_bloc_lu(m.group(1), ou)] = (m.group(2), f.name)
                elif (m := _AC.match(s)):
                    b = _bloc_lu(m.group(1), ou)
                    cfg.acl.setdefault(b, m.group(2))
                    if m.group(2) == "allow" and b not in cfg.allow:
                        cfg.allow.append(b)
                else:
                    reconnue = False
                if est_source and not reconnue:                 # préfixe permis, forme inattendue : jamais ignorée en silence
                    raise ErreurListes(f"{ou} : ligne non reconnue ({_directive(s)})")
    return cfg


# Ce que `lire` retient d'un fichier : un CONTEXTE qui ne change qu'ailleurs (local-data, interface:) ne change aucune décision.
_DECISIFS = ("local-zone:", "local-zone-override:", "access-control:", "access-control-view:", "name:", "view-first:")


def empreinte(fichiers: Iterable[Path]) -> str:
    """Empreinte de ce que le compilateur lit des fichiers de CONTEXTE (sections, vues, zones, dérogations, access-control),
    fichier par fichier dans l'ordre de lecture : 60-secubox-noms change plusieurs fois par jour (local-data) sans qu'il
    faille relancer deux minutes de compilation, mais une vue TV ou un réseau nouveau impose de recompiler (ses adresses ne
    porteraient aucune étiquette)."""
    h = hashlib.sha256()
    for f in sorted(fichiers, key=lambda p: Path(p).name):
        f = Path(f)
        fichier_vu, section, section_vue = False, "", False
        with f.open(encoding="utf-8", errors="replace") as fh:
            for ligne in fh:
                s = ligne.strip()
                if not ligne[:1].isspace() and re.fullmatch(r"[a-z-]+:", s):
                    section, section_vue = s, False
                    continue
                if not s.startswith(_DECISIFS):
                    continue
                if not fichier_vu:                     # un fichier sans ligne décisive (que des local-data) ne compte pas
                    h.update(b"\0F" + f.name.encode())
                    fichier_vu = True
                if not section_vue:
                    h.update(b"\0S" + section.encode())
                    section_vue = True
                h.update(b"\n" + " ".join(s.split()).encode())
    return h.hexdigest()


def _contient(petit: ipaddress._BaseNetwork, grand: ipaddress._BaseNetwork) -> bool:
    return petit.version == grand.version and petit.subnet_of(grand)


def _plus_specifique(net, candidats: Iterable[str]) -> Optional[str]:
    best = None
    for b in candidats:
        n = ipaddress.ip_network(b)
        if _contient(net, n) and (best is None or n.prefixlen > best[1].prefixlen):
            best = (b, n)
    return best[0] if best else None


class _Modele:
    """Décisions ACTUELLES d'Unbound pour une configuration, par classe de clients."""

    def __init__(self, cfg: Config, vues_gardees: set):
        self.cfg, self.vues_gardees = cfg, vues_gardees
        self.ov_par_bloc = cfg.ov_par_bloc
        self.noeuds = {*cfg.acl, *cfg.acv, *DEFAUTS_UNBOUND}            # éléments d'ACL de l'ANCIENNE configuration

    def noeud(self, net) -> Optional[str]:
        """L'élément d'ACL d'un client : le PLUS PRÉCIS de tous (access-control, vue). Unbound ne fait rien hériter d'un
        bloc plus large : ni sa vue, ni ses étiquettes (relecture #3205)."""
        return _plus_specifique(net, self.noeuds)

    def action(self, noeud: Optional[str]) -> Optional[str]:
        """Action d'accès de l'élément ; un élément créé par une vue (ou un défaut d'Unbound) est « allow » ; None : refusé."""
        if noeud is None:
            return None
        return self.cfg.acl.get(noeud, "allow")

    def profil(self, net) -> Tuple[Optional[str], Tuple[str, ...]]:
        """(vue, blocs de dérogation qui contiennent ce client, du plus spécifique au plus large)."""
        vb = self.noeud(net)
        vue = self.cfg.acv[vb][0] if vb in self.cfg.acv else None
        blocs = [b for b in self.ov_par_bloc if _contient(net, ipaddress.ip_network(b))]
        blocs.sort(key=lambda b: -ipaddress.ip_network(b).prefixlen)
        return vue, tuple(blocs)

    def _zone_globale(self, q: str) -> Optional[str]:
        if q in self.cfg.zones:
            return q
        for p in _parents(q):
            if p in self.cfg.zones:
                return p
        return None

    def decision(self, q: str, profil, global_seul: bool = False) -> bool:
        vue, blocs = profil
        if vue and not global_seul and vue in self.cfg.vues:
            v = self.cfg.vues[vue]
            zv = q if q in v["zones"] else next((p for p in _parents(q) if p in v["zones"]), None)
            if zv is not None and not (v["first"] and v["zones"][zv] in TRAVERSANTS):
                return v["zones"][zv] in BLOQUANTS
            if zv is None and not v["first"]:
                return False
        z = self._zone_globale(q)
        if z is None:
            return False
        for b in blocs:
            t = self.ov_par_bloc[b].get(z)
            if t is not None:
                return t in BLOQUANTS
        return self.cfg.zones[z] in BLOQUANTS


def decision_ancienne(cfg: Config, q: str, ip: str) -> bool:
    """Décision d'Unbound sur la configuration `cfg` telle quelle, pour un client (tests, banc)."""
    return _Modele(cfg, set()).decision(_nom(q), _Modele(cfg, set()).profil(ipaddress.ip_network(ip)))


def compiler(sources: Iterable[Path], contexte: Iterable[Path]) -> Tuple[str, dict]:
    """(texte de 92-secubox-listes.conf, statistiques). `sources` : les fichiers des générateurs ; `contexte` : les AUTRES
    fichiers de unbound.conf.d (lus pour le calcul, jamais réécrits). Lève ErreurListes sur une source illisible."""
    debut = time.monotonic()
    sources, contexte = [Path(p) for p in sources], [Path(p) for p in contexte]
    noms_sources = {p.name for p in sources}
    cfg = lire(sources + [p for p in contexte if p.name not in noms_sources], sources=noms_sources)
    vues_gardees = {v for v, d in cfg.vues.items() if d["fichier"] not in noms_sources}
    m = _Modele(cfg, vues_gardees)

    classes = sorted({*cfg.acl, *cfg.acv, *cfg.ov_par_bloc, *DEFAUTS_UNBOUND},
                     key=lambda b: (ipaddress.ip_network(b).version, ipaddress.ip_network(b).prefixlen, b))
    idx = {c: i for i, c in enumerate(classes)}
    toutes = (1 << len(classes)) - 1
    # Les classes de même profil (même vue, mêmes dérogations, même portée de vue) décident pareil : un calcul par profil.
    profils: Dict[tuple, int] = defaultdict(int)
    for c in classes:
        vue, blocs = m.profil(ipaddress.ip_network(c))
        profils[(vue, blocs, vue in vues_gardees)] |= 1 << idx[c]

    avant = (len(cfg.zones_sources) + sum(len(d["zones"]) for v, d in cfg.vues.items() if v not in vues_gardees)
             + sum(1 for b, zs in cfg.ov_par_bloc.items() for z in zs if z not in cfg.ov_contexte))
    exclus = (set(cfg.zones) - cfg.zones_sources) | {z for v in vues_gardees for z in cfg.vues[v]["zones"]} | {"."}
    references = cfg.ov_contexte

    def candidats():
        vus = set()
        for z in cfg.zones_sources:
            if z not in exclus:
                vus.add(z)
                yield z
        for v, d in cfg.vues.items():
            if v not in vues_gardees:
                for z in d["zones"]:
                    if z not in exclus and z not in vus:
                        vus.add(z)
                        yield z

    # S : classes qui voient chaque domaine bloqué ; X (rare) : classes à rendre transparentes sous un parent bloqué.
    S: Dict[str, int] = {}
    for d in candidats():
        s = 0
        for (vue, blocs, garde), masque in profils.items():
            if m.decision(d, (vue, blocs), global_seul=garde):
                s |= masque
        S[d] = s
    X: Dict[str, int] = {}
    for d, sd in S.items():
        nonb = toutes & ~sd
        if nonb:
            x = 0
            for a in _parents(d):
                sa = S.get(a)
                if sa:
                    x |= nonb & sa
            if x:
                X[d] = x

    elagues = set()
    for d, sd in S.items():
        if not sd or d in X or d in references:
            continue
        reste = sd
        for a in _parents(d):
            if not reste:
                break
            if a in S:
                touche = reste & (S[a] | X.get(a, 0))
                if touche & ~S[a]:
                    reste = -1                                 # le plus proche parent applicable répondrait autrement
                    break
                reste &= ~touche
        if reste == 0:
            elagues.add(d)

    nb_candidats, nb_elagues, nb_exceptions = len(S), len(elagues), len(X)
    emis = sorted(d for d, sd in S.items() if d not in elagues and (sd or d in X or d in references))
    del elagues
    groupes: Dict[Tuple[int, int], str] = {}
    etiquette: Dict[str, str] = {}
    for d in emis:
        cle = (S[d], X.get(d, 0))
        if cle == (toutes, 0):
            continue
        if cle not in groupes:
            groupes[cle] = f"sbx{len(groupes)}"
        etiquette[d] = groupes[cle]

    # Éléments d'ACL du 92. Une classe qui existe déjà dans la nouvelle configuration (access-control du contexte, vue du
    # contexte, défaut d'Unbound) n'est pas redéclarée. Une classe NOUVELLE (vue d'une source compilée, cible d'une
    # dérogation) reprend l'ACTION et la VUE GARDÉE de l'élément qui la couvrait : rien n'est ouvert qui ne l'était pas, et
    # un exempté sous une vue TV garde sa vue. Sans élément couvrant, la classe était refusée : aucun élément n'est créé.
    acl_rendu: Dict[str, Tuple[Optional[str], Optional[str]]] = {}            # classe -> (action à déclarer, vue à déclarer)
    sans_element = set()
    for c in classes:
        n = m.noeud(ipaddress.ip_network(c))
        action = m.action(n)
        if action is None or action in _ACTIONS_FERMEES:
            sans_element.add(c)                       # refusé avant, refusé après : ni élément nouveau, ni étiquettes
            continue
        if c in cfg.acl or c in DEFAUTS_UNBOUND or (c in cfg.acv and cfg.acv[c][1] not in noms_sources):
            continue                                  # existe déjà dans la nouvelle configuration
        vue = cfg.acv[n][0] if n in cfg.acv and cfg.acv[n][0] in vues_gardees else None
        acl_rendu[c] = (action, vue)
    for grand in (cfg.zones, cfg.vues, cfg.ov_par_bloc, cfg.zones_sources):   # libéré avant le rendu (pic mesuré sur gk2)
        grand.clear()
    sortie = io.StringIO()                       # pas de liste d'1,5 million de lignes : un seul tampon
    sortie.write("# SPDX-License-Identifier: LicenseRef-CMSD-1.0\n"
                 "# GÉNÉRÉ par secubox-dns-listes — ne pas éditer : les sources sont dans /var/lib/secubox-dns-listes/sources (#3205).\n"
                 "server:\n")
    if groupes:
        sortie.write('    define-tag: "' + " ".join(groupes.values()) + '"\n')
    for c, (action, vue) in acl_rendu.items():
        sortie.write(f"    access-control: {c} {action}\n")
        if vue:
            sortie.write(f"    access-control-view: {c} {vue}\n")
    for c in classes:
        if c in sans_element:
            continue
        i = idx[c]
        tags = [t for (s, x), t in groupes.items() if ((s | x) >> i) & 1]
        if tags:
            sortie.write(f'    access-control-tag: {c} "' + " ".join(tags) + '"\n')
        for (s, x), t in groupes.items():
            if (x >> i) & 1:
                sortie.write(f"    access-control-tag-action: {c} {t} always_transparent\n")
    for d in emis:
        if not _NOM_ZONE.fullmatch(d):
            raise ErreurListes(f"nom de zone inattendu : {d!r}")
        sortie.write(f'    local-zone: "{d}." always_nxdomain\n')
        if d in etiquette:
            sortie.write(f'    local-zone-tag: "{d}." "{etiquette[d]}"\n')
    stats = {"sources": sorted(noms_sources), "classes": len(classes), "profils": len(profils),
             "zones_chargees_avant": avant, "candidats": nb_candidats, "elagues": nb_elagues, "emis": len(emis),
             "etiquettes": len(groupes), "exceptions": nb_exceptions, "duree_s": round(time.monotonic() - debut, 1)}
    return sortie.getvalue(), stats
