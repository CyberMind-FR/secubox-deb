#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""SecuBox-Deb :: Metrics — statistiques par vhost

Ce que les gens font sur chaque vhost : visites, visiteurs, navigateurs — et
accessoirement les sondes qui viennent taper aux portes qui n'existent pas.

Nginx tient deja un journal par vhost (`/var/log/nginx/<nom>_access.log`), on
n'ajoute donc aucune collecte : on lit ce qui est ecrit de toute facon.

Deux regimes de lecture, parce qu'ils repondent a deux besoins opposes :

  - le suivi courant est *incremental* — on ne relit que ce qui s'est ajoute
    depuis le passage precedent, en suivant l'inode pour voir les rotations.
    Un rescan complet couterait 50 Mo toutes les deux minutes, ce qui est
    exactement le gaspillage qui a fait monter la charge de cette boite ;

  - le rafraichissement d'un vhost est *complet* — il relit ses journaux
    tournes, gzip compris, et rebatit son historique. C'est cher, donc c'est
    a la demande et pour un seul vhost a la fois.

Les compteurs sont ranges par jour, ce qui permet de repondre sur une journee
comme sur un mois sans garder chaque requete.
"""

import asyncio
import gzip
import json
import ipaddress
import os
import re
from collections import Counter, defaultdict
from datetime import date, datetime, timedelta
from pathlib import Path
from typing import Iterable, Optional

REP_LOGS = Path("/var/log/nginx")
CACHE = Path("/var/cache/secubox/metrics/vhost_stats.json")
SUFFIXE = "_access.log"

RETENTION = 30          # jours conserves
PLAFOND_IP = 20000      # IP distinctes memorisees par vhost et par jour

# Deux garde-fous contre la famine de la boucle. Le parsing est du Python pur :
# meme lance dans un thread il garde le GIL, et un gros volume affame la boucle
# asyncio — dans un groupe, cela veut dire les 82 modules qui la partagent.
#
#   AMORCE  : a la premiere rencontre d'un journal, on ne remonte pas a son
#             debut. Relire 22 Mo d'historique au demarrage bloquait tout ;
#             l'historique se recupere a la demande, par vhost.
#   PLAFOND : volume maximal traite par passage, tous journaux confondus. Le
#             reste attend le tour suivant plutot que de monopoliser le GIL.
AMORCE = 512 * 1024
PLAFOND_CYCLE = 4 * 1024 * 1024

PERIODES = {"jour": 1, "semaine": 7, "mois": 30}

# Journal commun porte par le domaine demande (format `sbx_host`, pose par
# secubox-metrics dans /etc/nginx/conf.d/). Quand il existe on ne lit que lui :
# c'est le SEUL qui permette de distinguer des domaines servis par un meme
# bloc server — « anibal-amiot.com », « .fr » et « .net » ecrivent sinon dans
# un unique fichier nomme d'apres le site, et rien ne les separe.
JOURNAL_HOTES = REP_LOGS / "secubox-hosts.log"

# Meme format que « combined », precede du domaine.
LIGNE_HOTE = re.compile(
    r'^(?P<hote>[A-Za-z0-9._:-]+) '
    r'(?P<ip>\S+) \S+ \S+ \[(?P<date>[^\]]+)\] '
    r'"(?P<methode>[A-Z]+) (?P<chemin>[^" ]*)[^"]*" '
    r'(?P<statut>\d{3}) (?P<octets>\d+|-) '
    r'"(?P<ref>[^"]*)" "(?P<ua>[^"]*)"'
)

# Format « combined » : IP - - [date] "METHODE chemin PROTO" statut octets "ref" "UA"
LIGNE = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<date>[^\]]+)\] '
    r'"(?P<methode>[A-Z]+) (?P<chemin>[^" ]*)[^"]*" '
    r'(?P<statut>\d{3}) (?P<octets>\d+|-) '
    r'"(?P<ref>[^"]*)" "(?P<ua>[^"]*)"'
)

# Chemins que personne de legitime ne demande : leur presence signe un scan.
SONDES = re.compile(
    r'(wp-admin|wp-login|wp-content|xmlrpc\.php|phpmyadmin|/\.env|/\.git|'
    r'/\.aws|/\.ssh|/vendor/|/cgi-bin/|\.php$|/actuator|/solr/|/boaform|'
    r'/HNAP1|/shell|eval\(|/config\.json|/backup|\.sql$)',
    re.IGNORECASE,
)

# L'ordre compte : Edge se declare Chrome, Chrome se declare Safari.
NAVIGATEURS = [
    ("Robot", re.compile(r'bot|crawl|spider|slurp|curl|wget|python-|go-http|'
                         r'okhttp|libwww|scrapy|headless|monitoring', re.I)),
    ("Edge", re.compile(r'Edg[e/]', re.I)),
    ("Opera", re.compile(r'OPR/|Opera', re.I)),
    ("Firefox", re.compile(r'Firefox/', re.I)),
    ("Chrome", re.compile(r'Chrome/|Chromium/', re.I)),
    ("Safari", re.compile(r'Safari/', re.I)),
]

PLATEFORMES = [
    ("Android", re.compile(r'Android', re.I)),
    ("iOS", re.compile(r'iPhone|iPad|iPod', re.I)),
    ("Windows", re.compile(r'Windows NT', re.I)),
    ("macOS", re.compile(r'Macintosh|Mac OS X', re.I)),
    ("Linux", re.compile(r'Linux|X11', re.I)),
]

# Un visiteur qui charge une page tire 40 fichiers derriere lui ; les compter
# comme des visites gonflerait les chiffres d'un facteur 40.
ACCESSOIRE = re.compile(
    r'\.(css|js|mjs|png|jpe?g|gif|svg|webp|avif|ico|woff2?|ttf|eot|map|'
    r'mp4|webm|m4s|ts|vtt)(\?|$)', re.I
)

# strptime lirait « Aug » selon la locale du processus ; une table ne ment pas.
MOIS = {m: i for i, m in enumerate(
    "Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split(), 1)}


# Suffixes publics a deux etiquettes. Sans eux, « exemple.co.uk » serait
# reduit a « exemple.co » et ne rejoindrait pas « exemple.fr ».
SUFFIXES_DOUBLES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "com.au", "net.au",
    "org.au", "co.nz", "co.jp", "com.br", "com.mx", "com.ar", "co.za",
    "com.tr", "co.in", "com.cn", "com.sg", "com.pl",
}


def famille(vhost: str) -> str:
    """Le domaine prive du suffixe public.

    La regle est volontairement etroite : seuls fusionnent les domaines qui ne
    different QUE par l'extension — « anibal-amiot.com », « .fr » et « .net »
    deviennent « anibal-amiot ». En revanche « apt.secubox.in » et
    « gitea.gk2.secubox.in » restent distincts, alors qu'une regle plus large
    les aurait tous ecrases sous « secubox ».
    """
    nom = vhost.lower().removeprefix("www.")
    parts = nom.split(".")
    if len(parts) >= 3 and ".".join(parts[-2:]) in SUFFIXES_DOUBLES:
        parts = parts[:-2]
    elif len(parts) >= 2:
        parts = parts[:-1]
    return ".".join(parts) or nom


def _classe(ua: str, table) -> str:
    for nom, motif in table:
        if motif.search(ua):
            return nom
    return "Autre"


def _jour_de(horodatage: str) -> Optional[str]:
    """« 17/Aug/2026:14:54:13 +0200 » -> « 2026-08-17 »."""
    try:
        j, m, reste = horodatage.split("/", 2)
        return f"{reste[:4]}-{MOIS[m]:02d}-{int(j):02d}"
    except (ValueError, KeyError, IndexError):
        return None


# ── GeoIP : pays du visiteur, avec drapeau ───────────────────────────────────
# La base GeoLite2-Country est deja sur la board (crowdsec + secubox-geoip). On
# resout le pays par IP avec un CACHE : une meme IP revient des centaines de fois
# dans un journal. Le geoip est un BONUS — une base absente ou une IP inconnue
# n'interrompt jamais le calcul des stats.
_GEOIP_MMDB = (
    "/var/lib/secubox/geoip/GeoLite2-Country.mmdb",
    "/usr/share/GeoIP/GeoLite2-Country.mmdb",
    "/var/lib/GeoIP/GeoLite2-Country.mmdb",
)
_geo_reader = None
_geo_essaye = False
_geo_cache: dict = {}


def _pays(ip: str) -> Optional[str]:
    """Code pays ISO-2 d'une IP PUBLIQUE, ou None (privee/inconnue/base absente)."""
    global _geo_reader, _geo_essaye
    if ip in _geo_cache:
        return _geo_cache[ip]
    cc = None
    try:
        adr = ipaddress.ip_address(ip)
        publique = not (adr.is_private or adr.is_loopback
                        or adr.is_link_local or adr.is_reserved or adr.is_multicast)
        if publique:
            if not _geo_essaye:
                _geo_essaye = True
                try:
                    import geoip2.database  # noqa: PLC0415
                    for chemin in _GEOIP_MMDB:
                        if os.path.exists(chemin):
                            _geo_reader = geoip2.database.Reader(chemin)
                            break
                except Exception:  # noqa: BLE001
                    _geo_reader = None
            if _geo_reader is not None:
                cc = _geo_reader.country(ip).country.iso_code
    except Exception:  # noqa: BLE001
        cc = None
    _geo_cache[ip] = cc
    return cc


def _drapeau(cc: Optional[str]) -> str:
    """Emoji drapeau depuis un code pays ISO-2 (indicateurs regionaux)."""
    if not cc or len(cc) != 2 or not cc.isalpha():
        return "\U0001F3F3"  # drapeau blanc = inconnu
    return chr(0x1F1E6 + ord(cc[0].upper()) - 65) + chr(0x1F1E6 + ord(cc[1].upper()) - 65)


def _vierge() -> dict:
    return {
        "visites": 0, "requetes": 0, "octets": 0,
        "ips": set(), "ips_debordees": False,
        "navigateurs": Counter(), "plateformes": Counter(),
        "statuts": Counter(), "chemins": Counter(), "referents": Counter(),
        "sondes": 0, "erreurs": 0, "robots": 0,
        # #1059 ② — visites de page SANS référent valide (accès direct) : le
        # complément des `referents`, pour calculer la part de trafic direct.
        "sans_ref": 0,
        "pays": Counter(),  # #geoip — visites par pays
    }


def _referents_synthese(referents: Counter, sans_ref: int, visites: int,
                        top_n: Optional[int] = None) -> dict:
    """① Référents regroupés (top des domaines référents) + ② part d'accès DIRECT.

    `directs_pct` = visites sans référent / total des visites — sur un domaine ou
    sur une famille regroupée (l'appelant passe des compteurs déjà fusionnés).
    """
    top = [{"hote": h, "n": n} for h, n in referents.most_common(top_n)]
    directs_pct = round(100.0 * sans_ref / visites, 1) if visites else 0.0
    return {"top": top, "directs_pct": directs_pct}


def _compter(s: dict, m: re.Match) -> None:
    """Impute une ligne deja reconnue dans le seau `s`."""
    g = m.groupdict()
    ua, chemin = g["ua"], g["chemin"]
    statut = int(g["statut"])

    s["requetes"] += 1
    if g["octets"].isdigit():
        s["octets"] += int(g["octets"])
    s["statuts"][f"{statut // 100}xx"] += 1

    if len(s["ips"]) < PLAFOND_IP:
        s["ips"].add(g["ip"])
    else:
        s["ips_debordees"] = True

    nav = _classe(ua, NAVIGATEURS)
    s["navigateurs"][nav] += 1
    if nav == "Robot":
        s["robots"] += 1
    else:
        s["plateformes"][_classe(ua, PLATEFORMES)] += 1

    if statut >= 400:
        s["erreurs"] += 1
    if SONDES.search(chemin):
        s["sondes"] += 1

    # Une « visite » = une vraie page, pas ses accessoires.
    if not ACCESSOIRE.search(chemin):
        s["visites"] += 1
        s["chemins"][chemin[:120]] += 1
        cc = _pays(g["ip"])  # #geoip — pays de cette visite
        if cc:
            s["pays"][cc] += 1
        ref = g["ref"]
        if ref and ref != "-" and "://" in ref:
            s["referents"][ref.split("://", 1)[1].split("/", 1)[0][:80]] += 1
        else:
            s["sans_ref"] += 1  # #1059 ② — page sans référent = accès direct


class VhostStatsAggregator:
    """Compte par vhost et par jour, en relisant le moins possible."""

    def __init__(self, cfg: Optional[dict] = None):
        cfg = cfg or {}
        self.intervalle = int(cfg.get("interval", 120))
        self.actif = bool(cfg.get("enabled", True))
        self.max_chemins = int(cfg.get("top_paths", 10))
        self.retention = int(cfg.get("retention_days", RETENTION))
        # inode+offset par fichier, pour ne relire que la queue
        self._suivi: dict[str, tuple[int, int]] = {}
        # jour -> vhost -> compteurs
        self._jours: dict[str, dict[str, dict]] = defaultdict(
            lambda: defaultdict(_vierge))
        self._maj: Optional[str] = None
        self._charger()

    # ── lecture incrementale ─────────────────────────────────────────────
    def _journaux(self) -> list[Path]:
        return sorted(REP_LOGS.glob(f"*{SUFFIXE}")) if REP_LOGS.is_dir() else []

    def _queue(self, f: Path, budget: int) -> list[str]:
        """Rend les lignes ajoutees depuis le dernier passage, dans le budget."""
        try:
            st = f.stat()
        except OSError:
            return []
        cle = str(f)
        connu = cle in self._suivi
        inode, offset = self._suivi.get(cle, (0, 0))
        # Rotation : l'inode change, ou le fichier a retreci sous notre marque.
        if st.st_ino != inode or st.st_size < offset:
            offset = 0
            connu = False
        if not connu:
            # Premiere rencontre : on se pose pres de la fin. Remonter au debut
            # d'un journal de 22 Mo bloquait la boucle plusieurs minutes.
            offset = max(0, st.st_size - AMORCE)
        if st.st_size <= offset or budget <= 0:
            return []
        # Lecture en binaire, et non en texte : le `tell()` d'un fichier texte
        # rend un jeton opaque, pas une position en octets. Reculer dessus pour
        # laisser une ligne partielle donnait une marque fausse, et la ligne
        # n'etait jamais recomptee une fois completee.
        try:
            with f.open("rb") as fh:
                fh.seek(offset)
                donnees = fh.read(budget)
        except OSError:
            return []
        fin = offset + len(donnees)
        if not connu and donnees:
            # On est tombe au milieu d'une ligne : on jette ce debut tronque
            # plutot que de compter une requete a moitie lue.
            saut = donnees.find(b"\n")
            if saut >= 0 and offset > 0:
                fin_debut = saut + 1
                offset += fin_debut
                donnees = donnees[fin_debut:]
        # Une derniere ligne encore en cours d'ecriture serait tronquee : on la
        # laisse pour le prochain tour plutot que de la compter a moitie.
        if donnees and not donnees.endswith(b"\n"):
            coupe = donnees.rfind(b"\n")
            fin -= len(donnees) - (coupe + 1)
            donnees = donnees[:coupe + 1]
        self._suivi[cle] = (st.st_ino, fin)
        return [l.decode("utf-8", "replace") for l in donnees.splitlines()]

    def collecter(self) -> None:
        if not self.actif:
            return
        budget = PLAFOND_CYCLE

        if JOURNAL_HOTES.exists():
            # Source unique : chaque ligne porte son domaine. On ne lit PAS en
            # plus les journaux par site, sans quoi tout serait compte deux
            # fois — une fois sous le domaine, une fois sous le nom du site.
            for ligne in self._queue(JOURNAL_HOTES, budget):
                m = LIGNE_HOTE.match(ligne)
                if not m:
                    continue
                jour = _jour_de(m.group("date"))
                if jour:
                    hote = m.group("hote").split(":")[0].lower()
                    _compter(self._jours[jour][hote], m)
        else:
            for f in self._journaux():
                if budget <= 0:
                    break       # le reste attend le prochain passage
                vhost = f.name[:-len(SUFFIXE)]
                lignes = self._queue(f, budget)
                budget -= sum(len(l) for l in lignes)
                for ligne in lignes:
                    m = LIGNE.match(ligne)
                    if not m:
                        continue
                    jour = _jour_de(m.group("date"))
                    if jour:
                        _compter(self._jours[jour][vhost], m)
        self._tailler()
        self._elaguer()
        self._maj = datetime.now().astimezone().isoformat()
        self._persister()

    # ── relecture complete d'un seul vhost ───────────────────────────────
    def _archives(self, vhost: str) -> Iterable[Path]:
        """Le journal courant et ses rotations, gzip compris."""
        base = JOURNAL_HOTES.name if JOURNAL_HOTES.exists() else f"{vhost}{SUFFIXE}"
        for f in sorted(REP_LOGS.glob(f"{base}*")):
            if f.name == base or re.fullmatch(rf"{re.escape(base)}\.\d+(\.gz)?", f.name):
                yield f

    def rafraichir(self, vhost: str) -> dict:
        """Rebatit l'historique d'un vhost depuis ses journaux, tout compris.

        Couteux par construction : reserve a une demande explicite depuis la
        page de detail, jamais appele par la boucle de fond.
        """
        if not re.fullmatch(r"[A-Za-z0-9._-]+", vhost):
            raise ValueError("nom de vhost invalide")
        fichiers = list(self._archives(vhost))
        if not fichiers:
            raise FileNotFoundError(f"aucun journal pour {vhost}")

        limite = (date.today() - timedelta(days=self.retention - 1)).isoformat()
        par_hote = JOURNAL_HOTES.exists()
        motif = LIGNE_HOTE if par_hote else LIGNE
        cible = vhost.lower()
        neuf: dict[str, dict] = defaultdict(_vierge)
        lues = 0
        for f in fichiers:
            ouvre = gzip.open if f.suffix == ".gz" else open
            try:
                with ouvre(f, "rt", errors="replace") as fh:
                    for ligne in fh:
                        # Le journal commun contient TOUS les domaines : on
                        # ecarte les autres avant l'expression reguliere, qui
                        # coute bien plus cher qu'une comparaison de prefixe.
                        if par_hote and not ligne.lower().startswith(cible + " "):
                            continue
                        m = motif.match(ligne)
                        if not m:
                            continue
                        jour = _jour_de(m.group("date"))
                        if jour and jour >= limite:
                            _compter(neuf[jour], m)
                            lues += 1
            except OSError:
                continue

        # Substitution seulement maintenant : si la relecture avait echoue en
        # route, les anciens compteurs seraient restes intacts.
        for jour in list(self._jours):
            self._jours[jour].pop(vhost, None)
        for jour, s in neuf.items():
            self._jours[jour][vhost] = s

        # Le journal courant a ete lu en entier : on recale la marque dessus,
        # sinon la boucle de fond recompterait toute la queue au tour suivant.
        courant = JOURNAL_HOTES if par_hote else REP_LOGS / f"{vhost}{SUFFIXE}"
        try:
            st = courant.stat()
            self._suivi[str(courant)] = (st.st_ino, st.st_size)
        except OSError:
            pass

        self._maj = datetime.now().astimezone().isoformat()
        self._persister()
        return {"vhost": vhost, "fichiers": len(fichiers), "lignes": lues,
                "jours": sorted(neuf)}

    # ── restitution ──────────────────────────────────────────────────────
    def _fusion(self, jours: list[str]) -> dict[str, dict]:
        """Additionne les seaux d'une periode, vhost par vhost."""
        total: dict[str, dict] = defaultdict(_vierge)
        for j in jours:
            for vhost, s in self._jours.get(j, {}).items():
                t = total[vhost]
                for c in ("visites", "requetes", "octets", "sondes", "erreurs", "robots", "sans_ref"):
                    t[c] += s[c]
                for c in ("navigateurs", "plateformes", "statuts", "chemins", "referents", "pays"):
                    t[c].update(s[c])
                # Union des IP : sur plusieurs jours c'est bien un nombre de
                # visiteurs distincts, pas une somme de journees.
                t["ips"] |= s["ips"]
                t["ips_debordees"] |= s["ips_debordees"]
        return total

    def _fenetre(self, periode: str) -> list[str]:
        n = PERIODES.get(periode, 1)
        aujourdhui = date.today()
        return [(aujourdhui - timedelta(days=i)).isoformat() for i in range(n)]

    def _rendre(self, vhost: str, s: dict) -> dict:
        return {
            "vhost": vhost,
            "visites": s["visites"],
            "requetes": s["requetes"],
            "visiteurs": len(s["ips"]),
            "visiteurs_minores": s["ips_debordees"],
            "octets": s["octets"],
            "robots": s["robots"],
            "humains": s["requetes"] - s["robots"],
            "part_robots": round(100 * s["robots"] / s["requetes"], 1) if s["requetes"] else 0.0,
            "erreurs": s["erreurs"],
            "sondes": s["sondes"],
            "navigateurs": dict(s["navigateurs"].most_common()),
            "plateformes": dict(s["plateformes"].most_common()),
            "statuts": dict(sorted(s["statuts"].items())),
            "top_chemins": [{"chemin": c, "n": n}
                            for c, n in s["chemins"].most_common(self.max_chemins)],
            "top_referents": [{"hote": h, "n": n}
                              for h, n in s["referents"].most_common(self.max_chemins)],
            # #1059 ② — part d'accès direct (visites sans référent) sur ce
            # domaine ou cette famille regroupée.
            "directs_pct": round(100.0 * s["sans_ref"] / s["visites"], 1)
                           if s["visites"] else 0.0,
            # #geoip — repartition des visites par pays, avec drapeau emoji.
            "pays": [{"code": cc, "drapeau": _drapeau(cc), "n": n}
                     for cc, n in s["pays"].most_common(15)],
        }

    def _regrouper(self, brut: dict[str, dict]) -> dict[str, dict]:
        """Fond les vhosts d'une meme famille en une seule entree."""
        fam: dict[str, dict] = defaultdict(_vierge)
        membres: dict[str, list[str]] = defaultdict(list)
        for vhost, s in brut.items():
            f = famille(vhost)
            membres[f].append(vhost)
            t = fam[f]
            for c in ("visites", "requetes", "octets", "sondes", "erreurs", "robots", "sans_ref"):
                t[c] += s[c]
            for c in ("navigateurs", "plateformes", "statuts", "chemins", "referents", "pays"):
                t[c].update(s[c])
            # Union et non somme : un visiteur qui passe sur le .com et le .fr
            # est une personne, pas deux.
            t["ips"] |= s["ips"]
            t["ips_debordees"] |= s["ips_debordees"]
        for f, s in fam.items():
            s["membres"] = sorted(membres[f])
        return fam

    def current(self, periode: str = "jour", grouper: bool = False) -> dict:
        if not self.actif:
            return {"actif": False, "vhosts": [], "periode": periode}
        fenetre = self._fenetre(periode)
        brut = {v: s for v, s in self._fusion(fenetre).items() if s["requetes"]}
        source = self._regrouper(brut) if grouper else brut
        vhosts = []
        for nom, s in source.items():
            d = self._rendre(nom, s)
            if grouper:
                d["membres"] = s.get("membres", [nom])
            vhosts.append(d)
        vhosts.sort(key=lambda x: x["visites"], reverse=True)
        nav, plat = Counter(), Counter()
        for v in vhosts:
            nav.update(v["navigateurs"])
            plat.update(v["plateformes"])
        # #1059 ①② — référents et accès directs remontés au total, depuis les
        # seaux bruts (les vues rendues n'ont que le top tronqué). `source` est
        # déjà regroupé par famille quand grouper=True.
        refs_tot, sans_ref_tot = Counter(), 0
        for s in source.values():
            refs_tot.update(s["referents"])
            sans_ref_tot += s["sans_ref"]
        synth_refs = _referents_synthese(
            refs_tot, sans_ref_tot,
            sum(v["visites"] for v in vhosts), self.max_chemins)
        # Courbe d'ensemble : tous vhosts confondus, du plus ancien au plus
        # recent. Sans elle l'histogramme de la vue liste resterait vide, et il
        # aurait fallu un appel par vhost pour la reconstituer cote navigateur.
        serie = []
        for j in reversed(fenetre):
            seaux = self._jours.get(j, {}).values()
            serie.append({
                "jour": j,
                "visites": sum(s["visites"] for s in seaux),
                "requetes": sum(s["requetes"] for s in seaux),
                "sondes": sum(s["sondes"] for s in seaux),
                "erreurs": sum(s["erreurs"] for s in seaux),
            })
        return {
            "actif": True,
            "periode": periode,
            "groupe": grouper,
            "serie": serie,
            "du": fenetre[-1], "au": fenetre[0],
            "maj": self._maj,
            "total": {
                "vhosts": len(vhosts),
                "domaines": len(brut),
                "visites": sum(v["visites"] for v in vhosts),
                "requetes": sum(v["requetes"] for v in vhosts),
                # Somme des visiteurs par vhost : une meme IP vue sur deux
                # vhosts compte deux fois. C'est voulu — dedoublonner a
                # l'echelle de la boite demanderait de garder toutes les IP.
                "visiteurs": sum(v["visiteurs"] for v in vhosts),
                "sondes": sum(v["sondes"] for v in vhosts),
                "erreurs": sum(v["erreurs"] for v in vhosts),
                "top_referents": synth_refs["top"],
                "directs_pct": synth_refs["directs_pct"],
                "navigateurs": dict(nav.most_common()),
                "plateformes": dict(plat.most_common()),
            },
            "vhosts": vhosts,
        }

    def detail(self, vhost: str, periode: str = "semaine") -> dict:
        """Un vhost — ou une FAMILLE — avec sa courbe jour par jour.

        Le nom demande peut etre celui d'une famille (« anibal-amiot ») et non
        d'un domaine. Ouvrir alors le detail d'un seul de ses membres ne
        montrerait qu'une fraction du trafic : on additionne donc tous les
        domaines de la famille, exactement comme la vue d'ensemble le fait.
        """
        fenetre = self._fenetre(periode)
        brut = self._fusion(fenetre)

        membres = [vhost] if vhost in brut else sorted(
            v for v in brut if famille(v) == vhost)
        if not membres:
            raise KeyError(vhost)

        if len(membres) == 1 and membres[0] == vhost:
            fondu = brut[vhost]
        else:
            fondu = self._regrouper({m: brut[m] for m in membres})[vhost]

        serie = []
        for j in reversed(fenetre):          # du plus ancien au plus recent
            seaux = [self._jours.get(j, {}).get(m) for m in membres]
            seaux = [s for s in seaux if s]
            ips: set = set()
            for s in seaux:
                ips |= s["ips"]
            serie.append({
                "jour": j,
                "visites": sum(s["visites"] for s in seaux),
                "visiteurs": len(ips),
                "requetes": sum(s["requetes"] for s in seaux),
                "sondes": sum(s["sondes"] for s in seaux),
                "erreurs": sum(s["erreurs"] for s in seaux),
            })
        d = self._rendre(vhost, fondu)
        d.update({"periode": periode, "serie": serie, "maj": self._maj,
                  "membres": membres})
        return d

    def vhosts_connus(self) -> list[str]:
        if JOURNAL_HOTES.exists():
            # Les domaines reellement vus, et non les noms de fichiers : c'est
            # tout l'interet du journal commun.
            return sorted({h for vh in self._jours.values() for h in vh})
        return sorted({f.name[:-len(SUFFIXE)] for f in self._journaux()})

    # ── persistance ──────────────────────────────────────────────────────
    def _tailler(self) -> None:
        """Borne les compteurs a longue traine.

        Un scanner demande des milliers de chemins tous differents : sans
        taille, `chemins` enfle indefiniment, la serialisation grossit et
        `most_common()` se met a couter cher a CHAQUE requete — sur la boucle,
        donc pour tous les modules du groupe. On ne garde que ce qu'on affiche.
        """
        for vhosts in self._jours.values():
            for s in vhosts.values():
                for cle, garde in (("chemins", 400), ("referents", 200)):
                    if len(s[cle]) > garde * 4:
                        s[cle] = Counter(dict(s[cle].most_common(garde)))

    def _elaguer(self) -> None:
        limite = (date.today() - timedelta(days=self.retention - 1)).isoformat()
        for j in [j for j in self._jours if j < limite]:
            del self._jours[j]

    def _serialiser(self) -> dict:
        return {
            "version": 2,
            "suivi": {k: list(v) for k, v in self._suivi.items()},
            "jours": {
                j: {v: {**{c: s[c] for c in ("visites", "requetes", "octets",
                                             "sondes", "erreurs", "robots")},
                        "ips": sorted(s["ips"]),
                        "ips_debordees": s["ips_debordees"],
                        **{c: dict(s[c]) for c in ("navigateurs", "plateformes",
                                                   "statuts", "chemins", "referents")}}
                    for v, s in vhosts.items()}
                for j, vhosts in self._jours.items()},
        }

    def _persister(self) -> None:
        try:
            CACHE.parent.mkdir(parents=True, exist_ok=True)
            tmp = CACHE.with_suffix(".tmp")
            tmp.write_text(json.dumps(self._serialiser()))
            os.replace(tmp, CACHE)      # remplacement atomique
        except OSError:
            pass

    def _charger(self) -> None:
        """Reprend le suivi apres redemarrage, sans relire tout l'historique."""
        try:
            d = json.loads(CACHE.read_text())
        except (OSError, ValueError):
            return
        if d.get("version") != 2:
            return          # ancien format : on repart proprement
        self._suivi = {k: tuple(v) for k, v in d.get("suivi", {}).items()}
        for j, vhosts in d.get("jours", {}).items():
            for v, s in vhosts.items():
                seau = _vierge()
                for c in ("visites", "requetes", "octets", "sondes", "erreurs", "robots", "sans_ref"):
                    seau[c] = s.get(c, 0)
                seau["ips"] = set(s.get("ips", []))
                seau["ips_debordees"] = s.get("ips_debordees", False)
                for c in ("navigateurs", "plateformes", "statuts", "chemins", "referents", "pays"):
                    seau[c] = Counter(s.get(c, {}))
                self._jours[j][v] = seau
        self._elaguer()

    async def run_forever(self) -> None:
        while True:
            try:
                await asyncio.to_thread(self.collecter)
            except Exception:
                pass
            await asyncio.sleep(self.intervalle)
