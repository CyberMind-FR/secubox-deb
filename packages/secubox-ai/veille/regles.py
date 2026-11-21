# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Règles du corrélateur (V2 § 8, complément corrélation § 2), #3721. Déterministes, sans IA, sans score.

Chaque règle reçoit les événements CORRÉLABLES de la fenêtre (déjà filtrés : ni `local`, ni autotest, ni plage de
documentation) et rend des `Candidat` (règle, clé, preuves). Les décisions de gk2 (bans de sbxwaf, de sbx-authwatch)
sont des faits : un ban seul n'est jamais un incident ; il ne sert de preuve qu'à une règle qui croise des sources.
`meme_outil_multi_adresses` vient avec l'identification d'outils (tâche 8), pas ici.
"""
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

ECHELLE = ("info", "low", "medium", "high", "critical")
# Familles sûres de gk2 (gestes_ia.CATEGORIES_SURES, décision du 14/11) : reconnaissance, sondes, leurres.
CATEGORIES_SURES = SURES = frozenset({"scanners", "recon_crawler", "host_anomaly", "leurre", "product_absent_probes", "honeypot",
                   "waf_fingerprint"})
# Requêtes servies par le leurre de la box (#3723, `leurresip.go` de sbxwaf) : l'adresse est DÉJÀ traitée par un
# geste ; la compter comme hostile ferait boucler leurre → ban. Jamais preuve d'une règle, ni tentative, ni récidive.
REDIRIGES = frozenset({"leurre_redirige"})
# Ni sûres ni d'attaque : décisions, trafic sans portée offensive, inconnues, leurre de la box.
NEUTRES = frozenset({"ban", "ban_actif", "decision", "inconnue", "body-inspect-skipped", "robots", "garde", "dns"}) \
    | REDIRIGES
LEURRES = frozenset({"leurre", "honeypot"})
# Sources qui portent des DÉCISIONS de gk2 (faits), pas des tentatives observées.
DECISIONS = frozenset({"bans", "bans_actifs", "decisions", "reevaluations"})


@dataclass
class Evt:
    id: str
    source: str
    horodatage: str
    famille: str
    sous_famille: Optional[str]
    gravite: str
    ip_src: Optional[str]
    bloc24: Optional[str]
    service: Optional[str]
    vhost: Optional[str]
    attributs: dict = field(default_factory=dict)

    @property
    def emetteur(self) -> str:
        """Source logique : sbx-authwatch se distingue de sbxwaf dans le flux des menaces ; les bans de sbxwaf
        restent « waf » (un ban du WAF et une sonde du WAF ne font pas deux sources)."""
        if self.source == "menaces":
            return "authwatch" if self.attributs.get("tool") == "authwatch" else "waf"
        if self.source in DECISIONS:
            return "waf"
        return self.source

    @property
    def classe_service(self) -> Optional[str]:
        """smtp / imap / ssh… (authwatch) ; `web` pour le WAF. Les vhosts d'un même balayage restent UN service."""
        if self.source != "menaces":
            return None
        if self.emetteur == "authwatch":
            return (self.service or self.vhost or "auth").lower()
        return "web"

    @property
    def observation(self) -> bool:
        return self.source not in DECISIONS

    @property
    def leurre(self) -> bool:
        return self.famille in LEURRES or bool(self.attributs.get("essais"))

    @property
    def attaque(self) -> bool:
        return self.observation and not self.leurre and self.famille not in SURES and self.famille not in NEUTRES


@dataclass
class Candidat:
    regle: str
    cle: str
    preuves: list
    cran: int = 0
    campagne_id: Optional[str] = None


def rang(g) -> int:
    return ECHELLE.index(g) if g in ECHELLE else 0


def _par(evts, cle):
    groupes = {}
    for e in evts:
        k = cle(e)
        if k:
            groupes.setdefault(k, []).append(e)
    return groupes


def multi_source(evts, ctx):
    return [Candidat("multi_source", ip, g) for ip, g in _par(evts, lambda e: e.ip_src).items()
            if len({e.emetteur for e in g}) >= 2]


def multi_service(evts, ctx):
    out = []
    for ip, g in _par([e for e in evts if e.classe_service], lambda e: e.ip_src).items():
        if len({e.classe_service for e in g}) >= 2:
            out.append(Candidat("multi_service", ip, g))
    return out


def bloc_mixte(evts, ctx):
    """Un /24 dont les adresses mêlent familles sûres et d'attaque (≥ 2 adresses) : jamais un cas sûr."""
    out = []
    for bloc, g in _par([e for e in evts if e.observation], lambda e: e.bloc24).items():
        sures = [e for e in g if e.famille in SURES]
        attaques = [e for e in g if e.attaque]
        if sures and attaques and len({e.ip_src for e in sures + attaques}) >= 2:
            out.append(Candidat("bloc_mixte", bloc, sures + attaques))
    return out


def retour_apres_ban(evts, ctx):
    """Observation d'une adresse après la fin d'un ban de cette adresse (ban de gk2 = fait, `exp` ou disparition des
    bans actifs), ou d'un bloc après la fin enregistrée de son ban (table `blocs`)."""
    out = []
    fins = ctx.get("fins_ban", {})       # ip -> [(fin RFC 3339, Evt du ban)]
    for ip, g in _par([e for e in evts if e.observation], lambda e: e.ip_src).items():
        for fin, ban in fins.get(ip, []):
            apres = [e for e in g if e.horodatage > fin]
            if apres:
                out.append(Candidat("retour_apres_ban", ip, [ban] + apres))
                break
    blocs = ctx.get("fins_bloc", {})     # bloc24 -> fin RFC 3339
    for bloc, g in _par([e for e in evts if e.observation], lambda e: e.bloc24).items():
        fin = blocs.get(bloc)
        apres = [e for e in g if fin and e.horodatage > fin]
        if apres:
            out.append(Candidat("retour_apres_ban", bloc, apres))
    return out


def campagne_etendue(evts, ctx):
    """Campagne du WAF (bans `campagne:<signature>`, faits de gk2) dont des membres paraissent chez sbx-authwatch."""
    out = []
    membres = ctx.get("membres_campagne", {})   # signature -> {ip: Evt du ban}
    auth = _par([e for e in evts if e.emetteur == "authwatch"], lambda e: e.ip_src)
    for sig, ips in membres.items():
        communs = sorted(set(ips) & set(auth))
        if communs:
            preuves = [ips[i] for i in communs] + [e for i in communs for e in auth[i]]
            out.append(Candidat("campagne_etendue", sig, preuves,
                                campagne_id=sig if sig in ctx.get("campagnes", ()) else None))
    return out


def leurre_puis_attaque(evts, ctx):
    """Contact d'un leurre puis tentative réelle de la même adresse ou du même bloc : gravité relevée d'un cran."""
    out, vus = [], set()
    for cle_de in (lambda e: e.ip_src, lambda e: e.bloc24):
        for cle, g in _par(evts, cle_de).items():
            leurres = [e for e in g if e.observation and e.leurre]
            if not leurres:
                continue
            premier = min(e.horodatage for e in leurres)
            suites = [e for e in g if e.attaque and e.horodatage > premier]
            ids = frozenset(e.id for e in leurres + suites)
            if suites and ids not in vus:
                vus.add(ids)
                out.append(Candidat("leurre_puis_attaque", cle, leurres + suites, cran=1))
    return out


def garde_et_waf(evts, ctx):
    """Événement de la garde (intrusion bannie…) et du WAF ou de sbx-authwatch sur la même adresse."""
    out = []
    for ip, g in _par(evts, lambda e: e.ip_src).items():
        garde = [e for e in g if e.emetteur == "garde"]
        autres = [e for e in g if e.emetteur in ("waf", "authwatch")]
        if garde and autres:
            out.append(Candidat("garde_et_waf", ip, garde + autres))
    return out


REGLES = (multi_source, multi_service, bloc_mixte, retour_apres_ban, campagne_etendue, leurre_puis_attaque,
          garde_et_waf)


def iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
