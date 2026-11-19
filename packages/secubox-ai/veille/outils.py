# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Identification des outils de l'attaquant sur empreintes SOURCÉES (complément corrélation § 3), #3795.

Catalogue : `/usr/share/secubox-ai/empreintes/*.toml` (paquet) puis `/etc/secubox/ai/empreintes.local.toml`
(opérateur, facultatif). Une entrée = `[[outil]]` (`nom`, `source` OBLIGATOIRE, `version` facultative) et ses
`[[outil.trait]]` (`type`, `couche`, `motif` OU `valeurs`, `min`, `groupe`, `source` facultatifs). Entrée sans source,
type ou couche inconnus, motif vide ou trop long : refusée au chargement (journalisée).

Motifs = texte LITTÉRAL, échappé (`re.escape`) puis compilé sans casse : aucune expression rationnelle fournie par le
catalogue, donc pas de ReDoS ; l'entrée observée (donnée non fiable de gk2) est en plus tronquée à ENTREE_MAX.

Indépendance : deux traits comptent pour deux s'ils diffèrent de (couche, groupe). Groupes par défaut : agent HTTP,
chemins, ordre des requêtes et champ `tool` de sbxwaf (heuristique tirée de l'agent et des chemins) = `requete` ;
empreinte HTTP et traits d'en-têtes = `entetes` ; identifiants, bannière, ja4, rythme des ports : chacun le sien.
Un outil n'est NOMMÉ qu'avec ≥ 2 traits indépendants (confiance « forte » si deux couches, « moyenne » sinon) ; sinon
`Attribution("inconnu", traits_observes=[…])` avec les traits vus, SANS nom d'outil.

Trait `faible` (identifiants de dictionnaire) : sa combinaison `requis` doit être vue entière ; deux traits faibles
d'une même couche comptent pour un. `groupe` n'est jamais choisi par le catalogue (valeur imposée par le type).

Identifiants des leurres : gk2 ne rend le mot de passe que par HMAC local, non comparable à une liste publique ; on
compare donc « compte:longueur » — limite documentée, d'où `min` paires distinctes exigées.
"""
import logging
import re
import tomllib
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Optional

log = logging.getLogger("secubox-ai-veille")

DOSSIER_PAQUET = Path("/usr/share/secubox-ai/empreintes")
DOSSIER_SOURCE = Path(__file__).resolve().parents[1] / "empreintes"      # arbre de développement
LOCAL = Path("/etc/secubox/ai/empreintes.local.toml")
ENTREE_MAX = 512           # longueur lue d'un champ observé
MOTIF_MAX = 128            # longueur d'un motif du catalogue
VALEURS_MAX = 64           # valeurs d'un trait
TRAITS_OBSERVES_MAX = 32
TYPES = {"agent": "waf", "chemins": "waf", "ordre_requetes": "waf", "outil_waf": "waf", "empreinte_http": "waf",
         "comportement": "waf", "identifiants": "leurre", "banniere": "leurre", "ja4": "dpi", "rythme_ports": "dpi"}
GROUPES = {"agent": "requete", "chemins": "requete", "ordre_requetes": "requete", "outil_waf": "requete",
           "empreinte_http": "entetes", "comportement": "entetes"}
A_MOTIF = frozenset({"agent", "banniere"})
COUCHES = frozenset(TYPES.values())


@dataclass
class Trait:
    type: str
    couche: str
    groupe: str
    source: str
    motif: Optional[re.Pattern] = None
    valeurs: tuple = ()
    min: int = 1
    faible: bool = False
    requis: tuple = ()

    def decrire(self):
        return {"type": self.type, "couche": self.couche, "source": self.source,
                "motif": self.motif.pattern if self.motif else None, "valeurs": list(self.valeurs)}


@dataclass
class Outil:
    nom: str
    source: str
    traits: list
    version: Optional[str] = None


@dataclass
class Attribution:
    outil: str
    traits_concordants: list = field(default_factory=list)
    confiance: Optional[str] = None
    version: Optional[str] = None
    traits_observes: list = field(default_factory=list)

    def dict(self):
        return asdict(self)


def _texte(v, n=ENTREE_MAX):
    if v is None or isinstance(v, (dict, list)):
        return None
    s = str(v)[:n]
    return s or None


def _trait(brut, source_outil):
    if not isinstance(brut, dict):
        raise ValueError("trait non objet")
    type_ = brut.get("type")
    if type_ not in TYPES:
        raise ValueError(f"type de trait inconnu : {type_!r}")
    couche = brut.get("couche", TYPES[type_])
    if couche not in COUCHES:
        raise ValueError(f"couche inconnue : {couche!r}")
    source = str(brut.get("source") or source_outil)
    groupe = GROUPES.get(type_, type_)
    if brut.get("groupe") not in (None, groupe):
        # Le groupe fixe l'indépendance : jamais choisi par le catalogue (on ne fabrique pas un second trait).
        log.warning("empreintes : groupe %r ignoré pour un trait %s (groupe %s)", brut.get("groupe"), type_, groupe)
    faible = brut.get("faible", False)
    if not isinstance(faible, bool):
        raise ValueError("faible non booléen")
    mini = brut.get("min", 1)
    if not isinstance(mini, int) or isinstance(mini, bool) or not 1 <= mini <= VALEURS_MAX:
        raise ValueError("min hors bornes")
    if type_ in A_MOTIF:
        motif = brut.get("motif")
        if not isinstance(motif, str) or not motif.strip() or len(motif) > MOTIF_MAX:
            raise ValueError("motif vide ou trop long")
        return Trait(type_, couche, groupe, source, motif=re.compile(re.escape(motif), re.IGNORECASE), faible=faible)
    valeurs = brut.get("valeurs")
    if (not isinstance(valeurs, list) or not valeurs or len(valeurs) > VALEURS_MAX
            or not all(isinstance(v, str) and 0 < len(v) <= MOTIF_MAX for v in valeurs)):
        raise ValueError("valeurs absentes ou hors bornes")
    requis = brut.get("requis", [])
    if not isinstance(requis, list) or not all(isinstance(v, str) and v in valeurs for v in requis):
        raise ValueError("requis hors des valeurs")
    return Trait(type_, couche, groupe, source, valeurs=tuple(valeurs), min=min(mini, len(set(valeurs))),
                 faible=faible, requis=tuple(requis))


def entree(brut) -> Outil:
    """Une entrée `[[outil]]` du catalogue ; ValueError si elle est sans source ou mal formée."""
    if not isinstance(brut, dict):
        raise ValueError("entrée non objet")
    nom, source = brut.get("nom"), brut.get("source")
    if not isinstance(nom, str) or not nom.strip() or len(nom) > 64 or nom.strip().lower() == "inconnu":
        raise ValueError("nom absent ou invalide")
    if not isinstance(source, str) or not source.strip():
        raise ValueError(f"entrée {nom!r} sans source : refusée")
    traits = [_trait(t, source.strip()) for t in brut.get("trait") or []]
    if not traits:
        raise ValueError(f"entrée {nom!r} sans trait")
    version = brut.get("version")
    return Outil(nom.strip(), source.strip(), traits, str(version) if version is not None else None)


def charger(chemins) -> list:
    """Lit les fichiers TOML donnés (fichiers ou dossiers de *.toml, absents ignorés) ; entrées refusées journalisées."""
    outils = []
    fichiers = []
    for c in chemins:
        c = Path(c)
        if c.is_dir():
            fichiers += sorted(c.glob("*.toml"))
        elif c.is_file():
            fichiers.append(c)
    for f in fichiers:
        try:
            donnees = tomllib.loads(f.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as e:
            log.warning("empreintes %s illisibles : %s", f, e)
            continue
        for brut in donnees.get("outil") or []:
            try:
                outils.append(entree(brut))
            except ValueError as e:
                log.warning("empreintes %s : %s", f, e)
    return outils


_CATALOGUE = None


def catalogue(recharger=False) -> list:
    global _CATALOGUE
    if _CATALOGUE is None or recharger:
        base = DOSSIER_PAQUET if DOSSIER_PAQUET.is_dir() else DOSSIER_SOURCE
        _CATALOGUE = charger([base, LOCAL])
    return _CATALOGUE


def faits(evts) -> dict:
    """Faits observés d'un dossier (événements chronologiques), par type de trait ; valeurs tronquées."""
    f = {t: [] for t in TYPES}
    for e in evts:
        a = e.attributs or {}
        for type_, cle in (("agent", "user_agent"), ("outil_waf", "tool"), ("empreinte_http", "http_fingerprint"),
                           ("banniere", "banniere"), ("ja4", "ja4")):
            v = _texte(a.get(cle))
            if v and v not in f[type_]:
                f[type_].append(v)
        chemin = _texte(a.get("path"))
        if chemin and chemin.startswith("/"):
            f["chemins"].append(chemin)
        for t in a.get("behavior_traits") or [] if isinstance(a.get("behavior_traits"), list) else []:
            v = _texte(t, 64)
            if v and v not in f["comportement"]:
                f["comportement"].append(v)
        for x in a.get("essais") or [] if isinstance(a.get("essais"), list) else []:
            if isinstance(x, dict) and _texte(x.get("compte"), 64) and isinstance(x.get("mot_de_passe_longueur"), int):
                v = f"{_texte(x['compte'], 64)}:{x['mot_de_passe_longueur']}"
                if v not in f["identifiants"]:
                    f["identifiants"].append(v)
        ports = a.get("rythme_ports")
        if _texte(ports, 64):
            f["rythme_ports"].append(_texte(ports, 64))
    return f


def _sous_suite(attendu, vus):
    it = iter(vus)
    return all(any(v == x for v in it) for x in attendu)


def _concorde(t: Trait, f: dict):
    """Valeur observée qui fait concorder le trait, ou None."""
    obs = f.get(t.type) or []
    if t.motif is not None:
        return next((v for v in obs if t.motif.search(v[:ENTREE_MAX])), None)
    if t.type == "ordre_requetes":
        return " → ".join(t.valeurs) if _sous_suite(t.valeurs, obs) else None
    vus = sorted({v for v in obs if v in t.valeurs})
    if not set(t.requis) <= set(vus):
        return None
    return ", ".join(vus) if len(vus) >= t.min else None


def identifier(dossier, cat=None) -> list:
    """Attributions d'un dossier (objet portant `faits_evts`, ou liste d'événements). ≥ 2 traits indépendants par
    outil nommé ; sinon une seule `Attribution("inconnu", traits_observes=…)` si au moins un trait a concordé ; [] si
    rien."""
    evts = getattr(dossier, "faits_evts", dossier)
    f = faits(evts)
    nommes, observes = [], []
    for o in catalogue() if cat is None else cat:
        concordants = []
        for t in o.traits:
            v = _concorde(t, f)
            if v is not None:
                concordants.append((t, v))
        if not concordants:
            continue
        # Deux traits faibles d'une même couche ne font qu'un.
        cles = {(t.couche, "faible" if t.faible else t.groupe) for t, _ in concordants}
        if len(cles) >= 2:
            couches = {t.couche for t, _ in concordants}
            nommes.append(Attribution(o.nom, [dict(t.decrire(), observe=v) for t, v in concordants],
                                      "forte" if len(couches) >= 2 else "moyenne", o.version))
        else:
            for t, v in concordants:
                d = {"type": t.type, "couche": t.couche, "observe": v}     # sans source : elle nommerait l'outil
                if d not in observes:
                    observes.append(d)
    if nommes:
        return sorted(nommes, key=lambda a: a.outil)
    if observes:
        return [Attribution("inconnu", traits_observes=observes[:TRAITS_OBSERVES_MAX])]
    return []
