# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: ad-guard :: moteur du mode « auto » (#1954) — pur : aucune entrée/sortie hors Magasin et Regles."""
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Dict, Iterable, List, Optional

try:
    from . import dnstv, dnstv_detect, dnstv_dpi, dnstv_profil, dnstv_regles, dnstv_signaux, dnstv_taxonomie
except ImportError:
    from api import dnstv, dnstv_detect, dnstv_dpi, dnstv_profil, dnstv_regles, dnstv_signaux, dnstv_taxonomie

if TYPE_CHECKING:                                    # pragma: no cover
    from .dnstv_indices import Index

HISTORIQUE_H = 48
# Motifs des règles nées d'un indice (#3666) : l'origine est nommée (« essai automatique, suggéré par gk2, gk6 »), ≤ 120 car.
PREFIXE_INDICE = "essai automatique, suggéré par "
PREFIXE_INDICE_CONFIRME = "confirmé, suggéré par "
MOTIF_INDICE_RETIRE = "indice retiré"
MOTIF_INDICE_INDISPONIBLE = "essai prolongé : indices indisponibles"
PROLONGATIONS_INDICE_MAX = 3         # prolongations consécutives d'un essai né d'indice ; au-delà, expiration ordinaire


@dataclass
class Reglage:
    declencheurs: tuple = ("fwmrm.net",)
    auto_essai: bool = False
    seuil_refus_min: int = dnstv_signaux.SEUIL_REFUS_MIN
    duree_rafale_min: int = dnstv_signaux.DUREE_RAFALE_MIN
    min_requetes_actif: int = dnstv_signaux.MIN_REQUETES_ACTIF
    # Ajout automatique et agrégation (#1959) — seuils de départ, à calibrer
    max_par_jour: int = 3
    delai_s: int = 3600
    retrait_jours: int = 7
    min_declencheurs: int = 5
    min_services: int = 2
    min_appareils_agreg: int = 2
    # Détection permanente (#2047), faux par défaut : l'administrateur les active dans ad-guard.toml
    confirmation_auto: bool = False      # un essai sans régression devient règle confirmée à l'échéance (au lieu d'être retiré)
    declencheurs_pub: bool = False       # un hôte de pub connu (listes), même déjà bloqué, ouvre la fenêtre de détection


TOML = Path("/etc/secubox/ad-guard.toml")


def reglage_depuis(etat: dict, toml: Path = TOML) -> Reglage:
    """Seuils de DÉPART (à calibrer) depuis la configuration ; `auto_essai` vient de l'état, sous le contrôle de l'administrateur."""
    r = Reglage(auto_essai=bool(etat.get("auto_essai", False)))
    try:
        import tomllib
        with open(toml, "rb") as h:
            c = tomllib.load(h).get("adblock_tv_auto", {})
    except (OSError, ValueError, ImportError):
        return r
    for k in ("confirmation_auto", "declencheurs_pub"):
        if isinstance(c.get(k), bool):
            setattr(r, k, c[k])
    decl = c.get("declencheurs")
    if isinstance(decl, list) and decl and all(isinstance(d, str) and dnstv.valider_domaine(d) == d for d in decl):
        r.declencheurs = tuple(decl)
    for k in ("seuil_refus_min", "duree_rafale_min", "min_requetes_actif", "max_par_jour", "delai_s", "retrait_jours", "min_declencheurs", "min_services", "min_appareils_agreg"):
        v = c.get(k)
        if isinstance(v, int) and not isinstance(v, bool) and v > 0:
            setattr(r, k, v)
    return r


def appareils(etat: dict) -> Dict[str, List[str]]:
    out: Dict[str, List[str]] = {}
    for c in etat["clients"]:
        if c["mode"] == "auto":
            out.setdefault(dnstv._slug(c["nom"]), []).append(c["ip"])
    return out


def _eprouver(r: dict, adresses: List[str], magasin, reglage, maintenant: int) -> str:
    """Bilan d'un essai échu : « regression » (rafale de refus, contenu habituel disparu), « peu_actif » (trop peu d'activité pour
    l'éprouver) ou « ok »."""
    evts = magasin.evenements(adresses, maintenant - HISTORIQUE_H * 3600)
    if dnstv_signaux.rafale(evts, {r["domaine"]}, maintenant, reglage.seuil_refus_min, reglage.duree_rafale_min):
        return "regression"
    depuis = [e for e in evts if e["ts"] >= r["maj"] and e["decision"] != "BLOCKED"]
    if len(depuis) < reglage.min_requetes_actif:
        return "peu_actif"
    jours = magasin.jours_vus(adresses, dnstv._jour(r["maj"]), dnstv._jour(r["maj"] - 7 * 86400))
    if dnstv_signaux.contenu_disparu(jours, {e["domaine"] for e in depuis}, len(depuis), min_requetes=reglage.min_requetes_actif):
        return "regression"
    return "ok"


def _ne_du_moteur(r: dict) -> bool:
    """Règle née d'un indice (#3666) que le MOTEUR a mise à l'essai (et, si confirmée, confirmée lui-même) : seule celle-là suit
    l'indice. Un essai lancé ou une règle confirmée par l'administrateur ne bouge jamais au gré des indices."""
    if not r.get("indice") or r.get("etat") not in ("essai", "confirme"):
        return False
    hist = r.get("historique") or []
    entree = next((h for h in reversed(hist) if h.get("vers") == "essai" and h.get("de") != "essai"), None)
    if entree is None or entree.get("origine") != "auto":
        return False
    return r["etat"] == "essai" or hist[-1].get("origine") == "auto"


def _confirmer_les_essais_echus(etat, regles, magasin, reglage, maintenant, note, refus=lambda app, d: None,
                                ignorer=lambda r: False) -> None:
    """Essais arrivés à échéance (#2047) : sans régression, la règle est CONFIRMÉE automatiquement ; si l'appareil a été trop peu
    actif pour l'éprouver, l'essai est prolongé d'une période ; en cas de régression (rafale de refus, contenu habituel disparu),
    on ne touche à rien : l'expiration normale retire la règle."""
    adr = appareils(etat)
    for r in [x for x in regles.liste() if x["etat"] == "essai" and maintenant > x["fin_essai"] and not ignorer(x)]:
        adresses = adr.get(r["appareil"])
        if not adresses:
            continue                                         # appareil plus en mode auto : l'expiration joue
        if refus(r["appareil"], r["domaine"]):
            continue                                         # catégorie protégée (#3374) : jamais confirmée seule, l'expiration la retire
        bilan = _eprouver(r, adresses, magasin, reglage, maintenant)
        if bilan == "regression":
            continue
        if bilan == "peu_actif":
            regles.prolonger_essai(r["id"], maintenant)
            continue
        note(regles.transiter(r["id"], "confirme", "auto", "essai sans régression", maintenant), "essai", "confirme", "essai sans régression")


def _noms_valides(noms: Iterable[str]) -> List[str]:
    return [n for n in noms if isinstance(n, str) and dnstv_regles.NOM_BOX_RE.match(n)]


def _motif_noms(prefixe: str, noms: List[str], plafond: int = 120) -> str:
    """« <préfixe>gk1, gk2 (+3) » tenu sous le plafond des motifs de règle (`valider_regle` tronque à 120)."""
    for k in range(len(noms), 0, -1):
        texte = prefixe + ", ".join(noms[:k]) + ("" if k == len(noms) else f" (+{len(noms) - k})")
        if len(texte) <= plafond:
            return texte
    return (prefixe + (noms[0] if noms else ""))[:plafond]


def _suivre_les_indices(etat, regles, magasin, reglage, maintenant, note, indices, suggestion, refus_ix) -> None:
    """Règles nées d'un indice et mises à l'essai (ou confirmées) par le moteur (#3666).

    Oubli : indice disparu ou déclaré légitime par une box → la règle est EFFACÉE (reproposable si l'indice revient). Jamais sur une
    lecture LOCALE ratée : rien si l'index est illisible, rien pour une règle dont un producteur est indisponible (fichier absent ou
    illisible ici). Un contenu signé mais invalide n'est pas une lecture ratée : `charger` le traite comme une liste vide.
    Échéance : essai sans régression → confirmé (origine auto, garde `refus_indice`), même `confirmation_auto` désactivé ; appareil
    peu actif ou indices indisponibles → essai prolongé, au plus PROLONGATIONS_INDICE_MAX fois de suite ; régression (rafale de refus,
    contenu habituel disparu), catégorie protégée ou plafond atteint → l'expiration ordinaire le retire."""
    if indices.lisible:
        for r in regles.liste():
            if not _ne_du_moteur(r):
                continue
            conf, leg = suggestion(r["domaine"])
            # Un légitime déclaré par un producteur lisible l'emporte toujours ; un producteur indisponible ne protège que du cas
            # « plus aucun confirmateur » (sa confirmation n'a peut-être disparu que faute de lecture).
            if not leg and (conf or set(r["indice"]) & indices.indisponibles):
                continue
            regles.oublier(r["id"])
            note(r, r["etat"], "", MOTIF_INDICE_RETIRE)
    adr = appareils(etat)
    for r in [x for x in regles.liste() if x["etat"] == "essai" and maintenant > x["fin_essai"] and _ne_du_moteur(x)]:
        adresses = adr.get(r["appareil"])
        if not adresses:
            continue                                         # appareil plus en mode auto : l'expiration joue
        if refus_ix(r["appareil"], r["domaine"]):
            continue                                         # catégorie protégée connue ici : l'expiration la retire
        if r.get("prolongations", 0) >= PROLONGATIONS_INDICE_MAX:
            continue                                         # plafond : un pair (ou une panne) ne fige jamais un blocage
        bilan = _eprouver(r, adresses, magasin, reglage, maintenant)
        if bilan == "regression":
            continue                                         # rafale de refus ou contenu disparu : l'expiration la retire
        conf, leg = suggestion(r["domaine"])
        # Restée là faute de lecture locale (index illisible ou producteur indisponible) : la protection n'est pas retirée à
        # l'aveugle ; l'essai est reconduit de 24 h, dans la limite du plafond ci-dessus.
        if not indices.lisible or not conf or leg:
            regles.prolonger_essai(r["id"], maintenant, MOTIF_INDICE_INDISPONIBLE)
        elif bilan == "peu_actif":
            regles.prolonger_essai(r["id"], maintenant)
        else:
            motif = _motif_noms(PREFIXE_INDICE_CONFIRME, conf)
            note(regles.transiter(r["id"], "confirme", "auto", motif, maintenant), "essai", "confirme", motif)


def tick(etat, regles, magasin, classer, reglage, maintenant, taxo=None, replis=None, guides=frozenset(),
         indices: Optional["Index"] = None) -> dict:
    """Un passage du moteur. `taxo` (#3374) : taxonomie complète (corrections manuelles comprises) ; à défaut, celle des listes du paquet
    avec le classeur `classer`. Garde : un domaine de catégorie protégée n'entre jamais SEUL en essai ni en confirmation.
    `guides` (lot 5b) : slugs des appareils en apprentissage guidé ; leurs candidats n'entrent JAMAIS seuls en essai, ils attendent la
    validation de l'administrateur dans l'assistant. Vide par défaut : AUTO pur inchangé.
    `indices` (#3666) : domaines confirmés publicitaires par d'autres box du maillage. N'agit que sur un domaine EXACT vu localement
    pendant une coupure d'un appareil en mode auto : candidat dès une coupure, puis essai automatique (même `auto_essai` désactivé,
    même risque « partage ») si l'appareil n'est pas guidé et que `refus_indice` le permet ; un légitime déclaré par une box le
    laisse candidat. Un essai né d'indices est retiré quand plus aucune box ne le confirme ou qu'une le déclare légitime.
    None (défaut) : comportement inchangé, aucun retrait."""
    changements, applique, candidats = [], False, 0
    taxo = taxo or dnstv_taxonomie.Taxonomie.depuis_dossier(classer=classer, regles=regles)
    macs = dnstv_taxonomie.macs_par_appareil(etat)
    admin = dnstv_taxonomie.confirmes_par_admin(regles)       # une fois par passage : le moteur ne confirme jamais au nom de l'administrateur

    def refus(appareil: str, domaine: str):
        return dnstv_taxonomie.refus_auto(taxo, domaine, macs.get(appareil, ()), admin)
    def note(r, de, vers, motif):
        nonlocal applique
        changements.append({"appareil": r["appareil"], "domaine": r["domaine"], "de": de, "vers": vers, "motif": motif})
        if (de in ("essai", "confirme")) != (vers in ("essai", "confirme")):
            applique = True
    def suggestion(d: str):
        """(confirmateurs aux noms valides, box qui le déclarent légitime) d'un domaine exact ; vides sans indices."""
        if indices is None:
            return [], []
        return _noms_valides(indices.confirmateurs(d)), indices.legitime_chez(d)
    def refus_ix(appareil: str, domaine: str):
        return dnstv_taxonomie.refus_indice(taxo, domaine, macs.get(appareil, ()), admin)
    domaines_indice = frozenset(d for d, par in indices.confirmes.items() if _noms_valides(par)) if indices is not None else frozenset()
    if indices is not None:
        _suivre_les_indices(etat, regles, magasin, reglage, maintenant, note, indices, suggestion, refus_ix)
    avant = {r["id"]: r["etat"] for r in regles.liste()}
    if reglage.confirmation_auto:
        _confirmer_les_essais_echus(etat, regles, magasin, reglage, maintenant, note, refus,
                                    ignorer=_ne_du_moteur if indices is not None else (lambda r: False))
    avant = {r["id"]: r["etat"] for r in regles.liste()}
    for r in regles.expirer(maintenant):
        note(r, avant[r["id"]], r["etat"], r["motif"])
    def declencheur(d: str) -> bool:
        if any(d == s or d.endswith("." + s) for s in reglage.declencheurs):
            return True
        return reglage.declencheurs_pub and classer(d) in dnstv_detect.CLASSES_PUB      # repère intelligent (#2047)

    for appareil, adresses in appareils(etat).items():
        evts = magasin.evenements(adresses, maintenant - HISTORIQUE_H * 3600)
        if indices is not None and appareil not in guides:
            # Candidat AUTO déjà connu (jamais touché par l'administrateur) que d'autres box confirment désormais : il entre à l'essai.
            # Arbitré : vaut aussi pour un candidat né d'un indice qui porte déjà `indice` (resté candidat « légitime chez … ») une fois
            # le légitime disparu ; son `indice` est alors remis à jour.
            for r in regles.liste():
                if (r["appareil"] != appareil or r["etat"] != "candidat" or r.get("origine") != "auto"
                        or r["risque"] not in ("faible", "partage") or any(h.get("origine") != "auto" for h in r.get("historique") or [])):
                    continue
                conf, leg = suggestion(r["domaine"])
                if not conf or leg or refus_ix(appareil, r["domaine"]):
                    continue
                regles.poser_indice(r["id"], conf[:dnstv_regles.INDICE_MAX])
                motif = _motif_noms(PREFIXE_INDICE, conf)
                note(regles.transiter(r["id"], "essai", "auto", motif, maintenant), "candidat", "essai", motif)
        exclus = {r["domaine"] for r in regles.liste() if r["appareil"] == appareil}
        for c in dnstv_detect.detecter(evts, declencheur, classer, exclus,
                                       evts_declencheurs=evts if reglage.declencheurs_pub else None, indices=domaines_indice):
            conf, leg = suggestion(c.domaine) if c.risque != "variable" else ([], [])   # un regroupement ne porte jamais l'indice
            # Décision LOCALE (essai automatique ordinaire) : jamais un appareil guidé, seul le risque « faible », jamais une catégorie
            # protégée (INCONNU compris). Un indice freiné par un légitime déclaré ailleurs revient à cette décision : la règle est
            # alors locale (sans `indice`), elle ne suit pas les indices.
            essai_local = reglage.auto_essai and appareil not in guides and c.risque == "faible" and not refus(appareil, c.domaine)
            if conf and leg and essai_local:
                conf = []
            kw = {}
            if conf:                                         # indice du maillage : les box sont nommées, la règle n'est jamais renvoyée (pas d'écho)
                kw = {"indice": conf[:dnstv_regles.INDICE_MAX],
                      "motif": _motif_noms("légitime chez ", _noms_valides(leg) or ["une autre box"]) if leg else _motif_noms("suggéré par ", conf)}
            try:
                n = regles.proposer(appareil, c.domaine, c.score, c.risque, maintenant, **kw)
            except dnstv_regles.ErreurRegle:
                break                                        # plafond atteint : on cesse de proposer, mais l'expiration et les signaux continuent
            if n is None:
                continue
            candidats += 1
            changements.append({"appareil": appareil, "domaine": c.domaine, "de": "", "vers": "candidat", "motif": n["motif"] if conf else c.motif})
            # Essai sur indice : ni `auto_essai`, ni le seul risque « faible » ; jamais un appareil guidé, un nom à partie variable,
            # un légitime déclaré ailleurs ni une catégorie protégée connue ici (INCONNU seul est levé par l'indice).
            essai_indice = (bool(conf) and not leg and appareil not in guides and c.risque in ("faible", "partage")
                            and refus_ix(appareil, c.domaine) is None)
            if essai_indice:
                motif = _motif_noms(PREFIXE_INDICE, conf)
                note(regles.transiter(n["id"], "essai", "auto", motif, maintenant), "candidat", "essai", motif)
            if not essai_indice and not conf and essai_local:   # « partagé », « variable » ou protégé : humain
                r = regles.transiter(n["id"], "essai", "auto", "essai automatique", maintenant)
                note(r, "candidat", "essai", "essai automatique")
        # Lot 4 (#3374, arbitrage 3) : anti faux repli — un domaine PUB apparu juste après un refus publicitaire est proposé puis mis à
        # l'essai ; garde inchangée (catégorie protégée jamais en essai), retrait par rafale de refus ou contenu disparu ci-dessous.
        # I3 : la corrélation est faite UNE fois, incrémentale, par le passage DPI ; le moteur reçoit ses découvertes (`replis`).
        for c in dnstv_dpi.candidats_repli((replis or {}).get(appareil, [])):
            if c["domaine"] in exclus:
                continue
            try:
                n = regles.proposer(appareil, c["domaine"], c["confiance"], "faible", maintenant, motif="repli publicitaire : " + c["raison"])
            except dnstv_regles.ErreurRegle:
                break
            if n is None:
                continue
            exclus.add(c["domaine"])
            candidats += 1
            changements.append({"appareil": appareil, "domaine": c["domaine"], "de": "", "vers": "candidat", "motif": n["motif"]})
            if reglage.auto_essai and appareil not in guides and not refus(appareil, c["domaine"]):
                r = regles.transiter(n["id"], "essai", "auto", "essai automatique (repli publicitaire)", maintenant)
                note(r, "candidat", "essai", "essai automatique (repli publicitaire)")
        en_essai = [r for r in regles.liste() if r["appareil"] == appareil and r["etat"] == "essai"]
        if not en_essai:
            continue
        for d in dnstv_signaux.rafale(evts, {r["domaine"] for r in en_essai}, maintenant, reglage.seuil_refus_min, reglage.duree_rafale_min):
            r = regles.get(dnstv_regles.identifiant(appareil, d))
            note(regles.transiter(r["id"], "retire", "auto", "rafale de refus", maintenant), "essai", "retire", "rafale de refus")
        restantes = [r for r in en_essai if regles.get(r["id"])["etat"] == "essai"]
        if restantes:
            debut = min(r["maj"] for r in restantes)
            depuis = [e for e in evts if e["ts"] >= debut and e["decision"] != "BLOCKED"]   # les relances d'un domaine refusé ne sont pas de l'activité
            vus = {e["domaine"] for e in depuis}
            jours = magasin.jours_vus(adresses, dnstv._jour(debut), dnstv._jour(debut - 7 * 86400))
            if (maintenant - debut >= dnstv_signaux.DUREE_MIN_S
                    and dnstv_signaux.contenu_disparu(jours, vus, len(depuis), min_requetes=reglage.min_requetes_actif)):
                for r in restantes:
                    note(regles.transiter(r["id"], "retire", "auto", "contenu habituel plus demandé", maintenant), "essai", "retire", "contenu habituel plus demandé")
    # Agrégation (#1959) : ce que l'administrateur a confirmé sur plusieurs appareils est PROPOSÉ (candidat, jamais actif) aux autres
    agrege = dnstv_profil.agreger(regles, reglage.min_appareils_agreg)
    avant_ids = {r["id"] for r in regles.liste()}
    try:
        candidats += dnstv_profil.candidats_agreges(regles, agrege, sorted(appareils(etat)), maintenant)
    except dnstv_regles.ErreurRegle:
        pass                                                 # plafond de règles atteint : on ne propose plus, le reste du passage est déjà fait
    for r in regles.liste():
        if r["id"] not in avant_ids:
            changements.append({"appareil": r["appareil"], "domaine": r["domaine"], "de": "", "vers": "candidat", "motif": r["motif"]})
    # Un domaine que l'administrateur a CONFIRMÉ sur ≥ N autres appareils entre à l'ESSAI (24 h, réversible : rafale de refus ou
    # contenu disparu le retire) quand l'essai automatique est actif. Restés « candidat » faute de cette étape, ads-canalplus et
    # vizchoice laissaient passer la pub sur une TV (gk2). Les autres candidats (risque non faible, proposés à la main) restent humains.
    if reglage.auto_essai:
        for r in regles.liste():
            if (r["etat"] == "candidat" and r.get("origine") == "auto" and r["risque"] == "faible" and r["appareil"] not in guides
                    and str(r.get("motif", "")).startswith("confirmé sur ") and not refus(r["appareil"], r["domaine"])):
                note(regles.transiter(r["id"], "essai", "auto", "essai automatique (confirmé ailleurs)", maintenant),
                     "candidat", "essai", "essai automatique (confirmé ailleurs)")
    return {"changements": changements, "candidats": candidats, "applique": applique, "agrege": agrege}
