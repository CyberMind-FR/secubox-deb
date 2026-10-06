# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: ad-guard :: moteur du mode « auto » (#1954) — pur : aucune entrée/sortie hors Magasin et Regles."""
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List

try:
    from . import dnstv, dnstv_detect, dnstv_profil, dnstv_regles, dnstv_signaux
except ImportError:
    from api import dnstv, dnstv_detect, dnstv_profil, dnstv_regles, dnstv_signaux

HISTORIQUE_H = 48


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


def _confirmer_les_essais_echus(etat, regles, magasin, reglage, maintenant, note) -> None:
    """Essais arrivés à échéance (#2047) : sans régression, la règle est CONFIRMÉE automatiquement ; si l'appareil a été trop peu
    actif pour l'éprouver, l'essai est prolongé d'une période ; en cas de régression (rafale de refus, contenu habituel disparu),
    on ne touche à rien : l'expiration normale retire la règle."""
    adr = appareils(etat)
    for r in [x for x in regles.liste() if x["etat"] == "essai" and maintenant > x["fin_essai"]]:
        adresses = adr.get(r["appareil"])
        if not adresses:
            continue                                         # appareil plus en mode auto : l'expiration joue
        evts = magasin.evenements(adresses, maintenant - HISTORIQUE_H * 3600)
        if dnstv_signaux.rafale(evts, {r["domaine"]}, maintenant, reglage.seuil_refus_min, reglage.duree_rafale_min):
            continue
        depuis = [e for e in evts if e["ts"] >= r["maj"] and e["decision"] != "BLOCKED"]
        if len(depuis) < reglage.min_requetes_actif:
            regles.prolonger_essai(r["id"], maintenant)
            continue
        jours = magasin.jours_vus(adresses, dnstv._jour(r["maj"]), dnstv._jour(r["maj"] - 7 * 86400))
        if dnstv_signaux.contenu_disparu(jours, {e["domaine"] for e in depuis}, len(depuis), min_requetes=reglage.min_requetes_actif):
            continue
        note(regles.transiter(r["id"], "confirme", "auto", "essai sans régression", maintenant), "essai", "confirme", "essai sans régression")


def tick(etat, regles, magasin, classer, reglage, maintenant) -> dict:
    changements, applique, candidats = [], False, 0
    def note(r, de, vers, motif):
        nonlocal applique
        changements.append({"appareil": r["appareil"], "domaine": r["domaine"], "de": de, "vers": vers, "motif": motif})
        if (de in ("essai", "confirme")) != (vers in ("essai", "confirme")):
            applique = True
    avant = {r["id"]: r["etat"] for r in regles.liste()}
    if reglage.confirmation_auto:
        _confirmer_les_essais_echus(etat, regles, magasin, reglage, maintenant, note)
    avant = {r["id"]: r["etat"] for r in regles.liste()}
    for r in regles.expirer(maintenant):
        note(r, avant[r["id"]], r["etat"], r["motif"])
    def declencheur(d: str) -> bool:
        if any(d == s or d.endswith("." + s) for s in reglage.declencheurs):
            return True
        return reglage.declencheurs_pub and classer(d) in dnstv_detect.CLASSES_PUB      # repère intelligent (#2047)

    for appareil, adresses in appareils(etat).items():
        evts = magasin.evenements(adresses, maintenant - HISTORIQUE_H * 3600)
        exclus = {r["domaine"] for r in regles.liste() if r["appareil"] == appareil}
        for c in dnstv_detect.detecter(evts, declencheur, classer, exclus,
                                       evts_declencheurs=evts if reglage.declencheurs_pub else None):
            try:
                n = regles.proposer(appareil, c.domaine, c.score, c.risque, maintenant)
            except dnstv_regles.ErreurRegle:
                break                                        # plafond atteint : on cesse de proposer, mais l'expiration et les signaux continuent
            if n is None:
                continue
            candidats += 1
            changements.append({"appareil": appareil, "domaine": c.domaine, "de": "", "vers": "candidat", "motif": c.motif})
            if reglage.auto_essai and c.risque == "faible":     # un candidat « partagé » ou « variable » reste à valider par un humain
                r = regles.transiter(n["id"], "essai", "auto", "essai automatique", maintenant)
                note(r, "candidat", "essai", "essai automatique")
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
            if (r["etat"] == "candidat" and r.get("origine") == "auto" and r["risque"] == "faible"
                    and str(r.get("motif", "")).startswith("confirmé sur ")):
                note(regles.transiter(r["id"], "essai", "auto", "essai automatique (confirmé ailleurs)", maintenant),
                     "candidat", "essai", "essai automatique (confirmé ailleurs)")
    return {"changements": changements, "candidats": candidats, "applique": applique, "agrege": agrege}
