# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: pilotage :: moteur des macros (#3702)

Déroule une macro sur des box réelles, EN SÉRIE : une box commence quand la précédente a fini sans écart ; écart, échec d'une étape,
délai dépassé ou box qui ne revient pas arrêtent toute l'exécution, les box suivantes restent `non_lancee`. Une box n'est que dans une
exécution à la fois (réservée avant le premier `await` du lancement : deux lancements simultanés donnent une exécution et un 409).
`arreter` agit APRÈS l'étape en cours, jamais au milieu d'une opération envoyée. Une étape `action` passe par l'`Executant` (en service :
`executer_action`, mêmes gardes et même audit `pilotage_action`) ; aucun autre chemin vers l'agent.

Le stockage (synchrone) est toujours appelé par `asyncio.to_thread`. Le temps est injecté (`horloge`, `attente`) : les essais ne dorment
jamais. Chaque décision est auditée (`pilotage_macro`) ; pas d'audit, pas de lancement (503). Le déroulement est publié sur le flux
`exec:<id>` (événement `macro`) ; les `operation` d'une box y sont relayées le temps de son tour.
"""
from __future__ import annotations

import asyncio
import logging
import re
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Awaitable, Callable, Optional, Protocol

from .macros import MacroInvalide, comparer, contient_forte, evaluer_condition, instantane, valider_etapes
from .operations import CATALOGUE, RE_UNITE
from .stockage import HORS_LIGNE_S

log = logging.getLogger("pilotage.moteur")

CIBLES_MAX = 32
FRAIS_S = 90.0                 # un relevé attend au plus ce délai un inventaire relevé APRÈS le début de l'étape
FENETRE_PROGRAMME_S = 120      # une macro programmée part dans les 120 s qui suivent son heure, jamais plus tard (pas de rattrapage)
ACTEUR_PLANIFICATEUR = "planificateur"
FINS_OPERATION = ("termine", "inconnu", "sans_reponse", "refuse")
RAISON_MAX = 300
TENTATIVES_MAX = 1024
NOTE_CONDITION = "mesure absente : condition tenue pour fausse"
NOTE_COMPARER = "mesure absente : comparaison impossible, aucun écart n'a pu être constaté"
_RE_HEURE = re.compile(r"([01]\d|2[0-3]):([0-5]\d)")


def cle_flux(ident: int) -> str:
    return f"exec:{ident}"


def _borne(v, n: int = RAISON_MAX) -> str:
    return "".join(c for c in str(v)[:n] if c.isprintable())


class EchecEtape(Exception):
    """Une étape a échoué ; le message est lisible (français) et borné. `resultat` complète le résultat rangé de l'étape."""

    def __init__(self, raison, resultat: Optional[dict] = None) -> None:
        super().__init__(_borne(raison))
        self.resultat = resultat


class RefusLancement(Exception):
    def __init__(self, statut: int, message: str) -> None:
        super().__init__(message)
        self.statut, self.message = statut, message


class Executant(Protocol):
    async def action(self, b: dict, action: str, args: dict, *, confirmation: Optional[str], support: Optional[str],
                     acteur: str) -> dict:
        """Rend au moins {"operation": int, "etat": str} ; lève EchecEtape."""

    async def releve(self, b: dict, duree_s: int, acteur: str) -> str:
        """Statut du relevé : ok, expire ou erreur ; lève EchecEtape."""


@dataclass
class _Execution:
    ident: int
    macro_id: Optional[str]
    nom: str
    etapes: list
    boxes: list
    confirmations: dict
    support: dict
    acteur: str
    programme: bool
    sautees: list = field(default_factory=list)

    @property
    def cibles(self) -> str:
        return ", ".join(b["nom"] for b in self.boxes)


def _noms_audit(noms: list) -> str:
    """Les noms de services lus sur une box ne vont à l'audit que s'ils ont la forme d'une unité secubox-* ; les autres sont comptés."""
    bons = [n for n in noms if isinstance(n, str) and RE_UNITE.fullmatch(n)]
    autres = len(noms) - len(bons)
    return ", ".join(bons) + (f" (+{autres} hors motif)" if autres else "")


def _decrire_ecart(etape: dict, r: dict) -> str:
    if etape["regle"] == "nouveau_service_en_echec":
        if r["nouveaux"]:
            return "nouveau service en échec : " + _noms_audit(r["nouveaux"])
        return f"services en échec en hausse de {r['hausse']}"
    return f"mémoire disponible en baisse de {r['baisse_mo']} Mo"


class Moteur:
    def __init__(self, stockage, executant: Executant, diffusion, audit: Callable[[str, dict], None], *,
                 horloge: Callable[[], float] = time.time, attente: Callable[[float], Awaitable] = asyncio.sleep,
                 sonde_s: float = 1.0, frais_s: float = FRAIS_S, resoudre: Callable[[str], Optional[dict]]) -> None:
        self.stockage, self.executant, self.diffusion, self.audit = stockage, executant, diffusion, audit
        self.horloge, self.attente, self.sonde_s, self.frais_s, self.resoudre = horloge, attente, sonde_s, frais_s, resoudre
        self.taches: dict = {}          # id d'exécution -> tâche de déroulement
        self._reservees: dict = {}      # Box.cle -> id d'exécution (None pendant le lancement)
        self._arrets: set = set()
        self._tentes: dict = {}         # macro programmée -> instant de l'heure déjà tentée (une tentative par heure)

    # --- outils ---

    def _en_ligne(self, b: Optional[dict]) -> bool:
        return b is not None and self.horloge() - b["vu_le"] < HORS_LIGNE_S

    def _champs(self, x: _Execution, evenement: str, etat: Optional[str], raison: Optional[str], **extra) -> dict:
        return {"evenement": evenement, "execution": x.ident, "macro": x.macro_id, "nom": x.nom, "cibles": x.cibles,
                "acteur": x.acteur, "etat": etat, "raison": raison, **extra}

    async def _auditer(self, champs: dict) -> None:
        """Après coup : un échec d'audit est journalisé, le déroulement continue (seul le lancement exige l'audit)."""
        try:
            await asyncio.to_thread(self.audit, "pilotage_macro", champs)
        except Exception:
            log.exception("audit pilotage_macro %s impossible", champs.get("evenement"))

    def _publier(self, x: _Execution, evenement: str, b: Optional[dict] = None, rang: Optional[int] = None,
                 type_: Optional[str] = None, etat: Optional[str] = None, resultat=None, raison: Optional[str] = None) -> None:
        self.diffusion.publier(cle_flux(x.ident), "macro", {
            "execution": x.ident, "evenement": evenement, "box": b["nom"] if b else None, "cle": b["cle"] if b else None,
            "rang": rang, "type": type_, "etat": etat, "resultat": resultat, "raison": raison})

    async def _noter(self, x: _Execution, b: dict, rang: int, etat: str, resultat=None, raison: Optional[str] = None) -> None:
        await asyncio.to_thread(self.stockage.etape_noter, x.ident, b["cle"], rang, etat, resultat)
        self._publier(x, "etape", b, rang, x.etapes[rang]["type"], etat, resultat, raison)

    # --- lancement ---

    async def lancer(self, macro: dict, boxes: list, confirmations: dict, support: dict, acteur: str, *,
                     programme: bool = False, absentes: tuple = ()) -> int:
        """`confirmations` et `support` sont indexés par `Box.cle`. `absentes` : noms de cibles introuvables (planificateur), notés à
        l'audit du lancement."""
        try:
            etapes = valider_etapes(macro.get("etapes"))
        except MacroInvalide as exc:
            raise RefusLancement(400, str(exc)) from None
        if not isinstance(boxes, list) or not 1 <= len(boxes) <= CIBLES_MAX:
            raise RefusLancement(400, f"une exécution vise 1 à {CIBLES_MAX} box")
        cles = [b["cle"] for b in boxes]
        if len(set(cles)) != len(cles):
            raise RefusLancement(400, "une box figure deux fois dans les cibles")
        prises = [b["nom"] for b in boxes if b["cle"] in self._reservees]
        if prises:
            raise RefusLancement(409, "box déjà dans une exécution en cours : " + ", ".join(prises))
        for c in cles:                  # réservées AVANT le premier await
            self._reservees[c] = None
        try:
            hors = [b["nom"] for b in boxes if not self._en_ligne(b)]
            if hors and not programme:
                raise RefusLancement(409, "box hors ligne : " + ", ".join(hors))
            for b in boxes:
                if b["reseau"] != "maillage":
                    sid = support.get(b["cle"])
                    if not isinstance(sid, str) or await asyncio.to_thread(self.stockage.support_ouvert, b["cle"], sid) is None:
                        raise RefusLancement(409, f"box cliente {b['nom']} : session de support ouverte requise (accord du détenteur)")
            if contient_forte(etapes):
                for b in boxes:
                    if b["reseau"] == "maillage" and confirmations.get(b["cle"]) != b["nom"]:
                        raise RefusLancement(400, f"confirmation : retapez exactement le nom de la box {b['nom']}")
            notes = []
            if absentes:
                notes.append("cible introuvable, sautée : " + ", ".join(absentes))
            if hors:
                notes.append("hors ligne au lancement : " + ", ".join(hors))
            x = _Execution(0, macro.get("id"), macro["nom"], etapes, list(boxes), dict(confirmations), dict(support),
                           _borne(acteur, 64), programme)
            try:
                await asyncio.to_thread(self.audit, "pilotage_macro", self._champs(x, "lancement", "en_cours", " ; ".join(notes) or None,
                                                                                  execution=None))
            except Exception:
                log.exception("audit du lancement impossible : exécution refusée")
                raise RefusLancement(503, "audit indisponible") from None
            x.ident = await asyncio.to_thread(self.stockage.execution_creer, x.macro_id, x.nom,
                                              [{"cle": b["cle"], "nom": b["nom"]} for b in boxes], etapes, x.acteur)
        except BaseException:
            for c in cles:
                self._reservees.pop(c, None)
            raise
        for c in cles:
            self._reservees[c] = x.ident
        tache = asyncio.create_task(self._derouler(x))
        self.taches[x.ident] = tache
        tache.add_done_callback(lambda _t, i=x.ident: self.taches.pop(i, None))
        return x.ident

    def arreter(self, ident: int) -> bool:
        """Demande l'arrêt après l'étape en cours. Faux si l'exécution est inconnue ou finie."""
        if ident not in self.taches:
            return False
        self._arrets.add(ident)
        return True

    def occupees(self) -> set:
        return set(self._reservees)

    # --- déroulement ---

    async def _derouler(self, x: _Execution) -> None:
        etat, raison = "terminee", None
        try:
            self._publier(x, "lancement", etat="en_cours")
            for b in x.boxes:
                issue, motif = await self._box(x, b)
                if issue == "sautee":
                    x.sautees.append(b["nom"])
                    continue
                if issue != "terminee":
                    etat, raison = issue, motif
                    break
            if etat == "arretee":
                await self._auditer(self._champs(x, "arret", etat, raison))
            if etat == "terminee" and x.sautees:
                raison = "box sautées (hors ligne) : " + ", ".join(x.sautees)
            await asyncio.to_thread(self.stockage.etapes_clore, x.ident, "non_lancee")
            await asyncio.to_thread(self.stockage.execution_finir, x.ident, etat, raison)
        except asyncio.CancelledError:
            raise                       # arrêt du service : l'exécution reste en_cours, interrompue au prochain démarrage
        except Exception:
            log.exception("exécution %s : erreur du moteur", x.ident)
            etat, raison = "echec", "erreur interne du moteur"
            try:
                await asyncio.to_thread(self.stockage.etapes_clore, x.ident, "non_lancee")
                await asyncio.to_thread(self.stockage.execution_finir, x.ident, etat, raison)
            except Exception:
                log.exception("exécution %s : fin non rangée", x.ident)
        finally:
            for b in x.boxes:
                if self._reservees.get(b["cle"]) == x.ident:
                    del self._reservees[b["cle"]]
            self._arrets.discard(x.ident)
        await self._auditer(self._champs(x, "fin", etat, raison))
        self._publier(x, "fin", etat=etat, raison=raison)

    async def _box(self, x: _Execution, b0: dict):
        """(issue, raison) : issue ∈ terminee, sautee, ecart, echec, arretee."""
        if x.ident in self._arrets:
            return "arretee", "arrêt demandé"
        b = await asyncio.to_thread(self.stockage.boite, b0["cle"])
        if not self._en_ligne(b):
            if x.programme:
                await asyncio.to_thread(self.stockage.etapes_clore, x.ident, "sautee", b0["cle"])
                self._publier(x, "box", b0, etat="sautee", raison="box hors ligne")
                return "sautee", None
            await self._noter(x, b0, 0, "echec", {"raison": "box hors ligne"}, "box hors ligne")
            self._publier(x, "box", b0, etat="echec", raison="box hors ligne")
            return "echec", f"{b0['nom']} : box hors ligne"
        flux = cle_flux(x.ident)
        self.diffusion.relayer(b["cle"], flux)
        try:
            self._publier(x, "box", b, etat="en_cours")
            issue, raison = await self._etapes(x, b)
            self._publier(x, "box", b, etat=issue, raison=raison)
            return issue, raison
        finally:
            self.diffusion.cesser(b["cle"], flux)

    async def _etapes(self, x: _Execution, b: dict):
        cliente = b["reseau"] != "maillage"
        sid = x.support.get(b["cle"]) if cliente else None
        reboots: list = []
        passer = False
        for rang, e in enumerate(x.etapes):
            if x.ident in self._arrets:
                return "arretee", "arrêt demandé"
            if passer:
                passer = False
                await self._noter(x, b, rang, "passee", {"raison": "passée par la condition précédente"})
                continue
            await self._noter(x, b, rang, "en_cours")
            try:
                if cliente and await asyncio.to_thread(self.stockage.support_ouvert, b["cle"], sid) is None:
                    raise EchecEtape("session de support échue")
                etat, resultat, note, effet = await self._etape(x, b, e, reboots)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                if not isinstance(exc, EchecEtape):
                    log.exception("exécution %s, %s, étape %d : erreur", x.ident, b["cle"], rang + 1)
                    exc = EchecEtape("erreur interne du moteur")
                motif = str(exc)
                await self._noter(x, b, rang, "echec", {**(exc.resultat or {}), "raison": motif}, motif)
                return "echec", f"{b['nom']} : étape {rang + 1} ({e['type']}) : {motif}"
            if note:
                resultat = {**resultat, "note": note}
                log.info("exécution %s, %s, étape %d : %s", x.ident, b["cle"], rang + 1, note)
            await self._noter(x, b, rang, etat, resultat, note)
            if effet == "ecart":
                motif = _decrire_ecart(e, resultat)
                await self._auditer(self._champs(x, "ecart", "ecart", f"{b['nom']} : {motif}",
                                                 nouveaux=_noms_audit(resultat["nouveaux"])))
                return "ecart", f"{b['nom']} : écart à l'étape {rang + 1} : {motif}"
            if effet == "arreter":
                await asyncio.to_thread(self.stockage.etapes_clore, x.ident, "passee", b["cle"])
                return "terminee", "condition vraie : reste de la box passé"
            passer = effet == "passer"
        return "terminee", None

    async def _etape(self, x: _Execution, b: dict, e: dict, reboots: list):
        """(etat, resultat, note, effet) ; effet ∈ None, ecart, arreter, passer. Lève EchecEtape."""
        t = e["type"]
        if t == "action":
            return "ok", await self._action(x, b, e, reboots), None, None
        if t == "releve":
            return "ok", await self._releve(x, b, e), None, None
        if t == "condition":
            releves = await asyncio.to_thread(self.stockage.releves_execution, x.ident, b["cle"])
            r = evaluer_condition(e, releves)
            return "ok", r, NOTE_CONDITION if r["mesure_absente"] else None, e["alors"] if r["vrai"] else None
        if t == "comparer":
            releves = await asyncio.to_thread(self.stockage.releves_execution, x.ident, b["cle"])
            r = comparer(e, releves)
            if r["ecart"]:
                return "ecart", r, None, "ecart"
            return "ok", r, NOTE_COMPARER if r["mesure_absente"] else None, None
        if t == "attendre":
            return "ok", await self._attendre(b, e, reboots), None, None
        raise EchecEtape("type d'étape inconnu")     # valider_etapes l'a déjà refusé

    async def _action(self, x: _Execution, b: dict, e: dict, reboots: list) -> dict:
        act = CATALOGUE[e["action"]]
        maillage = b["reseau"] == "maillage"
        confirmation = x.confirmations.get(b["cle"]) if act.forte and maillage else None
        support = x.support.get(b["cle"]) if not maillage else None
        limite = self.horloge() + e["delai_s"]
        rep = await self.executant.action(b, e["action"], e["args"], confirmation=confirmation, support=support, acteur=x.acteur)
        op = rep.get("operation")
        if rep.get("etat") != "accepte":
            if rep.get("etat") == "consentement":
                raise EchecEtape("une macro n'attend pas l'accord du détenteur", {"operation": op})
            raise EchecEtape(f"action refusée par la box ({_borne(rep.get('etat'), 40)})", {"operation": op})
        while True:
            o = await asyncio.to_thread(self.stockage.operation_lire, op)
            if o is None:
                raise EchecEtape("opération introuvable", {"operation": op})
            if o["etat"] in FINS_OPERATION:
                break
            if self.horloge() >= limite:
                raise EchecEtape(f"délai dépassé ({e['delai_s']} s) : l'opération n'est pas finie", {"operation": op})
            await self.attente(self.sonde_s)
        if e["action"] == "reboot":
            reboots.append(op)
        res = {"operation": op, "rc": o.get("rc"), "resume": o.get("resume")}
        if o["etat"] == "termine" and o.get("resultat") == "succes":
            return res
        raise EchecEtape(f"{e['action']} : {o.get('resultat') or o['etat']}", res)

    def _mesures(self, cle: str, depuis: float):
        """(resume, valeurs) si la box a un inventaire relevé à `depuis` ou après, sinon None."""
        resume = next((r for r in self.stockage.resumes() if r["cle"] == cle), None)
        le = resume.get("inventaire_le") if resume else None
        if not isinstance(le, (int, float)) or le < depuis:
            return None
        return resume, self.stockage.inventaire(cle)["valeurs"]

    async def _releve(self, x: _Execution, b: dict, e: dict) -> dict:
        t0 = self.horloge()
        statut = await self.executant.releve(b, e["duree_s"], x.acteur)
        if statut != "ok":
            raise EchecEtape(f"relevé : {_borne(statut, 40)}")
        # l'inventaire n'est relevé que périodiquement : jamais d'instantané sur un inventaire antérieur au début de l'étape
        limite = self.horloge() + self.frais_s
        while (m := await asyncio.to_thread(self._mesures, b["cle"], t0)) is None:
            if self.horloge() >= limite:
                raise EchecEtape(f"inventaire non rafraîchi {int(self.frais_s)} s après le relevé")
            await self.attente(self.sonde_s)
        inst = instantane(*m)
        await asyncio.to_thread(self.stockage.releve_ranger, x.ident, b["cle"], e["nom"], inst)
        return inst

    async def _attendre(self, b: dict, e: dict, reboots: list) -> dict:
        """Box vue depuis moins de HORS_LIGNE_S ET tout reboot de cette box dans cette exécution terminé (clos par vu() au nouveau
        boot_id)."""
        limite = self.horloge() + e["delai_s"]
        while True:
            vue = await asyncio.to_thread(self.stockage.boite, b["cle"])
            ops = [await asyncio.to_thread(self.stockage.operation_lire, op) for op in reboots]
            if self._en_ligne(vue) and all(o is not None and o["etat"] == "termine" for o in ops):
                return {"vu_le": vue["vu_le"]}
            if self.horloge() >= limite:
                raise EchecEtape("la box n'est pas revenue")
            await self.attente(self.sonde_s)

    # --- cycle de vie ---

    async def interrompre_au_demarrage(self) -> list:
        """Toute exécution `en_cours` (service arrêté pendant son déroulement) passe `interrompue`, sans reprise ; chacune est auditée."""
        lignes = await asyncio.to_thread(self.stockage.executions_interrompre)
        for e in lignes:
            await self._auditer({"evenement": "fin", "execution": e["id"], "macro": e["macro_id"], "nom": e["macro_nom"],
                                 "cibles": ", ".join(c["nom"] for c in e["cibles"]), "acteur": e["acteur"], "etat": "interrompue",
                                 "raison": e["raison"]})
        return [e["id"] for e in lignes]

    async def fermer(self) -> None:
        """Annule les déroulements ; leurs exécutions restent `en_cours` et passeront `interrompue` au démarrage suivant."""
        taches = list(self.taches.values())
        for t in taches:
            t.cancel()
        if taches:
            await asyncio.gather(*taches, return_exceptions=True)

    # --- planificateur ---

    async def tic(self, maintenant: datetime) -> list:
        """Lance les macros programmées dont l'heure (locale) est passée de moins de FENETRE_PROGRAMME_S ; une heure manquée n'est
        jamais rattrapée. Une macro en erreur n'empêche pas les autres. Rend les identifiants lancés."""
        lances = []
        for m in await asyncio.to_thread(self.stockage.macros_programmees):
            try:
                ident = await self._programmee(m, maintenant)
            except asyncio.CancelledError:
                raise
            except Exception:
                log.exception("planificateur : macro %s non lancée", m.get("id"))
                continue
            if ident is not None:
                lances.append(ident)
        return lances

    async def _programmee(self, m: dict, maintenant: datetime) -> Optional[int]:
        h = _RE_HEURE.fullmatch(str((m.get("programmation") or {}).get("quotidien", "")))
        if h is None:
            return None
        t = maintenant.replace(hour=int(h[1]), minute=int(h[2]), second=0, microsecond=0)
        if not 0 <= (maintenant - t).total_seconds() < FENETRE_PROGRAMME_S:
            return None
        depuis = int(t.timestamp())
        if self._tentes.get(m["id"]) == depuis or await asyncio.to_thread(self.stockage.execution_programmee_depuis, m["id"], depuis):
            return None
        if len(self._tentes) >= TENTATIVES_MAX:
            self._tentes.pop(next(iter(self._tentes)))
        self._tentes[m["id"]] = depuis
        x = _Execution(None, m["id"], m["nom"], m["etapes"], [], {}, {}, ACTEUR_PLANIFICATEUR, True)
        refus = "une étape exige la confirmation forte" if contient_forte(m["etapes"]) else None
        absentes = []
        for c in m.get("cibles") or []:
            b = await asyncio.to_thread(self.resoudre, c["cle"])
            if b is None:                  # renommée ou oubliée depuis l'enregistrement
                absentes.append(c.get("nom") or c["cle"])
                continue
            if b["reseau"] != "maillage":
                refus = refus or f"box cliente {b['nom']} : une macro programmée ne vise pas une box cliente"
            x.boxes.append(b)
        if refus is None and not x.boxes:
            refus = "aucune cible connue"
        if refus is None:
            try:
                return await self.lancer(m, x.boxes, {}, {}, ACTEUR_PLANIFICATEUR, programme=True, absentes=tuple(absentes))
            except RefusLancement as exc:
                refus = exc.message
        await self._auditer(self._champs(x, "refus_programme", "refuse", _borne(refus)))
        return None

    async def planifier(self, maintenant_local: Callable[[], datetime], periode_s: float = 60.0) -> None:
        """Boucle du planificateur : un tic toutes les `periode_s` ; un tic qui lève est journalisé et la boucle continue."""
        while True:
            try:
                await self.tic(maintenant_local())
            except asyncio.CancelledError:
                raise
            except Exception:
                log.exception("tic du planificateur en échec ; la boucle continue")
            await self.attente(periode_s)
