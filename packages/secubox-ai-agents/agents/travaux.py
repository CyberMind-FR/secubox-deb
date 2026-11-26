# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Travaux de fond (#3990) : recherche approfondie, digest du matin, planificateur. Lecture seule.

- Recherche : `NativeReActAgent` d'OpenJarvis (Thought / Action / Observation en texte). `DeepResearchAgent`
  exige l'appel d'outils natif, que Gemma 3 4B ne produit pas sur le llama-server du POC (essai du
  2026-11-26 : il répond sans chercher, en inventant) : il n'est donc pas utilisé.
- Digest : `MorningDigestAgent` d'OpenJarvis, avec NOTRE `digest_collect` (thèmes → SearXNG) ; synthèse vocale
  absente (outil retiré) : le digest est un texte. Archivé dans le `DigestStore` d'OpenJarvis et en mémoire.
- Planificateur : `TaskScheduler` + `SchedulerStore` d'OpenJarvis (SQLite, persistant) ; `system.ask` est ici
  un répartiteur vers nos deux travaux, rien d'autre.

Bornes : un travail à la fois (le moteur a deux places, l'une sert gk3) ; durée (échéance des outils + délai
du moteur) ; nombre d'appels d'outil ; tâches planifiées : 10 actives au plus, une heure entre deux passages au
moins. Annulation coopérative : les outils refusent, le résultat tardif est jeté.
Politique de capacités : refus par défaut ; seules les capacités de lecture des outils sont accordées, à
l'identifiant d'agent qui en a besoin.
"""
from __future__ import annotations

import json
import logging
import os
import re
import secrets
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from openjarvis.agents.digest_store import DigestStore
from openjarvis.agents.morning_digest import MorningDigestAgent
from openjarvis.agents.native_react import NativeReActAgent
from openjarvis.scheduler.scheduler import TaskScheduler
from openjarvis.scheduler.store import SchedulerStore
from openjarvis.security.capabilities import CapabilityPolicy

from agents.outils import CollecteDigest, Contexte, RechercheMemoire, RechercheWeb

log = logging.getLogger("secubox.ai.agents.travaux")

CONSIGNES = Path(__file__).parent / "consignes"
DUREE_MAX_S = 600
TRAVAUX_GARDES = 50
TACHES_MAX = 10
INTERVALLE_MIN_S = 3600
FUSEAU = "Europe/Paris"
ENTETE_RE = re.compile(r"\A<!--.*?-->", re.DOTALL)
HEURE_RE = re.compile(r"^([01]\d|2[0-3]):([0-5]\d)$")
THEMES_MAX = 6
AGENT_RECHERCHE, AGENT_DIGEST = "secubox-recherche", "secubox-digest"


def politique() -> CapabilityPolicy:
    p = CapabilityPolicy(default_deny=True)
    p.grant("recherche", "network:fetch")
    p.grant("recherche", "memory:read")
    p.grant("morning_digest", "network:fetch")
    p.grant("morning_digest", "memory:read")
    return p


def installer_consignes(oj_home: Path) -> None:
    """Consignes françaises par le mécanisme d'OpenJarvis ($OPENJARVIS_HOME/agents/…, prompts/personas/…)."""
    (oj_home / "agents/native_react").mkdir(parents=True, exist_ok=True)
    (oj_home / "prompts/personas").mkdir(parents=True, exist_ok=True)
    for source, cible in (("native_react.md", "agents/native_react/system_prompt.md"),
                          ("persona-secubox.md", "prompts/personas/secubox.md")):
        texte = ENTETE_RE.sub("", (CONSIGNES / source).read_text(encoding="utf-8"), count=1)
        (oj_home / cible).write_text(texte.lstrip(), encoding="utf-8")   # l'en-tête de licence n'est pas une consigne


class Travaux:
    def __init__(self, etat: Path, moteur, memoires, traces=None, evaluations=None) -> None:
        self.etat, self.moteur, self.memoires = etat, moteur, memoires
        self.traces, self.evaluations = traces, evaluations
        self._liste: dict[str, dict] = {}
        self._ctx: dict[str, Contexte] = {}
        self._verrou = threading.Lock()
        self._moteur_libre = threading.Lock()
        self.politique = politique()
        self._config_digest = etat / "digest.json"

    # -- registre -------------------------------------------------------------------------------------------
    def _nouveau(self, genre: str, titre: str, origine: str) -> tuple[str, Contexte]:
        with self._verrou:
            if any(t["etat"] == "en_cours" for t in self._liste.values()):
                raise RuntimeError("un travail est déjà en cours")
            ident = secrets.token_hex(8)
            self._liste[ident] = {"id": ident, "genre": genre, "titre": titre[:200], "origine": origine,
                                  "etat": "en_cours", "debut": time.time(), "fin": None, "resultat": "",
                                  "sources": [], "verifie": None, "erreur": None}
            ctx = Contexte(echeance=time.monotonic() + DUREE_MAX_S)
            self._ctx[ident] = ctx
            for vieux in sorted(self._liste, key=lambda k: self._liste[k]["debut"])[:-TRAVAUX_GARDES]:
                self._liste.pop(vieux, None)
                self._ctx.pop(vieux, None)
        return ident, ctx

    def _finir(self, ident: str, **champs: Any) -> None:
        with self._verrou:
            t = self._liste.get(ident)
            if t is None or t["etat"] == "annule":
                return                      # annulé : le résultat tardif est jeté
            t.update(champs, fin=time.time())

    def lister(self) -> list[dict]:
        with self._verrou:
            return sorted((dict(t) for t in self._liste.values()), key=lambda t: -t["debut"])

    def lire(self, ident: str) -> dict | None:
        with self._verrou:
            t = self._liste.get(ident)
            return dict(t) if t else None

    def annuler(self, ident: str) -> bool:
        with self._verrou:
            t = self._liste.get(ident)
            if not t or t["etat"] != "en_cours":
                return False
            t.update(etat="annule", fin=time.time())
            self._ctx[ident].annule.set()
        return True

    # -- recherche ----------------------------------------------------------------------------------------
    def demarrer_recherche(self, question: str, origine: str = "page") -> str:
        ident, ctx = self._nouveau("recherche", question, origine)
        threading.Thread(target=self._recherche, args=(ident, ctx, question), daemon=True,
                         name=f"recherche-{ident}").start()
        return ident

    def _recherche(self, ident: str, ctx: Contexte, question: str) -> None:
        try:
            with self._moteur_libre:
                agent = NativeReActAgent(self.moteur._e, self.moteur.modele(),
                                         tools=[RechercheWeb(ctx), RechercheMemoire(ctx, self.memoires)],
                                         max_turns=5, max_tokens=700, temperature=0.2,
                                         capability_policy=self.politique, agent_id="recherche")
                r = agent.run(question)
            web = [tr for tr in r.tool_results if tr.tool_name == "web_search" and tr.success]
            verifie = bool(ctx.sources) and bool(web)
            texte = r.content.strip()
            if not verifie:
                texte = "[Réponse non vérifiée : aucune source web n'a été lue.]\n\n" + texte
            self._finir(ident, etat="fini", resultat=texte, sources=list(ctx.sources), verifie=verifie)
            if verifie and not ctx.annule.is_set():
                corps = texte + "\n\nSources :\n" + "\n".join(f"[{i}] {s['titre']} — {s['url']}"
                                                              for i, s in enumerate(ctx.sources, 1))
                self.memoires._garder("recherche", question[:200], corps, "reponse")
        except Exception as exc:  # noqa: BLE001 — l'erreur est montrée, le contenu n'est pas journalisé
            log.warning("recherche en échec : %s", type(exc).__name__)
            self._finir(ident, etat="echec", erreur=type(exc).__name__)

    # -- digest -------------------------------------------------------------------------------------------
    def config_digest(self) -> dict:
        try:
            return json.loads(self._config_digest.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {"actif": False, "heure": "07:30", "themes": ["cybersécurité", "Debian"]}

    def ecrire_config_digest(self, actif: bool, heure: str, themes: list[str]) -> dict:
        if not HEURE_RE.match(heure):
            raise ValueError("heure HH:MM attendue")
        themes = [t.strip()[:80] for t in themes if t and t.strip()][:THEMES_MAX]
        if not themes:
            raise ValueError("au moins un thème")
        cfg = {"actif": bool(actif), "heure": heure, "themes": themes}
        tmp = self._config_digest.with_suffix(".tmp")
        tmp.write_text(json.dumps(cfg, ensure_ascii=False), encoding="utf-8")
        tmp.replace(self._config_digest)       # double tampon : jamais de fichier à moitié écrit
        return cfg

    def demarrer_digest(self, origine: str = "page") -> str:
        cfg = self.config_digest()
        ident, ctx = self._nouveau("digest", "Point du matin : " + ", ".join(cfg["themes"]), origine)
        ctx.appels_max = len(cfg["themes"])
        threading.Thread(target=self._digest, args=(ident, ctx, cfg["themes"]), daemon=True,
                         name=f"digest-{ident}").start()
        return ident

    def _digest(self, ident: str, ctx: Contexte, themes: list[str]) -> None:
        try:
            with self._moteur_libre:
                agent = MorningDigestAgent(self.moteur._e, self.moteur.modele(), tools=[CollecteDigest(ctx, themes)],
                                           capability_policy=self.politique, agent_id="morning_digest",
                                           max_tokens=700, temperature=0.3, persona="secubox", sections=["world"],
                                           section_sources={"world": ["searxng-local"]}, timezone=FUSEAU,
                                           honorific="", digest_store_path=str(self.etat / "digests.db"))
                r = agent.run("Point du matin")
            texte = r.content.strip()
            ok = bool(ctx.sources) and bool(texte)
            self._finir(ident, etat="fini" if ok else "echec", resultat=texte, sources=list(ctx.sources),
                        verifie=ok, erreur=None if ok else "aucune actualité lue")
            if ok and not ctx.annule.is_set():
                corps = texte + "\n\nSources :\n" + "\n".join(f"[{i}] {s['titre']} — {s['url']}"
                                                              for i, s in enumerate(ctx.sources, 1))
                self.memoires._garder("digest", datetime.now().strftime("Point du %d/%m/%Y"), corps, "reponse")
        except Exception as exc:  # noqa: BLE001
            log.warning("digest en échec : %s", type(exc).__name__)
            self._finir(ident, etat="echec", erreur=type(exc).__name__)

    def digests(self, n: int = 10) -> list[dict]:
        s = DigestStore(db_path=str(self.etat / "digests.db"))
        try:
            return [{"texte": d.text, "quand": d.generated_at.isoformat(timespec="minutes"),
                     "qualite": d.quality_score} for d in s.history(limit=n)]
        finally:
            s.close()


    # -- évaluation (#3992) -------------------------------------------------------------------------------
    @staticmethod
    def socket_second() -> str:
        return os.environ.get("SECUBOX_AI_AGENTS_MOTEUR2", "/run/secubox-ai-eval/moteur.sock")

    def second_disponible(self) -> bool:
        return Path(self.socket_second()).is_socket()

    def demarrer_evaluation(self, moteur: str, echantillons: int | None = None) -> str:
        socket = self.moteur.socket if moteur == "actif" else self.socket_second()
        ident, ctx = self._nouveau("evaluation", f"Évaluation — moteur {moteur}", "page")
        threading.Thread(target=self._evaluation, args=(ident, ctx, socket, moteur, echantillons), daemon=True,
                         name=f"evaluation-{ident}").start()
        return ident

    def _evaluation(self, ident: str, ctx: Contexte, socket: str, moteur: str, echantillons: int | None) -> None:
        from agents.evaluation import evaluer
        try:
            verrou = self._moteur_libre if moteur == "actif" else threading.Lock()
            with verrou:
                r = evaluer(socket, moteur, self.traces, self.etat / "evaluations", max_echantillons=echantillons)
            if ctx.annule.is_set():
                return
            self.evaluations.ajouter(r)
            self._finir(ident, etat="fini", verifie=True,
                        resultat=(f"{r['modele']} : {r['justes']}/{r['n']} justes, latence moyenne {r['latence_s']} s, "
                                  f"premier mot {r['premier_s']} s, {r['debit_js']} j/s"))
        except Exception as exc:  # noqa: BLE001
            log.warning("évaluation en échec : %s", type(exc).__name__)
            self._finir(ident, etat="echec", erreur=type(exc).__name__)


class Repartiteur:
    """Le `system` attendu par TaskScheduler : `ask(prompt, agent=…)` lance l'un de nos deux travaux et attend."""

    def __init__(self, travaux: Travaux) -> None:
        self.travaux = travaux

    def ask(self, prompt: str, agent: str = "", **_: Any) -> str:
        if agent == AGENT_DIGEST:
            ident = self.travaux.demarrer_digest(origine="planificateur")
        elif agent == AGENT_RECHERCHE:
            ident = self.travaux.demarrer_recherche(prompt, origine="planificateur")
        else:
            raise ValueError(f"agent planifié inconnu : {agent!r}")
        limite = time.monotonic() + DUREE_MAX_S + 60
        while time.monotonic() < limite:
            t = self.travaux.lire(ident) or {}
            if t.get("etat") != "en_cours":
                if t.get("etat") != "fini":
                    raise RuntimeError(t.get("erreur") or t.get("etat") or "travail perdu")
                return t.get("resultat", "")
            time.sleep(2)
        self.travaux.annuler(ident)
        raise TimeoutError("travail planifié trop long")


class Planificateur:
    def __init__(self, etat: Path, travaux: Travaux, *, intervalle_scrutation: int = 60) -> None:
        self.store = SchedulerStore(str(etat / "planificateur.db"))
        self.s = TaskScheduler(self.store, Repartiteur(travaux), poll_interval=intervalle_scrutation)
        self.travaux = travaux

    def demarrer(self) -> None:
        self.s.start()

    def arreter(self) -> None:
        self.s.stop()
        self.store.close()

    def lister(self) -> list[dict]:
        sortie = []
        for t in self.s.list_tasks():
            if t.status == "cancelled":
                continue
            d = t.to_dict()
            d["passages"] = self.store.get_run_logs(t.id, limit=5)
            sortie.append(d)
        return sortie

    def _actives(self) -> int:
        return sum(1 for t in self.s.list_tasks() if t.status == "active")

    def ajouter_recherche(self, question: str, type_: str, valeur: str) -> dict:
        if self._actives() >= TACHES_MAX:
            raise ValueError(f"au plus {TACHES_MAX} tâches actives")
        question = question.strip()[:500]
        if not question:
            raise ValueError("question vide")
        if type_ == "interval":
            if not valeur.isdigit() or int(valeur) < INTERVALLE_MIN_S:
                raise ValueError(f"intervalle : {INTERVALLE_MIN_S} s au moins")
        elif type_ == "once":
            try:
                quand = datetime.fromisoformat(valeur)
            except ValueError as exc:
                raise ValueError("date ISO attendue") from exc
            if quand.tzinfo is None:
                raise ValueError("date avec fuseau attendue")
            if quand < datetime.now(timezone.utc) + timedelta(minutes=1):
                raise ValueError("date passée")
            valeur = quand.astimezone(timezone.utc).isoformat()
        else:
            raise ValueError("type : interval ou once")
        return self.s.create_task(question, type_, valeur, agent=AGENT_RECHERCHE,
                                  metadata={"genre": "recherche"}).to_dict()

    def synchroniser_digest(self, cfg: dict) -> None:
        """Une seule tâche « digest », recréée à chaque réglage ; supprimée si le digest est désactivé."""
        for t in self.s.list_tasks():
            if (t.metadata or {}).get("genre") == "digest" and t.status != "cancelled":
                self.s.cancel_task(t.id)
        if cfg.get("actif"):
            hh, mm = cfg["heure"].split(":")
            self.s.create_task("Point du matin", "cron", f"{int(mm)} {int(hh)} * * *", agent=AGENT_DIGEST,
                               metadata={"genre": "digest", "timezone": FUSEAU})

    def mettre_en_pause(self, ident: str) -> None:
        self._connue(ident)
        self.s.pause_task(ident)

    def reprendre(self, ident: str) -> None:
        self._connue(ident)
        self.s.resume_task(ident)

    def annuler(self, ident: str) -> None:
        self._connue(ident)
        self.s.cancel_task(ident)

    def _connue(self, ident: str) -> None:
        if not re.fullmatch(r"[0-9a-f]{16}", ident) or self.store.get_task(ident) is None:
            raise KeyError(ident)
