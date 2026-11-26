# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Évaluation et apprentissage (#3992, tranche B) : ce qu'OpenJarvis fournit RÉELLEMENT, branché tel quel.

Évaluation — `openjarvis.evals.core` :
- `EvalRunner` (exécution, statistiques `RunSummary` : exactitude, latence, premier mot, débit) ;
- notre `DatasetProvider` (jeu local `agents/jeux/jeu-secubox-fr.jsonl`, aucun téléchargement) ;
- notre `Scorer` déterministe (mots attendus, sans juge LLM : les juges d'OpenJarvis visent un modèle
  infonuagique, `RunConfig.judge_engine = "cloud"`) ;
- notre `InferenceBackend` sur socket Unix (moteur actif du POC, ou second moteur d'évaluation).

Apprentissage — `openjarvis.traces` et `openjarvis.learning.routing` :
- chaque réponse de la conversation et chaque échantillon évalué devient une `Trace` (`TraceStore`, SQLite) ;
  le retour 👍/👎 est `TraceStore.update_feedback` (1,0 / 0,0) ;
- `LearnedRouterPolicy.update(trace_store)` apprend « classe de question → meilleur modèle » (0,6 × réussite
  + 0,4 × retour, 5 échantillons au moins par classe). Rendu en RECOMMANDATION : la conversation n'a qu'un
  moteur ; rien ne bascule seul.
- les corrections écrites au 👎 vont en mémoire (agent `corrections`) et sont reprises, en priorité, par les
  réponses suivantes : c'est l'effet visible des retours.

Ce qui existe dans OpenJarvis mais N'EST PAS utilisé ici : `LLMOptimizer` (exige un modèle infonuagique),
`dspy`/`gepa` (dépendances absentes du venv), `learning/training` (LoRA, SFT, GRPO : torch, entraînement de
poids, exclu sans accord du propriétaire), `personal/` (juge LLM), `spec_search`.
"""
from __future__ import annotations

import json
import sqlite3
import threading
import time
import unicodedata
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

import httpx
from openjarvis.core.types import StepType, Trace, TraceStep
from openjarvis.engine.openai_compat_engines import LlamaCppEngine
from openjarvis.evals.core.backend import InferenceBackend
from openjarvis.evals.core.dataset import DatasetProvider
from openjarvis.evals.core.runner import EvalRunner
from openjarvis.evals.core.scorer import Scorer
from openjarvis.evals.core.types import EvalRecord, RunConfig
from openjarvis.learning.routing.learned_router import LearnedRouterPolicy
from openjarvis.traces.store import TraceStore

JEU = Path(__file__).resolve().parent / "jeux" / "jeu-secubox-fr.jsonl"
CONSIGNE_EVAL = "Réponds en français, brièvement et exactement."
MAX_TOKENS = 200


def normaliser(texte: str) -> str:
    t = unicodedata.normalize("NFKD", texte.lower())
    return "".join(c for c in t if not unicodedata.combining(c)).replace("’", "'")


class JeuSecubox(DatasetProvider):
    dataset_id = "secubox-fr"
    dataset_name = "Jeu SecuBox (français)"

    def __init__(self, chemin: Path = JEU) -> None:
        self.chemin = chemin
        self._records: List[EvalRecord] = []

    def load(self, *, max_samples: Optional[int] = None, split: Optional[str] = None,
             seed: Optional[int] = None) -> None:
        lignes = [json.loads(ligne) for ligne in self.chemin.read_text(encoding="utf-8").splitlines() if ligne.strip()]
        self._records = [EvalRecord(record_id=e["id"], problem=e["question"], reference=json.dumps(e["attendus"]),
                                    category="chat", subject=e["categorie"]) for e in lignes][:max_samples]

    def iter_records(self) -> Iterable[EvalRecord]:
        return iter(self._records)

    def size(self) -> int:
        return len(self._records)


class MotsAttendus(Scorer):
    """Juste si, pour CHAQUE groupe attendu, l'une des formes apparaît dans la réponse (accents et casse ignorés)."""
    scorer_id = "mots-attendus"

    def score(self, record: EvalRecord, model_answer: str) -> Tuple[Optional[bool], Dict[str, Any]]:
        groupes = json.loads(record.reference)
        rep = normaliser(model_answer)
        trouves = [any(normaliser(f) in rep for f in g) for g in groupes]
        return all(trouves), {"groupes": len(groupes), "trouves": sum(trouves)}


class MoteurUnix(InferenceBackend):
    """Backend d'évaluation : un llama-server sur socket Unix, en flux (pour mesurer le premier mot)."""
    backend_id = "secubox-unix"
    framework_name = "openjarvis"

    def __init__(self, socket: str) -> None:
        self.socket = socket
        e = LlamaCppEngine(host="http://moteur")
        e._client.close()
        e._client = httpx.Client(base_url="http://moteur", timeout=300, transport=httpx.HTTPTransport(uds=socket))
        self._e = e

    def modele(self) -> str:
        return self._e.list_models()[0]

    def generate(self, prompt: str, *, model: str, system: str = "", temperature: float = 0.0,
                 max_tokens: int = 2048) -> str:
        return self.generate_full(prompt, model=model, system=system, temperature=temperature,
                                  max_tokens=max_tokens)["content"]

    def generate_full(self, prompt: str, *, model: str, system: str = "", temperature: float = 0.0,
                      max_tokens: int = 2048) -> Dict[str, Any]:
        corps = {"model": model, "messages": [{"role": "system", "content": system or CONSIGNE_EVAL},
                                              {"role": "user", "content": prompt}],
                 "temperature": temperature, "max_tokens": max_tokens, "stream": True,
                 "stream_options": {"include_usage": True}}
        debut, premier, morceaux, usage, timings = time.monotonic(), None, [], {}, {}
        with self._e._client.stream("POST", "/v1/chat/completions", json=corps) as r:
            r.raise_for_status()
            for ligne in r.iter_lines():
                if not ligne.startswith("data: ") or ligne == "data: [DONE]":
                    continue
                m = json.loads(ligne[6:])
                usage, timings = m.get("usage") or usage, m.get("timings") or timings
                for ch in m.get("choices", []):
                    t = (ch.get("delta") or {}).get("content")
                    if t:
                        premier = premier if premier is not None else time.monotonic() - debut
                        morceaux.append(t)
        duree = time.monotonic() - debut
        return {"content": "".join(morceaux), "usage": usage, "model": model, "latency_seconds": duree,
                "ttft": premier or 0.0, "cost_usd": 0.0,
                # Débit de génération mesuré par llama-server (timings), sinon estimé.
                "throughput_tok_per_sec": float(timings.get("predicted_per_second") or 0.0)}

    def close(self) -> None:
        self._e.close()


class Historique:
    """Évaluations passées (une ligne par passage), SQLite du service."""

    def __init__(self, etat: Path) -> None:
        self._c = sqlite3.connect(str(etat / "evaluations.db"), check_same_thread=False)
        self._v = threading.Lock()
        self._c.execute("CREATE TABLE IF NOT EXISTS evaluations (id INTEGER PRIMARY KEY, quand REAL, moteur TEXT,"
                        " modele TEXT, n INTEGER, justes INTEGER, exactitude REAL, latence_s REAL, premier_s REAL,"
                        " debit_js REAL, par_categorie TEXT, details TEXT)")
        self._c.commit()

    def ajouter(self, ligne: dict) -> None:
        with self._v:
            self._c.execute("INSERT INTO evaluations (quand, moteur, modele, n, justes, exactitude, latence_s, premier_s,"
                            " debit_js, par_categorie, details) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                            (ligne["quand"], ligne["moteur"], ligne["modele"], ligne["n"], ligne["justes"],
                             ligne["exactitude"], ligne["latence_s"], ligne["premier_s"], ligne["debit_js"],
                             json.dumps(ligne["par_categorie"]), json.dumps(ligne["details"], ensure_ascii=False)))
            self._c.commit()

    def lister(self, n: int = 30) -> list[dict]:
        with self._v:
            rows = self._c.execute("SELECT quand, moteur, modele, n, justes, exactitude, latence_s, premier_s, debit_js,"
                                   " par_categorie, details FROM evaluations ORDER BY id DESC LIMIT ?", (n,)).fetchall()
        cles = ("quand", "moteur", "modele", "n", "justes", "exactitude", "latence_s", "premier_s", "debit_js")
        return [{**dict(zip(cles, r[:9])), "par_categorie": json.loads(r[9]), "details": json.loads(r[10])}
                for r in rows]

    def fermer(self) -> None:
        self._c.close()


def _moyenne(valeurs: list[float]) -> float:
    v = [x for x in valeurs if x]
    return round(sum(v) / len(v), 3) if v else 0.0


def evaluer(socket: str, moteur: str, traces: TraceStore, sortie: Path, *,
            max_echantillons: Optional[int] = None) -> dict:
    """Une batterie sur le moteur du socket. Chaque échantillon devient aussi une Trace (réussite/échec)."""
    backend = MoteurUnix(socket)
    try:
        modele = backend.modele()
        nom = Path(modele).name
        sortie.mkdir(mode=0o700, parents=True, exist_ok=True)
        # Chemin EXPLICITE : sans lui, EvalRunner écrit sous ./results du dossier courant (runner.py l.927-934).
        fichier = sortie / f"{time.strftime('%Y%m%dT%H%M%S')}-{moteur}-{Path(modele).stem[:60]}.jsonl"
        cfg = RunConfig(benchmark="secubox-fr", backend=backend.backend_id, model=modele, max_samples=max_echantillons,
                        output_path=str(fichier),
                        max_workers=1, temperature=0.0, max_tokens=MAX_TOKENS, telemetry=False, gpu_metrics=False,
                        system_prompt=CONSIGNE_EVAL)
        jeu = JeuSecubox()
        runner = EvalRunner(cfg, jeu, backend, MotsAttendus())
        resume = runner.run()
        res = runner.results
        questions = {r.record_id: r.problem for r in jeu.iter_records()}
        for r in res:
            traces.save(Trace(query=questions.get(r.record_id, ""), agent="evaluation", model=nom, engine=moteur,
                              result=r.model_answer, outcome="success" if r.is_correct else "failure",
                              started_at=time.time() - r.latency_seconds, ended_at=time.time(),
                              total_tokens=r.completion_tokens + r.prompt_tokens,
                              total_latency_seconds=r.latency_seconds,
                              steps=[TraceStep(step_type=StepType.GENERATE, timestamp=time.time(),
                                               duration_seconds=r.latency_seconds)],
                              metadata={"evaluation": r.record_id}))
        return {"quand": time.time(), "moteur": moteur, "modele": nom, "n": resume.total_samples,
                "justes": resume.correct, "exactitude": round(resume.accuracy, 3),
                "latence_s": round(resume.mean_latency_seconds, 3),
                "premier_s": _moyenne([r.ttft for r in res]),
                "debit_js": _moyenne([r.throughput_tok_per_sec for r in res]),
                "par_categorie": resume.per_subject,
                "details": [{"id": r.record_id, "juste": r.is_correct, "latence_s": round(r.latency_seconds, 2),
                             "reponse": (r.model_answer or "")[:300], "erreur": r.error} for r in res]}
    finally:
        backend.close()


def recommandation(traces: TraceStore) -> dict:
    """LearnedRouterPolicy d'OpenJarvis sur toutes les traces (évaluations + conversations notées)."""
    p = LearnedRouterPolicy()
    r = p.update(traces)
    return {"carte": r.get("policy_map", {}), "echantillons_min": p.min_samples,
            "appliquee": False, "note": "recommandation seulement : la conversation garde le moteur actif"}


__all__ = ["Historique", "JeuSecubox", "MotsAttendus", "MoteurUnix", "evaluer", "recommandation"]
