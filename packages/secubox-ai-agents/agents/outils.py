# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Outils des agents (#3990) : les SEULS outils enregistrés auprès d'OpenJarvis. Lecture seule.

- `web_search` : la SearXNG locale, par le pont sur socket Unix (`SECUBOX_AI_AGENTS_PONT`) ; capacité
  `network:fetch` ;
- `memory_search` : la mémoire documentaire du service ; capacité `memory:read` ;
- `digest_collect` : actualités des thèmes du digest, par le même pont ; plancher d'OpenJarvis pour ce nom :
  `memory:read` + `network:fetch` (`security/capabilities.py` l.259).

Chaque appel est borné : nombre d'appels, échéance, annulation (un travail annulé ne fait plus rien).
Les sources sont numérotées dans l'ordre d'apparition, sur tout le travail : le [n] du texte final renvoie à
`Contexte.sources[n-1]`. Les résultats sont des DONNÉES : ils sont rendus au modèle comme tels.
"""
from __future__ import annotations

import json
import os
import threading
import time
from dataclasses import dataclass, field
from typing import Any

import httpx
from openjarvis.core.types import ToolResult
from openjarvis.tools._stubs import BaseTool, ToolSpec

PONT_DEFAUT = "/run/secubox-ai-pont/searxng.sock"


@dataclass
class Contexte:
    """État partagé des outils d'UN travail."""
    echeance: float
    appels_max: int = 4
    appels: int = 0
    annule: threading.Event = field(default_factory=threading.Event)
    sources: list[dict] = field(default_factory=list)
    verrou: threading.Lock = field(default_factory=threading.Lock)

    def autoriser(self) -> str | None:
        if self.annule.is_set():
            return "travail annulé"
        if time.monotonic() > self.echeance:
            return "délai du travail dépassé"
        with self.verrou:
            if self.appels >= self.appels_max:
                return f"au plus {self.appels_max} appels d'outil"
            self.appels += 1
        return None

    def numeroter(self, titre: str, url: str) -> int:
        with self.verrou:
            for i, s in enumerate(self.sources, 1):
                if s["url"] == url:
                    return i
            self.sources.append({"titre": titre, "url": url})
            return len(self.sources)


def pont_rechercher(q: str, *, categories: str = "general", periode: str = "",
                    pont: str | None = None) -> list[dict]:
    chemin = pont or os.environ.get("SECUBOX_AI_AGENTS_PONT", PONT_DEFAUT)
    params = {"q": q[:300], "categories": categories}
    if periode:
        params["time_range"] = periode
    with httpx.Client(transport=httpx.HTTPTransport(uds=chemin), base_url="http://pont", timeout=30) as c:
        r = c.get("/search", params=params)
        r.raise_for_status()
        return r.json().get("resultats", [])


def _refus(nom: str, raison: str) -> ToolResult:
    return ToolResult(tool_name=nom, content=f"Refusé : {raison}.", success=False)


class RechercheWeb(BaseTool):
    tool_id = "web_search"

    def __init__(self, ctx: Contexte, pont: str | None = None) -> None:
        self.ctx, self.pont = ctx, pont

    @property
    def spec(self) -> ToolSpec:
        return ToolSpec(name="web_search", description="Recherche sur le web (méta-moteur local). Argument : query.",
                        parameters={"type": "object", "properties": {"query": {"type": "string"}},
                                    "required": ["query"]},
                        required_capabilities=["network:fetch"], timeout_seconds=40)

    def execute(self, **params: Any) -> ToolResult:
        raison = self.ctx.autoriser()
        if raison:
            return _refus("web_search", raison)
        q = str(params.get("query") or "").strip()
        if not q:
            return _refus("web_search", "query vide")
        try:
            res = pont_rechercher(q, pont=self.pont)[:5]
        except (httpx.HTTPError, ValueError) as exc:
            return ToolResult(tool_name="web_search", content=f"Recherche indisponible ({type(exc).__name__}).",
                              success=False)
        if not res:
            return ToolResult(tool_name="web_search", content="Aucun résultat.", success=True)
        lignes = [f"[{self.ctx.numeroter(r['titre'], r['url'])}] {r['titre']} — {r['url']}\n{r['extrait']}"
                  for r in res]
        return ToolResult(tool_name="web_search", content="\n\n".join(lignes), success=True)


class RechercheMemoire(BaseTool):
    tool_id = "memory_search"

    def __init__(self, ctx: Contexte, memoires, agents: tuple[str, ...] = ("assistant", "recherche")) -> None:
        self.ctx, self.memoires, self.agents = ctx, memoires, agents

    @property
    def spec(self) -> ToolSpec:
        return ToolSpec(name="memory_search", description="Cherche dans la mémoire de SecuBox. Argument : query.",
                        parameters={"type": "object", "properties": {"query": {"type": "string"}},
                                    "required": ["query"]},
                        required_capabilities=["memory:read"])

    def execute(self, **params: Any) -> ToolResult:
        raison = self.ctx.autoriser()
        if raison:
            return _refus("memory_search", raison)
        q = str(params.get("query") or "")
        res = [r for a in self.agents for r in self.memoires._chercher(a, q, 3)]
        if not res:
            return ToolResult(tool_name="memory_search", content="Rien en mémoire.", success=True)
        return ToolResult(tool_name="memory_search", success=True,
                          content="\n\n".join(f"(mémoire) {r['titre']}\n{r['texte'][:800]}" for r in res))


class CollecteDigest(BaseTool):
    """Remplace `digest_collect` d'OpenJarvis (connecteurs de messagerie, d'agenda… : tous absents ici)."""
    tool_id = "digest_collect"

    def __init__(self, ctx: Contexte, themes: list[str], pont: str | None = None) -> None:
        self.ctx, self.themes, self.pont = ctx, themes, pont

    @property
    def spec(self) -> ToolSpec:
        return ToolSpec(name="digest_collect", description="Actualités du jour des thèmes configurés.",
                        parameters={"type": "object", "properties": {}},
                        required_capabilities=["memory:read", "network:fetch"], timeout_seconds=120)

    def execute(self, **params: Any) -> ToolResult:
        blocs = []
        for theme in self.themes:
            raison = self.ctx.autoriser()
            if raison:
                blocs.append({"theme": theme, "erreur": raison})
                continue
            try:
                res = pont_rechercher(theme, categories="news", periode="day", pont=self.pont)[:4]
            except (httpx.HTTPError, ValueError) as exc:
                blocs.append({"theme": theme, "erreur": type(exc).__name__})
                continue
            blocs.append({"theme": theme, "articles": [
                {"n": self.ctx.numeroter(r["titre"], r["url"]), "titre": r["titre"], "extrait": r["extrait"][:400],
                 "date": r["date"]} for r in res]})
        return ToolResult(tool_name="digest_collect", content=json.dumps(blocs, ensure_ascii=False), success=True)
