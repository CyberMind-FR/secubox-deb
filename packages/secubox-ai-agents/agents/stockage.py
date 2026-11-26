# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Conversations (SessionStore d'OpenJarvis) et mémoire documentaire par agent (SQLiteMemory, extension Rust).

Une seule base par usage, aucune copie ailleurs :
- `conversations.db` : SessionStore ; une conversation = une session dont `user_id` vaut `<sub>#<conversation>` ;
- `memoire/<agent>.db` : SQLiteMemory (FTS5 + BM25 en Rust) ; un fichier par agent = mémoire par agent.
Tous les appels SQLite passent par `asyncio.to_thread` (RULES-CODE § 6), sous un verrou par base.
"""
from __future__ import annotations

import asyncio
import re
import secrets
import threading
import time
from pathlib import Path
from typing import Any

from openjarvis.sessions.session import SessionStore
from openjarvis.tools.storage.sqlite import SQLiteMemory

AGENT_RE = re.compile(r"^[a-z][a-z0-9-]{0,31}$")
CONV_RE = re.compile(r"^[0-9a-f]{16}$")
DIX_ANS_H = 24.0 * 365 * 10   # SessionStore expire une session après max_age_hours : on garde l'historique
MOT_RE = re.compile(r"[^\W_]+", re.UNICODE)


def requete_fts(texte: str) -> str:
    """Des mots seuls (lettres et chiffres), sans aucune syntaxe FTS5 : l'extension Rust d'OpenJarvis découpe
    elle aussi la requête et réunit les mots (rust/crates/openjarvis-tools/src/storage/sqlite.rs l.193-215) ;
    des guillemets ou un OR transmis tels quels ne trouvent plus rien."""
    return " ".join([m for m in MOT_RE.findall(texte.lower()) if len(m) > 2][:16])


class Conversations:
    def __init__(self, etat: Path) -> None:
        self._s = SessionStore(etat / "conversations.db", max_age_hours=DIX_ANS_H)
        self._verrou = threading.Lock()

    @staticmethod
    def _cle(sub: str, conv: str) -> str:
        return f"{sub}#{conv}"

    def _ouvrir(self, sub: str, conv: str | None) -> tuple[str, Any]:
        with self._verrou:
            if conv is None:
                conv = secrets.token_hex(8)
            elif not CONV_RE.match(conv):
                raise ValueError("conversation invalide")
            return conv, self._s.get_or_create(self._cle(sub, conv))

    async def ouvrir(self, sub: str, conv: str | None) -> tuple[str, Any]:
        return await asyncio.to_thread(self._ouvrir, sub, conv)

    def _ajouter(self, session_id: str, role: str, texte: str, meta: dict | None) -> None:
        with self._verrou:
            self._s.save_message(session_id, role, texte, metadata=meta or {})

    async def ajouter(self, session_id: str, role: str, texte: str, meta: dict | None = None) -> None:
        await asyncio.to_thread(self._ajouter, session_id, role, texte, meta)

    def _lister(self, sub: str) -> list[dict]:
        with self._verrou:
            rows = self._s._conn.execute(  # lecture seule : SessionStore n'expose pas de filtre par préfixe
                "SELECT s.user_id, s.created_at, s.last_activity, COUNT(m.id),"
                " (SELECT content FROM session_messages WHERE session_id = s.session_id AND role = 'user'"
                "  ORDER BY id LIMIT 1)"
                " FROM sessions s LEFT JOIN session_messages m ON m.session_id = s.session_id"
                " WHERE s.user_id LIKE ? ESCAPE '\\' GROUP BY s.session_id ORDER BY s.last_activity DESC LIMIT 200",
                (sub.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "#%",),
            ).fetchall()
        return [{"id": u.split("#", 1)[1], "cree": c, "activite": a, "messages": n, "titre": (t or "")[:80]}
                for u, c, a, n, t in rows]

    async def lister(self, sub: str) -> list[dict]:
        return await asyncio.to_thread(self._lister, sub)

    def _lire(self, sub: str, conv: str) -> list[dict] | None:
        if not CONV_RE.match(conv):
            return None
        with self._verrou:
            existe = self._s._conn.execute("SELECT 1 FROM sessions WHERE user_id = ?",
                                           (self._cle(sub, conv),)).fetchone()
            if not existe:
                return None
            session = self._s.get_or_create(self._cle(sub, conv))
        return [{"role": m.role, "texte": m.content, "quand": m.timestamp} for m in session.messages]

    async def lire(self, sub: str, conv: str) -> list[dict] | None:
        return await asyncio.to_thread(self._lire, sub, conv)

    def _oublier(self, sub: str, conv: str) -> bool:
        if not CONV_RE.match(conv):
            return False
        with self._verrou:  # SessionStore n'a pas de suppression : même base, même transaction
            c = self._s._conn
            ids = [r[0] for r in c.execute("SELECT session_id FROM sessions WHERE user_id = ?",
                                           (self._cle(sub, conv),))]
            for sid in ids:
                c.execute("DELETE FROM session_messages WHERE session_id = ?", (sid,))
                c.execute("DELETE FROM sessions WHERE session_id = ?", (sid,))
            c.commit()
        return bool(ids)

    async def oublier(self, sub: str, conv: str) -> bool:
        return await asyncio.to_thread(self._oublier, sub, conv)

    def fermer(self) -> None:
        self._s.close()


class Memoires:
    """Une SQLiteMemory (Rust) par agent, ouverte à la demande."""

    def __init__(self, etat: Path) -> None:
        self._dossier = etat / "memoire"
        self._dossier.mkdir(mode=0o700, exist_ok=True)
        self._bases: dict[str, SQLiteMemory] = {}
        self._verrou = threading.Lock()

    def _base(self, agent: str) -> SQLiteMemory:
        if not AGENT_RE.match(agent):
            raise ValueError("agent invalide")
        if agent not in self._bases:
            self._bases[agent] = SQLiteMemory(self._dossier / f"{agent}.db")
        return self._bases[agent]

    def _garder(self, agent: str, titre: str, texte: str, source: str) -> str:
        ident = secrets.token_hex(8)
        with self._verrou:
            self._base(agent).store(texte, source=source or "note",
                                    metadata={"id": ident, "titre": titre, "cree": time.time()})
        return ident

    async def garder(self, agent: str, titre: str, texte: str, source: str = "") -> str:
        return await asyncio.to_thread(self._garder, agent, titre, texte, source)

    def _chercher(self, agent: str, question: str, n: int) -> list[dict]:
        q = requete_fts(question)
        if not q:
            return []
        with self._verrou:
            res = self._base(agent).retrieve(q, top_k=n)
        return [{"id": r.metadata.get("id"), "titre": r.metadata.get("titre", ""), "source": r.source,
                 "score": round(float(r.score), 3), "texte": r.content} for r in res]

    async def chercher(self, agent: str, question: str, n: int = 4) -> list[dict]:
        return await asyncio.to_thread(self._chercher, agent, question, n)

    def _compter(self, agent: str) -> int:
        with self._verrou:
            return self._base(agent).count()

    async def compter(self, agent: str) -> int:
        return await asyncio.to_thread(self._compter, agent)

    def fermer(self) -> None:
        for b in self._bases.values():
            b.close()
