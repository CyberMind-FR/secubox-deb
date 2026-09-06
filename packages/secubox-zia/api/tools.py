# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: ZIA — outils (lecture d'abord).

Les seuls gestes que ZIA peut poser. Chaque appel est validé (liste blanche + schéma
minimal) puis exécuté par le bus. AUCUN outil d'écriture au POC : le modèle ne peut ni
modifier, ni poster, ni contourner l'ACL — il ne fait que LIRE et ORIENTER.
"""
from __future__ import annotations

from typing import Any

# Liste blanche + schéma déclaratif (nom -> paramètres admis).
SCHEMc: dict = {
    "search_objects": {"query": str, "type": str},
    "get_object": {"id": str},
    "list_recent": {"limit": int},
    "open": {"id": str},
    "delegate": {"service": str, "reason": str},
    # Outil GÉNÉRIQUE de commande (RFC §4) — un seul, pas un par phrase. Il ne
    # touche PAS au DOM : il rend une ACTION SBX VALIDÉE que la couche Hall exécute.
    "act": {"target": str, "action": str, "params": dict},
}


class Tools:
    def __init__(self, bus):
        self.bus = bus

    def schemas(self) -> list[dict]:
        """Exposé (ex. /metrics ou tool-calls d'un vrai LLM plus tard)."""
        return [{"name": n, "params": {k: v.__name__ for k, v in p.items()}}
                for n, p in SCHEMc.items()]

    async def call(self, name: str, args: dict, role: str = "guest") -> dict:
        """Dispatch validé. Rend {ok, result|error}. Jamais d'exception qui remonte."""
        if name not in SCHEMc:
            return {"ok": False, "error": f"outil inconnu: {name}"}
        args = args or {}
        try:
            if name == "search_objects":
                objs = await self.bus.search(str(args.get("query", "")),
                                             str(args.get("type", "")), role)
                return {"ok": True, "result": objs}
            if name == "get_object":
                o = await self.bus.get(str(args.get("id", "")), role)
                return {"ok": bool(o), "result": o} if o else {"ok": False, "error": "introuvable"}
            if name == "list_recent":
                lim = int(args.get("limit", 6) or 6)
                return {"ok": True, "result": await self.bus.recent(lim, role)}
            if name == "open":
                o = await self.bus.get(str(args.get("id", "")), role)
                # On ne « fait » pas l'ouverture ici : on rend l'URI sbx:// que le
                # Hall sait ouvrir (viewer/embed). Séparation nette des rôles.
                return {"ok": bool(o), "result": {"uri": o.get("uri")} if o else None}
            if name == "delegate":
                return {"ok": True, "result": {"to": str(args.get("service", "")),
                                               "reason": str(args.get("reason", ""))}}
            if name == "act":
                # Le modèle a proposé une INTENTION structurée. Ici, code
                # déterministe : on valide cible + rôle + action + valeur, puis on
                # rend une action SBX prête à poster — SANS jamais exécuter le DOM.
                target = str(args.get("target", ""))
                action = str(args.get("action", ""))
                params = args.get("params") or {}
                from .bus import _service_de
                obj = await self.bus.get(target, role)
                service = (obj or {}).get("service") or _service_de(target)
                if not service:
                    return {"ok": False, "error": "cible introuvable"}
                allowed = self.bus.action_allowed(service, action, params, role)
                if not allowed.ok:
                    return {"ok": False, "error": allowed.error}
                return {"ok": True, "result": {
                    "kind": "sbx-action",
                    "target": target or f"service:{service}",
                    "service": service,
                    "action": action,
                    "params": allowed.params,
                }}
        except Exception as e:  # défensif : un outil qui trébuche ne casse pas le chat
            return {"ok": False, "error": str(e)}
        return {"ok": False, "error": "non exécuté"}
