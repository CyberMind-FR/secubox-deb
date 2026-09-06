# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: ZIA — registre de capacités (couche d'actions).

Traduit une action SÉMANTIQUE proposée par le modèle (« media.mute », « ui.zoom »)
en MESSAGE `sbx` natif que le Hall sait poster à la cardlet cible. Le LLM n'écrit
JAMAIS ici : il propose un nom d'action ; ce module VALIDE (liste blanche + type +
bornes) et TRADUIT. Une capacité inconnue ou un module absent → échec explicite,
jamais d'approximation (RFC §5, §9.12).

Deux sources, fusionnées :
  • un BOOTSTRAP déterministe (radio), ancré sur le vrai handler `radio.js` —
    toggle/pause/stop/zoom/vol(number 0..1)/muet(boolean) ; prev/next ABSENTS
    (un direct ne se parcourt pas) ;
  • les MANIFESTES déposés par les modules dans /usr/share/secubox/capabilities.d/
    *.json (autorité : un manifeste remplace le bootstrap du même service). Ainsi
    ZIA APPREND les capacités des modules installés sans les halluciner.

Le transport supporté au P1 est `sbx-postmessage` : chaque action porte un message
`{sbx:'cmd', action:'…'}`, éventuellement complété d'un champ de valeur validé.
"""
from __future__ import annotations

import glob
import json
import re
from pathlib import Path
from typing import Any, Optional

# Répertoire des manifestes de capacités (déposés par les paquets modules).
CAP_DIR = "/usr/share/secubox/capabilities.d"

# Un nom d'action est « famille.nom » (media.mute, ui.zoom). Le point est
# OBLIGATOIRE : cela écarte d'emblée les noms parasites (« __proto__ », « open »).
_ACTION_RE = re.compile(r"^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$")
_SERVICE_RE = re.compile(r"^[a-z0-9][a-z0-9_-]*$")

# BOOTSTRAP — radio, ancré sur packages/secubox-radio/internal/web/static/radio.js
# (handler `addEventListener('message')`, branche `d.sbx==='cmd'`). Forme interne
# déjà normalisée. prev/next volontairement absents.
_BOOTSTRAP: dict = {
    "radio": {
        "transport": "sbx-postmessage",
        "actions": {
            "media.toggle": {"message": {"sbx": "cmd", "action": "toggle"}},
            "media.pause":  {"message": {"sbx": "cmd", "action": "pause"}},
            "media.stop":   {"message": {"sbx": "cmd", "action": "stop"}},
            "media.mute":   {"message": {"sbx": "cmd", "action": "muet"},
                             "value": {"field": "v", "type": "boolean"}},
            "media.volume": {"message": {"sbx": "cmd", "action": "vol"},
                             "value": {"field": "v", "type": "number", "min": 0.0, "max": 1.0}},
            "ui.zoom":      {"message": {"sbx": "cmd", "action": "zoom"}},
        },
    },
}


class Resolved:
    """Résultat de résolution d'une action → message sbx natif (ou échec explicite)."""
    __slots__ = ("ok", "message", "error", "value")

    def __init__(self, ok: bool, message: Optional[dict] = None,
                 error: str = "", value: Any = None):
        self.ok = ok
        self.message = message
        self.error = error
        self.value = value


def _coerce_bool(v: Any):
    if isinstance(v, bool):
        return v, ""
    if isinstance(v, (int, float)) and v in (0, 1):
        return bool(v), ""
    if isinstance(v, str):
        s = v.strip().lower()
        if s in ("true", "1", "oui", "on", "vrai"):
            return True, ""
        if s in ("false", "0", "non", "off", "faux"):
            return False, ""
    return None, "valeur booléenne attendue"


def _coerce_num(v: Any, spec: dict):
    """Nombre, CLAMPÉ dans [min,max] (politique documentée : on borne, on ne rejette
    pas un dépassement — « volume 250 % » devient 1.0). Non numérique → rejet."""
    if isinstance(v, bool):  # bool est un int en Python : on ne l'accepte pas ici
        return None, "valeur numérique attendue"
    try:
        x = float(v)
    except (TypeError, ValueError):
        return None, "valeur numérique attendue"
    lo, hi = spec.get("min"), spec.get("max")
    if lo is not None:
        x = max(float(lo), x)
    if hi is not None:
        x = min(float(hi), x)
    return x, ""


class Capabilities:
    """Registre fusionné (bootstrap + manifestes), rechargeable."""

    def __init__(self, cap_dir: str = CAP_DIR):
        self.cap_dir = cap_dir
        self.reg: dict = {}
        self.reload()

    def reload(self) -> "Capabilities":
        reg: dict = {}
        for svc, spec in _BOOTSTRAP.items():
            n = self._norm(svc, spec)
            if n:
                reg[svc] = n
        try:
            paths = sorted(glob.glob(str(Path(self.cap_dir) / "*.json")))
        except Exception:
            paths = []
        for p in paths:
            try:
                m = json.loads(Path(p).read_text(encoding="utf-8"))
                svc = str(m.get("service", "")).strip()
                if not _SERVICE_RE.match(svc):
                    continue
                n = self._norm(svc, m)
                if n:                       # un manifeste valide fait AUTORITÉ
                    reg[svc] = n
            except Exception:
                continue                    # un manifeste cassé n'abat pas le registre
        self.reg = reg
        return self

    def _norm(self, svc: str, spec: dict) -> Optional[dict]:
        """Valide + normalise un bloc de capacités. Rejette toute action mal formée."""
        acts: dict = {}
        for name, a in (spec.get("actions") or {}).items():
            if not _ACTION_RE.match(str(name)):
                continue
            if not isinstance(a, dict):
                continue
            msg = a.get("message") or {}
            # Transport sbx-postmessage : message DOIT être {sbx:'cmd', action:'…'}.
            if not isinstance(msg, dict) or msg.get("sbx") != "cmd" or not msg.get("action"):
                continue
            entry: dict = {"message": {"sbx": "cmd", "action": str(msg["action"])}}
            val = a.get("value")
            if isinstance(val, dict) and val.get("type") in ("boolean", "number"):
                ve: dict = {"field": str(val.get("field", "v")), "type": val["type"]}
                if val["type"] == "number":
                    if "min" in val:
                        try:
                            ve["min"] = float(val["min"])
                        except (TypeError, ValueError):
                            pass
                    if "max" in val:
                        try:
                            ve["max"] = float(val["max"])
                        except (TypeError, ValueError):
                            pass
                entry["value"] = ve
            acts[str(name)] = entry
        if not acts:
            return None
        return {"transport": "sbx-postmessage", "actions": acts}

    def services(self) -> list:
        return sorted(self.reg)

    def has(self, service: str, action: str) -> bool:
        return action in (self.reg.get(service, {}).get("actions", {}))

    def actions_for(self, service: str) -> list:
        """Contrat d'objet : liste structurée [{name, params}] des capacités déclarées."""
        out = []
        for name, a in (self.reg.get(service, {}).get("actions", {})).items():
            params: dict = {}
            v = a.get("value")
            if v:
                spec: dict = {"type": v["type"]}
                if "min" in v:
                    spec["min"] = v["min"]
                if "max" in v:
                    spec["max"] = v["max"]
                params["value"] = spec
            out.append({"name": name, "params": params})
        return out

    def registry(self) -> dict:
        """Forme publique servie au Hall (client SBXCapabilities) — mêmes manifestes."""
        return {
            svc: {
                "transport": c["transport"],
                "actions": {
                    n: dict(a) for n, a in c["actions"].items()
                },
            }
            for svc, c in self.reg.items()
        }

    def resolve(self, service: str, action: str, params: Optional[dict]) -> Resolved:
        """Action sémantique → message sbx natif validé. Échec explicite sinon."""
        c = self.reg.get(service)
        if not c:
            return Resolved(False, error="module inconnu")
        a = c["actions"].get(action)
        if not a:
            return Resolved(False, error="capacité inconnue")
        msg = dict(a["message"])
        value = None
        spec = a.get("value")
        if spec:
            raw = (params or {}).get("value")
            if raw is None:
                return Resolved(False, error="valeur requise")
            if spec["type"] == "boolean":
                cv, err = _coerce_bool(raw)
            else:
                cv, err = _coerce_num(raw, spec)
            if err:
                return Resolved(False, error=err)
            msg[spec["field"]] = cv
            value = cv
        return Resolved(True, message=msg, value=value)
