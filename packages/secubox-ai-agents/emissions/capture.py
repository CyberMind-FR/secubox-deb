# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Capture d'admin masquée (#4058, Task 13).

Une page d'admin (hôte de la liste blanche de `masques.toml` seulement), zoomée sur une zone CSS facultative, est
prise par chromium headless (Playwright) APRÈS masquage des sélecteurs à risque (flou 12 px puis aplat opaque). Le
PNG passe ensuite le balayage OCR bloquant : un seul constat → `refusee` (jamais publiable). Sinon `a_valider` : seule
la validation visuelle du propriétaire (`valider_capture`) la fait entrer au diaporama.
"""
from __future__ import annotations

import json
import os
import re
import tomllib
from pathlib import Path
from typing import Any, Awaitable, Callable, Dict, List, Optional
from urllib.parse import urlsplit

from emissions.balayage import balayer, lire_noms_internes

MASQUES = Path(__file__).with_name("masques.toml")
ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
ZONE_RE = re.compile(r"^[A-Za-z0-9_#.\-\[\]=\"' >:()*,]{1,200}$")

# Masquage dans la page : flou d'abord, puis un aplat opaque posé par-dessus chaque élément (le flou seul se lit
# parfois). Retourne le nombre d'éléments masqués.
JS_MASQUER = """(sels) => {
  let n = 0;
  for (const s of sels) {
    let els = [];
    try { els = document.querySelectorAll(s); } catch (e) { continue; }
    for (const el of els) {
      el.style.setProperty('filter', 'blur(12px)', 'important');
      const r = el.getBoundingClientRect();
      const a = document.createElement('div');
      a.style.cssText = `position:absolute;left:${r.left + scrollX}px;top:${r.top + scrollY}px;` +
        `width:${r.width}px;height:${r.height}px;background:#3D35A0;z-index:2147483647;pointer-events:none`;
      document.body.appendChild(a);
      n++;
    }
  }
  return n;
}"""

Navigateur = Callable[[str, Optional[str], List[str], Path], Awaitable[int]]


def lire_masques(chemin: Path = MASQUES) -> Dict[str, List[str]]:
    d = tomllib.loads(Path(chemin).read_text(encoding="utf-8"))
    hotes = [h for h in (d.get("hotes") or {}).get("autorises") or [] if isinstance(h, str)]
    sels = [s for s in (d.get("masques") or {}).get("selecteurs") or [] if isinstance(s, str)]
    return {"hotes": hotes, "selecteurs": sels}


def url_admise(url: str, hotes: List[str]) -> bool:
    try:
        p = urlsplit(url)
        _ = p.port   # lève ValueError sur un port invalide
    except ValueError:
        return False
    return (p.scheme in ("http", "https") and p.hostname is not None and "@" not in p.netloc
            and p.hostname.lower() in {h.lower() for h in hotes})


async def chromium(url: str, zone: Optional[str], selecteurs: List[str], sortie: Path) -> int:
    """Prise de vue réelle : chromium headless par Playwright, sans réseau autre que la page demandée."""
    from playwright.async_api import async_playwright   # dépendance facultative : seulement pour la capture

    async with async_playwright() as pw:
        nav = await pw.chromium.launch(headless=True, args=["--no-proxy-server"])
        try:
            page = await nav.new_page(viewport={"width": 1280, "height": 800}, device_scale_factor=1)
            await page.goto(url, wait_until="networkidle", timeout=30000)
            n = int(await page.evaluate(JS_MASQUER, selecteurs))
            cible = page.locator(zone).first if zone else None
            if cible is not None:
                await cible.screenshot(path=str(sortie), timeout=15000)
            else:
                await page.screenshot(path=str(sortie), full_page=False)
            return n
        finally:
            await nav.close()


async def capturer(url: str, zone: Optional[str], sortie: Path, *, navigateur: Optional[Navigateur] = None,
                   ocr: Optional[Callable[[Path], str]] = None, masques: Optional[Path] = None,
                   noms_internes: Optional[List[str]] = None) -> Dict[str, Any]:
    """`{"png", "masques", "controle", "etat": "a_valider"|"refusee"}`. URL hors liste blanche ou zone invalide :
    ValueError (rien n'est pris)."""
    conf = lire_masques(masques or MASQUES)
    if not url_admise(url, conf["hotes"]):
        raise ValueError("adresse hors de la liste des pages d'admin autorisées")
    if zone is not None and not ZONE_RE.match(zone):
        raise ValueError("zone : sélecteur CSS invalide")
    sortie = Path(sortie)
    sortie.parent.mkdir(parents=True, exist_ok=True)
    n = await (navigateur or chromium)(url, zone, conf["selecteurs"], sortie)
    controle = balayer([], [sortie], noms_internes if noms_internes is not None else lire_noms_internes(), ocr=ocr)
    return {"png": sortie, "masques": int(n), "controle": controle, "etat": "refusee" if controle else "a_valider"}


# ── registre des captures d'un brouillon : <brouillon>/captures.json ──────────────────────────────────────────────
def _registre(brouillon: Path) -> Path:
    return Path(brouillon) / "captures.json"


def _lire(brouillon: Path) -> Dict[str, Dict[str, Any]]:
    try:
        d = json.loads(_registre(brouillon).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return d if isinstance(d, dict) else {}


def _ecrire(brouillon: Path, d: Dict[str, Any]) -> None:
    f = _registre(brouillon)
    tmp = f.with_name(f.name + ".tmp")
    tmp.write_text(json.dumps(d, ensure_ascii=False, indent=1), encoding="utf-8")
    os.replace(tmp, f)


def enregistrer_capture(brouillon: Path, ident: str, resultat: Dict[str, Any]) -> None:
    if not ID_RE.match(ident):
        raise ValueError("identifiant de capture invalide")
    d = _lire(brouillon)
    d[ident] = {"png": Path(resultat["png"]).name, "masques": resultat["masques"],
                "controle": resultat["controle"], "etat": resultat["etat"]}
    _ecrire(brouillon, d)


def valider_capture(brouillon: Path, ident: str, accord: bool) -> str:
    """Validation visuelle du propriétaire : `a_valider` → `validee` (accord) ou `rejetee`. Une capture `refusee` par
    le contrôle ne se valide jamais (ValueError). Retourne le nouvel état."""
    d = _lire(brouillon)
    c = d.get(ident)
    if not isinstance(c, dict):
        raise KeyError(ident)
    if c.get("etat") == "refusee" or c.get("controle"):
        raise ValueError("capture refusée par le contrôle : non publiable")
    c["etat"] = "validee" if accord else "rejetee"
    _ecrire(brouillon, d)
    return c["etat"]


def captures_validees(brouillon: Path) -> List[str]:
    """Les PNG qui peuvent entrer au diaporama (état `validee` et contrôle vide)."""
    return [c["png"] for c in _lire(brouillon).values()
            if isinstance(c, dict) and c.get("etat") == "validee" and not c.get("controle")]
