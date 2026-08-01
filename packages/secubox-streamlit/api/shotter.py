"""Capture d'écran d'une appli Streamlit, pilotée par CDP.

`chromium --screenshot` ne convient pas : il capture à l'événement `load`, or
Streamlit ne sert qu'une coquille HTML et ne peint qu'après connexion websocket
et push du serveur. Mesuré sur gk2 : 58 à 94 s pour un PNG de 4 à 6 Ko en
1280x800 — une page blanche.

On pilote donc chromium par le protocole DevTools : naviguer, ATTENDRE le
conteneur racine de Streamlit, puis capturer.

Une seule capture à la fois : deux chromium concurrents ne tiennent pas dans les
~2 Go disponibles sur la board.
"""
from __future__ import annotations

import asyncio
import base64
import json
import shutil
import subprocess
import tempfile
import urllib.request

CHROMIUM = shutil.which("chromium") or "/usr/bin/chromium"
WAIT_SELECTOR = '[data-testid="stAppViewContainer"]'
# Un rendu Streamlit réel pèse 50-300 Ko. En dessous de ce seuil, c'est la page
# blanche qu'on cherche précisément à ne plus archiver.
MIN_PNG_BYTES = 20000

_lock = asyncio.Lock()


class ShotError(RuntimeError):
    """Capture impossible, ou rendu jugé vide."""


def _reject_blank(png: bytes) -> None:
    if len(png) < MIN_PNG_BYTES:
        raise ShotError(f"rendu vide ({len(png)} octets < {MIN_PNG_BYTES})")


async def _cdp(ws_url: str, method: str, params: dict, msg_id: int) -> dict:
    import websockets
    async with websockets.connect(ws_url, max_size=None) as ws:
        await ws.send(json.dumps({"id": msg_id, "method": method, "params": params}))
        while True:
            msg = json.loads(await ws.recv())
            if msg.get("id") == msg_id:
                return msg.get("result", {})


async def capture(url: str, *, timeout: float = 90.0,
                  width: int = 1280, height: int = 800) -> bytes:
    """Navigue vers `url`, attend le rendu Streamlit, renvoie le PNG."""
    async with _lock:
        return await asyncio.wait_for(
            _capture_once(url, width, height), timeout=timeout)


async def _capture_once(url: str, width: int, height: int) -> bytes:
    import websockets  # noqa: F401  (échoue tôt si absent)
    profile = tempfile.mkdtemp(prefix="sbx-shot-")
    proc = subprocess.Popen(
        [CHROMIUM, "--headless=new", "--disable-gpu", "--no-sandbox",
         "--disable-dev-shm-usage", "--hide-scrollbars",
         f"--window-size={width},{height}",
         "--remote-debugging-port=0", f"--user-data-dir={profile}", "about:blank"],
        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    try:
        ws_url = await _devtools_url(proc)
        await _cdp(ws_url, "Page.navigate", {"url": url}, 1)
        await _wait_for_selector(ws_url)
        result = await _cdp(ws_url, "Page.captureScreenshot", {"format": "png"}, 3)
        png = base64.b64decode(result.get("data", ""))
        _reject_blank(png)
        return png
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
        shutil.rmtree(profile, ignore_errors=True)


async def _devtools_url(proc) -> str:
    """Lit le port de debug annoncé par chromium sur stderr, puis l'URL websocket."""
    for _ in range(100):
        line = proc.stderr.readline().decode("utf-8", "replace")
        if "DevTools listening on" in line:
            port = line.strip().split(":")[-1].split("/")[0]
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/json/list", timeout=10) as r:
                pages = json.load(r)
            for p in pages:
                if p.get("type") == "page":
                    return p["webSocketDebuggerUrl"]
        await asyncio.sleep(0.1)
    raise ShotError("chromium n'a pas annoncé son port de debug")


async def _wait_for_selector(ws_url: str, tries: int = 60) -> None:
    """Interroge le DOM jusqu'à ce que le conteneur Streamlit existe."""
    expr = f'!!document.querySelector({WAIT_SELECTOR!r})'
    for i in range(tries):
        res = await _cdp(ws_url, "Runtime.evaluate",
                         {"expression": expr, "returnByValue": True}, 100 + i)
        if res.get("result", {}).get("value") is True:
            await asyncio.sleep(1.5)   # laisser peindre après apparition
            return
        await asyncio.sleep(1.0)
    raise ShotError(f"sélecteur {WAIT_SELECTOR} jamais apparu")
