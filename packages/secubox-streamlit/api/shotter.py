"""Capture d'écran d'une appli Streamlit, pilotée par CDP.

`chromium --screenshot` ne convient pas : il capture à l'événement `load`, or
Streamlit ne sert qu'une coquille HTML et ne peint qu'après connexion websocket
et push du serveur. Mesuré sur gk2 : 58 à 94 s pour un PNG de 4 à 6 Ko en
1280x800 — une page blanche.

On pilote donc chromium par le protocole DevTools : naviguer, ATTENDRE le
conteneur racine de Streamlit, puis capturer.

Une seule capture à la fois : deux chromium concurrents ne tiennent pas dans les
~2 Go disponibles sur la board.

Aucun appel bloquant ne s'exécute directement dans une coroutine : le
sous-processus chromium est piloté via `asyncio.create_subprocess_exec` (lectures
de pipe natives à la boucle d'événements, réellement annulables par
`asyncio.wait_for`) ; l'appel HTTP synchrone (résolution du port DevTools) et
la suppression du profil temporaire (`shutil.rmtree`, potentiellement des
dizaines de petits fichiers Cache/GPUCache/blob_storage/sqlite) sont tous deux
déportés dans un exécuteur.
"""
from __future__ import annotations

import asyncio
import base64
import json
import shutil
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
    """Navigue vers `url`, attend le rendu Streamlit, renvoie le PNG.

    Lève `ShotError` dans tous les cas d'échec — y compris un dépassement du
    délai `timeout`, pour tenir le contrat de l'interface : un appelant qui ne
    rattrape que `ShotError` ne doit jamais se faire surprendre.
    """
    async with _lock:
        try:
            return await asyncio.wait_for(
                _capture_once(url, width, height), timeout=timeout)
        except asyncio.TimeoutError as exc:
            raise ShotError(f"délai dépassé ({timeout}s)") from exc


async def _capture_once(url: str, width: int, height: int) -> bytes:
    import websockets  # noqa: F401  (échoue tôt si absent)
    # Le répertoire de profil est créé avant le `try` qui couvre le lancement
    # du sous-processus : si celui-ci échoue (binaire absent, ENOMEM au fork
    # sous pression mémoire...), le `finally` doit quand même le nettoyer.
    profile = tempfile.mkdtemp(prefix="sbx-shot-")
    proc = None
    try:
        proc = await asyncio.create_subprocess_exec(
            CHROMIUM, "--headless=new", "--disable-gpu", "--no-sandbox",
            "--disable-dev-shm-usage", "--hide-scrollbars",
            f"--window-size={width},{height}",
            "--remote-debugging-port=0", f"--user-data-dir={profile}", "about:blank",
            stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.PIPE)
        ws_url = await _devtools_url(proc)
        await _cdp(ws_url, "Page.navigate", {"url": url}, 1)
        await _wait_for_selector(ws_url)
        result = await _cdp(ws_url, "Page.captureScreenshot", {"format": "png"}, 3)
        png = base64.b64decode(result.get("data", ""))
        _reject_blank(png)
        return png
    except ShotError:
        raise
    except Exception as exc:
        # Contrat de l'interface : « lève ShotError en cas d'échec ». Un
        # FileNotFoundError (chromium absent), une erreur de connexion
        # websocket ou un message CDP malformé doivent aussi passer par là —
        # la cause d'origine est conservée via `from exc`.
        raise ShotError(f"capture échouée : {exc}") from exc
    finally:
        if proc is not None:
            proc.terminate()
            try:
                await asyncio.wait_for(proc.wait(), timeout=10)
            except asyncio.TimeoutError:
                proc.kill()
        # Un profil chromium contient potentiellement des dizaines de petits
        # fichiers (Cache, GPUCache, blob_storage, sqlite...) : la suppression
        # est bornée mais synchrone — déportée dans un exécuteur pour ne
        # jamais bloquer directement la coroutine, comme l'appel urlopen().
        await asyncio.get_running_loop().run_in_executor(
            None, shutil.rmtree, profile, True)


async def _fetch_devtools_ws_url(port: str) -> str | None:
    """Résout l'URL websocket DevTools pour `port`.

    L'appel HTTP est synchrone (`urllib`) : il est déporté dans un exécuteur
    pour ne jamais bloquer directement la boucle d'événements.
    """
    def _fetch() -> list[dict]:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/json/list", timeout=10) as r:
            return json.load(r)

    loop = asyncio.get_running_loop()
    pages = await loop.run_in_executor(None, _fetch)
    for p in pages:
        if p.get("type") == "page":
            return p["webSocketDebuggerUrl"]
    return None


async def _devtools_url(proc) -> str:
    """Lit le port de debug annoncé par chromium sur stderr, puis l'URL websocket.

    `proc.stderr` est un `asyncio.StreamReader` (sous-processus lancé via
    `asyncio.create_subprocess_exec`) : `readline()` est une coroutine réellement
    annulable, contrairement à une lecture bloquante sur un `subprocess.Popen`
    classique — c'est ce qui permet à `asyncio.wait_for` de tenir son délai
    même si chromium n'écrit jamais rien.
    """
    for _ in range(100):
        line = await proc.stderr.readline()
        text = line.decode("utf-8", "replace")
        if "DevTools listening on" in text:
            port = text.strip().split(":")[-1].split("/")[0]
            ws_url = await _fetch_devtools_ws_url(port)
            if ws_url:
                return ws_url
        if not line:
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
