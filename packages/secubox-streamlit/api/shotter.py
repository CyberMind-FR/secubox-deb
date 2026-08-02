"""Capture d'écran d'une appli Streamlit, pilotée par CDP.

`chromium --screenshot` ne convient pas : il capture à l'événement `load`, or
Streamlit ne sert qu'une coquille HTML et ne peint qu'après connexion websocket
et push du serveur. Mesuré sur gk2 : 58 à 94 s pour un PNG de 4 à 6 Ko en
1280x800 — une page blanche.

On pilote donc chromium par le protocole DevTools : naviguer, ATTENDRE le
conteneur racine de Streamlit, puis ATTENDRE que le contenu soit réellement
produit, puis capturer.

Ces deux attentes sont distinctes et ne doivent pas être confondues.
Diagnostic mesuré sur une vraie appli, board sous charge :

    t=10s  readyState=interactive  texte visible=0   conteneur ABSENT
    t=30s  readyState=interactive  texte visible=0   conteneur ABSENT
    t=60s  readyState=complete     texte visible=4   conteneur PRÉSENT

Au moment où le conteneur apparaît, le seul texte visible est « Stop » (4
caractères) — le bouton que Streamlit affiche pendant que le script s'exécute
encore. Attendre la seule apparition du conteneur capture donc ce bouton, pas
le rendu. Il faut attendre, après le conteneur, que le texte visible dépasse
un seuil plancher ET soit stable entre deux relevés consécutifs — voir
`_wait_for_content`.

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

# Le bouton « Stop » affiché par Streamlit pendant l'exécution du script fait
# 4 caractères — c'est le seul texte visible au moment où le conteneur racine
# apparaît (mesuré sur une vraie appli, voir docstring du module). Le seuil
# doit dépasser largement ce faux positif sans exiger une appli bavarde.
MIN_VISIBLE_TEXT_CHARS = 40
# Deux relevés consécutifs, espacés de cet intervalle, doivent rapporter la
# même longueur de texte visible avant de juger le contenu stable — sinon on
# risque de capturer un rendu partiel, en cours de production.
CONTENT_POLL_INTERVAL = 1.0
# Nombre de relevés maximum avant d'abandonner. Borne indépendante de
# l'attente du conteneur (WAIT_SELECTOR ci-dessus) : ça permet de distinguer,
# à l'échec, un diagnostic « conteneur jamais apparu » d'un diagnostic
# « contenu jamais stabilisé ».
CONTENT_WAIT_TRIES = 180

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


async def capture(url: str, *, timeout: float = 240.0,
                  width: int = 1280, height: int = 800) -> bytes:
    """Navigue vers `url`, attend le rendu Streamlit, renvoie le PNG.

    Lève `ShotError` dans tous les cas d'échec — y compris un dépassement du
    délai `timeout`, pour tenir le contrat de l'interface : un appelant qui ne
    rattrape que `ShotError` ne doit jamais se faire surprendre.

    `timeout` par défaut à 240 s : mesuré sur la board sous charge, le
    conteneur racine Streamlit met déjà plus de 60 s à apparaître, et le
    texte visible n'a encore que 4 caractères (« Stop ») à ce même t=60s — le
    contenu réel prend donc encore plus longtemps à se stabiliser au-delà. Une
    capture est un événement rare, jamais une boucle : une marge large coûte
    peu et évite des vignettes rejetées par MIN_PNG_BYTES faute de temps.
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
        await _wait_for_content(ws_url)
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
    """Interroge le DOM jusqu'à ce que le conteneur racine Streamlit existe.

    Ceci ne prouve pas que le contenu est produit : voir `_wait_for_content`,
    appelé juste après par `_capture_once`. C'est un échec distinct
    (« conteneur jamais apparu ») de celui de `_wait_for_content`
    (« contenu jamais stabilisé »).
    """
    expr = f'!!document.querySelector({WAIT_SELECTOR!r})'
    for i in range(tries):
        res = await _cdp(ws_url, "Runtime.evaluate",
                         {"expression": expr, "returnByValue": True}, 100 + i)
        if res.get("result", {}).get("value") is True:
            return
        await asyncio.sleep(1.0)
    raise ShotError(f"sélecteur {WAIT_SELECTOR} jamais apparu")


async def _wait_for_content(ws_url: str) -> None:
    """Attend que le texte visible de la page dépasse un seuil plancher ET
    soit stable entre deux relevés consécutifs.

    Le conteneur racine Streamlit apparaît bien avant que le script ait fini
    de s'exécuter : pendant ce temps, le seul texte visible est le bouton
    « Stop » (`MIN_VISIBLE_TEXT_CHARS` est calibré pour dépasser largement ces
    4 caractères — voir la docstring du module pour la mesure). La condition
    de stabilité évite en plus de capturer un rendu partiel, en cours de
    production.

    Volontairement indépendant de tout indicateur d'exécution interne à
    Streamlit (`stStatusWidget` ou équivalent) : c'est un détail
    d'implémentation qui change entre versions, alors que le texte visible de
    la page est un signal stable dans le temps.
    """
    expr = "(document.body && document.body.innerText || '').length"
    previous_length = None
    for i in range(CONTENT_WAIT_TRIES):
        res = await _cdp(ws_url, "Runtime.evaluate",
                         {"expression": expr, "returnByValue": True}, 300 + i)
        length = res.get("result", {}).get("value") or 0
        if length >= MIN_VISIBLE_TEXT_CHARS and length == previous_length:
            return
        previous_length = length
        await asyncio.sleep(CONTENT_POLL_INTERVAL)
    raise ShotError(
        f"contenu jamais stabilisé (moins de {MIN_VISIBLE_TEXT_CHARS} "
        f"caractères visibles, ou instable) après {CONTENT_WAIT_TRIES} relevés")
