# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: shotter — capture d'écran pilotée par CDP

`chromium --screenshot` ne convient pas : il capture à l'événement `load`, or
une application dynamique (Streamlit) ne sert qu'une coquille HTML et ne
peint qu'après connexion websocket et push du serveur. Mesuré sur gk2 : 58 à
94 s pour un PNG de 4 à 6 Ko en 1280x800 — une page blanche.

On pilote donc chromium par le protocole DevTools : naviguer, ATTENDRE que la
page soit prête selon une stratégie fournie par l'appelant, puis capturer.

Ce module ne connaît que chromium et le protocole CDP — il ignore tout du
sens de « prêt » pour une cible donnée. Cette notion est déléguée à une
*stratégie d'attente*, une fonction asynchrone `(evaluate, progress) -> None`
qui interroge le DOM via `evaluate` (le seul point de contact fourni) et rend
la main quand la page est prête, ou lève `ShotError` avec une phase
identifiable. Deux stratégies prêtes à l'emploi couvrent les deux familles de
cibles connues à ce jour :

- `wait_static_ready` : une page statique peint au chargement. Mesuré sur
  https://3d.gk2.secubox.in/ : `readyState` passe à `"complete"`, le texte
  visible se stabilise dès le 5ᵉ relevé, pour un PNG final de 120 800 octets.
  Aucun sélecteur applicatif à connaître.
- `wait_streamlit_ready` (le défaut historique de ce module) : le conteneur
  `[data-testid="stAppViewContainer"]` apparaît vers 60 s, mais la page ne
  contient alors que « Stop » — le bouton affiché pendant l'exécution du
  script. Il faut attendre le conteneur PUIS la production du contenu.
  Diagnostic mesuré sur une vraie appli, board sous charge :

      t=10s  readyState=interactive  texte visible=0   conteneur ABSENT
      t=30s  readyState=interactive  texte visible=0   conteneur ABSENT
      t=60s  readyState=complete     texte visible=4   conteneur PRÉSENT

Les deux stratégies partagent la même condition de contenu
(`_wait_stable_visible_text`) : texte visible au-dessus d'un seuil plancher
ET stable entre deux relevés consécutifs — voir sa docstring.

Une seule capture à la fois : deux chromium concurrents ne tiennent pas dans les
~2 Go disponibles sur la board.

Une seule autorité gouverne la durée totale : le paramètre `timeout` de
`capture()`. Les phases d'attente (port de debug, stratégie fournie) ne
portent aucun plafond interne — elles tournent jusqu'à ce que leur condition
soit remplie ou que `asyncio.wait_for` les annule. Un plafond interne calibré
sur une mesure de board (chargée un jour, au repos un autre) est soit trop
court, soit trop long, et se dispute silencieusement la décision avec
`timeout` : exactement le bug observé en ronde 4, où l'ancienne attente du
sélecteur abandonnait à 60 tries (~60s) avant même que `timeout=600s` n'ait
voix au chapitre. Le diagnostic de phase (« bloqué à quelle étape ») est
conservé — voir `_Progress` — mais plus le pouvoir de décision. Une stratégie
d'attente qui réintroduirait un tel plafond romprait ce contrat : ne pas en
ajouter.

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
import itertools
import json
import shutil
import tempfile
import urllib.request

CHROMIUM = shutil.which("chromium") or "/usr/bin/chromium"

# Sélecteur du conteneur racine Streamlit — utilisé exclusivement par
# `wait_streamlit_ready`. Conservé comme constante de module (et pas
# recalculé à chaque appel) : c'est un contrat public, testé explicitement.
WAIT_SELECTOR = '[data-testid="stAppViewContainer"]'

# Un rendu réel (Streamlit ou page statique) pèse au minimum plusieurs
# dizaines de Ko. En dessous de ce seuil, c'est la page blanche qu'on cherche
# précisément à ne plus archiver.
MIN_PNG_BYTES = 20000

# Le bouton « Stop » affiché par Streamlit pendant l'exécution du script fait
# 4 caractères — c'est le seul texte visible au moment où le conteneur racine
# apparaît (mesuré sur une vraie appli, voir docstring du module). Le seuil
# doit dépasser largement ce faux positif sans exiger une appli bavarde.
MIN_VISIBLE_TEXT_CHARS = 40
# Deux relevés consécutifs, espacés de cet intervalle, doivent rapporter la
# même longueur de texte visible avant de juger le contenu stable — sinon on
# risque de capturer un rendu partiel, en cours de production. Ce n'est PAS un
# plafond de durée : la boucle qui utilise cet intervalle n'abandonne jamais
# d'elle-même, voir la docstring du module.
CONTENT_POLL_INTERVAL = 1.0

_lock = asyncio.Lock()


class ShotError(RuntimeError):
    """Capture impossible, ou rendu jugé vide."""


class _Progress:
    """Trace la dernière phase entamée par `_capture_once` ou par la
    stratégie d'attente en cours.

    Seul rôle : enrichir le diagnostic si `timeout` expire — savoir *où* ça a
    coincé (port de debug ? conteneur ? contenu ?). Ne participe à aucune
    décision de durée : ce n'est pas un budget, juste une étiquette lue après
    coup par `capture()` dans son `except asyncio.TimeoutError`. Une
    stratégie d'attente la reçoit en second paramètre et peut y écrire sa
    propre progression, plus fine que le simple « exécution de la stratégie
    d'attente » que `_capture_once` y aurait laissé sinon.
    """

    def __init__(self) -> None:
        self.phase = "lancement du sous-processus chromium"


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


def _make_evaluator(ws_url: str):
    """Renvoie `evaluate(expr) -> valeur JS`, l'unique moyen dont dispose une
    stratégie d'attente pour interroger le DOM de la page capturée.

    Les identifiants de message CDP démarrent à 100 pour ne jamais entrer en
    collision avec `Page.navigate` (id=1) et `Page.captureScreenshot` (id=3),
    envoyés directement par `_capture_once`.
    """
    counter = itertools.count(100)

    async def evaluate(expression: str):
        msg_id = next(counter)
        res = await _cdp(ws_url, "Runtime.evaluate",
                         {"expression": expression, "returnByValue": True}, msg_id)
        return res.get("result", {}).get("value")

    return evaluate


async def _wait_stable_visible_text(evaluate) -> None:
    """Attend que le texte visible de la page dépasse un seuil plancher ET
    soit stable entre deux relevés consécutifs.

    Partagée par `wait_static_ready` et `wait_streamlit_ready` : c'est la
    même condition de contenu pour les deux familles de cibles, seule la
    condition qui la précède diffère (`readyState` vs conteneur applicatif).

    Le seuil plancher évite de confondre une coquille bavarde (ex. le bouton
    « Stop » de Streamlit, 4 caractères) avec un rendu réel. La condition de
    stabilité évite en plus de capturer un rendu partiel, en cours de
    production.

    Boucle non bornée : aucun plafond interne, voir la docstring du module —
    seule `timeout` dans `capture()` peut interrompre cette attente.
    """
    expr = "(document.body && document.body.innerText || '').length"
    previous_length = None
    while True:
        length = await evaluate(expr) or 0
        if length >= MIN_VISIBLE_TEXT_CHARS and length == previous_length:
            return
        previous_length = length
        await asyncio.sleep(CONTENT_POLL_INTERVAL)


async def wait_static_ready(evaluate, progress: _Progress) -> None:
    """Stratégie d'attente pour une page statique (pas de websocket, peint au
    chargement — ex. un site généré par secubox-metablogizer).

    Mesuré sur https://3d.gk2.secubox.in/ : `readyState` passe à
    `"complete"`, puis le texte visible se stabilise dès le 5ᵉ relevé
    (CONTENT_POLL_INTERVAL=1s, donc ~5s), pour un PNG final de 120 800
    octets — très au-dessus de `MIN_PNG_BYTES`. Pas de conteneur applicatif à
    connaître : `readyState` complet, puis la même condition de contenu que
    `wait_streamlit_ready`, suffit.

    Boucle non bornée : aucun plafond interne, voir la docstring du module.
    """
    progress.phase = "attente du chargement de la page (readyState)"
    while await evaluate("document.readyState") != "complete":
        await asyncio.sleep(1.0)
    progress.phase = "attente de la stabilité du contenu visible"
    await _wait_stable_visible_text(evaluate)


async def wait_streamlit_ready(evaluate, progress: _Progress) -> None:
    """Stratégie d'attente pour une appli Streamlit.

    Le conteneur racine `WAIT_SELECTOR` apparaît (mesuré sur la board, page
    sous charge) vers t=60s — mais à cet instant la page ne contient que le
    bouton « Stop » (4 caractères), affiché tant que le script s'exécute
    encore. Il faut donc attendre le conteneur PUIS la même condition de
    contenu que `wait_static_ready` : texte visible au-dessus du seuil,
    stable entre deux relevés. Volontairement indépendant de tout indicateur
    d'exécution interne à Streamlit (`stStatusWidget` ou équivalent) : c'est
    un détail d'implémentation qui change entre versions, alors que le texte
    visible de la page est un signal stable dans le temps.

    Boucle non bornée : aucun plafond interne, voir la docstring du module.
    """
    progress.phase = "attente du conteneur racine Streamlit"
    selector_expr = f'!!document.querySelector({WAIT_SELECTOR!r})'
    while not await evaluate(selector_expr):
        await asyncio.sleep(1.0)
    progress.phase = "attente de la production du contenu"
    await _wait_stable_visible_text(evaluate)


async def capture(url: str, *, timeout: float = 240.0,
                  width: int = 1280, height: int = 800,
                  wait=wait_streamlit_ready) -> bytes:
    """Navigue vers `url`, attend le rendu selon `wait`, renvoie le PNG.

    `wait` est une stratégie d'attente branchable — une fonction asynchrone
    `(evaluate, progress) -> None` qui rend la main quand la page est prête,
    ou lève `ShotError` avec une phase identifiable. Par défaut
    `wait_streamlit_ready` (le comportement historique de ce module). Pour
    une page statique, passer `wait_static_ready`. Aucune stratégie fournie
    par ce module ne porte de plafond de durée interne : `timeout` reste la
    seule autorité — voir la docstring du module.

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
    progress = _Progress()
    async with _lock:
        try:
            return await asyncio.wait_for(
                _capture_once(url, width, height, progress, wait), timeout=timeout)
        except asyncio.TimeoutError as exc:
            raise ShotError(
                f"délai dépassé ({timeout}s) — bloqué à la phase : "
                f"{progress.phase}") from exc


async def _capture_once(url: str, width: int, height: int,
                        progress: _Progress, wait) -> bytes:
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
        progress.phase = "attente du port de debug chromium (stderr)"
        ws_url = await _devtools_url(proc)
        progress.phase = "navigation vers l'URL cible"
        await _cdp(ws_url, "Page.navigate", {"url": url}, 1)
        evaluate = _make_evaluator(ws_url)
        await wait(evaluate, progress)
        progress.phase = "capture d'écran"
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
        raise ShotError(
            f"capture échouée pendant « {progress.phase} » : {exc}") from exc
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

    Boucle non bornée : aucun plafond interne. La seule autorité sur la durée
    totale est `timeout` dans `capture()`, qui interrompt cette attente par
    annulation si nécessaire — voir la docstring du module.
    """
    while True:
        line = await proc.stderr.readline()
        text = line.decode("utf-8", "replace")
        if "DevTools listening on" in text:
            port = text.strip().split(":")[-1].split("/")[0]
            ws_url = await _fetch_devtools_ws_url(port)
            if ws_url:
                return ws_url
        if not line:
            await asyncio.sleep(0.1)
