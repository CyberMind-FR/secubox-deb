import asyncio
import base64
import os
import threading
import time

import pytest
from secubox_core import shotter


def test_rejects_a_blank_render():
    """Le défaut observé était un PNG de 4-6 Ko : une page blanche.
    C'est CE cas qui doit lever, sinon on archive des vignettes vides."""
    blank = b"\x89PNG\r\n\x1a\n" + b"\x00" * 3000
    with pytest.raises(shotter.ShotError, match="rendu vide"):
        shotter._reject_blank(blank)


def test_accepts_a_real_render():
    real = b"\x89PNG\r\n\x1a\n" + b"\x00" * 60000
    shotter._reject_blank(real)          # ne doit pas lever


def test_blank_threshold_is_explicit():
    assert shotter.MIN_PNG_BYTES == 20000


def test_wait_selector_targets_streamlit_root():
    assert shotter.WAIT_SELECTOR == '[data-testid="stAppViewContainer"]'


def test_content_threshold_and_interval_are_explicit_constants():
    """Comme MIN_PNG_BYTES : ajustables sans fouiller le code."""
    assert shotter.MIN_VISIBLE_TEXT_CHARS == 40
    assert shotter.CONTENT_POLL_INTERVAL == 1.0


def test_default_capture_timeout_leaves_a_real_margin():
    """Mesuré sur la board sous charge : le conteneur met déjà plus de 60s à
    apparaître. 90s (l'ancien défaut) était trop court en pratique."""
    import inspect
    default = inspect.signature(shotter.capture).parameters["timeout"].default
    assert default == 240.0


def test_wait_strategy_is_pluggable_with_streamlit_as_the_historical_default():
    """`capture()` accepte une stratégie d'attente branchable. Le défaut doit
    rester le comportement historique de ce module (Streamlit) pour ne pas
    surprendre les appelants existants ; `wait_static_ready` doit exister
    comme second choix nommé explicitement pour les pages statiques."""
    import inspect
    default = inspect.signature(shotter.capture).parameters["wait"].default
    assert default is shotter.wait_streamlit_ready
    assert shotter.wait_static_ready is not shotter.wait_streamlit_ready
    assert asyncio.iscoroutinefunction(shotter.wait_static_ready)
    assert asyncio.iscoroutinefunction(shotter.wait_streamlit_ready)


def test_wait_phases_carry_no_internal_cap():
    """Ronde 4 : deux budgets qui se disputent la décision sont une source de
    bugs sans fin. Aucune des stratégies fournies, ni la condition de
    contenu qu'elles partagent, ne doit accepter de paramètre de plafond
    (`tries`, `CONTENT_WAIT_TRIES`...) — la seule autorité sur la durée est
    `timeout` dans `capture()`."""
    import inspect
    for fn in (shotter.wait_static_ready, shotter.wait_streamlit_ready,
               shotter._wait_stable_visible_text):
        params = inspect.signature(fn).parameters
        assert "tries" not in params
        assert "max_tries" not in params
    assert not hasattr(shotter, "CONTENT_WAIT_TRIES")


# ─────────────────────────────────────────────────────────────────────────
# Stratégies d'attente, testées directement contre un `evaluate` factice —
# sans `_cdp`, sans websocket, sans chromium.
# ─────────────────────────────────────────────────────────────────────────

def test_wait_static_ready_waits_for_ready_state_then_stable_content(monkeypatch):
    """readyState doit passer à "complete" avant même de regarder le texte,
    puis le texte doit être stable au-dessus du seuil."""
    monkeypatch.setattr(shotter.asyncio, "sleep", _instant_sleep)

    ready_states = iter(["loading", "loading", "complete"])
    text_lengths = iter([4, 4, 45, 45])
    calls = []

    async def evaluate(expr):
        calls.append(expr)
        if "readyState" in expr:
            return next(ready_states, "complete")
        return next(text_lengths)

    progress = shotter._Progress()
    asyncio.run(shotter.wait_static_ready(evaluate, progress))

    # Les relevés readyState précèdent tous les relevés de texte.
    text_started_at = next(i for i, e in enumerate(calls) if "innerText" in e)
    assert all("readyState" in e for e in calls[:text_started_at])
    assert progress.phase == "attente de la stabilité du contenu visible"


def test_wait_static_ready_ignores_readyState_until_complete(monkeypatch):
    """Tant que readyState n'est pas "complete", le texte ne doit jamais être
    interrogé — l'ordre des deux conditions est un contrat, pas un détail.
    `evaluate` fait respecter cet ordre lui-même (assertion interne) plutôt
    que de compter des appels : toute violation remonte comme une erreur."""
    monkeypatch.setattr(shotter.asyncio, "sleep", _instant_sleep)
    calls = {"n": 0}

    async def evaluate(expr):
        assert "innerText" not in expr, "texte interrogé avant readyState complet"
        calls["n"] += 1
        return "complete" if calls["n"] >= 5 else "loading"

    progress = shotter._Progress()
    # `evaluate` fait respecter l'ordre lui-même : dès que readyState est
    # "complete" (au 5e relevé), wait_static_ready passe au texte visible et
    # l'assertion interne à `evaluate` lève — la preuve que le texte n'est
    # JAMAIS interrogé avant. Une violation de l'ordre ferait lever
    # l'assertion bien plus tôt (avec calls["n"] < 5).
    with pytest.raises(AssertionError, match="texte interrogé avant"):
        asyncio.run(shotter.wait_static_ready(evaluate, progress))
    assert calls["n"] >= 5


def test_wait_streamlit_ready_waits_for_container_then_stable_content(monkeypatch):
    monkeypatch.setattr(shotter.asyncio, "sleep", _instant_sleep)

    container_present = iter([False, False, True])
    text_lengths = iter([4, 4, 45, 45])
    calls = []

    async def evaluate(expr):
        calls.append(expr)
        if "querySelector" in expr:
            return next(container_present, True)
        return next(text_lengths)

    progress = shotter._Progress()
    asyncio.run(shotter.wait_streamlit_ready(evaluate, progress))

    text_started_at = next(i for i, e in enumerate(calls) if "innerText" in e)
    assert all("querySelector" in e for e in calls[:text_started_at])
    assert progress.phase == "attente de la production du contenu"


def test_wait_streamlit_ready_targets_the_declared_selector(monkeypatch):
    """La stratégie Streamlit doit interroger précisément WAIT_SELECTOR, pas
    un sélecteur codé en dur en double de la constante publique."""
    seen_exprs = []

    async def evaluate(expr):
        seen_exprs.append(expr)
        return True  # conteneur présent d'emblée

    monkeypatch.setattr(shotter, "_wait_stable_visible_text",
                         _noop_async_one_arg)
    progress = shotter._Progress()
    asyncio.run(shotter.wait_streamlit_ready(evaluate, progress))
    assert shotter.WAIT_SELECTOR in seen_exprs[0]


async def _instant_sleep(_delay):
    return None


async def _noop_async_one_arg(_evaluate):
    return None


def test_wait_stable_visible_text_stuck_below_threshold_never_returns():
    """Contre-épreuve : bloqué à 4 caractères ("Stop"), la fonction ne doit
    jamais rendre la main — bornée ici par un `wait_for` de test, pas par un
    plafond interne à la fonction elle-même."""
    async def evaluate(_expr):
        return 4

    async def run_bounded():
        await asyncio.wait_for(shotter._wait_stable_visible_text(evaluate), timeout=0.3)

    with pytest.raises(asyncio.TimeoutError):
        asyncio.run(run_bounded())


def test_wait_stable_visible_text_rejects_a_single_reading_above_threshold():
    """Un relevé isolé au-dessus du seuil ne suffit pas : il faut deux
    relevés consécutifs identiques."""
    counter = {"n": 0}

    async def evaluate(_expr):
        counter["n"] += 50
        return counter["n"]  # toujours croissant, jamais stable

    async def run_bounded():
        await asyncio.wait_for(shotter._wait_stable_visible_text(evaluate), timeout=0.3)

    with pytest.raises(asyncio.TimeoutError):
        asyncio.run(run_bounded())
    assert counter["n"] > shotter.MIN_VISIBLE_TEXT_CHARS


def test_wait_stable_visible_text_accepts_when_stable_above_threshold(monkeypatch):
    monkeypatch.setattr(shotter, "CONTENT_POLL_INTERVAL", 0)
    lengths = iter([4, 4, 45, 45])

    async def evaluate(_expr):
        return next(lengths)

    asyncio.run(shotter._wait_stable_visible_text(evaluate))  # ne doit pas lever


# ─────────────────────────────────────────────────────────────────────────
# `capture()` bout en bout, sous_processus/CDP simulés — un chromium
# factice n'est jamais lancé.
# ─────────────────────────────────────────────────────────────────────────

class _FakeProc:
    """Sous-processus chromium factice : juste assez pour que `_capture_once`
    puisse le lancer et le nettoyer sans jamais toucher un vrai chromium."""

    def __init__(self):
        self.terminate_called = False

    def terminate(self):
        self.terminate_called = True

    async def wait(self):
        return 0

    def kill(self):
        pass


def _patch_launch(monkeypatch):
    """Neutralise le lancement du sous-processus et la résolution DevTools —
    seul le comportement de la stratégie d'attente reste sous test."""
    fake_proc = _FakeProc()

    async def fake_create_subprocess_exec(*args, **kwargs):
        return fake_proc

    async def fake_devtools_url(proc):
        return "ws://fake"

    monkeypatch.setattr(shotter.asyncio, "create_subprocess_exec",
                         fake_create_subprocess_exec)
    monkeypatch.setattr(shotter, "_devtools_url", fake_devtools_url)
    monkeypatch.setattr(shotter.tempfile, "mkdtemp", lambda prefix="": "/tmp/sbx-shot-fake")
    monkeypatch.setattr(shotter.shutil, "rmtree", lambda *a, **k: None)
    return fake_proc


def test_streamlit_strategy_content_stuck_below_threshold_never_produces_a_capture(monkeypatch):
    """Le texte reste bloqué à 4 caractères (le bouton "Stop" affiché tant
    que le script Streamlit s'exécute) : la capture ne doit JAMAIS aboutir.

    Aucune des deux boucles ne porte de plafond interne (ronde 4) : seul le
    `timeout` global de `capture()` peut désormais interrompre l'attente. On
    le fixe donc court pour ce test et on vérifie que l'échec survient bien
    dans ce délai — pas de capture, quel que soit le temps qu'on lui
    laisserait."""
    _patch_launch(monkeypatch)

    async def fake_cdp(ws_url, method, params, msg_id):
        if method == "Runtime.evaluate":
            expr = params.get("expression", "")
            if "querySelector" in expr:
                return {"result": {"value": True}}   # conteneur présent d'emblée
            if "innerText" in expr:
                return {"result": {"value": 4}}       # "Stop", jamais au-dessus du seuil
        return {}

    monkeypatch.setattr(shotter, "_cdp", fake_cdp)

    start = time.monotonic()
    with pytest.raises(shotter.ShotError,
                       match="attente de la production du contenu"):
        asyncio.run(shotter.capture("http://example.invalid/", timeout=0.3))
    elapsed = time.monotonic() - start

    # Coupé par le délai global, pas par un plafond interne épuisé.
    assert elapsed < 2.0


def test_unstable_text_keeps_waiting_instead_of_capturing(monkeypatch):
    """Le texte franchit le seuil mais change à chaque relevé (rendu encore
    en cours) : la capture ne doit jamais aboutir sur un relevé isolé au-dessus
    du seuil — seul le délai global peut mettre fin à l'attente."""
    _patch_launch(monkeypatch)

    counter = {"n": 0}

    async def fake_cdp(ws_url, method, params, msg_id):
        if method == "Runtime.evaluate":
            expr = params.get("expression", "")
            if "querySelector" in expr:
                return {"result": {"value": True}}
            if "innerText" in expr:
                counter["n"] += 50
                return {"result": {"value": counter["n"]}}  # toujours croissant, jamais stable
        return {}

    monkeypatch.setattr(shotter, "_cdp", fake_cdp)

    start = time.monotonic()
    with pytest.raises(shotter.ShotError,
                       match="attente de la production du contenu"):
        asyncio.run(shotter.capture("http://example.invalid/", timeout=0.3))
    elapsed = time.monotonic() - start

    assert elapsed < 2.0
    assert counter["n"] > shotter.MIN_VISIBLE_TEXT_CHARS


def test_static_strategy_stuck_on_ready_state_never_produces_a_capture(monkeypatch):
    """Contre-épreuve côté page statique : readyState ne passe jamais à
    "complete" — la capture ne doit jamais aboutir, échec identifié à la
    bonne phase, borné par le seul timeout global."""
    _patch_launch(monkeypatch)

    async def fake_cdp(ws_url, method, params, msg_id):
        if method == "Runtime.evaluate":
            expr = params.get("expression", "")
            if "readyState" in expr:
                return {"result": {"value": "loading"}}
        return {}

    monkeypatch.setattr(shotter, "_cdp", fake_cdp)

    start = time.monotonic()
    with pytest.raises(shotter.ShotError,
                       match="attente du chargement de la page"):
        asyncio.run(shotter.capture("http://example.invalid/", timeout=0.3,
                                    wait=shotter.wait_static_ready))
    elapsed = time.monotonic() - start
    assert elapsed < 2.0


def test_static_strategy_succeeds_once_loaded_and_stable(monkeypatch):
    """Contre-épreuve positive côté page statique, bout en bout via
    `capture()` : readyState complet puis texte stable au-dessus du seuil
    doit produire un PNG accepté."""
    monkeypatch.setattr(shotter.asyncio, "sleep", _instant_sleep)
    _patch_launch(monkeypatch)

    ready_calls = {"n": 0}
    text_lengths = iter([4, 4, 45, 45])

    async def fake_cdp(ws_url, method, params, msg_id):
        if method == "Runtime.evaluate":
            expr = params.get("expression", "")
            if "readyState" in expr:
                ready_calls["n"] += 1
                return {"result": {"value": "complete" if ready_calls["n"] >= 3 else "loading"}}
            if "innerText" in expr:
                return {"result": {"value": next(text_lengths, 45)}}
        if method == "Page.captureScreenshot":
            payload = base64.b64encode(b"\x89PNG\r\n\x1a\n" + b"\x00" * 60000)
            return {"data": payload.decode("ascii")}
        return {}

    monkeypatch.setattr(shotter, "_cdp", fake_cdp)

    png = asyncio.run(shotter.capture("http://example.invalid/", timeout=30.0,
                                      wait=shotter.wait_static_ready))
    assert len(png) >= shotter.MIN_PNG_BYTES


def test_late_success_still_succeeds_beyond_the_former_internal_caps(monkeypatch):
    """Le test qui compte le plus pour cette ronde : la garantie que la
    suppression des plafonds internes est réelle, pas seulement documentée.

    Le conteneur n'apparaît qu'après 90 relevés (l'ancien plafond de
    l'attente du sélecteur était 60) et le contenu ne se stabilise qu'après
    250 relevés (l'ancien plafond de l'attente de contenu était 180). Avec un
    délai global généreux, la capture doit malgré tout aboutir. Si un plafond
    interne était réintroduit dans l'une ou l'autre boucle, ce test
    échouerait sur "sélecteur jamais apparu" ou "contenu jamais stabilisé"
    bien avant que la condition ne soit enfin remplie.

    Les pauses réelles entre relevés sont neutralisées (`asyncio.sleep`
    devient instantané) : seul le NOMBRE d'itérations nous intéresse ici, pas
    le temps réel. `asyncio.wait_for` s'appuie sur ses propres minuteries
    internes, indépendantes de `asyncio.sleep()` — le délai global reste donc
    réellement appliqué si jamais le scénario ne convergeait pas."""
    monkeypatch.setattr(shotter.asyncio, "sleep", _instant_sleep)
    _patch_launch(monkeypatch)

    SELECTOR_APPEARS_AT = 90     # > l'ancien plafond de 60
    CONTENT_STABLE_AT = 250      # > l'ancien plafond de 180

    selector_calls = {"n": 0}
    content_calls = {"n": 0}

    async def fake_cdp(ws_url, method, params, msg_id):
        if method == "Runtime.evaluate":
            expr = params.get("expression", "")
            if "querySelector" in expr:
                selector_calls["n"] += 1
                return {"result": {"value": selector_calls["n"] >= SELECTOR_APPEARS_AT}}
            if "innerText" in expr:
                content_calls["n"] += 1
                if content_calls["n"] < CONTENT_STABLE_AT:
                    return {"result": {"value": content_calls["n"]}}  # jamais stable
                return {"result": {"value": 9999}}  # se stabilise enfin
        if method == "Page.captureScreenshot":
            payload = base64.b64encode(b"\x89PNG\r\n\x1a\n" + b"\x00" * 60000)
            return {"data": payload.decode("ascii")}
        return {}

    monkeypatch.setattr(shotter, "_cdp", fake_cdp)

    png = asyncio.run(shotter.capture("http://example.invalid/", timeout=30.0))

    assert len(png) >= shotter.MIN_PNG_BYTES
    assert selector_calls["n"] >= SELECTOR_APPEARS_AT
    assert content_calls["n"] >= CONTENT_STABLE_AT


def test_capture_stays_responsive_while_the_launched_process_stays_silent(
        monkeypatch, tmp_path):
    """Le test qui compte le plus : si le sous-processus n'écrit jamais rien
    sur stderr, `capture()` doit rendre la main dans le délai imparti — et la
    boucle d'événements doit rester libre pendant l'attente, pas gelée.

    Honnêteté du test : on ne double PAS `asyncio.create_subprocess_exec`
    (l'ancien code fautif ne l'appelait même pas, il utilisait
    `subprocess.Popen` — un tel double ne rejouerait donc jamais la
    régression). On remplace `shotter.CHROMIUM` par un vrai sous-processus —
    un script shell qui `exec sleep`, silencieux, quel que soit l'argv qu'on
    lui passe. C'est un vrai processus OS : si `_devtools_url` redevenait une
    lecture bloquante (`subprocess.Popen(...).stderr.readline()`), cet appel
    gèlerait pour de vrai le thread qui fait tourner la boucle d'événements,
    exactement comme en production.

    Le scénario tourne dans un thread à part, borné par un `join(timeout=…)`
    : si l'implémentation redevient bloquante, ce thread ne rend pas la main
    à temps et l'assertion échoue — sans geler pytest lui-même. Régression
    visée : un appel bloquant dans une coroutine gèlerait tout le daemon
    FastAPI (déjà vu deux fois sur ce projet : rendu PDF synchrone, appel
    bloquant dans l'agrégateur)."""
    fake_chromium = tmp_path / "fake-chromium"
    fake_chromium.write_text("#!/bin/sh\nexec sleep 5\n")
    fake_chromium.chmod(0o755)
    monkeypatch.setattr(shotter, "CHROMIUM", str(fake_chromium))

    result = {}

    def worker():
        async def scenario():
            ticks = []

            async def ticker():
                # Tourne concurremment à la capture : si la boucle est gelée
                # par un appel bloquant, ce compteur n'avance pas du tout.
                for _ in range(40):
                    await asyncio.sleep(0.02)
                    ticks.append(1)

            async def do_capture():
                start = time.monotonic()
                try:
                    await shotter.capture("http://example.invalid/", timeout=0.3)
                except shotter.ShotError:
                    pass
                return time.monotonic() - start

            _, elapsed = await asyncio.gather(ticker(), do_capture())
            return ticks, elapsed

        ticks, elapsed = asyncio.run(scenario())
        result["ticks"] = ticks
        result["elapsed"] = elapsed

    worker_thread = threading.Thread(target=worker, daemon=True)
    worker_thread.start()
    # Le vrai sous-processus dort 5 s sans rien écrire ; le délai de capture
    # demandé est de 0.3 s. 2 s de marge suffit largement si l'attente est
    # bien non bloquante, et reste bien en-deçà des 5 s qu'exigerait un
    # readline() bloqué sur un flux qui ne se ferme jamais avant terme.
    worker_thread.join(timeout=2.0)

    assert not worker_thread.is_alive(), (
        "capture() n'a pas rendu la main dans le délai imparti — la lecture "
        "du sous-processus est probablement redevenue bloquante et gèle la "
        "boucle d'événements (et donc tout le daemon FastAPI)."
    )
    # Le temps réel écoulé reste proche du timeout demandé (0.3 s), pas de la
    # durée du sous-processus (5 s) : preuve que l'attente est bornée par
    # asyncio.wait_for, pas par une lecture bloquante.
    assert result["elapsed"] < 1.5
    # La boucle d'événements est restée libre pendant l'attente : le ticker
    # concurrent a progressé.
    assert len(result["ticks"]) > 5


def test_launch_failure_cleans_up_profile_dir(monkeypatch, tmp_path):
    """Si le lancement de chromium échoue, le répertoire de profil créé par
    `tempfile.mkdtemp()` ne doit pas fuir sur disque."""
    created = []

    def spy_mkdtemp(prefix=""):
        d = tmp_path / f"{prefix}spy"
        d.mkdir()
        created.append(str(d))
        return str(d)

    async def fake_create_subprocess_exec(*args, **kwargs):
        raise FileNotFoundError("chromium introuvable")

    monkeypatch.setattr(shotter.tempfile, "mkdtemp", spy_mkdtemp)
    monkeypatch.setattr(shotter.asyncio, "create_subprocess_exec",
                         fake_create_subprocess_exec)

    with pytest.raises(shotter.ShotError):
        asyncio.run(shotter.capture("http://example.invalid/", timeout=1.0))

    assert created, "le répertoire de profil aurait dû être créé"
    assert not os.path.exists(created[0])


class _FakeProcDeadOnTerminate:
    """Simule un chromium déjà mort au moment du nettoyage : `terminate()`
    lève `ProcessLookupError`, exactement le crash observé sur une board
    à ~2 Go de mémoire libre (OOM) ou après une bibliothèque manquante
    suite à une mise à jour."""

    async def wait(self):
        return 0

    def terminate(self):
        raise ProcessLookupError("process introuvable")

    def kill(self):
        raise ProcessLookupError("process introuvable")


def test_terminate_on_an_already_dead_process_still_cleans_up_and_raises_shoterror(
        monkeypatch, tmp_path):
    """Cas réel : chromium meurt avant que le nettoyage n'ait lieu.
    `proc.terminate()` lève alors `ProcessLookupError` dans le `finally` —
    cela ne doit ni faire fuir le répertoire de profil temporaire (le
    `rmtree` qui suit ne doit jamais être sauté), ni laisser échapper une
    exception brute qui romprait le contrat « capture() lève ShotError en
    cas d'échec »."""
    created = []

    def spy_mkdtemp(prefix=""):
        d = tmp_path / f"{prefix}spy"
        d.mkdir()
        created.append(str(d))
        return str(d)

    fake_proc = _FakeProcDeadOnTerminate()

    async def fake_create_subprocess_exec(*args, **kwargs):
        return fake_proc

    async def fake_devtools_url(proc):
        # Le processus est mort avant d'avoir jamais annoncé son port de
        # debug : c'est ce qui déclenche le ShotError d'origine que le
        # `finally` ne doit pas masquer.
        raise ConnectionRefusedError("chromium déjà mort, pas de port de debug")

    monkeypatch.setattr(shotter.tempfile, "mkdtemp", spy_mkdtemp)
    monkeypatch.setattr(shotter.asyncio, "create_subprocess_exec",
                         fake_create_subprocess_exec)
    monkeypatch.setattr(shotter, "_devtools_url", fake_devtools_url)

    with pytest.raises(shotter.ShotError):
        asyncio.run(shotter.capture("http://example.invalid/", timeout=1.0))

    assert created, "le répertoire de profil aurait dû être créé"
    assert not os.path.exists(created[0]), (
        "le répertoire de profil temporaire a fuité : terminate() a levé "
        "ProcessLookupError et interrompu le `finally` avant le rmtree"
    )


def test_low_level_failure_is_wrapped_as_shot_error(monkeypatch, tmp_path):
    """Le contrat de l'interface promet ShotError « en cas d'échec » — un
    échec de bas niveau (chromium absent, websocket injoignable, message CDP
    malformé) ne doit jamais ressortir brut : un appelant qui ne rattrape que
    ShotError ne doit pas se faire surprendre. La cause d'origine doit être
    conservée pour le diagnostic."""
    boom = ConnectionRefusedError("websocket injoignable")

    async def fake_create_subprocess_exec(*args, **kwargs):
        raise boom

    monkeypatch.setattr(shotter.tempfile, "mkdtemp",
                         lambda prefix="": str(tmp_path))
    monkeypatch.setattr(shotter.shutil, "rmtree", lambda *a, **k: None)
    monkeypatch.setattr(shotter.asyncio, "create_subprocess_exec",
                         fake_create_subprocess_exec)

    with pytest.raises(shotter.ShotError) as exc_info:
        asyncio.run(shotter.capture("http://example.invalid/", timeout=1.0))

    assert exc_info.value.__cause__ is boom
