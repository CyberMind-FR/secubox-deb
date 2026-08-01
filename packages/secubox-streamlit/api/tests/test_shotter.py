import asyncio
import os

import pytest
from api import shotter


class _HangingStderr:
    """Simule `proc.stderr` d'un chromium qui n'écrit jamais rien : la
    coroutine `readline()` ne rend jamais la main d'elle-même."""

    async def readline(self):
        await asyncio.sleep(999)
        return b""  # jamais atteint dans les tests ci-dessous


class _HangingProcess:
    """Simule un `asyncio.subprocess.Process` dont le sous-processus ne
    répond jamais sur stderr — le cas plausible sous pression mémoire sur la
    board (~2 Go disponibles)."""

    def __init__(self):
        self.stderr = _HangingStderr()
        self.terminate_called = False

    def terminate(self):
        self.terminate_called = True

    async def wait(self):
        return 0

    def kill(self):
        pass


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


def test_capture_times_out_without_freezing_the_event_loop(monkeypatch, tmp_path):
    """Le test qui compte le plus : si chromium n'écrit jamais sur stderr,
    `capture()` doit lever ShotError dans le délai imparti — et la boucle
    d'événements doit rester libre pendant l'attente, pas gelée.

    Régression visée : `proc.stderr.readline()` appelé de façon bloquante
    dans une coroutine gèlerait tout le daemon FastAPI (déjà vu deux fois sur
    ce projet : rendu PDF synchrone, appel bloquant dans l'agrégateur)."""
    hanging = _HangingProcess()

    async def fake_create_subprocess_exec(*args, **kwargs):
        return hanging

    monkeypatch.setattr(shotter.asyncio, "create_subprocess_exec",
                         fake_create_subprocess_exec)
    monkeypatch.setattr(shotter.tempfile, "mkdtemp",
                         lambda prefix="": str(tmp_path))
    monkeypatch.setattr(shotter.shutil, "rmtree", lambda *a, **k: None)

    async def scenario():
        ticks = []

        async def ticker():
            # Tourne pendant toute la durée de l'attente : si la boucle est
            # gelée par un appel bloquant, ce compteur n'avancera pas.
            for _ in range(30):
                await asyncio.sleep(0.02)
                ticks.append(1)

        async def do_capture():
            with pytest.raises(shotter.ShotError):
                await shotter.capture("http://example.invalid/", timeout=0.3)

        await asyncio.gather(ticker(), do_capture())
        return ticks

    ticks = asyncio.run(scenario())

    # La boucle a continué de tourner concurremment à l'attente : preuve
    # qu'aucun appel bloquant n'a gelé l'event loop.
    assert len(ticks) > 5
    # Le sous-processus (même « bloqué ») a bien été terminé au nettoyage.
    assert hanging.terminate_called


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
