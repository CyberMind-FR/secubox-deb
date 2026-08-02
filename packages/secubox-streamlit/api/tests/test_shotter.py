import asyncio
import os
import threading
import time

import pytest
from api import shotter


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
    assert shotter.CONTENT_WAIT_TRIES == 180


def test_default_capture_timeout_leaves_a_real_margin():
    """Mesuré sur la board sous charge : le conteneur met déjà plus de 60s à
    apparaître. 90s (l'ancien défaut) était trop court en pratique."""
    import inspect
    default = inspect.signature(shotter.capture).parameters["timeout"].default
    assert default == 240.0


def test_content_stuck_below_threshold_never_produces_a_capture(monkeypatch):
    """Le texte reste bloqué à 4 caractères (le bouton "Stop" affiché tant
    que le script Streamlit s'exécute) : _wait_for_content ne doit JAMAIS
    rendre la main normalement — seulement épuiser ses relevés et lever
    ShotError. C'est le défaut réellement mesuré : conteneur présent, texte
    encore "Stop" à t=60s."""
    monkeypatch.setattr(shotter, "CONTENT_WAIT_TRIES", 5)
    monkeypatch.setattr(shotter, "CONTENT_POLL_INTERVAL", 0)

    calls = []

    async def fake_cdp(ws_url, method, params, msg_id):
        calls.append(msg_id)
        return {"result": {"value": 4}}  # "Stop", stable, jamais au-dessus du seuil

    monkeypatch.setattr(shotter, "_cdp", fake_cdp)

    with pytest.raises(shotter.ShotError, match="jamais stabilisé"):
        asyncio.run(shotter._wait_for_content("ws://fake"))

    # Les CONTENT_WAIT_TRIES relevés ont bien tous été consommés : aucune
    # sortie anticipée sur un texte sous le seuil, même stable.
    assert len(calls) == 5


def test_unstable_text_keeps_waiting_instead_of_capturing(monkeypatch):
    """Le texte franchit le seuil mais change à chaque relevé (rendu encore
    en cours) : _wait_for_content doit continuer à patienter — jamais
    accepter un relevé isolé au-dessus du seuil comme preuve de contenu
    produit."""
    monkeypatch.setattr(shotter, "CONTENT_WAIT_TRIES", 6)
    monkeypatch.setattr(shotter, "CONTENT_POLL_INTERVAL", 0)

    # Toujours au-dessus du seuil (40) dès le 2e relevé, mais jamais deux
    # valeurs consécutives identiques : simule un rendu qui continue de
    # produire du texte, jamais figé.
    lengths = iter([10, 50, 90, 130, 170, 210])

    async def fake_cdp(ws_url, method, params, msg_id):
        return {"result": {"value": next(lengths)}}

    monkeypatch.setattr(shotter, "_cdp", fake_cdp)

    with pytest.raises(shotter.ShotError, match="jamais stabilisé"):
        asyncio.run(shotter._wait_for_content("ws://fake"))


def test_stable_text_above_threshold_is_accepted(monkeypatch):
    """Contre-épreuve positive : une fois le texte à la fois au-dessus du
    seuil et identique à deux relevés consécutifs, _wait_for_content doit
    rendre la main normalement (ni lever, ni attendre inutilement)."""
    monkeypatch.setattr(shotter, "CONTENT_WAIT_TRIES", 10)
    monkeypatch.setattr(shotter, "CONTENT_POLL_INTERVAL", 0)

    # "Stop" stable (4, 4) puis contenu réel stable au-dessus du seuil (45, 45).
    lengths = iter([4, 4, 45, 45])

    async def fake_cdp(ws_url, method, params, msg_id):
        return {"result": {"value": next(lengths)}}

    monkeypatch.setattr(shotter, "_cdp", fake_cdp)

    asyncio.run(shotter._wait_for_content("ws://fake"))  # ne doit pas lever


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
