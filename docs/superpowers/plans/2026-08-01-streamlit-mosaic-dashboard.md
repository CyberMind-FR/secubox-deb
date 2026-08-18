<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Mur mosaïque Streamlit — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Un mur d'écrans des applis Streamlit — vignette conservée, état éveillé/endormi, temps restant avant mise en veille — sans jamais empêcher une mise en veille.

**Architecture:** Trois couches indépendantes. Le `ctl` expose l'état d'inactivité par appli (déjà en base, jamais exposé). Un captureur CDP produit une vignette **sur événement**, jamais en boucle, et s'exclut lui-même du compteur d'activité. Le panneau lit ces deux surfaces et ne touche jamais aux applis.

**Tech Stack:** Bash (`streamlitctl`), Python 3.11 + FastAPI, chromium headless piloté par CDP via `websockets`, HTML/CSS/JS vanilla.

**Spec :** [`2026-08-01-streamlit-mosaic-dashboard-design.md`](../specs/2026-08-01-streamlit-mosaic-dashboard-design.md)

## Global Constraints

- Cible : Debian 12 bookworm, Python 3.11.2 (pas de syntaxe 3.12+).
- Tests : `.venv` du dépôt, exécution **par répertoire** (collision de `pytest.ini`).
- **Aucune tuile ni appel du panneau n'ouvre de session vers une appli.**
- **Aucun timer ne déclenche de capture.** Trois déclencheurs seulement : première inscription, mise à jour de l'appli, bouton manuel.
- Une capture à la fois, sérialisée (~2 Go de RAM disponibles sur la board).
- Look & feel : `WEBUI-PANEL-GUIDELINES.md` — `hybrid-dark`, Courier Prime, cyan `#00d4ff`, sidebar partagée via `/shared/sidebar.js`, jamais réécrite à la main.
- Ne jamais élargir les permissions d'un parent partagé (`/run/secubox`, `/var/cache/secubox`, `/var/lib/secubox`).
- Les messages de commit ne portent aucune référence à un assistant IA.
- Chaque tâche se termine par un commit.

## Chemins existants (à ne pas redéfinir)

```text
LXC_NAME="streamlit"
APPS_PATH="$DATA_PATH/apps"                      # un répertoire par appli
CONF_PATH="/etc/secubox/streamlit.toml"
IDLE_STATE_DIR="/var/lib/secubox/streamlit/idle" # <app>.state, mtime = last active
CTL = "/usr/sbin/streamlitctl"                   # côté API
```

Helpers déjà présents dans `streamlitctl`, à réutiliser tels quels :

| Helper | Comportement |
|---|---|
| `_idle_config <clé> <défaut>` | lit une clé dans `CONF_PATH` |
| `_app_running <nom>` | code retour 0 si le port écoute |
| `_app_last_active <nom>` | affiche le mtime de `<app>.state`, ou `0` |
| `_app_active_conns <nom>` | compte les connexions établies au port |

---

## Structure des fichiers

| Fichier | Responsabilité |
|---|---|
| `packages/secubox-streamlit/sbin/streamlitctl` | `app list` enrichi du tempo ; exclusion du captureur |
| `packages/secubox-streamlit/api/shotter.py` | **créé** — client CDP, une seule responsabilité : URL → PNG |
| `packages/secubox-streamlit/api/screenshots.py` | **créé** — stockage, fraîcheur, orchestration des déclencheurs |
| `packages/secubox-streamlit/api/main.py` | endpoints `/apps/{name}/screenshot` et `/apps/{name}/recapture` |
| `packages/secubox-streamlit/www/streamlit/wall.html` | **créé** — le mur, autonome |

`shotter.py` et `screenshots.py` sont séparés délibérément : le premier ne connaît que chromium, le second ne connaît que le cycle de vie des images. On peut tester le second sans navigateur.

---

### Task 1 : exposer le tempo de veille par appli

La donnée existe (`_app_last_active`, `timeout_minutes`) mais n'est exposée nulle part : `/power/status` ne parle que du conteneur LXC entier.

**Files:**
- Modify: `packages/secubox-streamlit/sbin/streamlitctl` (fonction `cmd_app_list`)
- Test: `packages/secubox-streamlit/api/tests/test_app_list_timing.py`

**Interfaces:**
- Consumes: `_app_running`, `_app_last_active`, `_idle_config` (existants)
- Produces: chaque entrée de `app list` gagne `state` (`running`|`sleeping`), `last_active` (epoch, `0` si jamais vue), `idle_seconds`, `sleep_after_seconds`.

- [ ] **Step 1 : écrire le test qui échoue**

```python
# packages/secubox-streamlit/api/tests/test_app_list_timing.py
import json
import subprocess
from pathlib import Path

CTL = Path(__file__).resolve().parents[2] / "sbin" / "streamlitctl"


def _run_app_list(tmp_path, apps, idle_files, timeout_minutes=30):
    """Exécute `streamlitctl app list` contre une arborescence factice."""
    apps_dir = tmp_path / "apps"
    idle_dir = tmp_path / "idle"
    apps_dir.mkdir(); idle_dir.mkdir()
    conf = tmp_path / "streamlit.toml"
    conf.write_text(f"[idle]\ntimeout_minutes = {timeout_minutes}\n")
    for name, port in apps.items():
        d = apps_dir / name
        d.mkdir()
        (d / "app.py").write_text("import streamlit\n")
        (d / ".streamlit.toml").write_text(f"port = {port}\n")
    for name, mtime in idle_files.items():
        f = idle_dir / f"{name}.state"
        f.write_text("")
        import os
        os.utime(f, (mtime, mtime))
    env = {
        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
        "SECUBOX_STREAMLIT_APPS_PATH": str(apps_dir),
        "SECUBOX_STREAMLIT_IDLE_DIR": str(idle_dir),
        "SECUBOX_STREAMLIT_CONF": str(conf),
    }
    r = subprocess.run(["bash", str(CTL), "app", "list"],
                       capture_output=True, text=True, env=env, timeout=30)
    return json.loads(r.stdout)


def test_app_list_reports_sleep_timing(tmp_path):
    import time
    now = int(time.time())
    out = _run_app_list(tmp_path, {"demo": 8501}, {"demo": now - 600})
    app = out["apps"][0]
    assert app["name"] == "demo"
    assert app["last_active"] == now - 600
    assert 595 <= app["idle_seconds"] <= 615
    assert app["sleep_after_seconds"] == 1800


def test_never_seen_app_reports_zero_not_absent(tmp_path):
    """Une appli jamais vue doit dire last_active=0, pas omettre le champ."""
    out = _run_app_list(tmp_path, {"neuve": 8502}, {})
    app = out["apps"][0]
    assert app["last_active"] == 0
    assert "idle_seconds" in app


def test_state_is_sleeping_when_port_is_closed(tmp_path):
    out = _run_app_list(tmp_path, {"demo": 8501}, {})
    assert out["apps"][0]["state"] == "sleeping"
```

- [ ] **Step 2 : lancer le test pour vérifier qu'il échoue**

Run : `cd packages/secubox-streamlit && ../../.venv/bin/pytest api/tests/test_app_list_timing.py -v`
Expected : FAIL — `KeyError: 'last_active'`, le JSON de `app list` ne porte que `name`, `main`, `running`, `port`.

- [ ] **Step 3 : rendre les chemins surchargeables par l'environnement**

En tête de `streamlitctl`, juste après les définitions existantes (ligne ~36), remplacer les affectations en dur :

```bash
APPS_PATH="${SECUBOX_STREAMLIT_APPS_PATH:-$DATA_PATH/apps}"
CONF_PATH="${SECUBOX_STREAMLIT_CONF:-/etc/secubox/streamlit.toml}"
IDLE_STATE_DIR="${SECUBOX_STREAMLIT_IDLE_DIR:-/var/lib/secubox/streamlit/idle}"
```

Sans ces surcharges le `ctl` n'est pas testable hors board — et un test qui exige la board n'est pas un test.

- [ ] **Step 4 : enrichir `cmd_app_list`**

Dans `cmd_app_list`, remplacer le bloc `cat << EOF` par :

```bash
        local state="sleeping"
        [ "$running" = "true" ] && state="running"
        local last; last=$(_app_last_active "$name")
        local now; now=$(date +%s)
        local idle=0
        [ "$last" -gt 0 ] && idle=$(( now - last ))
        local tmo; tmo=$(_idle_config "timeout_minutes" "30")

        cat << EOF
  {"name": "$name", "main": "$main_py", "running": $running, "port": ${port:-0},
   "state": "$state", "last_active": $last, "idle_seconds": $idle,
   "sleep_after_seconds": $(( tmo * 60 ))}
EOF
```

`last_active` est un **horodatage absolu** : le compte à rebours est calculé par le navigateur, jamais par le serveur (spec §5).

- [ ] **Step 5 : lancer les tests**

Run : `cd packages/secubox-streamlit && ../../.venv/bin/pytest api/tests/ -v`
Expected : PASS, y compris `test_idle.py` qui existe déjà.

- [ ] **Step 6 : commit**

```bash
git add packages/secubox-streamlit/sbin/streamlitctl \
        packages/secubox-streamlit/api/tests/test_app_list_timing.py
git commit -m "feat(streamlit): exposer le tempo de veille par appli dans app list

last_active, idle_seconds et sleep_after_seconds existaient en base (fichiers
d'état d'inactivité + timeout_minutes) mais n'étaient exposés nulle part :
/power/status ne parle que du conteneur LXC entier.

last_active est un horodatage absolu, pas un décompte — le compte à rebours
tourne dans le navigateur, ce qui permet un mur de 64 tuiles égrenant les
secondes sans générer un octet de trafic.

Les chemins deviennent surchargeables par l'environnement, sans quoi le ctl
n'est testable que sur la board."
```

---

### Task 1b : `streamlitctl app audit` — cartographier avant de réparer

**Ajoutée le 2026-08-01, après confrontation du plan à la board.** Le plan
supposait qu'une appli est un répertoire portant un `app.py` et un
`.streamlit.toml` avec son port. L'inventaire réel dit autre chose :

| | |
|---|---|
| Entrées sous `apps/` | 87 |
| — répertoires | 32 |
| — **scripts `.py` à plat** | **43** |
| — répertoires avec un fichier principal | 17 |
| Listées par `app list` | 31 |
| **Processus en ligne** | **15** |
| — dont scripts à plat | **12** |

`cmd_app_list` itère `"$APPS_PATH"/*/` : **les répertoires uniquement**. Les 43
scripts à plat lui sont invisibles, dont 12 des 15 applis qui tournent
réellement. Et `.streamlit.toml` n'existe que pour 10 applis, avec des ports
périmés, parce qu'il n'est écrit que quand `streamlitctl` démarre lui-même
l'appli.

Cette tâche ne répare rien : elle **établit la carte**, en lecture seule, pour
que la réparation vise juste.

**Files:**
- Modify: `packages/secubox-streamlit/sbin/streamlitctl` (nouveau verbe `app audit`)
- Test: `packages/secubox-streamlit/api/tests/test_app_audit.py`

**Interfaces:**
- Consumes: `_idle_config`, `_json_escape` (existants)
- Produces: `streamlitctl app audit` → JSON
  `{"apps":[{"name","shape","entrypoint","declared","running","port","issues":[]}],"summary":{...}}`
  avec `shape` ∈ `dir`|`script`, et `issues` parmi
  `no-entrypoint`, `not-declared`, `declared-missing`, `stale-port`, `running-unlisted`.

- [ ] **Step 1 : écrire le test qui échoue**

```python
# packages/secubox-streamlit/api/tests/test_app_audit.py
import json
import subprocess
from pathlib import Path

CTL = Path(__file__).resolve().parents[2] / "sbin" / "streamlitctl"


def _audit(tmp_path, dirs=(), scripts=(), declared=()):
    apps = tmp_path / "apps"; apps.mkdir()
    conf = tmp_path / "streamlit.toml"
    conf.write_text("".join(f'[apps.{n}]\n' for n in declared))
    for name, main in dirs:
        d = apps / name; d.mkdir()
        if main:
            (d / main).write_text("import streamlit\n")
    for name in scripts:
        (apps / name).write_text("import streamlit\n")
    env = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
           "SECUBOX_STREAMLIT_APPS_PATH": str(apps),
           "SECUBOX_STREAMLIT_CONF": str(conf),
           "SECUBOX_STREAMLIT_IDLE_DIR": str(tmp_path / "idle"),
           "SECUBOX_STREAMLIT_PS_SOURCE": str(tmp_path / "ps.txt")}
    (tmp_path / "ps.txt").touch()
    r = subprocess.run(["bash", str(CTL), "app", "audit"],
                       capture_output=True, text=True, env=env, timeout=30)
    return json.loads(r.stdout)


def test_sees_bare_scripts_not_only_directories(tmp_path):
    """43 des 87 entrées de la board sont des scripts à plat, et 12 d'entre
    elles tournent. Les ignorer était la cause du mur vide."""
    out = _audit(tmp_path, dirs=[("avec_dir", "app.py")], scripts=["a_plat.py"])
    names = {a["name"]: a["shape"] for a in out["apps"]}
    assert names == {"avec_dir": "dir", "a_plat": "script"}


def test_flags_directory_without_entrypoint(tmp_path):
    out = _audit(tmp_path, dirs=[("vide", None)])
    app = out["apps"][0]
    assert app["entrypoint"] == ""
    assert "no-entrypoint" in app["issues"]


def test_flags_declared_but_missing(tmp_path):
    out = _audit(tmp_path, declared=["fantome"])
    ghost = [a for a in out["apps"] if a["name"] == "fantome"][0]
    assert "declared-missing" in ghost["issues"]


def test_flags_present_but_undeclared(tmp_path):
    out = _audit(tmp_path, scripts=["orphelin.py"])
    app = out["apps"][0]
    assert "not-declared" in app["issues"]


def test_running_is_read_from_the_process_source(tmp_path):
    apps = tmp_path / "apps"; apps.mkdir()
    (apps / "vivant.py").write_text("import streamlit\n")
    (tmp_path / "ps.txt").write_text("streamlit run vivant.py --server.port 8599\n")
    conf = tmp_path / "streamlit.toml"; conf.write_text("[apps.vivant]\n")
    env = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
           "SECUBOX_STREAMLIT_APPS_PATH": str(apps),
           "SECUBOX_STREAMLIT_CONF": str(conf),
           "SECUBOX_STREAMLIT_IDLE_DIR": str(tmp_path / "idle"),
           "SECUBOX_STREAMLIT_PS_SOURCE": str(tmp_path / "ps.txt")}
    r = subprocess.run(["bash", str(CTL), "app", "audit"],
                       capture_output=True, text=True, env=env, timeout=30)
    app = json.loads(r.stdout)["apps"][0]
    assert app["running"] is True
    assert app["port"] == 8599


def test_summary_counts_match_the_app_list(tmp_path):
    out = _audit(tmp_path, dirs=[("d1", "app.py"), ("d2", None)], scripts=["s1.py"])
    assert out["summary"]["total"] == len(out["apps"]) == 3
    assert out["summary"]["running"] == 0
```

- [ ] **Step 2 : lancer le test pour vérifier qu'il échoue**

Run : `cd packages/secubox-streamlit && ../../.venv/bin/pytest api/tests/test_app_audit.py -v`
Expected : FAIL — le verbe `audit` n'existe pas, `main` sort en erreur « unknown verb ».

- [ ] **Step 3 : implémenter le verbe**

Trois sources croisées. La liste des processus vient de `lxc-attach … ps`, mais
passe par une variable d'environnement `SECUBOX_STREAMLIT_PS_SOURCE` quand elle
est définie — sans quoi la fonction n'est pas testable hors board.

```bash
# Liste des processus streamlit, une ligne par appli en cours.
# SECUBOX_STREAMLIT_PS_SOURCE permet de tester sans conteneur.
_ps_lines() {
    if [ -n "${SECUBOX_STREAMLIT_PS_SOURCE:-}" ]; then
        cat "$SECUBOX_STREAMLIT_PS_SOURCE" 2>/dev/null
        return
    fi
    lxc-attach -n "$LXC_NAME" -P "$LXC_PATH" -- \
        ps -eo args 2>/dev/null | grep "streamlit run" | grep -v grep
}

# Nom d'appli déduit d'un chemin de script : "a/app.py" -> "a", "b.py" -> "b".
_app_name_of_script() {
    case "$1" in
        */*) printf '%s' "${1%%/*}" ;;
        *)   printf '%s' "${1%.py}" ;;
    esac
}
```

`cmd_app_audit` parcourt ensuite les entrées du disque (répertoires **et**
scripts `.py`), les sections `[apps.*]` du TOML, et les lignes de processus ;
il émet un objet par appli avec ses `issues`, puis un `summary`.


- [ ] **Step 4 : lancer les tests**

Run : `cd packages/secubox-streamlit && ../../.venv/bin/pytest api/tests/ -v`
Expected : PASS — les 6 nouveaux plus les 9 existants.

- [ ] **Step 5 : passer l'audit sur la board**

```bash
scp packages/secubox-streamlit/sbin/streamlitctl root@192.168.1.200:/usr/sbin/streamlitctl
ssh root@192.168.1.200 'chmod 755 /usr/sbin/streamlitctl
  /usr/sbin/streamlitctl app audit | python3 -m json.tool | head -40'
```

Expected : les 15 applis en ligne apparaissent avec `running: true` et leur
port réel, dont les 12 scripts à plat qu'`app list` ne voyait pas.

- [ ] **Step 6 : commit**

```bash
git add packages/secubox-streamlit/sbin/streamlitctl \
        packages/secubox-streamlit/api/tests/test_app_audit.py
git commit -m "feat(streamlit): app audit — croiser disque, déclarations et processus

Le modèle d'appli ne connaissait qu'une forme : un répertoire portant un
app.py. La board en compte deux — 32 répertoires et 43 scripts .py à plat — et
12 des 15 applis réellement en ligne sont des scripts à plat, donc invisibles à
app list qui n'itère que les répertoires.

S'y ajoutent 15 répertoires sans point d'entrée et un .streamlit.toml présent
pour 10 applis sur 87, avec des ports périmés : il n'est écrit que lorsque
streamlitctl démarre lui-même l'appli.

audit ne répare rien — il établit la carte, en lecture seule, en croisant les
entrées du disque, les sections déclarées et les processus en cours."
```

---

### Task 2 : ABANDONNÉE — exclusion du captureur du compteur d'activité

**Décision du 2026-08-01 : cette tâche est retirée du plan.** Elle avait été
implémentée puis annulée avant revue.

Le raisonnement d'origine : la capture ouvre une connexion vers l'appli, donc
`_app_active_conns` la compte, donc elle repousse la mise en veille.

Ce qui l'invalide : **on ne photographie que des applis éveillées, et les seuls
déclencheurs retenus sont déjà des moments d'activité réelle** — un réveil
provoqué par un utilisateur, ou un clic sur « recapturer ». Dans les deux cas
l'appli est de toute façon maintenue éveillée par l'usage qui a déclenché la
photo. Traiter la capture comme une non-activité aurait ajouté une clé de
configuration, une fonction et quatre tests pour un effet nul dans les
conditions réelles d'emploi.

Le seul cas où l'effet serait mesurable est le premier passage sur les applis
déjà éveillées (Task 5, étape 5) : plusieurs captures d'affilée repoussent
d'autant de mises en veille. Si cela pose problème, la réponse est d'étaler ce
passage dans le temps — pas d'ajouter un mécanisme d'exclusion permanent.

`_app_active_conns` reste donc inchangée, et la fonctionnalité devient
**purement additive** : elle ne modifie aucune fonction du chemin d'inactivité.

---

### Task 3 : le client CDP

`chromium --screenshot` capture à l'événement `load` : sur Streamlit, qui ne peint qu'après connexion websocket, il produit une page blanche (mesuré : 4 à 6 Ko en 1280×800, contre 50 à 300 Ko pour un rendu réel). Il faut **attendre un sélecteur**.

**Files:**
- Create: `packages/secubox-streamlit/api/shotter.py`
- Test: `packages/secubox-streamlit/api/tests/test_shotter.py`

**Interfaces:**
- Consumes: rien
- Produces: `shotter.capture(url: str, *, timeout: float = 90.0, width: int = 1280, height: int = 800) -> bytes` — renvoie les octets PNG, lève `ShotError` en cas d'échec ou de rendu vide.

- [ ] **Step 1 : écrire le test qui échoue**

```python
# packages/secubox-streamlit/api/tests/test_shotter.py
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
```

- [ ] **Step 2 : lancer le test pour vérifier qu'il échoue**

Run : `cd packages/secubox-streamlit && ../../.venv/bin/pytest api/tests/test_shotter.py -v`
Expected : FAIL — `ModuleNotFoundError: No module named 'api.shotter'`.

- [ ] **Step 3 : implémenter**

```python
# packages/secubox-streamlit/api/shotter.py
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
```

**AVERTISSEMENT — défaut du code ci-dessus, corrigé en ronde 1.** Le
`proc.stderr.readline()` de `_devtools_url()` est un appel **bloquant** au
milieu d'une coroutine. Tel quel il gèle la boucle d'événements du daemon
FastAPI entier — plus aucune requête servie, d'aucun module — et il neutralise
`asyncio.wait_for`, dont l'annulation ne peut être délivrée qu'à un point
`await`. Le délai de 90 s n'est alors pas garanti, et un chromium bloqué laisse
un processus et un répertoire temporaire derrière lui.

Ce projet a déjà subi deux pannes de cette nature exacte. Toute lecture
bloquante doit être déportée dans un exécuteur. Deux autres défauts du même
extrait ont été corrigés en même temps : le répertoire temporaire créé hors du
`try` fuit si le lancement échoue, et les échecs de bas niveau (chromium
absent, websocket injoignable) doivent ressortir en `ShotError` pour que le
contrat de l'interface soit tenu.

- [ ] **Step 4 : lancer les tests**

Run : `cd packages/secubox-streamlit && ../../.venv/bin/pytest api/tests/test_shotter.py -v`
Expected : PASS — les quatre tests portent sur la logique pure, sans lancer chromium.

- [ ] **Step 5 : valider contre une vraie appli sur la board**

```bash
scp packages/secubox-streamlit/api/shotter.py root@192.168.1.200:/usr/lib/secubox/streamlit/api/
ssh root@192.168.1.200 'cd /usr/lib/secubox/streamlit && python3 -c "
import asyncio, sys
sys.path.insert(0, \".\")
from api import shotter
png = asyncio.run(shotter.capture(\"http://10.100.0.50:8520/\"))
print(f\"PNG: {len(png)} octets\")
open(\"/tmp/real.png\",\"wb\").write(png)
"'
```

Expected : plus de 20 000 octets. Si `ShotError: rendu vide`, augmenter l'attente dans `_wait_for_selector` — mais **ne jamais abaisser `MIN_PNG_BYTES`** : le seuil est là pour refuser exactement ce cas.

- [ ] **Step 6 : commit**

```bash
git add packages/secubox-streamlit/api/shotter.py \
        packages/secubox-streamlit/api/tests/test_shotter.py
git commit -m "feat(streamlit): captureur d'écran piloté par CDP

chromium --screenshot capture à l'événement load ; Streamlit ne sert qu'une
coquille HTML et ne peint qu'après connexion websocket. Mesuré sur gk2 : 58 à
94s pour un PNG de 4-6 Ko en 1280x800, soit une page blanche.

On pilote donc le protocole DevTools et on ATTEND le conteneur racine de
Streamlit avant de capturer. Un seuil de 20 Ko refuse les rendus vides plutôt
que de les archiver — c'est le défaut observé, donc le test qui compte.

Une capture à la fois : deux chromium ne tiennent pas dans les ~2 Go
disponibles."
```

---

### Task 4 : stockage, fraîcheur et déclencheur manuel

**Files:**
- Create: `packages/secubox-streamlit/api/screenshots.py`
- Modify: `packages/secubox-streamlit/api/main.py`
- Test: `packages/secubox-streamlit/api/tests/test_screenshots.py`

**Interfaces:**
- Consumes: `shotter.capture(url, ...) -> bytes`, `shotter.ShotError`
- Produces :
  - `screenshots.meta_path(app_dir: Path) -> Path` et `screenshots.png_path(app_dir: Path) -> Path`
  - `screenshots.is_stale(app_dir: Path, source: Path) -> bool`
  - `screenshots.record(app_dir: Path, source: Path, png: bytes | None, ok: bool) -> dict`
  - `screenshots.read_meta(app_dir: Path) -> dict` (`{}` si absent)

- [ ] **Step 1 : écrire le test qui échoue**

```python
# packages/secubox-streamlit/api/tests/test_screenshots.py
import json
import os
from api import screenshots


def _app(tmp_path, content="import streamlit\n"):
    d = tmp_path / "demo"; d.mkdir()
    src = d / "app.py"; src.write_text(content)
    return d, src


def test_no_meta_means_stale(tmp_path):
    d, src = _app(tmp_path)
    assert screenshots.is_stale(d, src) is True


def test_fresh_after_record(tmp_path):
    d, src = _app(tmp_path)
    screenshots.record(d, src, b"\x89PNG" + b"0" * 60000, ok=True)
    assert screenshots.is_stale(d, src) is False


def test_source_change_makes_it_stale(tmp_path):
    d, src = _app(tmp_path)
    screenshots.record(d, src, b"\x89PNG" + b"0" * 60000, ok=True)
    src.write_text("import streamlit\nst.title('v2')\n")
    os.utime(src, (2_000_000_000, 2_000_000_000))
    assert screenshots.is_stale(d, src) is True


def test_failed_capture_keeps_the_previous_image(tmp_path):
    """Effacer une vue valide parce qu'une capture a raté serait une régression."""
    d, src = _app(tmp_path)
    good = b"\x89PNG" + b"0" * 60000
    screenshots.record(d, src, good, ok=True)
    screenshots.record(d, src, None, ok=False)
    assert screenshots.png_path(d).read_bytes() == good
    assert screenshots.read_meta(d)["ok"] is False


def test_meta_records_the_version_fingerprint(tmp_path):
    d, src = _app(tmp_path)
    screenshots.record(d, src, b"\x89PNG" + b"0" * 60000, ok=True)
    meta = json.loads(screenshots.meta_path(d).read_text())
    assert meta["source_mtime"] == int(src.stat().st_mtime)
    assert meta["source_size"] == src.stat().st_size
    assert meta["captured_at"] > 0
```

- [ ] **Step 2 : lancer le test pour vérifier qu'il échoue**

Run : `cd packages/secubox-streamlit && ../../.venv/bin/pytest api/tests/test_screenshots.py -v`
Expected : FAIL — `ModuleNotFoundError: No module named 'api.screenshots'`.

- [ ] **Step 3 : implémenter**

```python
# packages/secubox-streamlit/api/screenshots.py
"""Cycle de vie des vignettes d'applis.

L'image vit à côté de l'appli, avec l'empreinte de la version qui l'a produite.
C'est cette empreinte — mtime + taille du fichier source — qui permet de savoir
qu'une vignette est périmée avec deux `stat`, SANS jamais interroger l'appli.

Rien ici ne connaît chromium : le module ne parle que de fichiers, et se teste
donc sans navigateur.
"""
from __future__ import annotations

import json
import os
import tempfile
import time
from pathlib import Path
from typing import Optional

PNG_NAME = "screenshot.png"
META_NAME = "screenshot.json"


def png_path(app_dir: Path) -> Path:
    return Path(app_dir) / PNG_NAME


def meta_path(app_dir: Path) -> Path:
    return Path(app_dir) / META_NAME


def read_meta(app_dir: Path) -> dict:
    try:
        return json.loads(meta_path(app_dir).read_text())
    except (OSError, ValueError):
        return {}


def is_stale(app_dir: Path, source: Path) -> bool:
    """Vrai si l'image manque, ou si le source a changé depuis la capture."""
    meta = read_meta(app_dir)
    if not meta or not png_path(app_dir).exists():
        return True
    try:
        st = Path(source).stat()
    except OSError:
        return True
    return (meta.get("source_mtime") != int(st.st_mtime)
            or meta.get("source_size") != st.st_size)


def record(app_dir: Path, source: Path, png: Optional[bytes], ok: bool) -> dict:
    """Enregistre le résultat d'une capture.

    Une capture en échec (`png=None`) met à jour les métadonnées mais NE TOUCHE
    PAS à l'image existante : perdre une vue valide parce qu'une capture a raté
    serait pire que d'afficher une vue ancienne.
    """
    app_dir = Path(app_dir)
    if png is not None and ok:
        tmp = tempfile.NamedTemporaryFile(dir=app_dir, delete=False, suffix=".tmp")
        try:
            tmp.write(png)
            tmp.close()
            os.replace(tmp.name, png_path(app_dir))
        finally:
            if os.path.exists(tmp.name):
                os.unlink(tmp.name)
    try:
        st = Path(source).stat()
        mtime, size = int(st.st_mtime), st.st_size
    except OSError:
        mtime, size = 0, 0
    meta = {"captured_at": int(time.time()), "source_mtime": mtime,
            "source_size": size, "ok": bool(ok)}
    meta_path(app_dir).write_text(json.dumps(meta))
    return meta
```

- [ ] **Step 4 : lancer les tests**

Run : `cd packages/secubox-streamlit && ../../.venv/bin/pytest api/tests/test_screenshots.py -v`
Expected : PASS.

- [ ] **Step 5 : exposer l'image et la recapture**

Dans `packages/secubox-streamlit/api/main.py`, à côté des routes `/app/{name}` existantes :

```python
from fastapi.responses import FileResponse
from pathlib import Path as _Path
from api import screenshots, shotter

APPS_DIR = _Path(os.environ.get("SECUBOX_STREAMLIT_APPS_PATH", "/data/streamlit/apps"))


def _app_source(name: str) -> _Path:
    d = APPS_DIR / name
    for candidate in ("app.py", "main.py", "streamlit_app.py"):
        if (d / candidate).exists():
            return d / candidate
    return d / "app.py"


def _app_port(name: str) -> int:
    """Port d'écoute déclaré dans le .streamlit.toml de l'appli, 0 si absent."""
    try:
        for line in (APPS_DIR / name / ".streamlit.toml").read_text().splitlines():
            if line.strip().startswith("port"):
                return int(line.split("=", 1)[1].strip().strip('"'))
    except (OSError, ValueError, IndexError):
        pass
    return 0


@router.get("/apps/{name}/screenshot")
def app_screenshot(name: str):
    """Sert la vignette conservée. Publique : le mur n'a pas à s'authentifier
    pour afficher une image, et cette route ne touche jamais l'appli."""
    p = screenshots.png_path(APPS_DIR / name)
    if not p.exists():
        raise HTTPException(status_code=404, detail="pas encore de vignette")
    meta = screenshots.read_meta(APPS_DIR / name)
    return FileResponse(p, media_type="image/png", headers={
        "Cache-Control": "no-cache",
        "X-Captured-At": str(meta.get("captured_at", 0)),
    })


@router.post("/apps/{name}/recapture")
async def app_recapture(name: str, user=Depends(require_jwt)):
    """Déclencheur MANUEL. Aucun timer n'appelle cette route (spec §3.1)."""
    app_dir = APPS_DIR / name
    if not app_dir.is_dir():
        raise HTTPException(status_code=404, detail="appli inconnue")
    port = _app_port(name)
    if not port:
        raise HTTPException(status_code=409, detail="port inconnu")
    url = f"http://{_cfg().get('ip', '10.100.0.50')}:{port}/"
    try:
        png = await shotter.capture(url)
    except shotter.ShotError as exc:
        screenshots.record(app_dir, _app_source(name), None, ok=False)
        raise HTTPException(status_code=502, detail=str(exc))
    meta = screenshots.record(app_dir, _app_source(name), png, ok=True)
    return {"ok": True, "bytes": len(png), **meta}
```

- [ ] **Step 6 : vérifier que rien ne capture périodiquement**

```bash
grep -rn "recapture\|shotter.capture" packages/secubox-streamlit/debian/*.timer \
     packages/secubox-streamlit/debian/*.service 2>/dev/null; echo "rc=$?"
```

Expected : aucune correspondance. **C'est l'invariant du design** — si une unité systemd appelle le captureur, la capture est redevenue une boucle.

- [ ] **Step 7 : commit**

```bash
git add packages/secubox-streamlit/api/screenshots.py \
        packages/secubox-streamlit/api/main.py \
        packages/secubox-streamlit/api/tests/test_screenshots.py
git commit -m "feat(streamlit): stockage des vignettes et déclencheur manuel

L'image vit à côté de l'appli avec l'empreinte de la version qui l'a produite
(mtime + taille du source) : deux stat suffisent à savoir qu'elle est périmée,
sans jamais interroger l'appli.

Une capture en échec conserve l'image précédente et se contente de marquer
l'échec — perdre une vue valide parce qu'une capture a raté serait pire que
d'afficher une vue ancienne.

Aucun timer n'appelle le captureur : trois déclencheurs seulement (première
inscription, mise à jour de l'appli, bouton manuel)."
```

---

### Task 5 : capture paresseuse au réveil

Le spec prévoit **trois** déclencheurs (§3.1). Task 4 n'a livré que le bouton
manuel. Les deux autres — première inscription et mise à jour — sont couverts
par un seul mécanisme : **quand une appli se réveille, si sa vignette est
périmée, on la capture**.

La détection de mise à jour est déjà gratuite : un `deploy` réécrit le fichier
source, donc son `mtime` change, donc `is_stale` devient vrai sans le moindre
crochet. C'est tout l'intérêt de l'empreinte choisie en Task 4.

**Files:**
- Modify: `packages/secubox-streamlit/api/main.py` (route `/apps/{name}/wake`)
- Test: `packages/secubox-streamlit/api/tests/test_lazy_capture.py`

**Interfaces:**
- Consumes: `screenshots.is_stale(app_dir, source) -> bool`, `screenshots.record(...)`, `shotter.capture(url) -> bytes`
- Produces: `main._maybe_capture(name: str) -> None` — coroutine, ne lève jamais.

- [ ] **Step 1 : écrire le test qui échoue**

```python
# packages/secubox-streamlit/api/tests/test_lazy_capture.py
import asyncio
import pytest
from api import main as m, screenshots


@pytest.fixture
def app_dir(tmp_path, monkeypatch):
    d = tmp_path / "demo"; d.mkdir()
    (d / "app.py").write_text("import streamlit\n")
    (d / ".streamlit.toml").write_text("port = 8501\n")
    monkeypatch.setattr(m, "APPS_DIR", tmp_path)
    return d


def test_captures_when_stale(app_dir, monkeypatch):
    calls = []

    async def fake_capture(url, **kw):
        calls.append(url)
        return b"\x89PNG" + b"0" * 60000

    monkeypatch.setattr(m.shotter, "capture", fake_capture)
    asyncio.run(m._maybe_capture("demo"))
    assert len(calls) == 1
    assert screenshots.png_path(app_dir).exists()


def test_skips_when_fresh(app_dir, monkeypatch):
    screenshots.record(app_dir, app_dir / "app.py", b"\x89PNG" + b"0" * 60000, ok=True)
    calls = []

    async def fake_capture(url, **kw):
        calls.append(url)
        return b"\x89PNG" + b"0" * 60000

    monkeypatch.setattr(m.shotter, "capture", fake_capture)
    asyncio.run(m._maybe_capture("demo"))
    assert calls == [], "une vignette fraîche ne doit pas être recapturée"


def test_failure_never_propagates(app_dir, monkeypatch):
    async def boom(url, **kw):
        raise m.shotter.ShotError("rendu vide")

    monkeypatch.setattr(m.shotter, "capture", boom)
    asyncio.run(m._maybe_capture("demo"))          # ne doit pas lever
    assert screenshots.read_meta(app_dir)["ok"] is False
```

- [ ] **Step 2 : lancer le test pour vérifier qu'il échoue**

Run : `cd packages/secubox-streamlit && ../../.venv/bin/pytest api/tests/test_lazy_capture.py -v`
Expected : FAIL — `AttributeError: module 'api.main' has no attribute '_maybe_capture'`.

- [ ] **Step 3 : implémenter**

Dans `packages/secubox-streamlit/api/main.py` :

```python
async def _maybe_capture(name: str) -> None:
    """Capture la vignette d'une appli SI elle est périmée.

    Couvre deux des trois déclencheurs du design : la première inscription
    (aucune vignette) et la mise à jour (le mtime du source a bougé). Aucun
    crochet n'est nécessaire sur le chemin de déploiement — réécrire le source
    suffit à rendre l'empreinte obsolète.

    Ne lève jamais : un réveil ne doit pas échouer parce qu'une photo a raté.
    """
    app_dir = APPS_DIR / name
    source = _app_source(name)
    if not app_dir.is_dir() or not screenshots.is_stale(app_dir, source):
        return
    port = _app_port(name)
    if not port:
        return
    url = f"http://{_cfg().get('ip', '10.100.0.50')}:{port}/"
    try:
        png = await shotter.capture(url)
        screenshots.record(app_dir, source, png, ok=True)
    except Exception as exc:                      # y compris ShotError
        log.warning("capture de %s échouée: %s", name, exc)
        screenshots.record(app_dir, source, None, ok=False)
```

Puis, dans la route de réveil existante `POST /apps/{name}/wake`, après le
réveil réussi et **sans bloquer la réponse** :

```python
    asyncio.create_task(_maybe_capture(name))
```

Le réveil rend la main immédiatement ; la capture, qui dure ~60 s, se fait en
arrière-plan. L'utilisateur qui réveille une appli n'attend pas sa photo.

- [ ] **Step 4 : lancer les tests**

Run : `cd packages/secubox-streamlit && ../../.venv/bin/pytest api/tests/ -v`
Expected : PASS.

- [ ] **Step 5 : premier passage sur les applis déjà éveillées**

Les 21 applis en cours d'exécution n'ont pas de vignette et ne passeront jamais
par un réveil. Une commande unique, à lancer **une fois**, sérialisée et non
répétée — surtout pas un timer :

```bash
ssh root@192.168.1.200 'for a in $(curl -s --unix-socket /run/secubox/streamlit.sock \
    http://localhost/apps | jq -r ".apps[] | select(.state==\"running\") | .name"); do
  echo -n "$a: "
  curl -s -o /dev/null -w "%{http_code}\n" -X POST \
    --unix-socket /run/secubox/streamlit.sock "http://localhost/apps/$a/recapture"
  sleep 5
done'
```

Les 43 endormies sont laissées telles quelles : elles seront capturées à leur
prochain réveil naturel. Les réveiller pour une photo serait exactement le
réveil de masse que ce design évite.

- [ ] **Step 6 : commit**

```bash
git add packages/secubox-streamlit/api/main.py \
        packages/secubox-streamlit/api/tests/test_lazy_capture.py
git commit -m "feat(streamlit): capturer paresseusement au réveil si la vignette est périmée

Couvre les deux déclencheurs restants du design — première inscription et mise
à jour — avec un seul mécanisme. La détection de mise à jour est gratuite : un
deploy réécrit le source, donc son mtime change, donc l'empreinte est obsolète.
Aucun crochet sur le chemin de déploiement.

La capture part en tâche de fond : un réveil rend la main tout de suite, sans
attendre les ~60s de la photo. Un échec de capture ne fait jamais échouer un
réveil."
```

---

### Task 6 : le mur

**Files:**
- Create: `packages/secubox-streamlit/www/streamlit/wall.html`
- Modify: `packages/secubox-streamlit/menu.d/` (entrée pour le mur)

**Interfaces:**
- Consumes: `GET /api/v1/streamlit/apps` (Task 1), `GET /api/v1/streamlit/apps/{name}/screenshot` et `POST /api/v1/streamlit/apps/{name}/recapture` (Task 4)
- Produces: rien

- [ ] **Step 1 : écrire la page**

```html
<!DOCTYPE html>
<html lang="fr">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>SecuBox — Mur Streamlit</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link href="https://fonts.googleapis.com/css2?family=Courier+Prime:wght@400;700&display=swap" rel="stylesheet">
  <link rel="stylesheet" href="/shared/hybrid-skin.css">
  <style>
    :root {
      --bg-dark:#0d1117; --bg-card:rgba(30,40,55,.8); --border:rgba(100,150,200,.2);
      --text:#e8e6d9; --cyan:#00d4ff; --green:#00dd44; --muted:#6b7b8b; --red:#ff4466;
    }
    * { box-sizing:border-box }
    body { margin:0; background:var(--bg-dark); color:var(--text);
           font-family:'Courier Prime',monospace; font-size:15px }
    .main { margin-left:220px; padding:60px 1.5rem 3rem; min-height:100vh }
    .grid { display:grid; gap:1rem;
            grid-template-columns:repeat(auto-fill,minmax(260px,1fr)) }
    .tile { border:1px solid var(--border); border-radius:8px; overflow:hidden;
            background:var(--bg-card); display:flex; flex-direction:column }
    .shot { aspect-ratio:16/10; background:#0a0d12 center/cover no-repeat;
            display:flex; align-items:center; justify-content:center;
            font-size:2.5rem; color:var(--muted) }
    .tile.sleeping .shot { filter:grayscale(1) brightness(.6) }
    .bar { display:flex; justify-content:space-between; align-items:center;
           gap:.5rem; padding:.5rem .6rem; border-top:1px solid var(--border) }
    .name { font-weight:700; overflow:hidden; text-overflow:ellipsis; white-space:nowrap }
    .tempo { font-size:.78rem; color:var(--muted) }
    .tile.running .tempo { color:var(--green) }
    .stale { font-size:.7rem; color:var(--red) }
    .acts { display:flex; gap:.3rem; padding:0 .6rem .6rem }
    .btn { flex:1; padding:.3rem; border:1px solid var(--border); border-radius:4px;
           background:transparent; color:var(--text); cursor:pointer;
           font-family:inherit; font-size:.75rem }
    .btn:hover { border-color:var(--cyan); color:var(--cyan) }
    body.tv .main { margin-left:0; padding:1rem }
    body.tv .sidebar, body.tv .acts { display:none }
    body.tv .grid { grid-template-columns:repeat(auto-fill,minmax(340px,1fr)) }
    @media (max-width:768px){ .main{ margin-left:0 } }
  </style>
</head>
<body class="hybrid-dark">
  <nav class="sidebar" id="sidebar"></nav>
  <script src="/shared/sidebar.js"></script>
  <main class="main">
    <header class="header" style="display:flex;justify-content:space-between;align-items:center;margin-bottom:1rem">
      <div><h1 style="margin:0">📺 Mur Streamlit</h1>
           <div class="tempo" id="sub">chargement…</div></div>
      <button class="btn" style="flex:0 0 auto;padding:.4rem .8rem" id="tv">Mode TV</button>
    </header>
    <div class="grid" id="grid"></div>
  </main>
  <script>
  (function () {
    "use strict";
    var API = "/api/v1/streamlit";
    var apps = [];
    var esc = function (s) { var d = document.createElement("div"); d.textContent = s == null ? "" : s; return d.innerHTML; };

    function fmt(sec) {
      if (sec == null || sec < 0) return "—";
      var m = Math.floor(sec / 60), s = Math.floor(sec % 60);
      if (m >= 60) return Math.floor(m / 60) + "h " + (m % 60) + "m";
      return m + "m " + String(s).padStart(2, "0") + "s";
    }

    // Le serveur renvoie un horodatage ABSOLU ; le compte à rebours tourne ici,
    // ce qui permet 64 tuiles qui égrènent les secondes sans aucun trafic.
    function tempo(a) {
      if (a.state !== "running") {
        return a.last_active ? "endormie depuis " + fmt(Date.now() / 1000 - a.last_active) : "endormie";
      }
      if (!a.last_active) return "éveillée";
      var left = a.sleep_after_seconds - (Date.now() / 1000 - a.last_active);
      return left > 0 ? "veille dans " + fmt(left) : "veille imminente";
    }

    function tile(a) {
      var t = document.createElement("div");
      t.className = "tile " + (a.state === "running" ? "running" : "sleeping");
      t.innerHTML =
        '<div class="shot" data-shot="' + esc(a.name) + '">🖼️</div>' +
        '<div class="bar"><span class="name">' + esc(a.name) + '</span>' +
        '<span>' + (a.state === "running" ? "🟢" : "😴") + '</span></div>' +
        '<div class="bar" style="border:none;padding-top:0">' +
        '<span class="tempo" data-tempo="' + esc(a.name) + '">' + tempo(a) + '</span></div>' +
        '<div class="acts">' +
        '<a class="btn" href="/streamlit/' + encodeURIComponent(a.name) + '/" target="_blank" rel="noopener">ouvrir</a>' +
        (a.state === "running"
          ? '<button class="btn" data-recap="' + esc(a.name) + '">recapturer</button>'
          : '<button class="btn" data-wake="' + esc(a.name) + '">réveiller</button>') +
        '</div>';
      return t;
    }

    // L'image n'est (re)chargée que si captured_at a changé — sur 64 tuiles,
    // recharger les PNG à chaque tick serait absurde.
    var shotSeen = {};
    function loadShot(name) {
      var el = document.querySelector('[data-shot="' + CSS.escape(name) + '"]');
      if (!el) return;
      var url = API + "/apps/" + encodeURIComponent(name) + "/screenshot";
      fetch(url, { method: "HEAD" }).then(function (r) {
        if (!r.ok) return;
        var at = r.headers.get("X-Captured-At") || "0";
        if (shotSeen[name] === at) return;
        shotSeen[name] = at;
        el.style.backgroundImage = 'url("' + url + '?t=' + at + '")';
        el.textContent = "";
      }).catch(function () {});
    }

    function render() {
      var g = document.getElementById("grid");
      g.replaceChildren.apply(g, apps.map(tile));
      apps.forEach(function (a) { loadShot(a.name); });
      var up = apps.filter(function (a) { return a.state === "running"; }).length;
      document.getElementById("sub").textContent =
        apps.length + " applis · " + up + " éveillées · " + (apps.length - up) + " endormies";
    }

    function tick() {
      apps.forEach(function (a) {
        var el = document.querySelector('[data-tempo="' + CSS.escape(a.name) + '"]');
        if (el) el.textContent = tempo(a);
      });
    }

    function refresh() {
      fetch(API + "/apps").then(function (r) { return r.json(); }).then(function (d) {
        apps = (d.apps || []).sort(function (x, y) {
          if ((x.state === "running") !== (y.state === "running")) return x.state === "running" ? -1 : 1;
          return x.name.localeCompare(y.name);
        });
        render();
      }).catch(function () {
        document.getElementById("sub").textContent = "backend injoignable";
      });
    }

    document.getElementById("grid").addEventListener("click", function (ev) {
      var r = ev.target.getAttribute && ev.target.getAttribute("data-recap");
      var w = ev.target.getAttribute && ev.target.getAttribute("data-wake");
      if (r) {
        ev.target.disabled = true; ev.target.textContent = "…";
        fetch(API + "/apps/" + encodeURIComponent(r) + "/recapture", { method: "POST" })
          .then(function () { shotSeen[r] = null; loadShot(r); })
          .finally(function () { ev.target.disabled = false; ev.target.textContent = "recapturer"; });
      } else if (w) {
        ev.target.disabled = true; ev.target.textContent = "…";
        fetch(API + "/apps/" + encodeURIComponent(w) + "/wake", { method: "POST" })
          .finally(function () { setTimeout(refresh, 3000); });
      }
    });

    document.getElementById("tv").addEventListener("click", function () {
      document.body.classList.toggle("tv");
    });

    refresh();
    setInterval(refresh, 30000);   // métadonnées seulement
    setInterval(tick, 1000);       // compte à rebours local, zéro trafic
  })();
  </script>
</body>
</html>
```

- [ ] **Step 2 : vérifier la conformité aux guidelines**

```bash
f=packages/secubox-streamlit/www/streamlit/wall.html
for p in 'class="hybrid-dark"' 'nav class="sidebar"' 'shared/sidebar.js' 'shared/hybrid-skin.css'; do
  printf '%-26s %s\n' "$p" "$(grep -c "$p" $f)"
done
```

Expected : `1` partout. La sidebar est partagée, jamais réécrite à la main.

- [ ] **Step 3 : vérifier l'invariant central**

```bash
grep -n "iframe\|<embed\|<object" packages/secubox-streamlit/www/streamlit/wall.html; echo "rc=$?"
```

Expected : aucune correspondance. **Un iframe ouvrirait une session vers l'appli et empêcherait sa mise en veille** — c'est ce que tout le design évite.

- [ ] **Step 4 : déployer et vérifier**

```bash
scp packages/secubox-streamlit/www/streamlit/wall.html \
    root@192.168.1.200:/usr/share/secubox/www/streamlit/wall.html
ssh root@192.168.1.200 'chmod 644 /usr/share/secubox/www/streamlit/wall.html
  curl -s -o /dev/null -w "wall: %{http_code}\n" -H "Host: admin.gk2.secubox.in" \
    http://127.0.0.1:9080/streamlit/wall.html'
```

Expected : `200`.

- [ ] **Step 5 : commit**

```bash
git add packages/secubox-streamlit/www/streamlit/wall.html \
        packages/secubox-streamlit/menu.d/
git commit -m "feat(streamlit): mur mosaïque des applis

Une tuile par appli : vignette conservée, état, temps restant avant mise en
veille, lien et actions. Les endormies sont grisées.

Aucune tuile n'ouvre de session vers une appli — pas d'iframe, uniquement des
PNG statiques et l'API du module. Le mur peut donc rester affiché en permanence
sur un écran sans empêcher une seule mise en veille.

Le compte à rebours tourne dans le navigateur à partir d'un horodatage absolu,
et les PNG ne sont rechargés que si captured_at a changé : 64 tuiles qui
égrènent les secondes ne génèrent aucun trafic."
```

---

## Critères de sortie

- [ ] `GET /apps` renvoie `state`, `last_active`, `idle_seconds`, `sleep_after_seconds` par appli.
- [ ] Le captureur produit un PNG > 20 Ko sur une appli réelle, et **lève** sur une page blanche.
- [ ] Une capture en échec conserve l'image précédente.
- [ ] Réveiller une appli à la vignette périmée la recapture ; une vignette fraîche n'est pas recapturée.
- [ ] Un échec de capture ne fait jamais échouer un réveil.
- [ ] Aucune unité systemd n'appelle le captureur.
- [ ] Le mur ne contient aucun `iframe`.
- [ ] Les 21 applis éveillées ont une vignette ; les 43 endormies restent endormies.

## Hors de ce plan

Le **lot 4** du spec — vhost wildcard `*.streamlit.gk2.secubox.in` et page de
réveil — dépend de la lacune de restauration des routes au réveil (#896). Il
fera l'objet d'un plan distinct. Le mur reste pleinement utilisable d'ici là
avec les URL par chemin actuelles.
