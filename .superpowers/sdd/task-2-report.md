# Task 2 — Rapport d'implémentation

Module : `secubox-picobrew`
Branche : `feat/picobrew-phase1-lxc`
Commit : `391612bb7de6f488ceabe0c8b3fc06c7ccc844d2`

(Note relecteur : ce fichier contenait précédemment un rapport pour une tâche `secubox-meshtastic` sans rapport avec ce module — probablement un rapport d'une session antérieure resté au même chemin. Il a été intégralement remplacé par le rapport ci-dessous, propre à cette tâche.)

## Fichiers déplacés / créés

- **Déplacé** (git mv, contenu inchangé) :
  `packages/secubox-picobrew/api/main.py` → `packages/secubox-picobrew/lib/stillwatch/legacy_controller.py`
  Vérification d'intégrité : `diff` entre le blob `HEAD:packages/secubox-picobrew/api/main.py` (avant déplacement) et le fichier final `lib/stillwatch/legacy_controller.py` → **exit code 0** (identique octet pour octet, 992 lignes, aucune modification).
  Note : dans le commit final, git n'affiche plus ce fichier comme "renamed" — il apparaît en `new file` pour `legacy_controller.py` et `modified` pour `api/main.py`. C'est un artefact normal : une fois `api/main.py` recréé avec un contenu très différent (la nouvelle API mince), git ne retrouve plus de similarité suffisante pour détecter un rename pur. L'historique de commande (`git mv` exécuté en premier, avant toute autre modification) et la vérification byte-à-byte ci-dessus confirment qu'il s'agit bien d'un déplacement sans altération du contenu original.

- **Créé** : `packages/secubox-picobrew/api/main.py` — nouvelle API de gestion mince (65 lignes), reprise verbatim du brief. En-tête SPDX `LicenseRef-CMSD-1.0` + ligne Copyright CyberMind présents.

- **Créé** : `packages/secubox-picobrew/tests/test_api_management.py` — 3 tests, repris verbatim du brief. En-tête SPDX présent ; pas de ligne Copyright sur ce fichier, conformément au snippet du brief (qui n'en porte pas).

Le fichier `packages/secubox-picobrew/api/__init__.py` existant n'a pas été touché.

Aucun autre fichier du paquet n'a été modifié (README, debian/*, sbin/picobrewctl, nginx/, www/, menu.d/). Le répertoire `packages/secubox-picobrew/debian/secubox-picobrew/` est un artefact de build **non suivi par git** (absent de `git ls-files`) contenant une ancienne copie build-time de `api/main.py` — non touché, non pertinent pour ce commit (sera régénéré au prochain `dpkg-buildpackage`).

## Méthode TDD — preuve d'échec puis de succès

Commande de test (depuis le répertoire du paquet, avec le venv racine du dépôt — `fastapi`/`httpx` absents de l'environnement global) :
```
cd packages/secubox-picobrew && /home/reepost/CyberMindStudio/secubox-deb/secubox-deb/.venv/bin/python3 -m pytest tests/test_api_management.py -q
```

### AVANT implémentation (après le seul `git mv`, avant création du nouveau `api/main.py`)

Sortie exacte :
```
==================================== ERRORS ====================================
___ ERROR collecting packages/secubox-picobrew/tests/test_api_management.py ____
ImportError while importing test module '/home/reepost/CyberMindStudio/secubox-deb/secubox-deb/packages/secubox-picobrew/tests/test_api_management.py'.
Hint: make sure your test modules/packages have valid Python names.
Traceback:
/usr/lib/python3.12/importlib/__init__.py:90: in import_module
    return _bootstrap._gcd_import(name[level:], package, level)
           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
tests/test_api_management.py:5: in <module>
    from api.main import app
E   ModuleNotFoundError: No module named 'api.main'
=========================== short test summary info ============================
ERROR tests/test_api_management.py
!!!!!!!!!!!!!!!!!!!! Interrupted: 1 error during collection !!!!!!!!!!!!!!!!!!!!
1 error in 0.34s
```
Conforme à l'attendu du brief (`ModuleNotFoundError` / `app` introuvable, l'ancien `main.py` ayant été déplacé).

### APRÈS implémentation (nouveau `api/main.py` créé)

Sortie exacte :
```
...                                                                      [100%]
3 passed in 0.29s
```

Vérification complémentaire — suite complète du répertoire `tests/` du paquet (inclut aussi `test_picobrewctl_guards.sh`, un test shell non collecté par pytest car ce n'est pas un fichier `.py`) :
```
...                                                                      [100%]
3 passed in 0.30s
```
Aucune régression détectée, aucun test additionnel silencieusement ignoré (le script shell est un test distinct, hors du scope pytest, non exécuté ni modifié dans cette tâche).

## Conformité aux contraintes du dépôt

- SPDX + Copyright CyberMind présents en tête de `api/main.py` (fichier créé). Absents de `legacy_controller.py` (fichier déplacé, non modifié — conforme à la consigne explicite de ne pas y toucher) et de `test_api_management.py` (le snippet du brief ne porte que le SPDX, sans ligne Copyright — reproduit verbatim, sans ajout de ma part).
- L'API ne fait aucune action privilégiée elle-même : `_ctl()` est l'unique point d'exécution externe dans `api/main.py`, via `sudo -n /usr/sbin/picobrewctl <args>`. Aucun autre appel `subprocess`/`os.system` dans le fichier.
- Dégradation propre : `_ctl()` capture `OSError` et `subprocess.SubprocessError` (ctl absent, timeout, etc.) et retourne toujours `(1, "")` plutôt que de lever une exception — `/status` répond alors `200` avec `installed: false` et une clé `error`, jamais de `500`. Comportement vérifié explicitement par `test_status_degrades_cleanly_when_ctl_fails`.
- `POST /start` et `POST /stop` délèguent strictement à `_ctl(["start"])` / `_ctl(["stop"])` — vérifié par `test_start_delegates_to_ctl_and_never_runs_privileged_itself`, qui inspecte l'argument exact passé au mock.

## Doutes / points d'attention pour le relecteur

1. **Rename non détecté par git dans le commit final** : voir explication détaillée ci-dessus (section "Fichiers déplacés / créés"). Preuve d'intégrité fournie par diff byte-à-byte contre le blob pré-déplacement, pas seulement par affirmation.
2. **`lib/stillwatch/` sans `__init__.py`** : le brief demande uniquement un emplacement de dépôt pour la phase 2 (le fichier déplacé n'est importé nulle part dans ce commit). Aucun `__init__.py` n'a donc été ajouté, pour rester strictement dans le périmètre de la tâche. Si une phase ultérieure doit importer ce module comme package Python, il faudra l'ajouter alors.
3. Le paramètre `timeout=20` de `_ctl()` est repris verbatim du brief ; aucun test ne couvre spécifiquement un dépassement de timeout (le brief n'en demandait pas).
4. Je n'ai pas touché à `debian/control` ni à `debian/rules` pour refléter la nouvelle arborescence `lib/stillwatch/` — ce n'était pas dans le périmètre de la tâche 2 (uniquement API + déplacement du contrôleur). Une phase ultérieure de packaging devra vraisemblablement inclure ce nouveau chemin dans les règles d'installation Debian si la phase 2 en a besoin côté paquet livré.
5. Ce fichier de rapport (`task-2-report.md`) existait déjà avant cette tâche avec un contenu concernant `secubox-meshtastic` (module distinct, sans rapport avec `secubox-picobrew`). Il a été entièrement remplacé — signalé ici par transparence, au cas où ce contenu antérieur avait une valeur que je n'ai pas perçue.

---

## Correctif post-revue — filet de test insuffisant sur `_ctl`

**Constat de la revue** (vérifié empiriquement par le relecteur) : les 3 tests
initiaux patchaient `api.main._ctl` en entier — le corps de `_ctl` (délégation
sudo exacte, capture d'exceptions OS, garde JSON) n'était donc jamais exécuté.
Le relecteur a démontré qu'on pouvait retirer `"sudo", "-n"` de l'argv réel, OU
supprimer tout le `try/except`, OU supprimer la garde `json.JSONDecodeError` —
les 3 tests passaient quand même.

**`api/main.py` non modifié** : confirmé par `git diff --stat -- packages/secubox-picobrew/api/main.py`
→ vide (aucune sortie), avant et après cette tâche.

### Tests ajoutés (fichier `tests/test_api_management.py`, 5 nouveaux tests, patchant `subprocess.run` et non plus `_ctl`)

1. `test_ctl_invokes_exact_privileged_argv` — vérifie que `_ctl(["start"])`
   appelle `subprocess.run` avec l'argv exact
   `["sudo", "-n", "/usr/sbin/picobrewctl", "start"]`.
2. `test_ctl_survives_missing_binary` — `subprocess.run` lève `FileNotFoundError`
   → `_ctl` ne lève jamais, renvoie `(1, "")`.
3. `test_ctl_survives_timeout` — `subprocess.run` lève
   `subprocess.TimeoutExpired(cmd="x", timeout=20)` → `_ctl` ne lève jamais,
   renvoie `(1, "")`.
4. `test_status_route_survives_empty_ctl_output` — route `/status`, rc=0 mais
   stdout vide → 200 avec `installed: false`, `running: false` et un champ
   `error` exploitable.
5. `test_status_route_survives_invalid_json` — route `/status`, rc=0 mais
   stdout non-JSON (`"ceci n'est pas du json"`) → 200 avec `installed: false`
   et un champ `error` exploitable (garde `JSONDecodeError`).

Les 3 tests existants (routeur→`_ctl`) sont conservés intacts.

### Méthode imposée — casser puis restaurer, un défaut à la fois

Commande de test (depuis le répertoire du paquet) :
```
cd packages/secubox-picobrew && /home/reepost/CyberMindStudio/secubox-deb/secubox-deb/.venv/bin/python3 -m pytest tests/ -q
```

**Baseline (code correct, avant tout correctif)** : `3 passed in 0.27s`.
**Après ajout des 5 nouveaux tests (code toujours correct)** : `8 passed in 0.29s`.

#### Casse 1 — retrait de `"sudo", "-n"` de l'argv réel

`api/main.py` : `subprocess.run(["sudo", "-n", CTL, *args], ...)` →
`subprocess.run([CTL, *args], ...)`.

Test ciblé, sortie obtenue :
```
$ pytest tests/test_api_management.py::test_ctl_invokes_exact_privileged_argv -q
F
AssertionError: assert ['/usr/sbin/picobrewctl', 'start'] == ['sudo', '-n', '/usr/sbin/picobrewctl', 'start']
  At index 0 diff: '/usr/sbin/picobrewctl' != 'sudo'
1 failed in 0.28s
```
Suite complète : `1 failed, 7 passed in 0.30s` (seul le test ciblé échoue).

Restauration de `api/main.py` à l'identique → suite complète : `8 passed in 0.30s`.

#### Casse 2 — suppression du `try/except (OSError, subprocess.SubprocessError)` dans `_ctl`

Sortie obtenue (les deux tests de dégradation échouent, avec l'exception réelle qui remonte au lieu d'être absorbée) :
```
$ pytest tests/test_api_management.py::test_ctl_survives_missing_binary tests/test_api_management.py::test_ctl_survives_timeout -q
FF
FileNotFoundError
...
subprocess.TimeoutExpired: Command 'x' timed out after 20 seconds
2 failed in 0.38s
```
Suite complète : `2 failed, 6 passed in 0.40s`.

Restauration de `api/main.py` à l'identique → suite complète : `8 passed in 0.31s`.

#### Casse 3 — suppression de la garde `except json.JSONDecodeError` dans `/status`

Sortie obtenue (l'exception JSON remonte jusqu'au client de test — `500` implicite au lieu d'un repli `200`) :
```
$ pytest tests/test_api_management.py::test_status_route_survives_invalid_json -q
F
...
api/main.py:40: in status
    return json.loads(out)
json.decoder.JSONDecodeError: Expecting value: line 1 column 1 (char 0)
1 failed in 0.47s
```
Suite complète : `1 failed, 7 passed in 0.47s`.

Restauration de `api/main.py` à l'identique → suite complète : `8 passed in 0.30s`.

### Vérification finale

```
$ git diff --stat -- packages/secubox-picobrew/api/main.py
```
→ aucune sortie : `api/main.py` strictement identique à son état avant ce correctif.

```
$ cd packages/secubox-picobrew && /home/reepost/CyberMindStudio/secubox-deb/secubox-deb/.venv/bin/python3 -m pytest tests/ -q
........                                                                 [100%]
8 passed in 0.30s
```

### Commit

Hash : `b2163fb3` — `fix(picobrew): tests _ctl→OS pour argv sudo, dégradation OS et garde JSON (ref revue tâche 2)`.

### Préoccupations pour le relecteur

- Les tests 2 (binaire absent) et 3 (timeout) appellent `_ctl` directement plutôt que de passer par une route HTTP ; c'est volontaire (le point de défaillance est dans `_ctl`, indépendant du routeur), mais je le signale car la consigne mentionnait `/status` explicitement pour les deux derniers cas seulement.
- `test_ctl_invokes_exact_privileged_argv` hardcode le chemin littéral `/usr/sbin/picobrewctl` plutôt que d'importer `api.main.CTL`, précisément pour que le test reste discriminant si `CTL` lui-même est modifié à la légère.
