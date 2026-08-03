# secubox-webllm

Automatisation **locale** d'une session de chat web (claude.ai, chatgpt.com,
gemini.google.com), dans un profil de navigateur Playwright **persistant**.

## Invariant — à ne jamais violer

- La session vit dans le profil de navigateur, point. Aucun cookie n'est
  jamais lu, extrait ni rejoué en dehors de Playwright.
- Aucun port, aucun endpoint HTTP n'est ouvert par ce package — pas de
  relais serveur, pas de proxy de l'interface, pas d'accès mutualisé entre
  utilisateurs.
- Mono-utilisateur, exécution locale, sous contrôle direct de l'opérateur.

Toute modification qui pousserait dans une autre direction (partage de
session, exposition réseau, rejeu de cookie) est hors périmètre de ce
package et ne doit pas être ajoutée ici.

## Installation

```bash
cd tools/secubox-webllm
pip install -e .
playwright install chromium   # une seule fois, télécharge le navigateur
```

## Premier login

Chaque backend a son propre profil, jamais partagé :
`~/.secubox/webllm/<backend>/profile`.

```bash
secubox-webllm --backend claude "bonjour"
```

Sans session valide dans le profil, la fenêtre s'ouvre (mode headed par
défaut) : connectez-vous manuellement, la session est alors persistée dans
le profil pour les lancements suivants — y compris `--headless`.

`--headless` sans session valide échoue immédiatement avec un message
explicite (jamais d'attente infinie) :

```
erreur : aucune session 'claude' valide dans /home/.../profile — relancez
une première fois sans --headless pour vous connecter manuellement
```

## Usage

```bash
# Prompt en argument
secubox-webllm --backend claude "résume-moi ce texte"

# Prompt sur stdin
cat notes.txt | secubox-webllm --backend gpt

# Nouvelle conversation avant l'envoi
secubox-webllm --backend gemini --new "nouvelle question"

# Headless (session déjà connectée), timeout personnalisé, profil alternatif
secubox-webllm --backend claude --headless --timeout 180 --profile /data/webllm "..."
```

`claude_web.py` (racine du package) est un **shim de compatibilité** : la
classe `ClaudeWeb` et sa CLI historique délèguent intégralement à
`webllm.WebLLMSession` / `webllm.cli`, verrouillés sur le backend `claude`.
Préférer directement `secubox-webllm --backend claude`.

## Architecture

- `webllm/session.py` — logique générique (profil, login, soumission,
  détection de fin de génération par stabilité). **Zéro constante
  spécifique à un fournisseur.**
- `webllm/backend.py` — dataclasses `Backend` / `Selectors` + registry
  (`@register`, `get_backend`, `available_backends`).
- `webllm/backends/*.py` — un fichier par fournisseur. Découverts
  automatiquement par `pkgutil` à l'import de `webllm.backends` : aucun
  autre fichier n'a besoin d'être modifié pour en ajouter un.
- `webllm/cli.py` — CLI unifiée, ignore tout ce qui est spécifique à un
  fournisseur (résolu via `get_backend(args.backend)`).

### Détection de fin de génération

Le principe hérité du client d'origine : une réponse est jugée complète
quand l'`innerText` du dernier message assistant est identique à la lecture
précédente **et** que le bouton d'arrêt (stop) est absent, pendant
`Config.stability_polls` lectures consécutives. Tout changement de texte ou
toute réapparition du bouton stop repart de zéro. Voir
`webllm.session.StabilityTracker` et `webllm.session.wait_stable`.

## Ajouter un backend (moins de 20 lignes, zéro fichier existant modifié)

Créer `webllm/backends/<nom>.py` :

```python
from __future__ import annotations

from webllm.backend import Backend, Selectors, register


@register
def _backend() -> Backend:
    return Backend(
        name="monfournisseur",
        url="https://monfournisseur.example/chat",
        selectors=Selectors(
            composer='div[contenteditable="true"]',
            send_button='button[aria-label="Send"]',
            stop_button='button[aria-label="Stop"]',
            assistant_message="div.message.assistant",
            login_indicator='div[contenteditable="true"]',
        ),
        submit_mode="enter",       # ou "button" pour un clic explicite
        line_break_key="Shift+Enter",
    )
```

C'est tout : `webllm/backends/__init__.py` importe automatiquement tout
fichier de ce répertoire (`pkgutil.iter_modules`), `session.py` et `cli.py`
ne connaissent que l'abstraction `Backend`. Le nouveau nom apparaît dans
`available_backends()` et dans les choix `--backend` de la CLI sans aucune
autre modification.

## Corriger un sélecteur cassé

Les sélecteurs de `webllm/backends/{claude,openai,gemini}.py` sont
**best-effort** — reconstruits sans accès à une version antérieure
retrouvée ou fournie, à partir de la structure connue des interfaces au
moment de l'écriture. **Aucun des trois n'est garanti fonctionner tel
quel** : les fournisseurs changent leur front-end sans préavis.

Pour corriger :

1. Ouvrir le chat web ciblé, DevTools (`F12`) → onglet *Elements*.
2. Repérer l'élément concerné (zone de saisie, bouton d'envoi, bouton stop,
   bulle de message assistant, un élément présent seulement une fois
   connecté pour `login_indicator`).
3. Clic droit → *Copy* → *Copy selector*, ou construire un sélecteur stable
   (attribut `data-testid`, `aria-label`, plutôt qu'une classe générée).
4. Mettre à jour le champ correspondant dans le `Selectors(...)` du fichier
   backend concerné.
5. Valider manuellement : `secubox-webllm --backend <nom> "test"` en mode
   headed (sans `--headless`).

## Tests

```bash
cd tools/secubox-webllm
pip install -e ".[dev]"  # ou : pip install pytest pytest-asyncio
pytest -q
```

Aucun test n'ouvre de navigateur ni de connexion réseau : la logique de
détection de stabilité, le découpage du prompt, le registry de backends et
le comportement de `WebLLMSession` sont testés avec un objet `page` factice
(`tests/fakes.py`) et une horloge/sommeil injectables.

## Hors périmètre

Pièces jointes / envoi de fichiers, persistance des conversations en base,
toute exposition réseau (voir Invariant ci-dessus).
