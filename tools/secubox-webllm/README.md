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
explicite (jamais d'attente, même bornée) :

```
erreur : composer introuvable en headless (claude) : session probablement
expirée. Relancez une fois en mode headed pour vous reconnecter
(profil : /home/.../.secubox/webllm/claude/profile).
```

**Changement de chemin de profil** : l'ancien client mono-backend stockait
sa session dans `~/.secubox/claude-web/profile`. Ce n'est **pas** migré
automatiquement — `claude_web.py` (le shim, voir plus bas) affiche un
avertissement si l'ancien profil existe mais que le nouveau n'a pas encore
de session, mais ne copie rien. Reconnectez-vous une fois en mode headed
avec le nouveau chemin.

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

`--timeout` (défaut 300s) borne l'attente de la réponse — c'est
`Config.answer_timeout_ms`, aligné sur la valeur `answer_timeout=300.0`
éprouvée par le client d'origine.

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

### Cycle d'un `ask()`

1. **Soumission** (`_submit`) : clic sur le composer, `fill("")` pour le
   vider, puis pour chaque ligne du prompt — `Shift+Enter` **entre** les
   lignes (jamais avant la première : dans ProseMirror, un Entrée seul
   déclenche l'envoi et tronquerait le prompt à sa 1re ligne), `type(line)`.
2. **Envoi** (`_trigger_send`) : tente le bouton d'envoi
   (`is_enabled(timeout=Config.send_button_timeout_ms)`, 1500ms par défaut)
   et le clique s'il est disponible ; sinon (absent, désactivé, ou la
   vérification expire) se rabat sur la touche Entrée dans le composer.
3. **Attente d'une NOUVELLE réponse** (`_wait_new_answer`) : avant de guetter
   la stabilité, attend que le nombre de messages assistant dépasse celui
   d'avant soumission, OU que le streaming démarre (bouton stop visible).
   Sans cette garde, un `ask()` enchaîné dans la même conversation verrait
   le dernier message du tour précédent déjà stable et le renverrait tel
   quel, périmé — un bug réel que `tests/test_session.py` démontre
   explicitement (`test_wait_for_completion_alone_would_return_the_stale_previous_answer`
   vs `test_ask_never_returns_the_stale_previous_answer`).
4. **Détection de fin de génération** (`_wait_for_completion`) : principe
   hérité du client d'origine — une réponse est jugée complète quand
   l'`innerText` du dernier message assistant est identique à la lecture
   précédente **et** que le bouton stop est absent, pendant
   `Config.stability_polls` lectures consécutives. Tout changement de texte
   ou toute réapparition du bouton stop repart de zéro. Voir
   `webllm.session.StabilityTracker` et `webllm.session.wait_stable`.

**Divergence assumée sur le timeout** : à l'expiration de
`answer_timeout_ms`, l'implémentation d'origine renvoyait le texte déjà lu
plutôt que d'échouer. Ce package **lève `TimeoutError`** à la place — un
appelant qui reçoit une réponse veut savoir si elle est complète ou
tronquée par un timeout ; masquer la différence en silence a semblé plus
dangereux qu'utile, d'autant que rien n'empêche l'appelant de traiter
`TimeoutError` comme un signal « best effort disponible » s'il le souhaite
via son propre `try/except`. C'est un changement de comportement assumé,
pas un oubli.

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
        line_break_key="Shift+Enter",  # touche de saut de ligne, entre les lignes
    )
```

Pas de champ « submit_mode » à choisir : `session.py` tente toujours le
bouton d'envoi et se rabat automatiquement sur Entrée s'il est
indisponible — un seul mécanisme, valable pour tout fournisseur.

C'est tout : `webllm/backends/__init__.py` importe automatiquement tout
fichier de ce répertoire (`pkgutil.iter_modules`), `session.py` et `cli.py`
ne connaissent que l'abstraction `Backend`. Le nouveau nom apparaît dans
`available_backends()` et dans les choix `--backend` de la CLI sans aucune
autre modification.

## Corriger un sélecteur cassé

- `webllm/backends/claude.py` : sélecteurs **repris de l'implémentation
  d'origine**, éprouvés en usage réel (mono-backend claude, avant cette
  industrialisation). Fiables au moment de l'écriture, mais pas immunisés
  contre un changement futur de l'UI claude.ai — même vigilance requise
  dans la durée.
- `webllm/backends/{openai,gemini}.py` : sélecteurs **best-effort**,
  reconstruits à partir de la structure connue des interfaces, jamais
  validés en conditions réelles. Ne pas leur accorder plus de confiance
  qu'à un point de départ à vérifier.

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
