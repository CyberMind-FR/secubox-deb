# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: BBS urlshot :: worker
CyberMind — https://cybermind.fr

Draine la file `urlshots` de `/var/lib/secubox/bbs/index.db` — la table est
créée et alimentée côté Go (`internal/store/urlshots.go`, migration
`0023_urlshots.sql`) ; ce module ne fait qu'y lire les lignes `pending` et
les faire progresser vers `done`/`failed`. La CLÉ (`cle`) est calculée côté
Go (sha256 normalisé, 32 hex) et réutilisée ici telle quelle — jamais
recalculée, jamais réinterprétée (voir Global Constraints #1120 : « no
cross-language key-agreement bug »).

Rappelé par `secubox-bbs-urlshot.timer` toutes les 2 minutes (Task 9), UNE
capture à la fois par tour par défaut (`n=3` lignes max par appel, mais
chaque ligne reste une capture chromium potentielle — coûteuse) : c'est le
timer qui étale la charge dans le temps, exactement le même principe que
`metablog-shotter` (`packages/secubox-metablogizer/api/shots.py`).

Garde de charge : AVANT toute lecture de la file, si la charge à 1 minute
dépasse `load_threshold` (défaut 4.0, comme metablog-shotter (valeur courante, ajustée le 2026-08-12)), ce tour est
sauté intégralement — aucune ligne n'est touchée, `capture_vignette` n'est
jamais appelé. Une board déjà saturée ne doit jamais voir son chromium
s'ajouter à la pile.

Contrat dur avec `capture.capture_vignette()` : ce module NE FAIT PAS
confiance à ce contrat pour autant — un `try/except` entoure chaque appel de
capture ligne par ligne. Une capture qui lèverait malgré tout (bug, cas non
prévu) ne doit JAMAIS interrompre la boucle : la ligne fautive est marquée
`failed` et le worker passe à la suivante, sans quoi une seule URL
pathologique gèlerait la file pour toutes les autres (même invariant que
`metablog-shotter` : « un échec ne bloque pas la file »).
"""
from __future__ import annotations

import json
import os
import sqlite3
import sys
import time
from pathlib import Path

import capture

# common/secubox_core doit être importable sans installation pip — voir la
# docstring de capture.py pour le même repli (dev / source tree uniquement ;
# en production, `secubox-core` est déjà sur sys.path via dist-packages).
_COMMON = Path(__file__).resolve().parents[4] / "common"
if _COMMON.is_dir() and str(_COMMON) not in sys.path:
    sys.path.insert(0, str(_COMMON))

from secubox_core import screenshots  # noqa: E402

DEFAULT_DB_PATH = "/var/lib/secubox/bbs/index.db"
DEFAULT_CACHE_BASE = "/var/cache/secubox/bbs/urlshots"

# SEUIL DE CHARGE — même valeur et même raisonnement que metablog-shotter à
# son introduction (#956) : au-delà, une capture chromium supplémentaire
# aggraverait une board déjà engorgée plutôt que de servir une vignette.
DEFAULT_LOAD_THRESHOLD = 4.0

# Nombre de lignes `pending` traitées au maximum par appel de `draine()` —
# UNE capture à la fois, jamais en parallèle (Global Constraints #1120).
DEFAULT_BATCH = 3

_SELECT_PENDING = (
    "SELECT cle, url FROM urlshots WHERE statut='pending' ORDER BY maj LIMIT ?"
)
_UPDATE_STATUT = "UPDATE urlshots SET statut=?, maj=? WHERE cle=?"


def _charge_ok(threshold: float) -> bool:
    """True si la charge à une minute est sous (ou égale à) `threshold`.

    Fail-open sur `OSError` (pas de `getloadavg()` sur cette plateforme) :
    ce cas n'est jamais rencontré sur Linux, la cible réelle, et geler la
    file indéfiniment serait pire qu'une capture de trop."""
    try:
        return os.getloadavg()[0] <= threshold
    except OSError:
        return True


def _connexion(db_path) -> sqlite3.Connection:
    """Connexion courte et WAL-friendly vers `index.db`, partagé avec le
    BBS Go qui l'écrit en continu. `isolation_level=None` (autocommit) :
    chaque `UPDATE` de ligne est validé indépendamment — une capture ratée
    en cours de lot ne fait pas perdre la progression déjà actée sur les
    lignes précédentes. `busy_timeout` absorbe une brève contention avec le
    processus Go plutôt que d'échouer immédiatement sur `database is
    locked`."""
    conn = sqlite3.connect(str(db_path), timeout=5.0, isolation_level=None)
    conn.execute("PRAGMA busy_timeout=5000")
    return conn


def draine(
    n: int = DEFAULT_BATCH,
    *,
    db_path=DEFAULT_DB_PATH,
    cache_base=DEFAULT_CACHE_BASE,
    load_threshold: float = DEFAULT_LOAD_THRESHOLD,
) -> dict:
    """Traite jusqu'à `n` lignes `pending`, une capture à la fois.

    Garde de charge appliquée EN PREMIER (voir docstring du module) : sous
    charge excessive, renvoie immédiatement sans avoir lu la file ni touché
    aucune ligne.

    Pour chaque ligne : `capture.capture_vignette(url)` (jamais laissé
    lever hors de cette fonction — voir docstring du module), puis
    `screenshots.record()` avec `fingerprint=url` (la fraîcheur/TTL de
    recapture est gouvernée ailleurs, via `screenshots.is_stale` — ce
    worker ne fait qu'enregistrer le résultat de la tentative), puis mise à
    jour du statut (`done`/`failed`) et de `maj` (epoch courant).

    Renvoie un résumé : `{"processed", "ok", "failed"}`, ou
    `{"skipped_load": True, "threshold": ...}` si la garde de charge a
    court-circuité ce tour."""
    if not _charge_ok(load_threshold):
        return {"skipped_load": True, "threshold": load_threshold}

    resultat = {"processed": 0, "ok": 0, "failed": 0}
    conn = _connexion(db_path)
    try:
        lignes = conn.execute(_SELECT_PENDING, (n,)).fetchall()

        for cle, url in lignes:
            try:
                png, ok = capture.capture_vignette(url)
            except Exception:
                # Contrat dur violé par capture_vignette (ne devrait jamais
                # arriver — voir docstring du module) : une ligne fautive
                # ne doit jamais wedger le worker.
                png, ok = None, False

            try:
                screenshots.record(cache_base, cle, png, fingerprint=url, ok=ok)
            except Exception:
                # L'écriture du cache elle-même a échoué (disque plein,
                # permissions...) : la ligne reste marquée en échec, elle
                # sera retentée au prochain tour.
                ok = False

            conn.execute(_UPDATE_STATUT, ("done" if ok else "failed", int(time.time()), cle))
            resultat["processed"] += 1
            resultat["ok" if ok else "failed"] += 1
    finally:
        conn.close()

    return resultat


def main() -> int:
    """Point d'entrée de `secubox-bbs-urlshot.service` (`python3 -m
    worker`). Toujours code 0 : un échec de capture est visible dans le
    résumé JSON imprimé (et dans `statut='failed'` en base), jamais traité
    comme une erreur bloquante par le timer — même convention que
    `metablog-shotter`."""
    resultat = draine()
    print(json.dumps(resultat))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
