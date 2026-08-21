# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: MetaBlogizer site.json schema validator + enricher
CyberMind — https://cybermind.fr
Author: Gérald Kerma <gandalf@gk2.net>
License: CMSD-1.0
"""
from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

import jsonschema

SCHEMA_PATH = Path(__file__).parent.parent / "schema" / "site.json.schema.json"


def load_schema() -> dict:
    """Read the JSON Schema once."""
    with SCHEMA_PATH.open() as f:
        return json.load(f)


# Champs qu'un opérateur peut PARAMÉTRER depuis la page site (#1089). Le nom
# (clé de répertoire) n'en fait pas partie, et `published` reste piloté par les
# actions publish/unpublish, jamais par une édition de métadonnées.
CHAMPS_EDITABLES = (
    "domain", "title", "description", "category", "tags",
    "aliases", "source_url", "gitea_repo", "streamlit_app",
)
# Champs DÉRIVÉS, recalculés par enrich() à chaque lecture (git). Les persister
# figerait une valeur périmée : on les retire avant d'écrire.
CHAMPS_DERIVES = ("version", "last_updated")


def fusionner(existant: dict, patch: dict) -> tuple[dict, list[str]]:
    """Applique un patch d'édition sur un `site.json` et valide le résultat.

    - seules les clés de `CHAMPS_EDITABLES` sont prises en compte ; les autres
      clés du patch sont ignorées silencieusement ;
    - une valeur `None` EFFACE le champ (retour au défaut) ;
    - le nom n'est jamais modifié ici, et les champs dérivés ne sont jamais
      persistés ;
    - le document final est validé contre le schéma. Un alias qui n'est pas un
      domaine est ainsi refusé AVANT écriture — défense en profondeur : la
      génération nginx (`alias_du_site`) le refiltre de toute façon.

    Retourne `(doc, erreurs)` ; `erreurs` non vide ⇒ ne pas écrire.
    """
    out = dict(existant)
    for k in CHAMPS_EDITABLES:
        if k in patch:
            v = patch[k]
            if v is None:
                out.pop(k, None)
            else:
                out[k] = v
    for k in CHAMPS_DERIVES:
        out.pop(k, None)
    ok, errs = validate(out)
    return out, errs


def validate(doc: dict) -> tuple[bool, list[str]]:
    """Validate doc against the schema.

    Returns (ok, errors).  Permissive: doc may have extra fields (the schema
    has additionalProperties: true).
    """
    schema = load_schema()
    validator = jsonschema.Draft7Validator(schema)
    errors = [
        f"{'.'.join(map(str, e.path)) or '<root>'}: {e.message}"
        for e in validator.iter_errors(doc)
    ]
    return (not errors, errors)


def _git(*args: str, cwd: Path) -> str | None:
    """Run git with a 5-second timeout; return stripped stdout or None."""
    try:
        out = subprocess.run(
            ["git", "-C", str(cwd), *args],
            capture_output=True, text=True, timeout=5,
        )
        if out.returncode == 0:
            return out.stdout.strip() or None
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    return None


def enrich(doc: dict, app_dir: Path) -> dict:
    """Fill derived fields (version, last_updated) if missing.

    - version    -> git describe --tags --exact-match (else --tags --always)
    - last_updated -> git log -1 --format=%cI (RFC 3339)

    Does nothing if app_dir has no .git/.
    """
    out: dict[str, Any] = dict(doc)
    if not (app_dir / ".git").exists():
        return out
    if not out.get("version"):
        out["version"] = (
            _git("describe", "--tags", "--exact-match", cwd=app_dir)
            or _git("describe", "--tags", "--always", cwd=app_dir)
        )
    if not out.get("last_updated"):
        out["last_updated"] = _git("log", "-1", "--format=%cI", cwd=app_dir)
    return out
