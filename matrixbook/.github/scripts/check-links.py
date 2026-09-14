#!/usr/bin/env python3
"""Vérifie les liens internes et les ancres de tous les fichiers Markdown.

Sans dépendance externe. Pour chaque lien Markdown `[texte](cible)` :
- une cible `http(s)://`, `mailto:` ou `#` seule est ignorée ;
- une cible relative doit désigner un fichier ou un dossier existant ;
- une ancre `fichier.md#section` (ou `#section` dans le même fichier) doit
  correspondre à un titre du fichier visé, selon l'algorithme de GitHub
  (minuscules, ponctuation retirée, espaces remplacés par des tirets).

Code de sortie 0 si tout est valide, 1 sinon. Les erreurs sont imprimées au
format des annotations GitHub Actions.
"""
from __future__ import annotations

import re
import sys
import unicodedata
from pathlib import Path
from urllib.parse import unquote

ROOT = Path(__file__).resolve().parents[2]
LINK_RE = re.compile(r"(?<!\!)\[([^\]]*)\]\(([^)\s]+)(?:\s+\"[^\"]*\")?\)")
HEADING_RE = re.compile(r"^(#{1,6})\s+(.*?)\s*#*\s*$")
FENCE_RE = re.compile(r"^(```|~~~)")
INLINE_CODE_RE = re.compile(r"`[^`]*`")
LINK_TEXT_RE = re.compile(r"\[([^\]]*)\]\([^)]*\)")


def github_slug(text: str) -> str:
    """Reproduit la génération d'ancres de GitHub pour un titre."""
    text = LINK_TEXT_RE.sub(r"\1", text)
    text = re.sub(r"[*_`~]", "", text)
    text = text.strip().lower()
    out = []
    for ch in text:
        if ch == " " or ch == "-":
            out.append("-" if ch == " " else "-")
        elif unicodedata.category(ch)[0] in ("L", "N") or ch == "_":
            out.append(ch)
    return "".join(out)


def headings(path: Path) -> set[str]:
    slugs: dict[str, int] = {}
    result: set[str] = set()
    in_fence = False
    for line in path.read_text(encoding="utf-8").splitlines():
        if FENCE_RE.match(line):
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        m = HEADING_RE.match(line)
        if not m:
            continue
        slug = github_slug(m.group(2))
        n = slugs.get(slug, 0)
        slugs[slug] = n + 1
        result.add(slug if n == 0 else f"{slug}-{n}")
    return result


def links(path: Path):
    in_fence = False
    for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if FENCE_RE.match(line):
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        stripped = INLINE_CODE_RE.sub("", line)
        for m in LINK_RE.finditer(stripped):
            yield lineno, m.group(2)


def main() -> int:
    md_files = sorted(p for p in ROOT.rglob("*.md") if "node_modules" not in p.parts)
    heading_cache: dict[Path, set[str]] = {}
    errors = 0
    checked = 0

    for md in md_files:
        for lineno, target in links(md):
            if target.startswith(("http://", "https://", "mailto:")) or target == "#":
                continue
            checked += 1
            file_part, _, anchor = target.partition("#")
            file_part = unquote(file_part)
            dest = md if not file_part else (md.parent / file_part).resolve()
            rel = md.relative_to(ROOT)
            if not dest.exists():
                print(f"::error file={rel},line={lineno}::cible introuvable : {target}")
                errors += 1
                continue
            if anchor:
                if dest.is_dir() or dest.suffix.lower() != ".md":
                    print(f"::error file={rel},line={lineno}::ancre sur un fichier non Markdown : {target}")
                    errors += 1
                    continue
                if dest not in heading_cache:
                    heading_cache[dest] = headings(dest)
                if unquote(anchor).lower() not in heading_cache[dest]:
                    print(f"::error file={rel},line={lineno}::ancre introuvable : {target}")
                    errors += 1

    print(f"{len(md_files)} fichiers Markdown, {checked} liens internes vérifiés, {errors} erreur(s)")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
