#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: audit documentaire du dépôt.

Produit l'inventaire des modules à partir du DÉPÔT SEUL — jamais d'une liste
tenue à la main, qui vieillirait sans que personne ne s'en aperçoive.

RÈGLE UNIQUE ET NON NÉGOCIABLE : ce script n'invente rien. Une donnée absente
du dépôt ressort comme `À documenter`, jamais comme une valeur plausible. Une
documentation qui comble les trous par de la vraisemblance est pire qu'une
documentation lacunaire : elle ne se laisse plus auditer.

Sorties :
  tutorial/catalog/modules.yaml  — inventaire structuré (source machine)
  tutorial/catalog/modules.md    — le même, en tableau lisible

Le YAML est la source ; le Markdown en dérive. L'inverse condamnerait à
resaisir la même chose deux fois, donc à diverger.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

RACINE = Path(__file__).resolve().parent.parent
PAQUETS = RACINE / "packages"
SORTIE = RACINE / "tutorial" / "catalog"

ABSENT = "À documenter"


# ── Lecture des manifestes ────────────────────────────────────────────────

def lire_manifeste(paquet: Path) -> dict:
    """Lit `debian/secubox.yaml` sans dépendre de PyYAML.

    Le schéma est plat et stable (name/category/tier/description/depends/
    api/ui) : un analyseur minimal suffit et évite d'imposer une dépendance
    pour lire six clés. S'il devient imbriqué, il faudra passer à PyYAML —
    d'où la garde ci-dessous, qui préfère ignorer une clé qu'inventer sa
    valeur.
    """
    f = paquet / "debian" / "secubox.yaml"
    if not f.exists():
        return {}
    d: dict = {}
    section = None
    for ligne in f.read_text(errors="replace").splitlines():
        if not ligne.strip() or ligne.lstrip().startswith("#"):
            continue
        if not ligne.startswith((" ", "\t", "-")):
            m = re.match(r"^([a-z_]+):\s*(.*)$", ligne)
            if not m:
                continue
            cle, val = m.group(1), m.group(2).strip().strip('"')
            section = cle if not val else None
            # UNE CLE SANS VALEUR RESTE INDETERMINEE. La pre-remplir en
            # dictionnaire condamnait les listes : `depends:` devenait `{}`,
            # puis chaque `- secubox-core` etait jete faute d'etre une liste —
            # et le catalogue annoncait « À documenter » sur une dependance
            # pourtant ecrite noir sur blanc. C'est la premiere ligne fille qui
            # decide de la nature.
            if val:
                d[cle] = val
        elif ligne.lstrip().startswith("-") and section:
            if not isinstance(d.get(section), list):
                d[section] = []
            d[section].append(ligne.lstrip()[1:].strip().strip('"'))
        elif section:
            if not isinstance(d.get(section), dict):
                d[section] = {}
            m = re.match(r"^\s+([a-z_]+):\s*(.*)$", ligne)
            if m:
                d[section][m.group(1)] = m.group(2).strip().strip('"')
    return d


# ── Extraction depuis le code ─────────────────────────────────────────────

def routes_api(paquet: Path) -> list:
    """Les endpoints declares, lus dans les decorateurs FastAPI.

    On lit le CODE et non une documentation d'API : c'est le seul endroit qui
    ne peut pas mentir sur ce qui est reellement servi.
    """
    routes = []
    for f in paquet.rglob("api/*.py"):
        if "/tests/" in str(f):
            continue
        try:
            texte = f.read_text(errors="replace")
        except OSError:
            continue
        for m in re.finditer(
                r'@(?:app|router)\.(get|post|put|delete|patch)\(\s*["\']([^"\']+)', texte):
            routes.append(f"{m.group(1).upper()} {m.group(2)}")
    return sorted(set(routes))


def endpoints_proteges(paquet: Path) -> bool:
    """Le module exige-t-il un jeton ? `Depends(require_jwt)` en est la marque."""
    for f in paquet.rglob("api/*.py"):
        try:
            if "require_jwt" in f.read_text(errors="replace"):
                return True
        except OSError:
            continue
    return False


def outils_cli(paquet: Path) -> list:
    d = paquet / "sbin"
    if not d.is_dir():
        return []
    return sorted(f.name for f in d.iterdir()
                  if f.is_file() and not f.name.endswith((".bak", ".orig")))


def unites_systemd(paquet: Path) -> list:
    d = paquet / "debian"
    if not d.is_dir():
        return []
    return sorted(f.name for f in d.iterdir()
                  if f.suffix in (".service", ".timer", ".path", ".socket"))


def routes_web(paquet: Path) -> list:
    """server_name et listen declares dans les vhosts livres par le paquet."""
    out = []
    for f in list(paquet.rglob("nginx/*.conf")) + list(paquet.rglob("*.nginx")):
        try:
            texte = f.read_text(errors="replace")
        except OSError:
            continue
        for m in re.finditer(r"^\s*server_name\s+([^;]+);", texte, re.M):
            out.extend(m.group(1).split())
    return sorted(set(out))


def ports_ecoutes(paquet: Path) -> list:
    out = []
    for f in list(paquet.rglob("nginx/*.conf")) + list(paquet.rglob("debian/*.service")):
        try:
            texte = f.read_text(errors="replace")
        except OSError:
            continue
        for m in re.finditer(r"^\s*listen\s+(?:[\d.]+:)?(\d+)", texte, re.M):
            out.append(m.group(1))
    return sorted(set(out), key=int)


def conteneur_lxc(paquet: Path) -> bool:
    """Le module tourne-t-il dans un conteneur dédié ?

    TROIS INDICES, parce qu'un seul ment. Le premier jet ne cherchait que
    `lib/*/install-lxc.sh` et annonçait 12 modules conteneurisés là où la board
    en fait tourner une trentaine : d'autres paquets rangent le même script
    sous `lxc/`, et certains provisionnent sans script d'installation dédié
    mais pilotent bien un conteneur depuis leur API.
    """
    if any(paquet.rglob("install-lxc.sh")):
        return True
    for f in list(paquet.rglob("*.sh")) + list(paquet.rglob("api/*.py")):
        try:
            texte = f.read_text(errors="replace")
        except OSError:
            continue
        if "lxc-create" in texte or "lxc-attach" in texte:
            return True
    return False


def a_interface_web(paquet: Path) -> bool:
    d = paquet / "www"
    return d.is_dir() and any(d.rglob("*.html"))


def documentation(paquet: Path) -> list:
    return sorted(f.name for f in paquet.glob("README*")) or []


def tests(paquet: Path) -> int:
    return len(list(paquet.rglob("test_*.py"))) + len(list(paquet.rglob("*_test.go")))


# ── Assemblage ────────────────────────────────────────────────────────────

def inventorier() -> list:
    modules = []
    for p in sorted(PAQUETS.iterdir()):
        # Les artefacts de construction portent le meme prefixe que les
        # sources : les inventorier gonflerait le catalogue de doublons.
        if not p.is_dir() or not p.name.startswith("secubox-"):
            continue
        m = lire_manifeste(p)
        api = m.get("api") if isinstance(m.get("api"), dict) else {}
        ui = m.get("ui") if isinstance(m.get("ui"), dict) else {}
        depends = m.get("depends") if isinstance(m.get("depends"), list) else []

        modules.append({
            "id": p.name,
            "nom": m.get("name") or p.name,
            "categorie": m.get("category") or ABSENT,
            "tier": m.get("tier") or ABSENT,
            "description": m.get("description") or ABSENT,
            "depends": depends or [],
            "manifeste": bool(m),
            "api": {
                "socket": api.get("socket") or ABSENT,
                "health": api.get("health") or ABSENT,
                "routes": routes_api(p),
                "authentifie": endpoints_proteges(p),
            },
            "interface_web": {
                "presente": a_interface_web(p),
                "chemin": ui.get("path") or ABSENT,
                "vhosts": routes_web(p),
            },
            "cli": outils_cli(p),
            "systemd": unites_systemd(p),
            "ports": ports_ecoutes(p),
            "lxc": conteneur_lxc(p),
            "documentation": documentation(p),
            "tests": tests(p),
        })
    return modules


def ecrire_yaml(modules: list) -> None:
    """Ecrit le YAML a la main, pour ne pas imposer PyYAML au depot."""
    lignes = [
        "# tutorial/catalog/modules.yaml — inventaire des modules SecuBox.",
        "#",
        "# GENERE PAR scripts/tutorial-audit.py A PARTIR DU DEPOT. Ne pas editer a la",
        "# main : la prochaine execution ecraserait la correction. Pour corriger",
        "# une entree, corriger sa SOURCE — le plus souvent debian/secubox.yaml.",
        "#",
        "# `À documenter` signifie que la donnee est absente du depot, jamais",
        "# qu'elle est inconnue de l'auteur : c'est une tache, pas une lacune de",
        "# redaction.",
        f"# modules: {len(modules)}",
        "",
        "modules:",
    ]
    for m in modules:
        lignes.append(f"  - id: {m['id']}")
        lignes.append(f"    nom: {json.dumps(m['nom'], ensure_ascii=False)}")
        lignes.append(f"    categorie: {json.dumps(m['categorie'], ensure_ascii=False)}")
        lignes.append(f"    tier: {json.dumps(m['tier'], ensure_ascii=False)}")
        lignes.append(f"    description: {json.dumps(m['description'], ensure_ascii=False)}")
        lignes.append(f"    manifeste: {str(m['manifeste']).lower()}")
        lignes.append(f"    lxc: {str(m['lxc']).lower()}")
        lignes.append(f"    tests: {m['tests']}")
        for cle in ("depends", "cli", "systemd", "ports", "documentation"):
            if m[cle]:
                lignes.append(f"    {cle}:")
                lignes.extend(f"      - {json.dumps(v, ensure_ascii=False)}" for v in m[cle])
            else:
                lignes.append(f"    {cle}: []")
        lignes.append("    api:")
        lignes.append(f"      socket: {json.dumps(m['api']['socket'], ensure_ascii=False)}")
        lignes.append(f"      health: {json.dumps(m['api']['health'], ensure_ascii=False)}")
        lignes.append(f"      authentifie: {str(m['api']['authentifie']).lower()}")
        lignes.append(f"      nb_routes: {len(m['api']['routes'])}")
        if m["api"]["routes"]:
            lignes.append("      routes:")
            lignes.extend(f"        - {json.dumps(r, ensure_ascii=False)}"
                          for r in m["api"]["routes"])
        lignes.append("    interface_web:")
        lignes.append(f"      presente: {str(m['interface_web']['presente']).lower()}")
        lignes.append(f"      chemin: {json.dumps(m['interface_web']['chemin'], ensure_ascii=False)}")
        if m["interface_web"]["vhosts"]:
            lignes.append("      vhosts:")
            lignes.extend(f"        - {json.dumps(v, ensure_ascii=False)}"
                          for v in m["interface_web"]["vhosts"])
        else:
            lignes.append("      vhosts: []")
    SORTIE.mkdir(parents=True, exist_ok=True)
    (SORTIE / "modules.yaml").write_text("\n".join(lignes) + "\n")


def ecrire_markdown(modules: list) -> None:
    def oui(v):
        return "oui" if v else "—"

    l = [
        "# Catalogue des modules SecuBox",
        "",
        "> **Généré** par `scripts/tutorial-audit.py` à partir du dépôt.",
        "> Ne pas éditer à la main — corriger la source, le plus souvent",
        "> `packages/<module>/debian/secubox.yaml`, puis relancer le script.",
        "",
        f"**{len(modules)} modules** recensés.",
        "",
        "`À documenter` signale une donnée **absente du dépôt**. C'est une tâche,",
        "pas une lacune de rédaction — et c'est ce qui rend ce catalogue auditable.",
        "",
        "| Module | Catégorie | Tier | Web | API | CLI | systemd | LXC | Tests | Doc |",
        "|---|---|---|---|---|---|---|---|---|---|",
    ]
    for m in modules:
        l.append(
            f"| `{m['id']}` | {m['categorie']} | {m['tier']} | "
            f"{oui(m['interface_web']['presente'])} | "
            f"{len(m['api']['routes']) or '—'} | "
            f"{len(m['cli']) or '—'} | {len(m['systemd']) or '—'} | "
            f"{oui(m['lxc'])} | {m['tests'] or '—'} | "
            f"{oui(m['documentation'])} |")

    l += ["", "## Détail par module", ""]
    for m in modules:
        l.append(f"### `{m['id']}`")
        l.append("")
        l.append(f"{m['description']}")
        l.append("")
        l.append(f"- **Catégorie** : {m['categorie']} · **Tier** : {m['tier']}")
        l.append(f"- **Dépend de** : {', '.join(f'`{d}`' for d in m['depends']) or ABSENT}")
        l.append(f"- **API** : {len(m['api']['routes'])} route(s), "
                 f"socket `{m['api']['socket']}`, "
                 f"authentification {'requise' if m['api']['authentifie'] else ABSENT}")
        l.append(f"- **Interface web** : "
                 f"{'oui, ' + m['interface_web']['chemin'] if m['interface_web']['presente'] else ABSENT}")
        if m["interface_web"]["vhosts"]:
            l.append(f"- **Vhosts livrés** : {', '.join(f'`{v}`' for v in m['interface_web']['vhosts'])}")
        l.append(f"- **CLI** : {', '.join(f'`{c}`' for c in m['cli']) or ABSENT}")
        l.append(f"- **Units systemd** : {', '.join(f'`{u}`' for u in m['systemd']) or ABSENT}")
        l.append(f"- **Ports** : {', '.join(m['ports']) or ABSENT}")
        l.append(f"- **Conteneur LXC** : {'oui' if m['lxc'] else 'non'}")
        l.append(f"- **Tests** : {m['tests'] or ABSENT}")
        l.append(f"- **Documentation existante** : {', '.join(m['documentation']) or ABSENT}")
        l.append(f"- **Source technique** : `packages/{m['id']}/`")
        l.append("")
    SORTIE.mkdir(parents=True, exist_ok=True)
    (SORTIE / "modules.md").write_text("\n".join(l) + "\n")


def main() -> int:
    modules = inventorier()
    if not modules:
        print("aucun module trouvé — mauvais répertoire ?", file=sys.stderr)
        return 1
    ecrire_yaml(modules)
    ecrire_markdown(modules)

    sans_manifeste = [m["id"] for m in modules if not m["manifeste"]]
    sans_doc = [m["id"] for m in modules if not m["documentation"]]
    print(f"  {len(modules)} modules inventoriés")
    print(f"  {len(modules) - len(sans_manifeste)} avec manifeste, "
          f"{len(sans_manifeste)} sans")
    print(f"  {sum(1 for m in modules if m['interface_web']['presente'])} avec interface web")
    print(f"  {sum(1 for m in modules if m['api']['routes'])} avec API")
    print(f"  {sum(1 for m in modules if m['cli'])} avec CLI")
    print(f"  {sum(1 for m in modules if m['lxc'])} en conteneur LXC")
    print(f"  {len(sans_doc)} sans README")
    return 0


if __name__ == "__main__":
    sys.exit(main())
