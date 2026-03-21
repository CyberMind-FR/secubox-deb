#!/usr/bin/env python3
"""
scripts/rewrite-xhr.py — Réécriture automatique des appels ubus/RPCD → REST FastAPI
=====================================================================================
Transforme les appels LuCI RPC des fichiers JS :

  AVANT (LuCI ubus):
    var callDecisions = rpc.declare({
        object: 'luci.crowdsec-dashboard',
        method: 'decisions',
        expect: { decisions: [] }
    });
    return callDecisions().then(...);

  APRÈS (fetch REST):
    async function callDecisions(params) {
        return sbxFetch('/api/v1/crowdsec/decisions', params);
    }
    return callDecisions().then(...);

Usage :
    python3 scripts/rewrite-xhr.py --module crowdsec packages/secubox-crowdsec/www/
    python3 scripts/rewrite-xhr.py --module crowdsec --dry-run packages/secubox-crowdsec/www/
    python3 scripts/rewrite-xhr.py --all   # tous les modules
"""
from __future__ import annotations
import argparse
import re
import sys
from pathlib import Path

# ── Préfixes luci.X → /api/v1/X ──────────────────────────────────
MODULE_MAP = {
    "luci.secubox":             "hub",
    "luci.crowdsec-dashboard":  "crowdsec",
    "luci.netdata-dashboard":   "netdata",
    "luci.wireguard-dashboard": "wireguard",
    "luci.network-modes":       "netmodes",
    "luci.client-guardian":     "nac",
    "luci.auth-guardian":       "auth",
    "luci.bandwidth-manager":   "qos",
    "luci.media-flow":          "mediaflow",
    "luci.cdn-cache":           "cdn",
    "luci.vhost-manager":       "vhost",
    "luci.system-hub":          "system",
    "luci.netifyd-dashboard":   "dpi",
}

# ── Header injecté en haut de chaque fichier JS modifié ──────────
SBX_HEADER = """\
/* SecuBox-DEB: appels REST (généré par rewrite-xhr.py — ne pas éditer) */
if (typeof sbxFetch === 'undefined') {
    window.sbxFetch = async function(endpoint, params, method) {
        method = method || 'GET';
        const token = localStorage.getItem('sbx_token') || '';
        const opts = {
            method: method,
            headers: {
                'Content-Type': 'application/json',
                'Authorization': 'Bearer ' + token
            }
        };
        if (params && method === 'POST') opts.body = JSON.stringify(params);
        const url = method === 'GET' && params
            ? endpoint + '?' + new URLSearchParams(params).toString()
            : endpoint;
        const r = await fetch(url, opts);
        if (!r.ok) { const e = await r.json().catch(() => ({})); throw e; }
        return r.json();
    };
}
"""


def _find_balanced_brace(src: str, start: int) -> int:
    """Trouve l'index de la } fermante correspondante, gère les imbrications."""
    depth = 0
    i = start
    while i < len(src):
        if src[i] == '{':
            depth += 1
        elif src[i] == '}':
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return -1


def find_rpc_declares(src: str) -> list[dict]:
    """
    Trouve tous les blocs rpc.declare({...}) et extrait object+method.
    Retourne une liste de dicts : {var_name, object, method, full_block}.
    Gère les accolades imbriquées (ex: expect: { }).
    """
    # Pattern pour trouver le début : var|const|let <name> = rpc.declare({
    pat_start = re.compile(
        r'(?:var|const|let)\s+(\w+)\s*=\s*rpc\.declare\s*\(\s*\{',
        re.DOTALL
    )
    results = []

    for m in pat_start.finditer(src):
        var_name = m.group(1)
        brace_start = m.end() - 1  # Position de la {

        # Trouver la } fermante correspondante
        brace_end = _find_balanced_brace(src, brace_start)
        if brace_end == -1:
            continue

        # Trouver la fin complète : });
        rest = src[brace_end:]
        end_match = re.match(r'\}\s*\)\s*;', rest)
        if not end_match:
            continue

        full_end = brace_end + end_match.end()
        full_block = src[m.start():full_end]
        inner = src[brace_start + 1:brace_end]

        obj_m = re.search(r"object\s*:\s*['\"]([^'\"]+)['\"]", inner)
        mth_m = re.search(r"method\s*:\s*['\"]([^'\"]+)['\"]", inner)

        if obj_m and mth_m:
            results.append({
                "var_name":   var_name,
                "object":     obj_m.group(1),
                "method":     mth_m.group(1),
                "full_block": full_block,
            })
    return results


def rewrite_file(path: Path, dry_run: bool = False) -> int:
    """
    Réécrit un fichier JS. Retourne le nombre de remplacements effectués.
    """
    src = path.read_text(encoding="utf-8")
    declares = find_rpc_declares(src)
    if not declares:
        return 0

    modified = src
    count = 0
    header_needed = False

    for d in declares:
        obj    = d["object"]
        method = d["method"]
        vname  = d["var_name"]

        # Trouver le module API
        api_module = MODULE_MAP.get(obj)
        if not api_module:
            # Essai par préfixe
            for prefix, mod in MODULE_MAP.items():
                if obj.startswith(prefix.split(".")[0] + "."):
                    api_module = mod
                    break
        if not api_module:
            print(f"  ⚠  {path.name}: objet inconnu '{obj}' — skip", file=sys.stderr)
            continue

        endpoint = f"/api/v1/{api_module}/{method}"

        # Détecter si c'est une action (POST) ou une lecture (GET)
        http_method = "POST" if any(
            method.startswith(p) for p in
            ("set_", "apply", "ban", "unban", "add_", "remove_", "delete_",
             "create_", "enable_", "disable_", "restart_", "stop_", "start_",
             "rollback", "confirm", "purge", "generate_")
        ) else "GET"

        replacement = (
            f"async function {vname}(params) {{\n"
            f"    return sbxFetch('{endpoint}', params, '{http_method}');\n"
            f"}}"
        )

        modified = modified.replace(d["full_block"], replacement, 1)
        header_needed = True
        count += 1
        print(f"  ✓  {path.name}: {vname} → {http_method} {endpoint}")

    # Supprimer les imports LuCI inutiles devenus obsolètes
    if header_needed:
        modified = re.sub(r"'require rpc';\s*\n?", "", modified)
        modified = re.sub(r"'require baseclass';\s*\n?", "", modified)

        # Injecter le header sbxFetch si pas déjà présent
        if "sbxFetch" not in modified:
            modified = SBX_HEADER + "\n" + modified

    if not dry_run and count > 0:
        path.write_text(modified, encoding="utf-8")

    return count


def process_directory(www_dir: Path, dry_run: bool = False) -> None:
    js_files = list(www_dir.rglob("*.js"))
    if not js_files:
        print(f"⚠  Aucun fichier .js dans {www_dir}")
        return

    total = 0
    for f in sorted(js_files):
        n = rewrite_file(f, dry_run=dry_run)
        total += n

    mode = "[DRY-RUN] " if dry_run else ""
    print(f"\n{mode}✅ {total} appels rpc.declare réécrits dans {www_dir}")


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("www_dir", nargs="?", type=Path,
                   help="Répertoire www/ du module à réécrire")
    p.add_argument("--module", metavar="NAME",
                   help="Nom du module (crowdsec, wireguard, …) pour auto-chercher dans packages/")
    p.add_argument("--all",    action="store_true",
                   help="Réécrire tous les modules dans packages/*/www/")
    p.add_argument("--dry-run", action="store_true",
                   help="Afficher les changements sans modifier les fichiers")
    args = p.parse_args()

    repo_root = Path(__file__).parent.parent

    if args.all:
        for d in sorted((repo_root / "packages").glob("*/www")):
            print(f"\n── {d.parent.name} ──")
            process_directory(d, dry_run=args.dry_run)

    elif args.module:
        d = repo_root / "packages" / f"secubox-{args.module}" / "www"
        if not d.exists():
            print(f"❌ Répertoire introuvable : {d}")
            sys.exit(1)
        process_directory(d, dry_run=args.dry_run)

    elif args.www_dir:
        if not args.www_dir.exists():
            print(f"❌ Répertoire introuvable : {args.www_dir}")
            sys.exit(1)
        process_directory(args.www_dir, dry_run=args.dry_run)

    else:
        p.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
