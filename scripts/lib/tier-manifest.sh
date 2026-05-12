# scripts/lib/tier-manifest.sh
# Resolve a tier name to a flat JSON array of package names.
# Usage (after sourcing): tier_manifest <tier> <out.json>
# Tiers: base | tier-lite | tier-standard | tier-pro
#
# Note: secubox gen emits manifest.yaml (YAML, not JSON).
# Package list lives at the top-level .packages[] key.

_secubox_bin() {
  local bin
  bin="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/cmd/secubox/secubox"
  if [[ -x "$bin" ]]; then echo "$bin"; return 0; fi
  if command -v secubox >/dev/null 2>&1; then command -v secubox; return 0; fi
  echo "ERROR: secubox binary not found" >&2
  return 1
}

tier_manifest() {
  local tier="$1" out="$2"

  if [[ -z "$tier" || -z "$out" ]]; then
    echo "Usage: tier_manifest <tier> <out.json>" >&2
    return 2
  fi

  if [[ "$tier" == "base" ]]; then
    printf '["secubox-core","secubox-hub"]\n' > "$out"
    return 0
  fi

  local sb; sb="$(_secubox_bin)" || return 1
  local tmpdir; tmpdir="$(mktemp -d)"

  if ! "$sb" gen --tier "$tier" --board mochabin --out "$tmpdir" >/dev/null 2>&1; then
    echo "ERROR: secubox gen --tier $tier failed" >&2
    rm -rf "$tmpdir"
    return 1
  fi

  # secubox gen emits manifest.yaml (YAML format, not JSON)
  local mf
  mf="$(find "$tmpdir" -maxdepth 2 -name 'manifest.yaml' -type f | head -1)"

  if [[ ! -f "$mf" ]]; then
    echo "ERROR: secubox gen produced no manifest.yaml in $tmpdir" >&2
    find "$tmpdir" -type f >&2
    rm -rf "$tmpdir"
    return 1
  fi

  # Parse YAML with python3/pyyaml; extract .packages[] as a unique JSON array.
  python3 - "$mf" "$out" <<'PYEOF'
import sys, json, yaml

manifest_path = sys.argv[1]
out_path = sys.argv[2]

with open(manifest_path, "r") as f:
    doc = yaml.safe_load(f)

packages = doc.get("packages", [])
if not isinstance(packages, list):
    print(f"ERROR: .packages is not a list in {manifest_path}", file=sys.stderr)
    sys.exit(1)

# Deduplicate while preserving order
seen = set()
unique = []
for p in packages:
    if p not in seen:
        seen.add(p)
        unique.append(p)

with open(out_path, "w") as f:
    json.dump(unique, f)
    f.write("\n")
PYEOF

  rm -rf "$tmpdir"
}
