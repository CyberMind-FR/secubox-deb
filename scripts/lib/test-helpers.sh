# scripts/lib/test-helpers.sh
# Sourced by test scripts. No external deps.

assert_eq() {
  local expected="$1" actual="$2" msg="${3:-}"
  if [[ "$expected" != "$actual" ]]; then
    echo "FAIL: ${msg}"
    echo "  expected: $expected"
    echo "  actual:   $actual"
    return 1
  fi
}

assert_contains() {
  local haystack="$1" needle="$2" msg="${3:-}"
  if [[ "$haystack" != *"$needle"* ]]; then
    echo "FAIL: ${msg}"
    echo "  haystack: $haystack"
    echo "  needle:   $needle"
    return 1
  fi
}

assert_file() {
  local path="$1" msg="${2:-file missing}"
  if [[ ! -f "$path" ]]; then
    echo "FAIL: ${msg}: $path"
    return 1
  fi
}

pass() { echo "PASS: $*"; }
