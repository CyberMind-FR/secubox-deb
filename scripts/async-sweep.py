#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""SecuBox-Deb :: async-sweep codemod (#738)

Convert blocking FastAPI route handlers declared `async def` but containing NO
`await` into plain `def`. Mounted in the aggregator's single event loop, an
`async def` handler that calls blocking code (subprocess, openssl, argon2,
requests…) freezes the whole loop. A `def` handler is run by Starlette in the
AnyIO threadpool instead, so the blocking call no longer stalls the gateway.

Safety rules — a handler is converted ONLY when ALL hold:
  * decorated with an HTTP verb (router/app .get/.post/.put/.delete/.patch/
    .options/.head/.trace) — NOT .websocket
  * its own body has no `await`, `async with`, `async for`, `yield`
    (genuinely-async or streaming handlers are left untouched)
  * its name is never used as a coroutine elsewhere in the file
    (`await name(`, `create_task(name`, `gather(name`, `ensure_future(name`)

Only the leading `async ` token on the `def` line is removed; formatting is
otherwise preserved. Every rewritten file is re-parsed + py_compile'd.

Usage:
  async-sweep.py --check  PATH...     # report only, no writes
  async-sweep.py --apply  PATH...     # rewrite in place
"""
from __future__ import annotations

import argparse
import ast
import py_compile
import sys
import tempfile
from pathlib import Path

HTTP_VERBS = {"get", "post", "put", "delete", "patch", "options", "head", "trace"}

# Attribute calls that block the event loop when run inline (sync I/O / CPU).
_BLOCK_ATTR = {
    "run", "call", "check_call", "check_output", "Popen",          # subprocess.*
    "communicate", "wait",                                          # Popen.*
    "system", "popen",                                             # os.*
    "sleep",                                                        # time.sleep
    "urlopen",                                                      # urllib
    "check_password", "verify_password", "verify", "hash",         # argon2 / auth
}
# Bare/standalone names whose call blocks (sync HTTP clients, etc.).
_BLOCK_FUNC_HINT = {"verify_password", "check_password"}
# Module roots whose sync methods block (requests.get, httpx.get, openssl via subprocess…).
_BLOCK_MODULE = {"requests", "subprocess", "socket"}


class _BlockingFinder(ast.NodeVisitor):
    """True if the direct body issues a known blocking call (excludes nested
    function bodies)."""

    def __init__(self) -> None:
        self.found = False

    def _stop(self, _node):
        return

    visit_FunctionDef = _stop
    visit_AsyncFunctionDef = _stop
    visit_Lambda = _stop

    def visit_Call(self, node):
        fn = node.func
        if isinstance(fn, ast.Attribute):
            if fn.attr in _BLOCK_ATTR:
                self.found = True
            root = fn.value
            if isinstance(root, ast.Name) and root.id in _BLOCK_MODULE:
                self.found = True
        elif isinstance(fn, ast.Name) and fn.id in _BLOCK_FUNC_HINT:
            self.found = True
        self.generic_visit(node)


def _body_blocks(node: ast.AsyncFunctionDef) -> bool:
    f = _BlockingFinder()
    for stmt in node.body:
        f.visit(stmt)
        if f.found:
            return True
    return False


def _decorator_verbs(node: ast.AsyncFunctionDef) -> set[str]:
    verbs = set()
    for dec in node.decorator_list:
        call = dec.func if isinstance(dec, ast.Call) else dec
        if isinstance(call, ast.Attribute):
            verbs.add(call.attr)
    return verbs


class _AwaitFinder(ast.NodeVisitor):
    """True if the *direct* body uses await/async-context/yield — i.e. excludes
    awaits that belong to nested (async) functions defined inside."""

    def __init__(self) -> None:
        self.found = False

    def _stop(self, _node):  # don't descend into nested function bodies
        return

    visit_FunctionDef = _stop
    visit_AsyncFunctionDef = _stop
    visit_Lambda = _stop

    def visit_Await(self, node):
        self.found = True

    def visit_AsyncWith(self, node):
        self.found = True

    def visit_AsyncFor(self, node):
        self.found = True

    def visit_Yield(self, node):
        self.found = True

    def visit_YieldFrom(self, node):
        self.found = True


def _body_has_await(node: ast.AsyncFunctionDef) -> bool:
    f = _AwaitFinder()
    for stmt in node.body:
        f.visit(stmt)
        if f.found:
            return True
    return False


def _coroutine_referenced_names(tree: ast.Module) -> set[str]:
    """Names used as coroutines: awaited, or passed to create_task/gather/
    ensure_future. Such functions MUST stay async."""
    names: set[str] = set()
    for n in ast.walk(tree):
        if isinstance(n, ast.Await):
            tgt = n.value
            if isinstance(tgt, ast.Call):
                fn = tgt.func
                if isinstance(fn, ast.Name):
                    names.add(fn.id)
                elif isinstance(fn, ast.Attribute):
                    names.add(fn.attr)
        elif isinstance(n, ast.Call):
            fn = n.func
            sched = isinstance(fn, ast.Attribute) and fn.attr in {
                "create_task", "ensure_future", "gather",
            }
            if sched:
                for a in n.args:
                    if isinstance(a, ast.Name):
                        names.add(a.id)
                    elif isinstance(a, ast.Call) and isinstance(a.func, ast.Name):
                        names.add(a.func.id)
    return names


def analyze(path: Path):
    """Return (conversions, skips). conversions = list of (lineno, col, name)."""
    src = path.read_text(encoding="utf-8")
    try:
        tree = ast.parse(src)
    except SyntaxError as e:
        return None, [("<parse>", f"SyntaxError: {e}")]

    coro_names = _coroutine_referenced_names(tree)
    conversions, skips = [], []

    for node in ast.walk(tree):
        if not isinstance(node, ast.AsyncFunctionDef):
            continue
        verbs = _decorator_verbs(node)
        if not (verbs & HTTP_VERBS):
            continue  # not an HTTP route handler
        if "websocket" in verbs:
            skips.append((node.name, "websocket"))
            continue
        if _body_has_await(node):
            skips.append((node.name, "await/stream"))
            continue
        if node.name in coro_names:
            skips.append((node.name, "referenced-as-coroutine"))
            continue
        if not _body_blocks(node):
            skips.append((node.name, "no-blocking-call"))
            continue
        conversions.append((node.lineno, node.col_offset, node.name))

    return conversions, skips


def apply_file(path: Path) -> tuple[int, list]:
    conversions, skips = analyze(path)
    if conversions is None:
        return 0, skips
    if not conversions:
        return 0, skips

    lines = path.read_text(encoding="utf-8").splitlines(keepends=True)
    for lineno, col, name in conversions:
        line = lines[lineno - 1]
        if line[col:col + 6] != "async ":
            raise RuntimeError(f"{path}:{lineno}: expected 'async ' at col {col}, got {line[col:col+10]!r}")
        lines[lineno - 1] = line[:col] + line[col + 6:]

    new_src = "".join(lines)
    # validate: must parse + compile
    ast.parse(new_src)
    with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as tf:
        tf.write(new_src)
        tmp = tf.name
    try:
        py_compile.compile(tmp, doraise=True)
    finally:
        Path(tmp).unlink(missing_ok=True)

    path.write_text(new_src, encoding="utf-8")
    return len(conversions), skips


def main() -> int:
    ap = argparse.ArgumentParser()
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--check", action="store_true")
    g.add_argument("--apply", action="store_true")
    ap.add_argument("paths", nargs="+", type=Path)
    args = ap.parse_args()

    files: list[Path] = []
    for p in args.paths:
        if p.is_dir():
            files.extend(sorted(p.rglob("api/main.py")))
        else:
            files.append(p)

    total_conv = total_files = 0
    for f in files:
        if args.check:
            conv, skips = analyze(f)
            if conv is None:
                print(f"  PARSE-FAIL {f}: {skips}")
                continue
            if conv:
                total_conv += len(conv)
                total_files += 1
                print(f"  {f.relative_to(Path.cwd()) if f.is_absolute() else f}: {len(conv)} handlers → def")
        else:
            n, skips = apply_file(f)
            if n:
                total_conv += n
                total_files += 1
                print(f"  {f}: {n} converted")
    print(f"\n{'CHECK' if args.check else 'APPLY'}: {total_conv} handlers across {total_files} files")
    return 0


if __name__ == "__main__":
    sys.exit(main())
