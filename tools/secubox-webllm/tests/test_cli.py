# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""
SecuBox-Deb :: tests.test_cli — parsing d'arguments et résolution du prompt.
Ne lance jamais de session réelle (pas d'appel à `main()` en bout de course).
"""

from __future__ import annotations

import io

import pytest

from webllm.cli import _build_config, _read_prompt, build_parser


def test_backend_choices_include_all_shipped_backends():
    parser = build_parser()
    backend_action = next(a for a in parser._actions if a.dest == "backend")
    assert set(backend_action.choices) >= {"claude", "gpt", "gemini"}


def test_backend_defaults_to_claude():
    args = build_parser().parse_args([])
    assert args.backend == "claude"


def test_unknown_backend_rejected_by_argparse():
    with pytest.raises(SystemExit):
        build_parser().parse_args(["--backend", "does-not-exist", "hi"])


def test_prompt_from_positional_arguments_is_joined():
    args = build_parser().parse_args(["bonjour", "le", "monde"])
    assert _read_prompt(args) == "bonjour le monde"


def test_prompt_falls_back_to_stdin_when_no_positional_argument(monkeypatch):
    args = build_parser().parse_args([])
    monkeypatch.setattr("sys.stdin", io.StringIO("prompt depuis stdin\n"))
    assert _read_prompt(args) == "prompt depuis stdin\n"


def test_empty_prompt_and_blank_stdin_exits_explicitly(monkeypatch):
    args = build_parser().parse_args([])
    monkeypatch.setattr("sys.stdin", io.StringIO("   \n"))
    with pytest.raises(SystemExit):
        _read_prompt(args)


def test_headless_flag_propagates_into_config():
    args = build_parser().parse_args(["--headless", "hi"])
    config = _build_config(args)
    assert config.headless is True


def test_timeout_seconds_converted_to_milliseconds():
    args = build_parser().parse_args(["--timeout", "42", "hi"])
    config = _build_config(args)
    assert config.answer_timeout_ms == 42_000


def test_profile_override_replaces_default_root(tmp_path):
    args = build_parser().parse_args(["--profile", str(tmp_path), "hi"])
    config = _build_config(args)
    assert config.profile_root == tmp_path
