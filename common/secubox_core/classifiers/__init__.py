# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Shared classifiers used by mitm-ingest enrich_hooks across modules.

  - host_app   : host/SNI → app + category + emoji
  - cookie     : cookie name → provider + category + emoji
  - avatar     : UA → device + browser + os + emoji
  - ja4        : TLS ClientHello fingerprint hash
"""
from . import host_app, cookie, avatar, ja4  # noqa: F401
