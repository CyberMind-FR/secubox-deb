<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Gitea Actions workflows

This directory mirrors `.github/workflows/` for the self-hosted Gitea
Actions runner at `gitea.gk2.secubox.in` (board-internal CI).

## Source of truth

`.github/workflows/*.yml` is the source of truth — workflows are edited
there and mirrored here. The two trees should stay byte-identical;
divergence is a bug.

Eventual goal: a single CI definition tree consumed by both runners.
For now, the mirror is mechanical (cp) and tracked in PRs that touch
both directories together.

## Compatibility notes

- `runs-on: ubuntu-latest` works because the `act_runner` registered on
  the dev box advertises the `ubuntu-latest` label (Phase B of the
  migration, separate ticket).
- `uses: actions/*` references are auto-fetched from `github.com` thanks
  to `DEFAULT_ACTIONS_URL = github` in
  `/var/lib/gitea/custom/conf/app.ini` (set during Phase A1).
- Secrets are NOT carried by repo mirroring — re-add in
  Gitea Settings → Actions → Secrets per repo:
  `GPG_PRIVATE_KEY`, `DEPLOY_SSH_KEY`, `DEPLOY_KNOWN_HOSTS`, etc.
- Some workflows use `gh` (GitHub CLI) which is not installed by default
  on `act_runner`. Those jobs will fail visibly until they are migrated
  to `tea` (Gitea CLI) — to be addressed per-workflow.

## Refs

- Phase A1: Gitea Actions enabled in app.ini (done 2026-05-17)
- Phase A2: pull mirror github → gitea — blocked on
  [#176](https://github.com/CyberMind-FR/secubox-deb/issues/176)
  (missing `giteactl repo mirror` verb)
- Phase A3: this directory ([#177](https://github.com/CyberMind-FR/secubox-deb/issues/177))
- Phase B: install + register `act_runner` (separate ticket TBD)
