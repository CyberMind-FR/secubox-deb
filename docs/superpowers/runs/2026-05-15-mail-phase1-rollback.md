<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Mail Phase 1 — Rollback recipe

Backups produced 2026-05-15 07:41 on test board 192.168.1.200 by
`docs/superpowers/plans/2026-05-15-mail-phase1-lxc-consolidation.md` Task 0.

## What's in `/srv/backups/mail-phase1/`

| File | Size | Contents |
|---|---|---|
| `data-volumes-mail-2026-05-15-0741.tar.gz` | 48K | Entire `/data/volumes/mail/` tree — vmail dirs for `secubox.in/{gk2,bat,bourdon,lemurien,ragondin}`, Postfix lookup tables, ACME certs |
| `lxc-mail-config-2026-05-15-0741.tar.gz` | 4.0K | `/data/lxc/mail/config` (the LXC's unprivileged-veth network config) |
| `mail-toml-2026-05-15-0741.bak` | 0.4K | Original `/etc/secubox/mail.toml` (still has legacy keys) |
| `pkglist-2026-05-15-0741.txt` | 0.7K | `dpkg -l` output for `secubox-mail*` + `secubox-webmail*` pre-deploy |

## Rollback procedure

If Phase 1 deploy breaks the mail stack on the board:

```bash
ssh root@192.168.1.200 'set -euo pipefail
  lxc-stop -n mail 2>/dev/null || true

  # Restore /data/volumes/mail (vmail + config + ssl)
  rm -rf /data/volumes/mail
  tar -xzf /srv/backups/mail-phase1/data-volumes-mail-2026-05-15-0741.tar.gz -C /

  # Restore LXC config
  tar -xzf /srv/backups/mail-phase1/lxc-mail-config-2026-05-15-0741.tar.gz -C /

  # Restore toml + downgrade packages
  cp /srv/backups/mail-phase1/mail-toml-2026-05-15-0741.bak /etc/secubox/mail.toml
  apt install --allow-downgrades -y \
    secubox-mail=2.1.0-1~bookworm1 \
    secubox-mail-lxc=1.1.0-1~bookworm1 \
    secubox-webmail=1.0.0-1~bookworm1 \
    secubox-webmail-lxc=1.1.0-1~bookworm1

  systemctl restart secubox-mail nginx haproxy'
```

## Priority guarantees

- The data tarball preserves the 5 live `secubox.in` mailboxes (`gk2`, `bat`,
  `bourdon`, `lemurien`, `ragondin`) and the ACME certs from Feb 2026.
- Per spec rev. 2 invariant **I13**, this data MUST NOT be lost. If anything
  goes wrong, restoring this tarball is the first and most important step.
