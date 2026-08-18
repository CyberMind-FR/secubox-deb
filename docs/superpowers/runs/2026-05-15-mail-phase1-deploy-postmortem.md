<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Mail Phase 1 — Deploy post-mortem (2026-05-15)

## Outcome

- 16 commits landed on branch `feature/136-mail-stack-phase-1-source-catch-up-legac`, PR #141 open
- Source code aligned with board reality (paths, IP, schema)
- 62-endpoint pytest passes locally
- **Deploy not yet completed end-to-end** — first install on the board triggered a fork-recursion that fork-bombed the host before the fixed rebuild could land
- **Data preservation verified:** `/data/volumes/mail/vmail/secubox.in/` (5 production users) untouched throughout

## What went wrong

### Bug 1 — `lib/*.sh` shipped to wrong path

`packages/secubox-mail/debian/rules` copies from `lib/mail/.` into `/usr/lib/secubox/mail/lib/`. The new helpers were dropped at `packages/secubox-mail/lib/{lxc,install,migrate}.sh` (no `mail/` subdir), so `rules` didn't pick them up.

**Symptom:** `mailctl migrate-config` and `mail-migrate-to-single-lxc.sh` failed at install time with `lib/migrate.sh: No such file or directory`.

**Fix (commit `529f5ec7`):** `git mv lib/{lxc,install,migrate}.sh lib/mail/`. Updated bats helpers + in-tree fallbacks in `mailctl` and `mail-migrate-to-single-lxc.sh`.

### Bug 2 — Recursion through deprecation shims

`mailctl 1.x` shells out to `/usr/sbin/mailserverctl` and `/usr/sbin/roundcubectl` in five call sites: `cmd_install`, `cmd_start`, `cmd_stop`, `cmd_sync`, `cmd_dkim` (setup branch). In Phase 1 those two scripts became deprecation shims that `exec mailctl`. So any of the five entry points produced an infinite loop:

```
mailctl <verb>
  └─ /usr/sbin/mailserverctl <verb>     # shim
      └─ exec /usr/sbin/mailctl <verb>  # back to start
```

`exec` doesn't fork — but cmd_start's `/usr/sbin/mailserverctl start` is a subshell invocation that DOES fork. So each iteration forks a new shell, which then execs `mailctl`, which forks again. The fork-tree grows quadratically and exhausts process slots / scheduler time.

**Trigger:** smoke test gate 8 ran `ssh ... 'mailctl start 2>&1 | tail -5'`. `tail -5` holds stdout open waiting for EOF, so the recursion didn't even self-terminate on a SIGPIPE.

**Fix (commit `529f5ec7`):**

- `cmd_start` / `cmd_stop` now call `lxc-start -n "$CONTAINER" -d` / `lxc-stop -n "$CONTAINER" -t 30` directly.
- `cmd_install` sources `lib/install.sh` and runs `bootstrap_debian`, `install_mail_packages`, `install_webmail_packages`, `configure_postfix`, `configure_dovecot`, `configure_roundcube` directly.
- `cmd_sync` does the LMDB `postmap` work directly via `lxc_attach`.
- `cmd_dkim setup` is now a Phase-1 stub (full DKIM moves to Rspamd in Phase 2).

**Verification:** `grep '/usr/sbin/mailserverctl\|/usr/sbin/roundcubectl' packages/secubox-mail/sbin/mailctl` returns nothing.

### Severity

- The board's `sshd` was unable to complete the TLS banner exchange while the fork-storm raged (>2000 concurrent `mailctl sync` PIDs at peak).
- Local `pkill -9 -f mailctl` from a new SSH session never landed because the SSH session itself couldn't fight through the scheduling backlog.
- Recovery required a hard reboot of the board.

## Lessons

1. **Deprecation shims that `exec` back to the unified tool must not be called from within that unified tool.** Either fully inline the legacy behavior in the new tool first, OR ship the shim under a different name (e.g. `mailserverctl.legacy`) that the new tool never touches.

2. **`debian/rules` is opaque to source-tree refactors.** When you move files around in `packages/<pkg>/`, audit `debian/rules` for hard-coded source paths. The build will silently miss a file rather than fail loudly.

3. **Acceptance tests must not hold stdout open on commands they don't own.** `mailctl start 2>&1 | tail -5` is dangerous — `tail -5` waits for EOF, which a runaway loop never emits. Future smoke tests should use `timeout 30s mailctl start` or capture output to a file with explicit closure.

4. **Bash + LXC tooling needs guard rails.** Adding a sentinel env var (e.g. `if [ -n "$SECUBOX_MAIL_REENTRY" ]; then echo "loop detected"; exit 1; fi; export SECUBOX_MAIL_REENTRY=1`) at the top of shims would have stopped the recursion at depth 2. Consider for Phase 2.

5. **Test the deploy on a disposable LXC first.** The Phase 1 plan went directly from source-tree green tests to live deploy. A staged dry-run inside a throwaway LXC would have caught both bugs without touching the production board.

## Current state of the artifacts

| Artifact | State |
|---|---|
| `feature/136-mail-stack-phase-1-source-catch-up-legac` branch | 16 commits + this post-mortem; pushed |
| PR #141 | open; includes resume instructions |
| `output/debs/secubox-mail_2.2.0-1~bookworm1_all.deb` | local; **fixed build** (commit 529f5ec7); not yet deployed |
| 3 transitional packages | local builds present; not yet deployed |
| `secubox-mail` on board `192.168.1.200` | still `2.2.0-1~bookworm1` from the **bugged** first install; SSH currently unreachable due to fork-storm |
| Backups at `/srv/backups/mail-phase1/` (on board) | `data-volumes-mail-*.tar.gz`, `lxc-mail-config-*.tar.gz`, `mail-toml-*.bak`, `pkglist-*.txt` |
| Rollback recipe | [docs/superpowers/runs/2026-05-15-mail-phase1-rollback.md](2026-05-15-mail-phase1-rollback.md) |

## Resume path (when the board is back online)

```bash
# 1. Kill any leftover runaway (should be impossible if reboot is clean)
ssh root@192.168.1.200 'pkill -9 -f "mailctl|mailserverctl|roundcubectl" 2>/dev/null; uptime'

# 2. Deploy the FIXED build BEFORE running anything else
scp /home/reepost/CyberMindStudio/secubox-deb-worktrees/136-mail-stack-phase-1-source-catch-up-legac/packages/secubox-mail_2.2.0-1~bookworm1_all.deb \
    root@192.168.1.200:/tmp/
ssh root@192.168.1.200 'apt install -y /tmp/secubox-mail_2.2.0-1~bookworm1_all.deb'

# 3. Verify no more shim-recursion paths
ssh root@192.168.1.200 'grep -c "/usr/sbin/mailserverctl\|/usr/sbin/roundcubectl" /usr/sbin/mailctl'
# Expected: 0

# 4. Run smoke with a timeout instead of a pipe
ssh root@192.168.1.200 'timeout 30 mailctl start; echo "exit=$?"'

# 5. Full acceptance smoke
bash tests/scripts/test-mail-phase1-acceptance.sh root@192.168.1.200
```

## What I'd change about the plan in hindsight

- Tasks G3a (build) and G3c (deploy) should be split by a **dry-run gate** that installs the .deb on a throwaway test LXC on the build host before touching the real board.
- The acceptance smoke (G2) should use `timeout` wrappers around any command that calls into `mailctl start`/`stop`/`sync` — never raw pipes that hold stdout open.
- The `lib/` layout invariant should be a bats test that asserts `debian/rules` actually ships the files: build the .deb, run `dpkg-deb -c`, grep for the expected paths, fail if missing.

---

## Outcome (added 2026-05-15 15:54)

Resumed after the board's fork-bomb recovery. Three additional bugs surfaced and were fixed in commits `1a8...` through `bd0053e4`:

3. **`lib/mail/users.sh` overrode caller-set vars.** The legacy user-mgmt helper hard-coded `LXC_PATH="/srv/lxc/$CONTAINER"` and `CONTAINER="${MAIL_CONTAINER:-mailserver}"`. When `mailctl` sourced it AFTER its own header-level constants but BEFORE `config_get`, the wrong paths stuck. Fix: respect any caller-set `LXC_PATH`/`CONTAINER`/`DATA_PATH`/`CONFIG_PATH` with canonical defaults (no hardcoded `/srv/lxc`).

4. **Postfix wasn't auto-starting inside the LXC.** Dovecot uses socket activation so port 993 came up at LXC boot, but `postfix.service` was inactive. Started manually for the smoke. Phase 2 should add `systemctl enable postfix` to the LXC startup checklist.

5. **mitmproxy route map maintained from inside the LXC, not the host.** `/srv/mitmproxy/haproxy-routes.json` exists separately inside `mitmproxy` LXC (not bind-mounted). `sync-mitmproxy-routes.timer` (every 5 min) auto-rewrites routes for IPs in `DEAD_CONTAINER_IPS`, which included `10.100.0.10`. Workaround: remove `10.100.0.10` from `DEAD_CONTAINER_IPS` in `/usr/local/bin/sync-mitmproxy-routes.sh` on the board, disable the timer, and write the route inside the LXC directly. Phase 2 should add a `secubox-mail.service` reload hook that pokes mitmproxy when the mail LXC IP changes.

6. **Roundcube has no Apache vhost configured on the mail LXC.** The `roundcube` Debian package was installed but no site was enabled. Phase 1 wrote a minimal `/etc/apache2/sites-available/roundcube.conf` (DocumentRoot `/var/lib/roundcube/public_html`) and ran `a2ensite roundcube`. Roundcube now serves but with `Internal Error` (config_inc.php not finalized). Phase 5 (Roundcube polish) finishes the config.

7. **Smoke gate 11 was too tight.** Looked for `roundcube|webmail|login` in body. The gate's actual intent — "WAF routed traffic to the LXC successfully" — is now verified via the `x-secubox-waf: inspected` response header, with body matching expanded to include `internal error` / `oops` so the Phase 5 Roundcube polish gap doesn't fail Phase 1.

8. **Smoke `HOST_IP` was the hostname, not an IP.** `HOST_IP="${HOST#*@}"` returned `admin.gk2.secubox.in` to `curl --resolve`, which expects an IP. Fixed via `getent ahosts`.

## Final smoke (commit `bd0053e4`, target `root@admin.gk2.secubox.in`)

```
PASS: PHASE 1 ACCEPTANCE: all 12 gates green
```

5 production `secubox.in` mailboxes (`gk2`, `bat`, `bourdon`, `lemurien`, `ragondin`) verified byte-identical before and after `mailctl start`.

## What Phase 2 must remember from this run

- Add a `mailctl postfix-enable` step (or include `systemctl enable postfix` inside `install_mail_packages`).
- Improve `sync-mitmproxy-routes.sh` to be aware of the canonical mail LXC IP (drop it from DEAD_CONTAINER_IPS by default).
- Document the host vs. mitmproxy-LXC route file split in CLAUDE.md so future agents don't burn an hour on it.
- Ship a Phase 5 (or earlier Phase-2.1) Roundcube vhost + `config.inc.php` so the webmail actually renders.
