# Task 10 — Packaging report

## Status: DONE

The task brief assumed a `debian/*.install` file; the package actually ships
files via `override_dh_auto_install` in `debian/rules`, so that recipe was
extended instead (per the corrected instructions), plus `debian/postinst`
and `debian/changelog`.

## Part 1 — debian/rules

Added, right after the existing `sbin/*` install line inside
`override_dh_auto_install`:

```make
	install -d debian/secubox-metablogizer/etc/sudoers.d
	[ -f debian/secubox-publish-wizard.sudoers ] && install -m 0440 debian/secubox-publish-wizard.sudoers debian/secubox-metablogizer/etc/sudoers.d/secubox-publish-wizard || true
```

Tab-indented, matching the rest of the recipe. This installs the
Task-1-created `debian/secubox-publish-wizard.sudoers` to
`/etc/sudoers.d/secubox-publish-wizard` at mode 0440.

`sbin/secubox-publishctl` itself was already covered by the pre-existing
`install -m 755 sbin/*` line — no duplication added.

## Part 2 — debian/postinst

Inserted before the final `exit 0` (after the existing
daemon-reload/enable/start block):

```bash
# Publisher wizard: the sbxwaf/haproxy/cert steps run through the
# secubox-publishctl root helper, authorized by this sudoers drop-in.
chmod 0755 /usr/sbin/secubox-publishctl 2>/dev/null || true
if [ -f /etc/sudoers.d/secubox-publish-wizard ]; then
  chmod 0440 /etc/sudoers.d/secubox-publish-wizard
  visudo -cf /etc/sudoers.d/secubox-publish-wizard >/dev/null 2>&1 || rm -f /etc/sudoers.d/secubox-publish-wizard
fi
```

This re-asserts perms post-dpkg-unpack and self-heals (removes) a malformed
sudoers drop-in rather than leaving a broken file that would break sudo
host-wide. `postinst` is a plain `set -e` script (no `case "$1" in
configure)` guard) — the block runs unconditionally on install/upgrade,
consistent with the rest of the file.

## Part 3 — debian/changelog

Prepended entry `secubox-metablogizer (1.3.0-1~bookworm1) bookworm;
urgency=medium`, dated `Sat, 11 Jul 2026 13:00:00 +0200`, author
`Gerald KERMA <devel@cybermind.fr>`, bullet text as specified in the task
brief (publisher wizard flow, secubox-publishctl + sudoers, cert handling,
.sbxsite backup, retiring the mitmproxy-LXC route sync, new
`/publish/{wizard,route,export,import}` endpoints). Formatting (2-space
indent before `*`, blank line before ` -- ` sign-off with two spaces before
the name) matches the existing top entry.

## Verify output

```
== bash -n postinst ==
OK
== changelog version ==
1.3.0-1~bookworm1
== tab-indented sudoers lines in rules ==
	install -d debian/secubox-metablogizer/etc/sudoers.d
	[ -f debian/secubox-publish-wizard.sudoers ] && install -m 0440 debian/secubox-publish-wizard.sudoers debian/secubox-metablogizer/etc/sudoers.d/secubox-publish-wizard || true
```

All three checks pass as specified.

## Concerns

- Did not run an actual `dpkg-buildpackage` in this pass (out of scope per
  the task instructions, which only ask for the three listed verify
  commands); the `.install`-vs-`rules` distinction was the main risk and is
  now resolved by following the actual `rules` mechanism.
- Pre-existing unstaged changes to `.superpowers/sdd/task-2-report.md`,
  `task-4-report.md`, `task-8-report.md` were present in the worktree before
  this task started (not touched, not committed as part of this task).
- `visudo` must be present on the target system for the postinst self-heal
  check to run; it ships in the base `sudo` package, which is a safe
  assumption on Debian bookworm SecuBox images.
