<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# SecuBox Auth Rework — `secubox-users` as Identity Source + TOTP 2FA

**Status:** Design approved 2026-05-13 · Issue [#120](https://github.com/CyberMind-FR/secubox-deb/issues/120)
**Author:** Gérald Kerma (Gandalf) · brainstormed with Claude
**Target:** SecuBox-DEB on MOCHAbin (`gk2`), CSPN-grade posture

---

## 1. Problem

The Hub admin login at `https://admin.<board>.secubox.in/` authenticates against `/etc/secubox/auth.toml`:

```toml
[users.admin]
password = "secubox"
```

`secubox_core.auth._check_password()` does a literal string compare against this plain-text value. The same board ships `secubox-users` (v1.3.0) — a full RBAC user-management package with a web UI at `/users/`, a CLI (`usersctl`), and `/etc/secubox/users.json` — but **none of it is wired into the actual login path**. The result:

- The real admin password is a six-character word in a plaintext file.
- `users.json` is mid-migration: a legacy top-level `admin` key with a SHA-256 hash co-exists with a v2 `users[]` array that has the right schema but no password fields.
- Disabling a user via the `/users/` UI has no effect — the user can still log in.
- No second factor.
- `usersctl` mutates `users.json` directly with `jq`, drifting from the API.

The goal of this rework is to make `secubox-users` the authoritative identity source for login, replace `auth.toml` with an emergency-only fallback, force argon2id + TOTP for admins, and unify CLI/API behind a single Python engine.

## 2. Goals & non-goals

### Goals

1. **One identity store.** `users.json` (v2 schema) is the source of truth. `auth.toml` `[users.*]` becomes a logged-warning fallback consulted only when `users.json` is missing or unreadable.
2. **Two seed users at install time.** `secubox-users` postinst provisions `admin` and `<hostname>` (e.g., `gk2`) with `role=admin`, `enabled=true`, `must_change_password=true`, no usable hash. First-login flow forces a strong password set, then TOTP enrollment.
3. **argon2id** for password hashes (ANSSI-aligned, future-proof against GPU attacks).
4. **TOTP (RFC 6238) second factor** via any authenticator app (Google Authenticator, Aegis, Authy, …). Mandatory for `role=admin`, optional for others. Backup codes shown once at enrollment, single-use, argon2id-hashed at rest.
5. **Kill-on-disable.** Disabling a user atomically flips `enabled=false` AND removes every session of theirs from `sessions.json`. The next request from a stale JWT gets `401 session revoked`. Re-enabling restores the account but does NOT resurrect old sessions.
6. **Active-sessions log.** Already partially wired (`set_session_callback`); we extend it to record `login_success`, `login_failed`, `mfa_*`, `totp_*`, `password_set`, `user_disabled`, `sessions_revoked` into `sessions.json` (live state) + new `/var/lib/secubox/auth/audit.log` (append-only JSONL, immutable per CSPN baseline).
7. **CLI ≡ API parity.** Every mutation flows through a single `secubox_users.engine` module. `usersctl` is rewritten in Python as a thin wrapper. A CI parity test diffs the file states produced by equivalent CLI and API calls.

### Non-goals (deferred)

- **"Sign in with Google" OIDC.** Considered during brainstorming, dropped in favor of authenticator-app TOTP per user direction. The schema leaves room (`google: null`) to add later without a v3 bump.
- **Encryption-at-rest for TOTP secrets.** Same trust boundary as `password_hash`. Revisit under the PARAMETERS double-buffer hardening pass.
- **Per-user `totp_required` override.** Current policy is role-driven (admin = required). A per-user toggle is left for later.
- **Webauthn / passkeys.** Out of scope; TOTP covers the CSPN MFA requirement.
- **LDAP / IdP federation.** Out of scope.

## 3. Architecture

```
                       ┌──────────────────────────────────┐
   Browser  ─────────▶ │  /api/v1/auth/login              │  password flow
                       │  /api/v1/auth/login/mfa          │  TOTP challenge
                       │  /api/v1/auth/totp/enroll        │
                       │  /api/v1/auth/totp/confirm       │
                       │  /api/v1/auth/set-password       │
                       └────────────────┬─────────────────┘
                                        │ verify_password / verify_totp
                                        ▼
                       ┌──────────────────────────────────┐
                       │  secubox_core.user_store         │  READ-ONLY canonical reader
                       │  • load_with_fallback()          │
                       │  • verify_password(u, pw)        │
                       │  • is_enabled(u)                 │
                       │  • get_user(u)                   │
                       └────────────────┬─────────────────┘
                                        │ primary              fallback only
                       /etc/secubox/users.json    ─ ─ ─ ─▶  /etc/secubox/auth.toml
                                        ▲                   (warning + banner)
                                        │ writes
                       ┌────────────────┴─────────────────┐
                       │  secubox_users.engine            │  SINGLE mutation entry
                       │  • create_user / disable_user    │
                       │  • set_password / clear_password │
                       │  • enroll_totp / verify_totp     │
                       │  • touch_totp_step               │
                       │  • consume_backup_code           │
                       │  • touch_last_login              │
                       │  • revoke_sessions               │
                       └─────┬────────────────────┬───────┘
                  CLI thin   │                    │   FastAPI thin
                  wrapper    ▼                    ▼   wrapper
                       ┌──────────────┐    ┌─────────────────────┐
                       │ usersctl     │    │ secubox-users API   │
                       │ (Python)     │    │  /api/v1/users/*    │
                       └──────────────┘    └─────────────────────┘
                                                       │
                                                       │ on disable / revoke
                                                       ▼
                                          ┌──────────────────────┐
                                          │ secubox-auth IPC     │
                                          │ revoke_sessions(u)   │ → sessions.json
                                          │                      │ → audit.log
                                          └──────────────────────┘
```

### Two parity guarantees

1. **CLI ≡ API.** Every mutation has exactly one implementation: a function in `secubox_users.engine`. The CLI and the FastAPI handlers are both thin wrappers. Bash + `jq` direct writes are removed.
2. **Auth ≡ `users.json`.** `secubox_core.user_store` is the only module any service uses to authenticate. `secubox_core.auth._check_password()` becomes a one-liner that delegates to `user_store.verify_password()`. No service reads `users.json` or `auth.toml` directly anymore.

### Two transports, one identity

| Transport | Endpoint | Backend |
|---|---|---|
| Password | `POST /api/v1/auth/login` | `user_store.verify_password(name, plaintext)` — argon2id |
| Password + TOTP | `POST /auth/login` → `mfa_token` → `POST /auth/login/mfa` | argon2id + `pyotp.TOTP.verify` (window ±1) |
| Initial setup | empty password on `must_change_password=true` user → `setup_token` (15-min, scope=set-password) → `POST /auth/set-password` | bypasses verify; only acts on user matching `token.sub` |

All three converge on `create_token(username)` after `enabled=true` is confirmed.

## 4. `users.json` v2 schema

```json
{
  "$schema": "https://secubox.in/schemas/users-v2.json",
  "version": 2,
  "users": [
    {
      "username": "admin",
      "email": "admin@gk2.local",
      "role": "admin",
      "enabled": true,
      "password_hash": null,
      "must_change_password": true,
      "totp": null,
      "google": null,
      "services": [],
      "created": "2026-05-13T06:00:00+00:00",
      "last_login": null
    }
  ],
  "groups": []
}
```

### Field rules

| Field | Type | Notes |
|---|---|---|
| `username` | `string`, `^[a-z0-9_-]{2,32}$` | unique, lowercased on write |
| `email` | `string \| null` | RFC-5322 validated when set |
| `role` | `enum admin \| operator \| viewer` | drives RBAC in the existing secubox-users API |
| `enabled` | `bool` | **false ⇒ no login (password or TOTP) + all sessions revoked** |
| `password_hash` | `string \| null` | argon2id PHC string; null = no local password |
| `must_change_password` | `bool` | true ⇒ login with `""` returns `setup_token` instead of access token |
| `totp` | `object \| null` | `{secret, enabled, enrolled_at, last_step, backup_codes: [{hash, used_at}]}` |
| `google` | `object \| null` | reserved for future OIDC; always `null` in this rework |
| `services` | `list` | existing — unchanged |
| `created`, `last_login` | iso8601 | `last_login` set by login success path |

### Engine invariants

- `password_hash is None AND totp is None` ⇒ `must_change_password == true`. Engine rejects creation that would violate this.
- `disable_user` is the only path that flips `enabled=false`; it MUST also call `revoke_sessions(username)` in the same atomic mutation.
- `username` is the immutable primary key. Engine refuses to rename — admin must `delete` + `create`.
- `totp.secret` is base32 (160-bit). `totp.last_step` tracks the most recently accepted RFC 6238 step counter to refuse replay.
- Each backup code is 10 chars base32, argon2id-hashed; once `used_at` is set it is never accepted again.

### Migration v1 → v2 (idempotent, runs in postinst)

The board today has a split layout (legacy top-level `admin` key + new `users[]` array). `migrate_v1_to_v2.py`:

1. Detects v1 by presence of top-level non-`users`/`groups`/`version` keys.
2. For each legacy top-level user with `password_hash` (SHA-256): **discards** the hash (it can't be converted to argon2id), sets `must_change_password=true`, preserves `email`/`role`/`created`.
3. Merges with any matching entry in `users[]` (array wins for non-secret fields).
4. Writes v2 atomically (`tempfile + os.rename`) with a `users.json.v1.bak` backup kept indefinitely.
5. Also parses `/etc/secubox/auth.toml` `[users.*]` sections and ensures each appears in v2 with the same rule (discard plain text, force `must_change_password=true`).

Postinst is idempotent — re-running once `version: 2` is present is a no-op.

## 5. Flows

### 5.1 Password login

```
POST /api/v1/auth/login   { "username": "admin", "password": "<plaintext>" }

  ├─▶ user_store.get_user("admin")             [unknown → 401 "Identifiants incorrects"]
  ├─▶ if not user.enabled                       → 401 (same body; no enumeration)
  ├─▶ if user.must_change_password and password == "":
  │       → 200 { setup_required: true, setup_token }    (15-min, scope=set-password)
  ├─▶ if user.password_hash is None             → 401 "Aucun mot de passe local"
  ├─▶ argon2id.verify(hash, password)           [false → 401]
  │
  │   password OK from here ─────────────────────────────────
  │
  ├─▶ if user.totp.enabled:                     ── branch A ──
  │       → 200 { mfa_required: true,
  │               mfa_token: "<JWT, 5min, scope=mfa-challenge, sub=admin>" }
  │
  ├─▶ elif user.role == "admin" and not user.totp.enabled:   ── branch B ──
  │       → 200 { enrollment_required: true,
  │               enrollment_token: "<JWT, 15min, scope=totp-enroll, sub=admin>" }
  │
  └─▶ else (operator/viewer, no TOTP):          ── branch C ──
          → 200 { access_token, token_type: "bearer", expires_in: 86400 }
            (jti minted, sessions.json appended, last_login touched)
```

### 5.2 First-login set-password

```
UI sees { setup_required: true, setup_token } in the login response
  → renders "Définir le mot de passe initial" form (new + confirm)
  → POST /api/v1/auth/set-password   { new_password }
      Authorization: Bearer <setup_token>

Backend:
  ├─▶ decode setup_token: scope must be "set-password"
  ├─▶ user = user_store.get_user(token.sub)
  ├─▶ if not user.enabled                       → 403
  ├─▶ password_policy.validate(new_password, user)    [non-compliant → 422]
  ├─▶ engine.set_password(user.username, new_password)
  │     ├─ hash = argon2id.hash(plaintext)
  │     ├─ atomic write users.json: password_hash=hash, must_change_password=false
  │     └─ emit audit "password_set"
  ├─▶ engine.revoke_sessions(user.username)     ← clears any prior setup_token
  └─▶ 200 { ok: true, message: "Mot de passe défini, veuillez vous reconnecter" }
```

The same endpoint serves "change my password" for an already-logged-in user — same handler, but accepts a full Bearer JWT (not `scope=set-password`) and requires the old password in the body. The engine dispatches by inspecting the token's `scope` claim.

### 5.3 TOTP challenge (verify)

```
POST /api/v1/auth/login/mfa   { "code": "123456" }
     Authorization: Bearer <mfa_token>

  ├─▶ decode mfa_token: scope=="mfa-challenge", age < 5min
  ├─▶ user = user_store.get_user(token.sub)
  ├─▶ if not user.enabled                       → 401
  ├─▶ try TOTP first:
  │     step = pyotp.TOTP(user.totp.secret).timecode(now)
  │     if step == user.totp.last_step          → 401 "Code déjà utilisé"
  │     if pyotp.TOTP(secret).verify(code, valid_window=1):
  │         engine.touch_totp_step(user, step)
  │         goto issue
  │     else:
  │         try backup codes:
  │             for bc in user.totp.backup_codes where used_at is None:
  │                 if argon2id.verify(bc.hash, code):
  │                     engine.consume_backup_code(user, bc)
  │                     goto issue
  │   if neither matched               → 401 "Code invalide"
  │
  issue:
  ├─▶ jti = secrets.token_hex(8)
  ├─▶ token = create_token(sub=user.username, jti=jti, expires=24h)
  ├─▶ sessions.append({ id=jti, username, ip, user_agent, created, expires })
  ├─▶ engine.touch_last_login(user.username)
  └─▶ 200 { access_token, token_type: "bearer", expires_in: 86400 }
```

### 5.4 TOTP enrollment (branch B)

```
POST /api/v1/auth/totp/enroll
     Authorization: Bearer <enrollment_token>

  ├─▶ decode: scope=="totp-enroll", sub=user.username
  ├─▶ if user.totp.enabled                      → 409 "Déjà enrôlé"
  ├─▶ secret = pyotp.random_base32()
  ├─▶ STASH candidate in /var/lib/secubox/auth/totp-pending.json
  │   keyed by enrollment_token.jti, TTL 15min
  │   (NOT yet in users.json — only persisted after confirm)
  ├─▶ otpauth_uri = pyotp.totp.TOTP(secret).provisioning_uri(
  │       name=user.username,
  │       issuer_name=f"SecuBox · {hostname}")
  └─▶ 200 { secret, otpauth_uri, qr_png_b64: <base64 200x200 PNG> }

POST /api/v1/auth/totp/confirm   { "code": "123456" }
     Authorization: Bearer <enrollment_token>

  ├─▶ pending = totp-pending.json[token.jti]    [missing → 410 "Enrôlement expiré"]
  ├─▶ pyotp.TOTP(pending.secret).verify(code, valid_window=1)
  │     [false → 401 "Code invalide", pending preserved]
  ├─▶ engine.enroll_totp(user.username, pending.secret)
  │     ├─ generate 10 backup codes (10 chars base32 each)
  │     ├─ atomic write users.json:
  │     │     totp = { secret, enabled=true, enrolled_at=now, last_step=null,
  │     │             backup_codes = [{hash: argon2(c), used_at: null} for c in codes] }
  │     ├─ delete totp-pending.json entry
  │     └─ emit audit "totp_enrolled"
  ├─▶ issue real JWT (5.3 issue: tail)
  └─▶ 200 { access_token, …,
            backup_codes: [<plaintext × 10>],   ← ONE-TIME display
            backup_codes_note: "Conservez ces codes. Affichés une seule fois." }
```

### 5.5 Disable → kill sessions

```
POST /api/v1/users/<u>/disable     (caller must have users.edit permission)

engine.disable_user("alice"):
  ├─ atomic write users.json: users[alice].enabled = false
  ├─ revoke_sessions("alice"):
  │     ├─ sessions.json: remove every entry where username=="alice"
  │     └─ emit audit "sessions_revoked count=<n>"
  └─ emit audit "user_disabled"

require_jwt() (every authenticated request):
  ├─ decode JWT
  ├─ session = sessions.json.find(id == jwt.jti)
  ├─ if session is None         → 401 "Session révoquée"
  ├─ user = user_store.get_user(jwt.sub)
  ├─ if not user.enabled        → 401 "Compte désactivé"  (defense in depth)
  │       + best-effort sessions.json cleanup
  └─ pass payload to handler
```

The `revoke_sessions` step is the immediate-kill mechanism. It runs inside the same atomic mutation as the `enabled=false` flip — no window where a disabled user keeps a valid session entry.

### 5.6 Active sessions / audit log

The existing `secubox_core.auth.set_session_callback` callback is unchanged in shape; only the event types and the destination broaden:

- `sessions.json` — live state, keyed by JWT `jti`. Entries: `{id, username, ip, user_agent, created, expires, type}`.
- `audit.log` — append-only JSONL at `/var/lib/secubox/auth/audit.log`, rotated by logrotate without truncate. Every auth-relevant event lands here: `login_success`, `login_failed`, `mfa_challenge_issued`, `mfa_failed`, `mfa_replay`, `totp_enrollment_required`, `totp_enrolled`, `totp_disabled`, `setup_token_issued`, `password_set`, `user_disabled`, `user_enabled`, `sessions_revoked`, `fallback_active`, `rate_limited`.

## 6. Password policy (engine.set_password)

| Rule | Value |
|---|---|
| Min length | 12 |
| Charset | ≥ 3 of: lowercase, uppercase, digit, symbol |
| Username inclusion | forbidden (case-insensitive substring) |
| Max length | 128 (DoS guard on argon2id) |
| Reject if in `/usr/share/secubox/users/common-passwords.txt` | top-10k SecLists |

Argon2id parameters (tuned for Cortex-A72): `time_cost=3`, `memory_cost=65536` (64 MiB), `parallelism=4`, `hash_len=32`, `salt_len=16`. Engine uses a singleton `argon2.PasswordHasher` — no per-call construction.

## 7. TOTP rules

| Rule | Value |
|---|---|
| Algorithm | HMAC-SHA1, 6 digits, 30s step (RFC 6238 defaults — Google Authenticator compatible) |
| Window | current step ± 1 (±30s drift tolerance) |
| Replay protection | `user.totp.last_step` refuses re-use of the same step counter |
| Backup codes | 10 codes, 10 chars base32, argon2id-hashed at rest, single-use |
| Rate limit | 5 failed MFA attempts / 5 min / username → 429, invalidates `mfa_token` |
| Pending enrollment | 15-min TTL in `/var/lib/secubox/auth/totp-pending.json` |
| Disable TOTP (self) | requires re-entering password AND current TOTP code in same call |
| Disable TOTP (admin) | only via `usersctl totp-disable` OR API `POST /users/<u>/totp/disable` |

## 8. Secrets layout

| Path | Mode | Owner | Content |
|---|---|---|---|
| `/etc/secubox/users.json` | 640 | `root:secubox-users` | identity store (v2) |
| `/etc/secubox/auth.toml` | 600 | `root:root` | jwt_secret + emergency `[users.*]` fallback |
| `/var/lib/secubox/auth/sessions.json` | 640 | `secubox-auth:secubox-auth` | live sessions keyed by jti |
| `/var/lib/secubox/auth/audit.log` | 640 | `secubox-auth:secubox-auth` | append-only JSONL |
| `/var/lib/secubox/auth/totp-pending.json` | 600 | `secubox-auth:secubox-auth` | candidate TOTP secrets, 15-min TTL |

`secubox-users` group is added by `secubox-users.postinst`; the FastAPI service for that package and `secubox_core.user_store` callers must be in it (or the file ACL covers them).

## 9. Error matrix

| Scenario | HTTP | Body | Audit event |
|---|---|---|---|
| Wrong password | 401 | `Identifiants incorrects` | `login_failed reason=invalid_credentials` |
| Unknown username | 401 | (same — no enumeration) | `login_failed reason=unknown_user` |
| Disabled user | 401 | (same) | `login_failed reason=disabled` |
| Empty pw on `must_change_password=true` | 200 | `{setup_required, setup_token}` | `setup_token_issued` |
| Setup-token used on a non-set-password endpoint | 403 | `Token hors scope` | `setup_token_misuse` |
| Password OK, TOTP required | 200 | `{mfa_required, mfa_token}` | `mfa_challenge_issued` |
| Password OK, admin must enroll | 200 | `{enrollment_required, enrollment_token}` | `totp_enrollment_required` |
| MFA code wrong | 401 | `Code invalide` | `mfa_failed` |
| MFA replay (same step) | 401 | `Code déjà utilisé` | `mfa_replay` |
| MFA rate-limited (≥5 / 5min) | 429 | `Trop d'essais` | `mfa_rate_limited` |
| Backup code consumed | 200 | normal JWT | `backup_code_used remaining=<n>` |
| Backup codes exhausted | 200 + warning | normal JWT + warning field | `backup_codes_exhausted` |
| TOTP enrollment code wrong | 401 | `Code invalide` (pending kept) | `totp_enroll_failed` |
| Re-enrollment attempt | 409 | `Déjà enrôlé` | — |
| `users.json` missing → fallback active | 200 (auth still works) | normal JWT + UI banner | `fallback_active` (every call) |

## 10. File / endpoint surface

### New / modified files

```
common/secubox_core/
  user_store.py                NEW  canonical reader (load_with_fallback, verify_password, …)
  auth.py                      MOD  delegate to user_store; mint jti; scope-aware require_jwt

packages/secubox-users/
  api/main.py                  MOD  handlers → engine.*
  api/engine.py                NEW  single mutation entry point (Python)
  api/password_policy.py       NEW  validate_password()
  api/totp.py                  NEW  pyotp wrapper, backup-code generator
  api/migrate_v1_to_v2.py      NEW  schema migration (idempotent)
  sbin/usersctl                REWRITE in Python (argparse → engine.*)
  schema/users.json.schema.json  NEW v2 JSON Schema
  debian/control               MOD  Depends += python3-argon2, python3-pyotp, python3-qrcode,
                                              python3-jsonschema, python3-tomli
  debian/postinst              MOD  migration + seed admin + seed <hostname>

packages/secubox-auth/
  api/main.py                  MOD  /auth/login/mfa, /auth/totp/enroll, /auth/totp/confirm,
                                    /auth/totp/disable, /auth/set-password, /auth/logout, /auth/me;
                                    rate-limiter for mfa_failed; revoke_sessions IPC
  api/totp_pending.py          NEW  pending-enrollment store with TTL

tests/scripts/
  test-users-auth-live.sh      NEW  live smoke against the canonical board
```

### Endpoint surface

| Method | Path | Auth | Purpose |
|---|---|---|---|
| POST | `/auth/login` | none | Password (returns full JWT, mfa_token, enrollment_token, or setup_token) |
| POST | `/auth/login/mfa` | `mfa_token` | TOTP or backup code → full JWT |
| POST | `/auth/totp/enroll` | `enrollment_token` | Returns QR + otpauth URI |
| POST | `/auth/totp/confirm` | `enrollment_token` | Confirms, writes secret + backup codes, full JWT |
| POST | `/auth/totp/disable` | full JWT + password + current code | Self-disable |
| POST | `/auth/set-password` | `setup_token` OR full JWT (+ old password) | Initial / change |
| POST | `/auth/logout` | full JWT | Removes session |
| GET  | `/auth/me` | full JWT | Returns current user (no secrets) |
| POST | `/users/<u>/disable` | `users.edit` | Disables + revokes |
| POST | `/users/<u>/enable` | `users.edit` | |
| POST | `/users/<u>/password` | `users.password` | Admin-set password (clears must_change_password) |
| POST | `/users/<u>/totp/disable` | `users.edit` | Admin-disable TOTP for a user |
| POST | `/users/<u>/totp/backup-codes` | `users.edit` OR self | Regenerate (invalidates old codes) |
| GET  | `/users/<u>/sessions` | `users.view` OR self | List active |
| POST | `/users/<u>/sessions/revoke` | `users.edit` OR self | Force-logout |

### CLI surface (`usersctl`)

```
usersctl list
usersctl show <user>
usersctl add <user> --email=... --role=admin|operator|viewer
usersctl set-password <user>              # prompts, hashes argon2id
usersctl clear-password <user>            # sets must_change_password=true
usersctl enable <user>
usersctl disable <user>                   # revokes sessions
usersctl totp-enroll <user>               # interactive: prints ASCII QR + secret, prompts for code
usersctl totp-disable <user>              # admin path, no second-factor needed
usersctl totp-backup-codes <user>         # prints fresh codes (invalidates old)
usersctl sessions <user>
usersctl revoke <user>                    # force-logout without disabling
usersctl migrate-v1-to-v2                 # idempotent; also called from postinst
```

## 11. Testing

### 11.1 Unit (no I/O, no FastAPI)

| Module | Cases |
|---|---|
| `secubox_core.user_store` | argon2id verify accepts correct hash, rejects wrong/empty/None; `is_enabled` returns false for disabled; `load_with_fallback` falls back to auth.toml when users.json missing/corrupt and logs the warning |
| `secubox_users.engine` | `create_user` rejects bad username regex; `disable_user` flips flag AND calls `revoke_sessions`; `set_password` hashes argon2id and clears `must_change_password`; `enroll_totp` writes secret + 10 backup codes; `verify_totp` accepts ±1 window, rejects replay; backup-code consumption marks `used_at` exactly once |
| `secubox_users.password_policy` | 12-char min, charset rule, username substring rejection, common-password rejection |
| `secubox_users.totp` | `provisioning_uri` is RFC 6238 valid; secret base32 length 32; backup codes are 10 chars base32 hashed argon2id |
| `secubox_users.migrate_v1_to_v2` | Idempotent (second run is a no-op); discards SHA-256 hashes; merges legacy top-level keys with `users[]` entries; creates `.v1.bak` |

### 11.2 API integration (`packages/secubox-auth/tests/test_auth_flows.py`)

In-process FastAPI with tempdir users.json + sessions.json:

- **Branch C** (viewer, no TOTP): login → access_token → `/auth/me` works.
- **Branch B** (admin, no TOTP yet): login → enrollment_required → `/totp/enroll` → confirm with bad code (401, pending preserved) → confirm with good code → access_token + backup_codes shown once → second `/totp/enroll` returns 409.
- **Branch A** (admin with TOTP): login → mfa_required → `/login/mfa` with TOTP → access_token; replay same code → 401; backup code → access_token, `used_at` set; reuse same backup code → 401.
- **First-login**: empty password on `must_change_password=true` → setup_token → `/set-password` with weak password → 422; with strong → 200; subsequent login flows into branch B or C.
- **Disabled user**: enable, log in, capture jti → admin disables → original token's request → 401 "session revoked"; new login attempt with correct password → 401.
- **Fallback path**: rename users.json out of the way → login still works via auth.toml emergency entry; audit.log contains a `fallback_active` warning event.
- **Rate limit**: 5 wrong passwords in 5 min → 429; 5 wrong TOTP codes → 429 + mfa_token invalidated.

### 11.3 CLI ↔ API parity (`packages/secubox-users/tests/test_cli_api_parity.py`)

For each mutation, run once via `usersctl` and once via the API on a fresh users.json, then `diff` resulting files modulo timestamps. Covers: `add`, `enable`, `disable`, `set-password`, `clear-password`, `totp-enroll`, `totp-disable`, `totp-backup-codes`, `revoke`. CI fails if they diverge.

### 11.4 Live smoke (`tests/scripts/test-users-auth-live.sh`)

Runs against `https://admin.gk2.secubox.in/` after deploy:

1. Snapshot `users.json` + `sessions.json` over SSH.
2. Login as admin with the seed must-change flow → set password → enroll TOTP → log in normally.
3. `usersctl disable admin` from SSH → curl with stale token → assert 401.
4. `usersctl enable admin` → re-login → assert 200.
5. Diff `audit.log` entries against expected event sequence.
6. Restore snapshot.

## 12. Rollout

Feature flag `/etc/secubox/users.feature_flags.toml`:

```toml
[auth]
enforce_v2 = false           # false = old auth.toml path stays authoritative
require_totp_for_admin = true
```

**Phase 1 — Ship dormant.** Build & deploy `secubox-users` + updated `secubox_core.auth` + updated `secubox-auth` with `enforce_v2 = false`. New endpoints exist but `/auth/login` still uses the legacy path. Postinst runs migration to v2 (idempotent; harmless even if dormant). Nothing user-visible changes.

**Phase 2 — Cut over.** Flip `enforce_v2 = true`. Login goes through `user_store`. Existing `admin` from auth.toml is in `users.json` with `must_change_password=true`. Next login forces password set + TOTP enrollment. If anything misbehaves, flip back to `false` and the legacy path resumes — no data lost because `users.json` was maintained in parallel.

**Phase 3 — Remove the flag.** After Phase 2 is stable on the canonical board for one week, the flag is deleted from code; `auth.toml` is downgraded to pure emergency fallback.

## 13. Risks & mitigations

| Risk | Mitigation |
|---|---|
| Admin locks themselves out (TOTP device lost, no backup codes saved) | `usersctl totp-disable <user>` via SSH/console is always available (root-on-box trumps web auth). Documented in `secubox-users` README. |
| Migration corrupts users.json | Atomic write (`tempfile + os.rename`) + `.v1.bak` preserved indefinitely; migration is idempotent and a no-op once `version: 2`. |
| Argon2id too slow on Cortex-A72 | Benchmark on first build (`tests/perf/test-argon2-latency.py`); if p95 > 250ms, reduce `memory_cost` from 64 MiB to 32 MiB. |
| TOTP clock drift | Board already runs `chrony` (ANSSI baseline); pyotp `valid_window=1` (±30s) absorbs typical drift. Healthy NTP becomes a documented requirement. |
| Disabled-user race (in-flight request when admin disables) | `require_jwt` reads `sessions.json` on every call; window is bounded by single request duration. No further locking needed. |
| `auth.toml` fallback hides a real `users.json` bug | Every fallback activation logs WARNING + emits `fallback_active` audit event + the sidebar surfaces a red banner "Identity store in fallback mode". |

## 14. References

- Issue: [#120](https://github.com/CyberMind-FR/secubox-deb/issues/120) (this rework)
- Related: #114 (Hub sidebar fix — same module surface, different bug)
- CLAUDE.md sections: "Séparation de privilèges", "Secrets hors code", "Journalisation immuable"
- RFC 6238 — TOTP
- ANSSI password recommendations
- argon2-cffi documentation
- pyotp documentation
