<!-- SPDX-License-Identifier: LicenseRef-CMSD-1.0 -->
# SecuBox-Deb — CSPN Test Matrix (draft)

Maps the ANSSI **CSPN** evaluation themes + the project's stated security
functions (CLAUDE.md §"Contraintes ANSSI CSPN") to **concrete, mostly
automatable tests**. Target home for the automated rows: `tests/cspn/`
(pytest, gated in CI). Each row is an *acceptance check* with a command/
assertion and the evidence artifact an evaluator would expect.

**Legend** — Type: `A`=automated (pytest/CI), `M`=manual/pentest, `D`=doc/spec.
Status: ⬜ todo · 🔄 partial · ✅ covered.

> Scope note: the **cible de sécurité** (security target) must be written
> first (TOE boundary, assumptions, threats, security functions). This
> matrix is the *robustness + conformity* test plan that hangs off it.

---

## 0. Security target & conformity (D)
| ID | Requirement | Type | Method / artifact | Pass | St |
|----|-------------|------|-------------------|------|----|
| ST-01 | Cible de sécurité rédigée (TOE, hypothèses, menaces, FS) | D | `docs/cspn/cible-securite.md` reviewed | doc complete + signed | ⬜ |
| ST-02 | TOE boundary & versions pinned | D | version manifest (pkg list + hashes) per release | matches APT repo | ⬜ |
| ST-03 | Conformity: spec ↔ impl traceability | D | each FS → code path + test ID | 100% FS mapped | ⬜ |

## 1. Cryptography — TLS / keys / RNG
| ID | Requirement | Type | Method / assertion | Pass | St |
|----|-------------|------|-------------------|------|----|
| CRY-01 | TLS 1.3 min; TLS ≤1.1 refused (HAProxy frontends) | A | `openssl s_client -tls1_1 -connect <vhost>:443` → handshake fail; `-tls1_3` → ok | 1.0/1.1/1.2-weak refused | ⬜ |
| CRY-02 | Strong cipher suites only (no RC4/3DES/CBC-legacy) | A | `nmap --script ssl-enum-ciphers` / testssl.sh grade ≥ A | A grade, no weak | ⬜ |
| CRY-03 | HSTS + secure headers on exposed vhosts | A | `curl -sI` → `Strict-Transport-Security`, `X-Content-Type-Options` | present | ⬜ |
| CRY-04 | Private keys 0600, owner-restricted, not world-readable | A | `stat -c %a` on `/etc/secubox/**/key.pem`, ACME keys | 600, non-root svc owner | 🔄 |
| CRY-05 | CA / mitm keys never in VCS or logs | A | `git grep -nE 'BEGIN (RSA |EC )?PRIVATE KEY'` == empty; journald scrub | no hits | ⬜ |
| CRY-06 | RNG source = kernel CSPRNG for tokens/keys | A | code audit: `secrets`/`os.urandom`, no `random` for security | no `random.` in sec paths | 🔄 |
| CRY-07 | mitm R3 CA fingerprint published & verifiable | A | `/ca/fingerprint?ca=wg` == cert on disk (sha256) | match (D5:E4:3A…) | ✅ |

## 2. Authentication & session
| ID | Requirement | Type | Method / assertion | Pass | St |
|----|-------------|------|-------------------|------|----|
| AUT-01 | All API endpoints require JWT (`Depends(require_jwt)`) | A | enumerate FastAPI routes; assert auth dep except allowlist | 100% gated | 🔄 |
| AUT-02 | Unauthenticated request → 401, no data leak | A | `curl` each `/api/v1/*` sans token | 401, empty body | ⬜ |
| AUT-03 | JWT signature verified; tampered/expired rejected | A | forge/expire token → 401 | rejected | ⬜ |
| AUT-04 | Social/report tokens = HMAC, TTL-bound, salt-rotated | A | expired/forged `/social/{token}` → 403; salt rotates daily | rejected + rotation | 🔄 |
| AUT-05 | No default/hardcoded credentials | A | grep configs + first-boot generates per-device secrets | none | 🔄 |
| AUT-06 | Brute-force handled at the WAF layer (per project doctrine) | M | rate-limit probe via HAProxy/CrowdSec | throttled/banned | 🔄 |
| AUT-07 | ZKP auth (GK-HAM-2025) NIZK soundness, G rotation 24h PFS | M+A | protocol test vectors + rotation timer check | proofs verify, rotates | ⬜ |

## 3. Access control / privilege separation
| ID | Requirement | Type | Method / assertion | Pass | St |
|----|-------------|------|-------------------|------|----|
| ACL-01 | Each daemon runs as `secubox-<module>` (not root) | A | `systemctl show -p User` over all `secubox-*` units | non-root each | 🔄 |
| ACL-02 | AppArmor profile present + **enforce** per service | A | `aa-status` lists each profile in enforce | all enforce | ⬜ |
| ACL-03 | systemd hardening (ProtectSystem, NoNewPrivileges, etc.) | A | `systemd-analyze security secubox-*` score | exposure ≤ medium | ⬜ |
| ACL-04 | Filesystem perms: `/etc/secubox/secrets` 0600, parents traversable but not writable | A | `stat` perms + traversal test as svc user | 0600 secrets, 0755 parents | 🔄 |
| ACL-05 | No unintended setuid/world-writable shipped | A | `find / -perm -4000 / -perm -0002` in image | known allowlist only | ⬜ |

## 4. Network filtering / attack surface
| ID | Requirement | Type | Method / assertion | Pass | St |
|----|-------------|------|-------------------|------|----|
| NET-01 | nftables policy DEFAULT DROP (input/forward) | A | `nft list chain inet filter input` → `policy drop` | drop | ✅ (verify) |
| NET-02 | Only declared ports open; no stray listeners | A | `ss -tlnp` ∩ documented port map | exact match | 🔄 |
| NET-03 | WAN-side SSH closed (key-only + source-restricted) | A | sshd `PasswordAuthentication no`; nft SSH-guard drops non-LAN/tunnel | enforced | ✅ |
| NET-04 | No IPv6 leak past the v4 firewall guards | A | nft inet covers v6; `ss` v6 listeners reviewed | covered | ⬜ |
| NET-05 | nft rules persist across reboot + survive pkg upgrade | A | reboot/upgrade → drop-ins reload; ruleset intact | persists | 🔄 |
| NET-06 | DNS = Unbound only; DoH/DoT exfil detected/blocked (opt-in) | A | resolve via Unbound; DoH probe flagged | controlled | 🔄 |

## 5. WAF / traffic inspection integrity (no bypass)
| ID | Requirement | Type | Method / assertion | Pass | St |
|----|-------------|------|-------------------|------|----|
| WAF-01 | No `waf_bypass` anywhere; all vhosts → mitm inspector | A | grep HAProxy cfg; each backend = mitmproxy_inspector (or documented exception) | no bypass | 🔄 |
| WAF-02 | mitm CA only trusted on consenting (R2/R3) clients | A | non-consenting client not MITM'd | scoped | ✅ |
| WAF-03 | Banner/transparency shown to inspected clients (CSPN R2 req) | A | inspected HTML carries the banner guard | present | ✅ |
| WAF-04 | Active interference (spoof/ghost) is opt-in + logged + reversible | A | filters default-safe; every action → audit.log; toggle off restores | conforms | ✅ |
| WAF-05 | mitm fail-open never serves attacker-controlled content | M | malformed upstream / addon exception → flow unbroken, no inject error | safe | 🔄 |

## 6. Logging & audit (immutability)
| ID | Requirement | Type | Method / assertion | Pass | St |
|----|-------------|------|-------------------|------|----|
| LOG-01 | Security decisions (ban/unban/spoof/escalate/rule-change) logged to `/var/log/secubox/audit.log` | A | trigger each → grep audit line | logged | 🔄 |
| LOG-02 | Timestamps RFC 3339 / ISO-8601 with TZ | A | regex each audit line | conforms | 🔄 |
| LOG-03 | Append-only / rotation without truncate (immutability) | A | `chattr +a` or rotate-copy-truncate disabled; tamper test | no in-place edit | ⬜ |
| LOG-04 | Logs free of secrets/PII (mac→hash, no tokens) | A | grep audit/journal for token/cookie/key patterns | none | 🔄 |
| LOG-05 | Audit survives service crash + reboot | A | crash mid-write → log consistent | intact | ⬜ |

## 7. Configuration management & rollback (4R / double-buffer)
| ID | Requirement | Type | Method / assertion | Pass | St |
|----|-------------|------|-------------------|------|----|
| CFG-01 | Sensitive config change = shadow→validate→atomic swap | A | `secubox-params swap` flow; partial write never live | atomic | ⬜ |
| CFG-02 | 4R rollback restores prior state (R1..R4 snapshots) | A | mutate → `rollback --target R1` → state == pre | restored | ⬜ |
| CFG-03 | Validation rejects bad config before swap (4R: Read→Write→Validate→Rollback/Commit) | A | inject invalid → swap refused, live unchanged | refused | ⬜ |
| CFG-04 | Config swap audit-logged + (ZKP-gated where required) | A | swap → audit line | logged | ⬜ |

## 8. Update mechanism
| ID | Requirement | Type | Method / assertion | Pass | St |
|----|-------------|------|-------------------|------|----|
| UPD-01 | APT repo GPG-signed; unsigned/altered pkg refused | A | tamper a .deb → `apt` refuses | refused | 🔄 |
| UPD-02 | Upgrade preserves runtime state + restarts services (no outage) | A | upgrade → portal up, kbin 200, nft intact (regression of #581) | no downtime | ✅ |
| UPD-03 | Downgrade / rollback path defined | D+A | pinned prior version installs cleanly | works | ⬜ |
| UPD-04 | Reproducible build / provenance | A | CI build hashes recorded per release | recorded | 🔄 |

## 9. Data protection at rest
| ID | Requirement | Type | Method / assertion | Pass | St |
|----|-------------|------|-------------------|------|----|
| DAT-01 | Secrets only under `/etc/secubox/secrets` 0600, svc-owned | A | inventory + `stat` | conforms | 🔄 |
| DAT-02 | No secrets in code / TOML / git history | A | `git log -p` + `git grep` secret patterns | none | 🔄 |
| DAT-03 | SQLite stores hashed identifiers (mac_hash, cookie_id_hash), not raw PII | A | schema + sample-row audit | hashed | 🔄 |
| DAT-04 | Data retention enforced (social 7d, logs rotation) | A | retention timers prune | enforced | 🔄 |

## 10. Resilience / fail-safe
| ID | Requirement | Type | Method / assertion | Pass | St |
|----|-------------|------|-------------------|------|----|
| RES-01 | Service crash → auto-recovery (watchdog), portal probe | A | kill portal → restored + kbin 200 | recovers | ⬜ |
| RES-02 | RAM-pressure: no OOM cascade under load (Armada budget) | M+A | load test; per-service MemoryMax; no thundering-herd | stable | 🔄 |
| RES-03 | Fail-secure: filter/addon error must not open the WAF or break pages | A | inject addon exception → default-drop / fail-open page-safe | secure | 🔄 |

## 11. Hardening / vulnerability management
| ID | Requirement | Type | Method / assertion | Pass | St |
|----|-------------|------|-------------------|------|----|
| HRD-01 | No known-vuln Python deps | A | `pip-audit` / safety in CI | 0 high/critical | ⬜ |
| HRD-02 | No known-vuln OS packages in the image | A | `debsecan`/trivy on the image | 0 high/critical | ⬜ |
| HRD-03 | Attack-surface minimal: unused services disabled | A | enabled-units ∩ required set | minimal | 🔄 |
| HRD-04 | SAST clean on the codebase | A | `bandit` (py) in CI | no high | ⬜ |
| HRD-05 | Pentest of the exposed surface (kbin, HAProxy, R3) | M | grey-box assessment report | no critical | ⬜ |

## 12. Conformity glue (CI)
| ID | Requirement | Type | Method / assertion | Pass | St |
|----|-------------|------|-------------------|------|----|
| CI-01 | `tests/cspn/` runs in CI, gates merge | A | workflow job red on fail | gating | ⬜ |
| CI-02 | Coverage ≥80% on security-critical modules | A | coverage report | ≥80% | ⬜ |
| CI-03 | `compliance-lint` (AppArmor/user/secrets/no-bypass/SPDX) per PR | A | linter job | clean | 🔄 (SPDX only) |

---

## How to operationalise
1. Write the **cible de sécurité** (ST-01) — everything else traces to it.
2. Scaffold `tests/cspn/` (pytest), one module per theme above
   (`test_crypto.py`, `test_authz.py`, `test_firewall.py`, `test_audit.py`,
   `test_rollback.py`, …). Each `XXX-NN` ID = one test function id.
3. Add a CI job (CI-01) running it against a built image / a staging board.
4. Add `compliance-lint` (CI-03) for the static rows (perms, AppArmor,
   no-bypass, SPDX, no-secrets).
5. Burn down ⬜→✅; the ✅ rows above are already verifiable today.

Priority order (highest CSPN risk first): **§6 audit immutability**, **§7
4R rollback**, **§3 AppArmor enforce + privilege**, **§1 TLS**, **§12 CI
gate/coverage** — these are the criteria most likely to fail an assessment
today given the current ~9% test coverage.
