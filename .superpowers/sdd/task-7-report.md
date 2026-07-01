# Task 7 Report — Consumer activate + mesh listener + revoke-access

**Date:** 2026-07-01
**Status:** DONE
**Branch:** feature/secubox-annuaire (worktree 771-macro-subsystem-tor-exit-reference-kind)

---

## Files changed

| File | Change |
|------|--------|
| `packages/secubox-p2p/api/main.py` | Added `_get_our_mesh_ip`, `_provider_mesh_ip_from_offer`, `_pull_grant`, `_macroctl_activate`, `_macroctl_revoke`; extended `activate_service` with M2 macro path; added `revoke_access` endpoint |
| `packages/secubox-p2p/nginx/p2p-macro-mesh.conf.tpl` | New — mesh listener template for the grant endpoint |
| `packages/secubox-p2p/debian/rules` | Added install of `p2p-macro-mesh.conf.tpl` to `/usr/share/secubox/p2p/` |
| `packages/secubox-p2p/debian/postinst` | Added mesh conf render + nginx -t revert guard + nft 8798 allow rule |
| `packages/secubox-p2p/debian/postrm` | Created — removes rendered `p2p-macro-mesh.conf` on remove/purge |
| `packages/secubox-p2p/tests/test_services_endpoints.py` | Added 5 new M2 tests (activate pulls + macroctl activate; pull failure; local unchanged; revoke-access calls macroctl revoke; unknown service error) |

---

## How `_pull_grant` signing matches `_verify_subscription_sig`

`_verify_subscription_sig` (provider, in `main.py`) strips `{"sig","signer_did","subscriber_pubkey"}` from the presented dict, then verifies the ed25519 sig over:

```python
json.dumps(payload, sort_keys=True, separators=(",",":")).encode("utf-8")
```

`_pull_grant` (consumer, also in `main.py`) builds the same signed set:

```python
to_sign = {k: v for k, v in payload.items() if k not in ("sig", "signer_did")}
# payload has keys: subscription_id, subscriber, service_id, requested_at, sig=None, signer_did=None
# to_sign has: subscription_id, subscriber, service_id, requested_at
canonical = json.dumps(to_sign, sort_keys=True, separators=(",",":")).encode("utf-8")
sig_bytes = priv_key.sign(canonical)
```

`subscriber_pubkey` is intentionally NOT in `to_sign` — it is added to the POST body only, exactly as the verifier strips it before reconstructing the signed payload. This mirrors the annuaire `verbs.py::subscribe()` signing exactly (the model's `model_dump()` does not include `subscriber_pubkey` because it is not a Subscription field).

The `signer_did` in the POST body is set to `did` (our DID), not included in the signed bytes. `_verify_subscription_sig` also strips `signer_did` before verifying. Consistent.

---

## `_verify_subscription_sig` flow vs `_pull_grant` — field-by-field

| Field | In POST body | In signed payload | In verifier strip-set |
|-------|-------------|-------------------|-----------------------|
| `subscription_id` | yes | yes | no |
| `subscriber` | yes | yes | no |
| `service_id` | yes | yes | no |
| `requested_at` | yes | yes | no |
| `sig` | yes | no | yes |
| `signer_did` | yes | no | yes |
| `subscriber_pubkey` | yes | no | yes |

---

## pytest output

```
46 passed, 1 warning in 0.80s
```

(41 pre-existing M1 + 5 new M2 tests)

---

## sh -n outputs

```
postinst OK
postrm OK
```

---

## Template verification

`p2p-macro-mesh.conf.tpl` confirms:
- `listen __MESH_IP__:8798;` — binds only the mesh IP
- `allow 10.10.0.0/24; deny all;` — non-mesh sources refused
- `proxy_set_header X-Real-IP $remote_addr;` — provider-observed source IP forwarded
- `location ~ ^/api/v1/p2p-macro/` — prefix regex covers all `grant/<service_id>` paths
- `proxy_pass http://unix:/run/secubox/p2p.sock;` — reaches the p2p FastAPI via socket

---

---

## Review fixes applied (2026-07-01, ref #771)

### FIX 1 — packaging: Depends secubox-annuaire

**File:** `packages/secubox-p2p/debian/control`, line 10

Added `, secubox-annuaire` to the `Depends:` line of `Package: secubox-p2p`.
The p2p macro mesh listener binds the wg-mesh IP (10.10.0.x) on port 8798.
`net.ipv4.ip_nonlocal_bind=1` is required so nginx can bind that IP before
wg-mesh is up at boot. That sysctl is shipped by secubox-annuaire's
`/etc/sysctl.d/30-secubox-nonlocal-bind.conf`. Declaring the dependency
ensures apt enforces co-install ordering; no duplicate sysctl file is shipped.

### FIX 2 — revoke-access: 409 when no mesh IP

**File:** `packages/secubox-p2p/api/main.py`, lines 1192-1196

Changed `_get_our_mesh_ip() or "0.0.0.0"` to a guarded pattern:

```python
our_mesh_ip = _get_our_mesh_ip()
if not (our_mesh_ip and our_mesh_ip.startswith("10.10.0.")):
    return JSONResponse({"error": "node has no wg-mesh IP; cannot revoke"}, status_code=409)
```

macroctl rejects non-mesh IPs with a confusing error; now the API returns a
clean 409 before even calling macroctl. Both `None` and `"0.0.0.0"` fallbacks
are caught.

**Test added:** `test_revoke_access_no_mesh_ip_returns_409` in
`packages/secubox-p2p/tests/test_services_endpoints.py` — patches
`_get_our_mesh_ip` to return `None`, asserts HTTP 409 and error message.
Existing `test_revoke_access_calls_macroctl_revoke` already patches to
`"10.10.0.3"` (success path); no change needed there.

**pytest result:** 47 passed, 1 warning (was 46 pre-review).

---

## Concerns

1. **Provider mesh IP derivation for non-10.10.0.x endpoints**: `_provider_mesh_ip_from_offer` returns `None` if the offer endpoint host is not `10.10.0.x` and not found in `wg_mesh.json` peers. This is intentional — in M2 all active mesh nodes should have 10.10.0.x endpoints; non-mesh offers are not automatable. The error surfaces clearly via `_pull_grant` → `"cannot resolve provider mesh IP"`. A future enhancement could add a DID→mesh-IP directory.

2. **`activate_service` M2 guard**: the M2 path fires only when `is_remote AND has_macro AND st == "approved"`. If the subscription state is not yet approved the M1 error path catches it first (`"remote service not approved"`). This is correct per spec increment-1 scope (auto mode only; no pending-mode cross-node approval).

3. **No sysctl net.ipv4.ip_nonlocal_bind guard in postinst**: the annuaire postinst applies `/etc/sysctl.d/30-secubox-nonlocal-bind.conf` so nginx can bind the wg-mesh IP at boot before wg-quick runs. The p2p postinst does not add this — it relies on the annuaire package being present (which installs both that sysctl and the flag). If p2p is installed standalone without annuaire, the `:8798` listener will fail to bind at boot until wg-mesh is up. This is acceptable for M2 (p2p depends on annuaire).
