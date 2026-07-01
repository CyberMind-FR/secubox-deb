# Task 2 Report — annuaire_client.py

## Files Changed

- **Created**: `packages/secubox-p2p/api/annuaire_client.py`
- **Created**: `packages/secubox-p2p/tests/test_annuaire_client.py`

No other files touched.

---

## Pytest Command and Full Output

```
cd packages/secubox-p2p && python3 -m pytest tests/test_annuaire_client.py -v
```

```
============================= test session starts ==============================
platform linux -- Python 3.12.3, pytest-9.0.2, pluggy-1.6.0
cachedir: .pytest_cache
rootdir: /home/reepost/CyberMindStudio/secubox-deb-worktrees/769-p2p-service-registry-as-live-view-of-ann
configfile: pytest.ini
plugins: anyio-4.12.1, asyncio-1.3.0
asyncio: mode=Mode.STRICT, debug=False, asyncio_default_fixture_loop_scope=None

collecting ... collected 4 items

tests/test_annuaire_client.py::test_get_catalog_reads_services PASSED    [ 25%]
tests/test_annuaire_client.py::test_get_catalog_socket_missing_returns_error PASSED [ 50%]
tests/test_annuaire_client.py::test_node_identity_reads_key PASSED       [ 75%]
tests/test_annuaire_client.py::test_node_identity_missing PASSED         [100%]

============================== 4 passed in 0.56s ===============================
```

Full suite (no regressions):
```
cd packages/secubox-p2p && python3 -m pytest tests/ -q
29 passed in 0.60s
```

---

## Test Harness Choice and Rationale

### The brief's `_serve_unix` approach

The brief's helper used `http.server.HTTPServer.__new__` to bypass `__init__`,
then manually assigned `srv.socket`. This is fragile because:

1. `socketserver.BaseServer.serve_forever()` calls `selectors.register(self, ...)`,
   which in turn calls `_fileobj_to_fd(fileobj)` — it expects `fileobj.fileno()`.
   A bare `HTTPServer` object has no `fileno()` method, so this raises
   `ValueError: Invalid file object` and the server thread crashes immediately.
2. Even if it didn't crash, `HTTPServer.__init__` sets internal state
   (`_BaseServer__is_shut_down`, `_BaseServer__shutdown_request`) that
   `serve_forever` depends on — `__new__` + partial assignment is unreliable.

### Chosen approach: `socketserver.BaseServer` subclass with `fileno()`

Implemented `_UnixSocketHTTPServer(socketserver.ThreadingMixIn, socketserver.BaseServer)`:

- `__init__` creates and binds the AF_UNIX socket (no `bind_and_activate` bypass needed).
- `fileno()` delegates to `self.socket.fileno()` — required by `serve_forever`'s selector.
- `get_request()` accepts and returns `(conn, server_address)`.
- `server_bind()` / `server_activate()` are no-ops (socket already bound/listening).
- `shutdown_request()` / `close_request()` follow the stdlib pattern.

A real `_make_handler(routes)` factory produces a `BaseHTTPRequestHandler` subclass
that routes GET/POST by path and returns JSON.

### Why not monkeypatching?

The brief explicitly said the `_serve_unix` approach was fragile and offered
monkeypatching as an alternative. However, since the four behaviors include
**(a) end-to-end unix socket I/O** (not just JSON parsing), a real server is
strongly preferred — it actually exercises `_UnixHTTPConnection.connect()`.
Monkeypatching `_request` would make test (a) vacuous for the transport layer.
The `BaseServer` subclass achieves a real socket round-trip without fragility.

---

## Self-Review

### Correctness
- `did_from_pubkey_hex` matches the spec exactly: `"did:plc:" + sha256(pubkey_bytes).hexdigest()[:32]`.
- `node_identity` derives the public key via `cryptography.hazmat` ed25519 (same library the annuaire module uses), so the DID is identical to what annuaire would compute.
- `_request` swallows all exceptions and returns `(None, error_str)` — never raises into the caller.
- `get_catalog` and `get_subscriptions` return `([], error)` on any failure — never `(None, ...)`.

### Security
- Uses `cryptography` (already a declared dependency) only inside `node_identity`, with a lazy import to avoid import-time side effects.
- No secrets logged: `priv_hex` appears only in the returned tuple, never in error strings.
- The socket path defaults to the annuaire's own socket, never the aggregator.

### Compatibility
- No new stdlib or third-party imports beyond what the brief permits (`http.client`, `socket`, `json`, `hashlib`, plus `cryptography` already present).
- SPDX header and copyright block match `api/mesh.py` exactly.

---

## Concerns

None blocking. One minor note:

- `subscribe()` forwards `priv_hex` in the POST body to the annuaire. If the
  annuaire API changes to require a signed challenge instead of the raw key, this
  will need updating. The interface is documented in the docstring.
- The `_TIMEOUT = 3.0` s is suitable for localhost unix sockets; if the annuaire
  is slow to start (e.g., during board boot), callers may get transient errors.
  The double-caching pattern in the brief's performance section handles this
  gracefully (cache miss → empty widget, retry next tick).
