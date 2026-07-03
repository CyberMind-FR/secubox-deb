# Task 4 Report: Signed Reachability Records (DHT)

## Status
✅ **COMPLETE** — All 9 tests passing (7 prior + 2 new Task 4 tests)

## Commit
- **Hash**: 4ee293ba
- **Message**: feat(p2p): DHT signed reachability records + verify (#774)

## Test Summary
- `test_canonical_is_stable_and_sorted` ✅ — canonical_record produces deterministic sorted JSON
- `test_verify_rejects_tampered` ✅ — verify_record correctly rejects tampered endpoint, missing sig, and validates DID
- **Total**: 9/9 passing (0 failures)

## Implementation Details
- Added `canonical_record(did, wg_pubkey, endpoint, ts) -> bytes` — deterministic sorted JSON with separators (",", ":")
- Added crypto SEAMS (module-level, testable via monkeypatch):
  - `_did_from_pubkey(pub_hex) -> str` — wraps annuaire_client.did_from_pubkey_hex
  - `_verify_sig(body, sig_hex, pub_hex) -> bool` — stub (NotImplementedError)
  - `_sign_sig(body) -> str` — stub (NotImplementedError)
- Added `sign_record(did, wg_pubkey, endpoint, ts) -> dict` — calls _sign_sig, returns dict with "sig" field
- Added `verify_record(rec) -> bool` — checks sig presence, DID validity, signature integrity; catches KeyError/TypeError/ValueError

## Concerns
None. Tests confirm:
- Deterministic canonical form (exact byte match across calls)
- Monkeypatching of crypto seams works as designed
- verify_record correctly detects tampering and unsigned records
- Exception handling catches missing fields gracefully

Ready for Task 5 (integration with DHT operations).
