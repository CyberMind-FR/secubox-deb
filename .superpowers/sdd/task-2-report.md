# Task 2 Report: DHTNode + DHTBucket (k-bucket with LRU)

## Status
**DONE**

## Commit Hash
`5843ca7e`

## Test Summary
All 5 tests passing (3 from Task 1 + 2 from Task 2):
- test_node_id_is_sha1_of_did ✅
- test_xor_distance_symmetry_and_zero ✅
- test_constants ✅
- test_bucket_add_and_refresh_moves_to_tail ✅ (Task 2)
- test_bucket_full_rejects_new_and_reports_oldest ✅ (Task 2)

**Test command:** `cd packages/secubox-p2p && python3 -m pytest tests/test_dht.py -v`
**Result:** 5 passed in 0.04s

---

## Implementation Summary

### Files Modified
- `packages/secubox-p2p/api/dht.py` — appended imports + DHTNode + DHTBucket classes
- `packages/secubox-p2p/tests/test_dht.py` — appended 2 new test cases

### What Was Implemented

**DHTNode (dataclass):**
```python
@dataclass
class DHTNode:
    node_id: bytes
    did: str
    endpoint: tuple  # (host, port)
    last_seen: float = 0.0
```

**DHTBucket (k-bucket with LRU via OrderedDict):**
- `__init__(k: int = KAD_K)` — initializes empty OrderedDict
- `add(node: DHTNode) -> bool` — updates node.last_seen, returns True if stored/refreshed, False if full; refresh moves node to tail (most-recent)
- `remove(node_id: bytes) -> None` — removes node from bucket
- `oldest() -> DHTNode|None` — returns head node (oldest), or None if empty
- `nodes` property — returns list of all nodes in LRU order

**Imports Added:**
```python
import time
from collections import OrderedDict
from dataclasses import dataclass, field
```

### Test Behavior

**test_bucket_add_and_refresh_moves_to_tail:**
- Creates bucket with k=2
- Adds nodes a, c → stored in order [a, c]
- Adds a again (refresh) → moves to tail, now [c, a]
- Tests OrderedDict.move_to_end() semantics

**test_bucket_full_rejects_new_and_reports_oldest:**
- Creates bucket with k=1 (capacity 1)
- Adds node a → stored
- Adds node c → returns False (full), c not stored
- oldest() returns a (the head/oldest)
- Tests full bucket rejection and oldest() accessor

---

## TDD Workflow Completed

1. ✅ **Step 1:** Appended failing tests (ImportError: DHTNode)
2. ✅ **Step 2:** Ran pytest → confirmed failure
3. ✅ **Step 3:** Implemented DHTNode + DHTBucket
4. ✅ **Step 4:** Ran pytest → all 5 tests pass
5. ✅ **Step 5:** Committed with message `feat(p2p): DHT k-bucket with LRU (#774)`

---

## Quality Notes

### Correctness
- OrderedDict provides O(1) LRU operations: insertion, lookup, move_to_end, iteration order
- DHTNode matches brief signature exactly
- LRU semantics: new adds to tail, refresh moves to tail, oldest() reads head
- add() properly handles both new insertion (capacity check) and refresh (move_to_end)

### No Regressions
- All 3 Task 1 tests still pass
- Test helper `_n()` isolates test setup

### Code Quality
- SPDX header preserved (did not modify)
- Follows existing module conventions
- Concise implementation (~40 lines for both classes)

---

## Concerns
None. Implementation straightforward and tested.
