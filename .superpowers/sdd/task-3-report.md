# Task 3 Report: RoutingTable (160 buckets, closest-N)

## Status
✅ **COMPLETE** — RoutingTable implemented and all 7 tests GREEN.

## Commit
- **Hash:** `a062f379`
- **Message:** `feat(p2p): DHT routing table + closest-N (#774)`

## Files Changed

### `packages/secubox-p2p/api/dht.py`
- Appended `RoutingTable` class with:
  - `__init__(self_id: bytes)`: creates 160 DHTBucket instances
  - `_bucket_index(node_id)`: computes shared-prefix length (0–159)
  - `insert(node) -> bool`: returns False for self_id or full bucket, else adds to appropriate bucket
  - `closest(target_id, count=KAD_K)`: returns count nearest nodes sorted by xor_distance
  - `all_nodes()`: flattens all 160 buckets into a single list

### `packages/secubox-p2p/tests/test_dht.py`
- Appended 2 tests:
  - `test_closest_orders_by_xor_distance`: verifies ordering by XOR distance and exact target match
  - `test_insert_ignores_self`: verifies self_id rejection

## Test Results

```
$ cd packages/secubox-p2p && python3 -m pytest tests/test_dht.py -v
collected 7 items

tests/test_dht.py::test_node_id_is_sha1_of_did PASSED
tests/test_dht.py::test_xor_distance_symmetry_and_zero PASSED
tests/test_dht.py::test_constants PASSED
tests/test_dht.py::test_bucket_add_and_refresh_moves_to_tail PASSED
tests/test_dht.py::test_bucket_full_rejects_new_and_reports_oldest PASSED
tests/test_dht.py::test_closest_orders_by_xor_distance PASSED
tests/test_dht.py::test_insert_ignores_self PASSED

============================== 7 passed in 0.03s ===============================
```

All 5 prior tests remain GREEN; 2 new tests added and GREEN.

## Deliverable Verification

✅ `RoutingTable` class appended to `api/dht.py` (line 73–104)
✅ `__init__(self_id: bytes)` creates 160 DHTBucket instances
✅ `insert(node: DHTNode) -> bool` returns False for self_id or full buckets
✅ `closest(target_id: bytes, count=KAD_K) -> list[DHTNode]` sorted nearest-first by xor_distance
✅ `all_nodes() -> list[DHTNode]` flattens all buckets
✅ TDD: tests written first, implementation follows brief exactly

## Concerns

None. Implementation follows the brief verbatim. TDD cycle complete with all tests GREEN. Ready for Task 4.
