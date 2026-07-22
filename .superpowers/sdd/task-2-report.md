# Task 2: Meshtastic mesh data model + packet parser — Report

## Status: COMPLETE ✓

## TDD Workflow: RED → GREEN → COMMIT

### RED: Failing Tests (Step 1-2)

Created `tests/test_model.py` with 4 test cases per brief specification:
- `test_parse_packet_fields`: parse_packet() conversion
- `test_meshstate_census_updates_last_heard`: temporal tracking (first_heard/last_heard)
- `test_text_message_lands_in_channel_log`: TEXT_MESSAGE_APP channel logging
- `test_nodeinfo_sets_names_and_role`: node metadata merge

```bash
$ python -m pytest tests/test_model.py -q
FFFF                                                                     [100%]
4 failed in 0.07s
```

### GREEN: Implementation Complete (Step 3-4)

Implemented `api/model.py` with:
- `_nid(n)` — Hex ID normalization (0x11 → "!00000011")
- `Packet` dataclass — 9 fields: from_id, to_id, channel, portnum, decoded, rssi, snr, hop, ts
- `parse_packet(pkt: dict)` — Meshtastic pubsub dict consumer
- `Node` dataclass — Mesh participant census with temporal tracking
- `MeshState` class — State machine with apply_packet(), apply_nodeinfo(), to_dict()

```bash
$ python -m pytest tests/test_model.py -q
....                                                                     [100%]
4 passed in 0.06s
```

Full package test suite (4 model + 6 config tests):
```bash
$ python -m pytest tests/ -q
..........                                                               [100%]
10 passed in 0.07s
```

## Commits

| SHA | Subject |
|-----|---------|
| `8adb9cd3` | `feat(meshtastic): mesh state model + packet parser` |

## Files Created

| Path | Size |
|------|------|
| `api/model.py` | 98 lines |
| `tests/test_model.py` | 43 lines |

## Design Compliance

✓ Plain dataclasses (Packet, Node) — enables `vars()` serialization for downstream bridge task
✓ MeshState.to_dict() returns `nodes` as `[vars(n) for n in ...]` list
✓ No meshtastic import in tests — tests construct raw dicts directly
✓ Parser consumes meshtastic pubsub shape: `{"from":int, "to":int, "channel":int, "decoded":dict, "rxRssi":int, "rxSnr":float, "hopLimit":int, "rxTime":float}`
✓ SPDX header: LicenseRef-CMSD-1.0, (c) 2026 CyberMind — Gérald Kerma

## Key Patterns

| Pattern | Implementation |
|---------|-----------------|
| ID normalization | `_nid()` handles int/str, produces "!XXXXXXXX" format |
| Channel logging | `dict[int, list[dict]]` — TEXT_MESSAGE_APP packets appended with from/text/ts |
| Signal tracking | RSSI/SNR updated per packet; positions (POSITION_APP), battery (TELEMETRY_APP) cached |
| Temporal audit | first_heard on node creation, last_heard on every apply_packet() |
| Nullability | decoded, pos, battery, rssi, snr, hop all optional per meshtastic spec |

## Concerns

None. Brief code transcribed verbatim, all tests pass, no deviations required.
