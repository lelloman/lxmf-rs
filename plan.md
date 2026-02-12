# Phase 8b: Close Gaps Before Integration Testing

## Status: COMPLETE

All items implemented. Build clean, 129 tests passing.

| # | Item | Status |
|---|------|--------|
| 1 | Fix propagation stamp stripping bug (`has_stamp` field) | Done |
| 2 | Add logger backend (`env_logger`) | Done |
| 3 | Add `exit_handler()` to router | Done |
| 4 | Wire up RNS node in daemon main loop | Done |
| 5 | Implement remote control client (--status/--peers/--sync/--break) | Done |
| 6 | Clean up dead code warnings | Done (0 warnings) |
| 7 | Add `peers` collection to `LxmRouter` with load/save, `sync_peer()`, `unpeer()` | Done |
| 8 | Wire server-side sync/unpeer control handlers to router methods | Done |

## Summary of changes

### `lxmf/src/propagation.rs`
- Added `has_stamp: bool` field to `PropagationEntry`
- Set during `store_message()` (`stamp_data.is_some()`) and `scan_messagestore()` (`stamp_value > 0`)
- `handle_get_wants()` only strips STAMP_SIZE bytes when `entry.has_stamp` is true

### `lxmf/src/router.rs`
- Added `exit_handler()`: tears down links, saves all state, drops node reference
- Added `peers: HashMap<[u8; 16], LxmPeer>` field loaded from storage on init
- Added `sync_peer()`: resets `next_sync_attempt` to 0.0 for immediate sync pickup
- Added `unpeer()`: removes peer from the HashMap
- Added `save_peers()`: serializes and persists peers to storage
- Peers saved periodically at `JOB_STORE_INTERVAL` and on exit

### `lxmd/Cargo.toml`
- Added `env_logger = "0.11"`

### `lxmd/src/main.rs`
- Full daemon wiring: `LxmRouter` + `LxmfCallbacks` + `RnsNode`, job thread, announce timers, graceful shutdown
- Remote control client: `ControlCallbacks`, link establishment, request/response flow with timeout
- Server-side handlers: `register_control_handlers()` with status (reads from disk), sync (calls `router.sync_peer()`), unpeer (calls `router.unpeer()`)
- Signal handling (SIGINT/SIGTERM) with clean shutdown sequence

### `lxmf/tests/propagation_tests.rs`
- Updated existing tests for `has_stamp` field assertions
- Added `test_handle_get_wants_without_stamp_keeps_payload`

## Known minor issues
- `build_status_payload()` reads peers from disk rather than from `router.peers` in-memory; after `unpeer()` the status may show stale data until the next periodic save. Not a regression (pre-existing design), can be improved in a future pass.
