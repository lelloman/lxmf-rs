# Upstream LXMF Backlog

Tracks upstream Python LXMF commits that have appeared after the Rust port's
last reviewed upstream point and have not yet been integrated or explicitly
closed out.

## Current State

- Last checked: 2026-11-09
- Upstream checkout: `/home/lelloman/LXMF`
- Upstream remote: `git@github.com:markqvist/LXMF.git`
- Upstream branch: `origin/master`
- Current upstream head: `101fd447815b4f4f699f8bb700e0df613f71efce`
- Last reviewed Rust-port upstream point:
  `101fd447815b4f4f699f8bb700e0df613f71efce`
- Rust branch at latest review: `dev`
- Rust port commit: `d700a89` (plus the interop test commit that follows it)

The local upstream worktree branch `master` intentionally remains at the older
`fab12ad` baseline. Do not use its `HEAD` as the reviewed Rust-port baseline;
the authoritative reviewed commit is recorded in `UPSTREAM.md`. The remote
`origin/master` was checked at `101fd44` during the 2026-11-09 refresh.

## Open Upstream Commits

None. Every commit in
`fab12ad9bf9f997797034950f289fe41a79dcf5a..101fd447815b4f4f699f8bb700e0df613f71efce`
is ported, covered by tests, or explicitly closed as metadata/design-equivalent.

## Reviewed 2026-11-09: `795fdaa..101fd44` (LXMF 1.2.0, 1.3.0)

Ported by Rust commit `d700a89` together with the move to `rns-core` 0.7 /
`rns-net` 0.12, which provide the fractional stamp, link cost, medium timing,
announce filtering and resource app-flag APIs these commits rely on. Interop
is covered by the upstream-generated vectors in
`lxmf-core/tests/lxmf13_interop.rs` and the live Python interop run
(`tests/interop/run_live.sh`).

| Upstream commit(s) | Status |
| --- | --- |
| `6e898e6`, `3297f21` | Ported: costs are `StampCost` and values `StampValue` on the 1/256 grid. Delivery announces carry `ceil(cost)` in [1] and the exact cost in [3]; PN announces carry ceil'd costs in [5] and exact costs in [7]; parsers prefer the exact elements and accept floats wherever upstream does. Message store filenames use quantized float values; peers and stamp costs persist as floats; `lxmd` parses costs as floats; `set_inbound_stamp_cost` caps at `STAMP_COST_CAP`; propagation resources carry the app flag and static-only nodes admit app-flagged client resources. Covered by `lxmf13_interop` (byte-identical announces, parsing, quantization, stamp values) and `propagation_node_tests`. |
| `98e09bb`, `700a462`, `308498e`, `d6df0f7`, `c98bca2`, `1df7ebc`, `8669218` | LXStamper now wraps `RNS.Stamps`; Rust already delegates to `rns_core::stamp`, now with fractional costs. Remaining changes are Python worker/multiprocessing internals and a log fix; not applicable to the Rayon stamper. Upstream-generated stamps validate in `upstream_generated_stamps_validate`. |
| `0889401`, `fbc821e`, `acaa9e3`, `beac6bc`, `170e71d`, `43a077b`, `5745f85` | Ported in `lxmf/src/outbound.rs` and `process_outbound`: medium-aware round trips, scheduled attempts and attempt limits with airtime jitter, debounced path requests (60 s with a slow interface online), stale-path rediscovery, `awaiting_path` wakeups from announces and path updates, slow-path holds with one in-flight message per slow target, and idempotent delivered/propagated marking. Covered by `outbound_tests`. |
| `2470081` | Ported: send errors fail the message instead of retrying silently. Covered by `send_errors_fail_the_message`. The deferred-stamp parts do not apply (no deferred stamp pipeline in Rust). |
| `3fc60af` | Ported: `ENCRYPTED_PACKET_MDU` is `Packet.ENCRYPTED_MDU` (383; Rust had 399), and oversized opportunistic messages fall back to direct delivery as `LXMessage.pack` does. Covered by `constants_match_upstream` and `oversized_opportunistic_message_falls_back_to_direct`. |
| `c3ff2d6` | Ported: PN metadata carries `PN_META_IMPL_NAME` (`lxmf-rs`), `PN_META_VERSION` and the configured node name, which Rust previously never announced. Covered by `pn_announces_match_upstream`. |
| `a0793f6` | Ported: delivery and propagation destinations set a link cost of 3.25. |
| `810c345` | Ported: the router registers `lxmf.delivery` and `lxmf.propagation` with `wants_destination_type`. |
| `40dcd7d` | Ported: `pn_stamp_throttle` in `RouterConfig`, `[propagation] propagation_stamp_throttle` (minutes, 5-minute floor) in `lxmd`, default 300 s. Covered by `fractional_costs_and_stamp_throttle_follow_upstream_bounds`. |
| `d845503` | Ported: stamp costs are marked dirty and saved with the periodic store job and on exit. Covered by `stamp_cost_update_replaces_cache_and_persists_all_destinations`. |
| `c939e25` | Ported: an unanswered peer path request backs off the peer and marks it not alive. Covered by `unanswered_peer_path_requests_back_off`. |
| `2059784` | Ported: announce data is retained when a propagated message is accepted, as for delivered messages. Covered by `small_propagated_message_is_sent_as_link_packet`. |
| `2b09146` | Already covered: display-name decoding returns `None` on unpack or UTF-8 failure. |
| `8ded002` | Not applicable: Rust has no outbound cancel or deferred-stamp API. Revisit if one is added. |
| `c7a902f` | Closed as a design choice: the SQLite backend is Python-local persistence with legacy-file import; it changes no wire or interop format. Its peer identity resolution retry is matched by resolving peer keys from announces or the transport on every sync pass. |
| `3290c4e` | Ported: `ENCRYPTION_DESCRIPTION_AES` is "AES-256". |
| `da1b9c0`, `6fb5a36`, `599bb67`, `e8ba024`, `01387b1`, `cc702b7` | Python version and RNS floor metadata (now `rns>=1.6.0`); dependency-parity context only. |
| `41cdce6`, `1dc8097`, `2c69fd3` | Log level and log message cleanup. |
| `aa7137d` | GitHub issue template removal. |
| `e52016c`, `db2bd9e` | README and micron README documentation. |
| `101fd44` | LICENSE copyright year. |

Found while porting this range (pre-existing Rust gaps, fixed in `d700a89`):
concluded messages were never removed from the outbound queue; transient ID
caches expired after 30 days instead of upstream's 180; propagation nodes
accepted only offered peer transfers, not client uploads; delivery and
propagation destinations had no proof strategy, so their packets were never
proven; propagation nodes never generated peering keys; and propagated link
packets never reached the sent state.

## Recently Reviewed And Closed

These upstream commits are not open backlog items because they were already
ported, tracked as no-op metadata, or judged Python/tooling-specific in review
passes from 2026-05-24 through 2026-07-23.

| Upstream commit(s) | Status |
| --- | --- |
| `727830c` | Python RNS dependency metadata; tracked as dependency-parity input, no direct Rust code change. |
| `4ecbdb3`, `9d413c0`, `ad616fc`, `f9967db` | Upstream README churn; no Rust-port behavior change. |
| `189f523` | Already ported as `OutboundError::MissingOutboundPropagationNode` behavior; covered by `propagated_outbound_requires_configured_propagation_node`. |
| `25b7fcf`, `2c4dfdd`, `6a00d82`, `7b0e702`, `84613f8`, `dffbf4d` | Python package version/RNS dependency metadata; no direct Cargo change, retained as dependency-parity context. |
| `83fbe80` | Already ported in delivery announce display-name normalization; covered by `test_delivery_announce_display_name_strips_nulls_and_trims_v050`. |
| `a8505ea` | Already ported in propagation-node announce outbound wakeup; covered by `propagation_node_announce_wakes_matching_propagated_outbound`. |
| `0cb62dd` | Python 3.14 multiprocessing-specific stamper lifecycle; not applicable to Rust Rayon implementation, with Rust cancellation coverage in place. |
| `29c7917`, `b415a13` | Python Makefile/release tooling; no Rust-port action. |
| `7f0e262`, `d6ec051`, `1bef747` | Ported by Rust commit `97db2b2a4a12e89a89fe64986878b533a8516170` as atomic propagation-store writes. |
| `764758d` | Ported in this pass by adding reply/reaction/comment/continuation field constants and dict indices to `lxmf-core/src/constants.rs`; covered by `test_message_field_constants_match_upstream` and `test_interaction_field_dict_indices_match_upstream`. |
| `b53a3ce` | Ported in this pass as the `FIELD_THREAD` doc comment in `lxmf-core/src/constants.rs`; covered by `test_message_field_constants_match_upstream` for the unchanged field value. |
| `55620bf` | Python `lxmd.py` config-path typo fix; no matching Rust typo in `lxmd/src/main.rs`. |
| `599406e` | Ported by Rust commit `8b98355f7bad2eab36567b87b8367ba009f0a8b1` as delivery announce compression support signalling; covered by `delivery_announce_data_signals_compression_support`. |
| `2ac2b10` | Ported by Rust commit `4a6dc6f954b5d58d45fe89860d22cda815980cda` as inbound blackholed-source dropping; covered by `blackholed_source_is_dropped_before_delivery_callback`. |
| `575fb7d`, `5be161c` | Python `LXMessage.write_to_directory` write-race fixes. Rust propagation-store atomic writes are already ported and covered; no direct Rust message-container persistence API exists. |
| `312e0a8`, `044f3d2` | Python LXMF/RNS dependency metadata; no direct Cargo change, retained as dependency-parity context. |
| `bf924c7` | Python comment/format cleanup with no protocol constant value changes; no Rust-port action. |
| `11b2480`, `c877efa`, `a29c4a0` | Python package/version metadata only; no Rust crate version change. |
| `2086413` | Ported in this pass: propagation sync retry after `ERROR_NO_IDENTITY` identifies with the router identity and retries the offer; covered by `peer_sync_no_identity_identifies_with_router_identity_and_retries_offer`. |
| `fab12ad` | Python Makefile/setup.py build-script upload metadata; no Rust-port action. |
| `fb0fd24` | Python LXMF version and Python RNS minimum dependency metadata. Rust has an independent crate version line; retain the RNS 1.3.8 floor as compatibility context for later resource API ports. |
| `8395793` | Ported by routing all msgpack state persistence through a shared atomic writer, covering peers, transient-ID caches, stamp costs, node stats, and tickets as well as the already-atomic propagation message store. Tests cover replacement, symlink safety, failed-write cleanup, concurrent writers, and every state helper. |
| `548be10` | No separate map locks are needed in Rust: router mutation is serialized through `Arc<Mutex<LxmRouter>>` and cache mutation requires `&mut self`. Added a concurrent writer/cleanup regression test that also verifies the persisted caches contain every non-expired update. |
| `4a93697` | Rust already used saturating subtraction for the peer offer stamp floor, equivalent to upstream's corrected `max(0, target-flexibility)`. Factored the rule into a named helper and added boundary coverage for below/at threshold, underflow-to-zero, and zero flexibility. |
| `982c9fc` | Ported by returning an empty-offer result before changing peer state or replacing `last_offer`. Tests cover empty results caused independently by stamp-cost, per-message transfer-size, and cumulative sync-size filtering. |
| `ca02fa5` | Ported the independent `[lxmf] stamp_cost`, sequential PN validation, static-peer bypass, and maximum inbound-sync settings through `lxmd` and `RouterConfig`. Delivery announces no longer reuse the propagation target cost. Added Unicode NFKC/category-based peer-name sanitization at the terminal display boundary, plus default, parsing, clamping, independence, forwarding, example-config, and hostile-Unicode tests. |
| `241b29c` | Ported inbound `/offer` handling, peering-key validation, wanted-ID responses, accepted/transferring/validating lifecycle accounting, transfer-size admission, sequential validation pressure, maximum concurrent inbound syncs, configurable static-peer bypass, stamp-failure throttling, asynchronous PN stamp validation, message-store/distribution updates, and cleanup on invalid payloads, link closure, and resource failure. Tests cover every admission branch, offer parsing/key failure, lifecycle transition, direct/PN resource limits, asynchronous storage, and cleanup paths. |
| `3e2cd36` | Python LXMF package version 1.0.2 → 1.1.0 only. Rust maintains an independent workspace version and does not mirror Python release numbers. |
| `5769d46` | Ported the safer 1 KB default direct-delivery resource limit in both runtime defaults and generated config. Delivery limits now remain floating-point kilobytes through `RouterConfig`, preserving upstream's 0.38 KB minimum instead of truncating it to zero. Resource acceptance logs the resource type, byte size, link, and accept/reject outcome for direct delivery and propagation transfers. Tests cover the new default, example config, configured floor, exact forwarding, and byte-boundary admission. |
| `d909619` | Ported inbound direct-resource identity, count/list APIs, monotonic progress, completion/failure/link cleanup, exact-hash cancellation APIs, cancel-all, and propagation response size/progress tracking and reset. The `rns-net` adapter cancels an accepted incoming resource by rejecting its exact hash, preserving the containing link and its other transfers. Tests cover multiple resources on a shared link, progress clamping, exact/cancel-all dispatch, callback lifecycle, rejected resources, failure cleanup, and propagation size reset. |
| `7bb4bcf` | Added pathing-detail (`trace`) logging for outbound stamp-cost updates. Regression tests cover cache replacement, multiple destinations, atomic persistence, expiry filtering, and refresh after expiry. |
| `795fdaa` | Python RNS minimum dependency metadata (1.3.8 → 1.4.0). No direct Cargo version mirroring; the behavioral dependency review for exact receiver-side cancellation is documented on `d909619`. |

## Refresh Procedure

From the `lxmf-rs` workspace, read the reviewed baseline from `UPSTREAM.md`
rather than assuming that the upstream checkout's current branch points to it:

```bash
LXMF_UPSTREAM_DIR="$(sed -n '/^[[:space:]]*#/d; /^[[:space:]]*$/d; p; q' .local/lxmf-upstream.path)"
LXMF_REVIEWED_BASELINE="$(sed -n 's/^- Commit: `\([0-9a-f]\{40\}\)`$/\1/p' UPSTREAM.md)"
test -n "$LXMF_UPSTREAM_DIR"
test -n "$LXMF_REVIEWED_BASELINE"
git -C "$LXMF_UPSTREAM_DIR" fetch origin --prune
git -C "$LXMF_UPSTREAM_DIR" log --oneline --reverse "$LXMF_REVIEWED_BASELINE..origin/master"
```

For each new commit:

1. Inspect the diff with `git show --stat <commit>` and `git show <commit>`.
2. Add a row under "Open Upstream Commits" unless the commit is immediately
   closed as Python-only, docs-only, or already covered by Rust code.
3. When a Rust commit ports or closes an item, move it to "Recently Reviewed
   And Closed" and record the Rust commit hash or no-op reason.
4. Advance "Last reviewed Rust-port upstream point" only after every commit up
   to that upstream hash is either ported or explicitly closed. Update the
   current reference baseline in `UPSTREAM.md` in the same change.
