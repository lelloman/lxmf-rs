# Upstream LXMF Backlog

Tracks upstream Python LXMF commits that have appeared after the Rust port's
last reviewed upstream point and have not yet been integrated or explicitly
closed out.

## Current State

- Last checked: 2026-07-23
- Upstream checkout: `/home/lelloman/LXMF`
- Upstream remote: `git@github.com:markqvist/LXMF.git`
- Upstream branch: `origin/master`
- Current upstream head: `795fdaa2b0777c13033787d933d1afc94a2377cb`
- Last reviewed Rust-port upstream point:
  `fab12ad9bf9f997797034950f289fe41a79dcf5a`
- Rust branch at latest review: `dev`
- Rust head at latest review:
  `4a6dc6f954b5d58d45fe89860d22cda815980cda`

The local upstream worktree branch `master` remains at the last reviewed
baseline. The remote `origin/master` was checked at `795fdaa` during the
2026-07-23 review pass.

## Open Upstream Commits

The following commits after `fab12ad` remain to be ported or explicitly closed:

| Upstream commit | Subject |
| --- | --- |
| `548be10` | Added transient ID processing locks |
| `4a93697` | Fixed PN peer offer preparation minimum stamp cost |
| `982c9fc` | Early sync completion for empty filtered offers |
| `ca02fa5` | Added `lxmd` configuration and peer-name sanitization |
| `241b29c` | Added bounded/sequential inbound PN sync processing |
| `3e2cd36` | Updated version |
| `5769d46` | Improved resource logging and safer delivery limit |
| `d909619` | Added inbound resource tracking and cancellation |
| `7bb4bcf` | Updated stamp-cost logging |
| `795fdaa` | Updated versions |

## Recently Reviewed And Closed

These upstream commits are not open backlog items because they were already
ported, tracked as no-op metadata, or judged Python/tooling-specific in the
2026-05-24 and 2026-05-29 review passes.

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

## Refresh Procedure

From the upstream checkout:

```bash
cd ~/LXMF
git fetch origin --prune
git log --oneline --reverse fab12ad9bf9f997797034950f289fe41a79dcf5a..origin/master
```

For each new commit:

1. Inspect the diff with `git show --stat <commit>` and `git show <commit>`.
2. Add a row under "Open Upstream Commits" unless the commit is immediately
   closed as Python-only, docs-only, or already covered by Rust code.
3. When a Rust commit ports or closes an item, move it to "Recently Reviewed
   And Closed" and record the Rust commit hash or no-op reason.
4. Advance "Last reviewed Rust-port upstream point" only after every commit up
   to that upstream hash is either ported or explicitly closed.
