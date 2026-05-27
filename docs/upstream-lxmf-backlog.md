# Upstream LXMF Backlog

Tracks upstream Python LXMF commits that have appeared after the Rust port's
last reviewed upstream point and have not yet been integrated or explicitly
closed out.

## Current State

- Last checked: 2026-05-26
- Upstream checkout: `/home/lelloman/LXMF`
- Upstream remote: `git@github.com:markqvist/LXMF.git`
- Upstream branch: `origin/master`
- Current upstream head: `b53a3ce37dc8b385dd04005f6dfca314ed8c9ed5`
- Last reviewed Rust-port upstream point:
  `b53a3ce37dc8b385dd04005f6dfca314ed8c9ed5`
- Rust branch at latest review: `dev`
- Rust head at latest review:
  `b90f6d05bd2812139a616327f363735294127ac4`

The local upstream worktree branch `master` may be behind `origin/master`; use
`origin/master` as the source of truth for this tracker.

## Open Upstream Commits

None. The upstream range
`8499729024a4cddfceb47ca07188bb5b1d11d179..b53a3ce37dc8b385dd04005f6dfca314ed8c9ed5`
contains 22 commits; every commit in that range is now either ported, covered by
tests, or explicitly closed as non-applicable to the Rust port.

## Recently Reviewed And Closed

These upstream commits are not open backlog items because they were already
ported, tracked as no-op metadata, or judged Python/tooling-specific in the
2026-05-24 review pass.

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
| `7f0e262`, `d6ec051`, `1bef747` | Ported by Rust commit `91d2cbeaea3a3c712d0eba5639adb9688e17603c` as atomic propagation-store writes. |
| `764758d` | Ported in this pass by adding reply/reaction/comment/continuation field constants and dict indices to `lxmf-core/src/constants.rs`; covered by `test_message_field_constants_match_upstream` and `test_interaction_field_dict_indices_match_upstream`. |
| `b53a3ce` | Ported in this pass as the `FIELD_THREAD` doc comment in `lxmf-core/src/constants.rs`; covered by `test_message_field_constants_match_upstream` for the unchanged field value. |

## Refresh Procedure

From the upstream checkout:

```bash
cd ~/LXMF
git fetch origin --prune
git log --oneline --reverse b53a3ce37dc8b385dd04005f6dfca314ed8c9ed5..origin/master
```

For each new commit:

1. Inspect the diff with `git show --stat <commit>` and `git show <commit>`.
2. Add a row under "Open Upstream Commits" unless the commit is immediately
   closed as Python-only, docs-only, or already covered by Rust code.
3. When a Rust commit ports or closes an item, move it to "Recently Reviewed
   And Closed" and record the Rust commit hash or no-op reason.
4. Advance "Last reviewed Rust-port upstream point" only after every commit up
   to that upstream hash is either ported or explicitly closed.
