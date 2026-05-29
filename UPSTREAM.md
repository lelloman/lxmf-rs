# Upstream Tracking

This repository is a Rust implementation of the Python LXMF project.

The current upstream reference baseline is:

- Project: LXMF
- Repository: `git@github.com:markqvist/LXMF.git`
- Local checkout used: `~/LXMF`
- Branch: `origin/master`
- Commit: `5be161cb1e50e99925f20852324dc3c82a3c0cd1`
- Describe: `0.9.8-17-g5be161c`
- Commit date: `2026-05-28T08:44:22-04:00`
- Subject: `Prevent message write race among different processes touching the same message`

The previous baseline was `8499729024a4cddfceb47ca07188bb5b1d11d179`
(`0.9.6`). The upstream range
`8499729024a4cddfceb47ca07188bb5b1d11d179..5be161cb1e50e99925f20852324dc3c82a3c0cd1`
contains 30 commits and has been reviewed. Applicable behavior has been ported,
and non-applicable Python packaging, Makefile, and upstream README changes have
been explicitly closed out. The first `0.9.6..0.9.8` segment was reviewed and
ported with the following local commits:

- `1a6b87c` Track LXMF upstream 727830c
- `db814ee` Track LXMF upstream 4ecbdb3
- `3eeebe1` Track LXMF upstream 9d413c0
- `337bc8c` Track LXMF upstream ad616fc
- `c90d1e6` Track LXMF upstream f9967db
- `d965900` Port LXMF propagated send precondition
- `1cb921d` Track LXMF upstream 25b7fcf
- `0bf2bce` Port LXMF display name normalization
- `a4cdee2` Track LXMF upstream 2c4dfdd
- `7e6598b` Track LXMF upstream 6a00d82
- `fe449e4` Port LXMF propagation announce wakeup
- `fd9cd7d` Cover LXMF stamper cancellation lifecycle
- `794cab7` Track LXMF upstream 0.9.8

Additional upstream commits after `7b0e7028321180a03713c5e71a34cb0d8ef99d13`
were reviewed as follows:

- `29c7917` and `b415a13`: Python Makefile release/upload tooling; no Rust
  port action.
- `7f0e262`, `d6ec051`, and `1bef747`: ported by Rust commit
  `97db2b2a4a12e89a89fe64986878b533a8516170` as atomic propagation-store
  writes.
- `84613f8` and `dffbf4d`: Python version and RNS dependency metadata; kept as
  dependency-parity context, no direct Rust code change.
- `764758d`: ported by Rust commit
  `7950c58d1e20221c825d76a2e953c808b6a15bce`, adding reply, reaction,
  comment, and continuation field constants plus dict indices to
  `lxmf-core/src/constants.rs`.
- `b53a3ce`: ported as the `FIELD_THREAD` documentation clarification in
  `lxmf-core/src/constants.rs`.
- `55620bf`: Python `lxmd.py` config-path typo fix; not applicable to the Rust
  `lxmd` config path implementation.
- `599406e`: ported by Rust commit
  `8b98355f7bad2eab36567b87b8367ba009f0a8b1`, adding compression support
  signalling to delivery announce app-data.
- `2ac2b10`: ported by Rust commit
  `4a6dc6f954b5d58d45fe89860d22cda815980cda`, dropping inbound LXMs from
  blackholed source identities before delivery processing.
- `575fb7d` and `5be161c`: Python `LXMessage.write_to_directory` race fixes.
  Rust propagation-store atomic writes are already ported and tested; there is
  no direct Rust `LXMessage.write_to_directory` persistence API at this point.
- `312e0a8`, `044f3d2`, and `bf924c7`: Python version/dependency metadata and
  comment cleanup; no direct Rust-port action.

The constants port is covered by
`test_message_field_constants_match_upstream` and
`test_interaction_field_dict_indices_match_upstream` in
`lxmf-core/tests/interop.rs`.

The post-`b53a3ce` behavior ports are covered by
`delivery_announce_data_signals_compression_support` in `lxmf/src/router.rs`
and `blackholed_source_is_dropped_before_delivery_callback` in
`lxmf/tests/router_tests.rs`.

## RNS Dependency Baseline

`lxmf-rs` depends on published Rust Reticulum crates from crates.io:

- `rns-crypto` `=0.1.7`
- `rns-core` `=0.1.12`
- `rns-net` `=0.5.9`

The corresponding `rns-rs` integration baseline is:

- Repository: `git@github.com:lelloman/rns-rs.git`
- Branch used for integration work: `dev`
- GitHub release tag commit: `869a4bc2354329bf4ea480b1c27efcbef605a722`

When updating RNS integration, publish the required `rns-rs` crates, update the
exact versions in `Cargo.toml`, and record the release commit here.

The current upstream Python LXMF post-`0.9.8` head requires `rns>=1.3.2`. The
Rust dependency baseline above uses the corresponding latest published `rns-rs`
crates; treat Python RNS dependency bumps as dependency-parity review input,
not as direct Cargo version edits.

When integrating upstream changes, compare this commit against the new LXMF
upstream commit, update protocol constants, message formats, propagation
behavior, fixtures, and compatibility tests as needed, then update this file to
the new baseline commit.
