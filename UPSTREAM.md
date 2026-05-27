# Upstream Tracking

This repository is a Rust implementation of the Python LXMF project.

The current upstream reference baseline is:

- Project: LXMF
- Repository: `git@github.com:markqvist/LXMF.git`
- Local checkout used: `~/LXMF`
- Branch: `origin/master`
- Commit: `b53a3ce37dc8b385dd04005f6dfca314ed8c9ed5`
- Describe: `0.9.8-9-gb53a3ce`
- Commit date: `2026-05-24 23:16:15 +0200`
- Subject: `Clarified FIELD_THREAD`

The previous baseline was `8499729024a4cddfceb47ca07188bb5b1d11d179`
(`0.9.6`). The upstream range
`8499729024a4cddfceb47ca07188bb5b1d11d179..b53a3ce37dc8b385dd04005f6dfca314ed8c9ed5`
contains 22 commits and has been reviewed. Applicable behavior has been ported,
and non-applicable Python packaging, Makefile, and upstream README changes have
been explicitly closed out. The first `0.9.6..0.9.8` segment was reviewed and
ported with the following local commits:

- `343ef15` Track LXMF upstream 727830c
- `4fd6824` Track LXMF upstream 4ecbdb3
- `0496309` Track LXMF upstream 9d413c0
- `b427451` Track LXMF upstream ad616fc
- `54dbb15` Track LXMF upstream f9967db
- `9e5e2ad` Port LXMF propagated send precondition
- `fb38fa3` Track LXMF upstream 25b7fcf
- `b9df9a9` Port LXMF display name normalization
- `a38330a` Track LXMF upstream 2c4dfdd
- `261f2cb` Track LXMF upstream 6a00d82
- `6fd4e57` Port LXMF propagation announce wakeup
- `3cce4fd` Cover LXMF stamper cancellation lifecycle

Additional upstream commits after `7b0e7028321180a03713c5e71a34cb0d8ef99d13`
were reviewed as follows:

- `29c7917` and `b415a13`: Python Makefile release/upload tooling; no Rust
  port action.
- `7f0e262`, `d6ec051`, and `1bef747`: ported by Rust commit
  `91d2cbeaea3a3c712d0eba5639adb9688e17603c` as atomic propagation-store
  writes.
- `84613f8` and `dffbf4d`: Python version and RNS dependency metadata; kept as
  dependency-parity context, no direct Rust code change.
- `764758d`: ported by adding reply, reaction, comment, and continuation field
  constants plus dict indices to `lxmf-core/src/constants.rs`.
- `b53a3ce`: ported as the `FIELD_THREAD` documentation clarification in
  `lxmf-core/src/constants.rs`.

The constants port is covered by
`test_message_field_constants_match_upstream` and
`test_interaction_field_dict_indices_match_upstream` in
`lxmf-core/tests/interop.rs`.

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

The current upstream Python LXMF post-`0.9.8` head requires `rns>=1.3.0`. The
Rust dependency baseline above uses the corresponding latest published `rns-rs`
crates; treat Python RNS dependency bumps as dependency-parity review input,
not as direct Cargo version edits.

When integrating upstream changes, compare this commit against the new LXMF
upstream commit, update protocol constants, message formats, propagation
behavior, fixtures, and compatibility tests as needed, then update this file to
the new baseline commit.
