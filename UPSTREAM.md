# Upstream Tracking

This repository is a Rust implementation of the Python LXMF project.

The current upstream reference baseline is:

- Project: LXMF
- Repository: `git@github.com:markqvist/LXMF.git`
- Local checkout used: `~/LXMF`
- Branch: `master`
- Commit: `7b0e7028321180a03713c5e71a34cb0d8ef99d13`
- Describe: `0.9.8`
- Commit date: `2026-05-10 17:20:26 +0200`
- Subject: `Updated versions`

The previous baseline was `8499729024a4cddfceb47ca07188bb5b1d11d179`
(`0.9.6`). The upstream range
`8499729024a4cddfceb47ca07188bb5b1d11d179..7b0e7028321180a03713c5e71a34cb0d8ef99d13`
has been reviewed and ported with the following local commits:

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

The final upstream commit `7b0e7028321180a03713c5e71a34cb0d8ef99d13` only
raises the Python `rns` package requirement from `>=1.2.4` to `>=1.2.5`.

## RNS Dependency Baseline

`lxmf-rs` depends on published Rust Reticulum crates from crates.io:

- `rns-crypto` `=0.1.6`
- `rns-core` `=0.1.11`
- `rns-net` `=0.5.8`

The corresponding `rns-rs` integration baseline is:

- Repository: `git@github.com:lelloman/rns-rs.git`
- Branch used for integration work: `dev`
- GitHub release tag commit: `fd2a29258362d5a8371428af52925498bce7cf67`

When updating RNS integration, publish the required `rns-rs` crates, update the
exact versions in `Cargo.toml`, and record the release commit here.

The Python LXMF `0.9.8` package requires `rns>=1.2.5`. The Rust dependency
baseline above is unchanged in this port series and should be re-evaluated when
the corresponding `rns-rs` releases are available.

When integrating upstream changes, compare this commit against the new LXMF
upstream commit, update protocol constants, message formats, propagation
behavior, fixtures, and compatibility tests as needed, then update this file to
the new baseline commit.
