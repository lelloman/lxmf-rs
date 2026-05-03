# Upstream Tracking

This repository is a Rust implementation of the Python LXMF project.

The current upstream reference baseline is:

- Project: LXMF
- Repository: `git@github.com:markqvist/LXMF.git`
- Local checkout used: `~/LXMF`
- Branch: `master`
- Commit: `8499729024a4cddfceb47ca07188bb5b1d11d179`
- Describe: `0.9.6`
- Commit date: `2026-04-22 13:40:02 +0200`
- Subject: `Updated versions`

The previous baseline was `269ce43afc6552e934c212887c2450718311396a`
(`0.9.4-1-g269ce43`). The upstream range
`269ce43afc6552e934c212887c2450718311396a..8499729024a4cddfceb47ca07188bb5b1d11d179`
has been reviewed and ported with the following local commits:

- `76eabb2` Port LXMF compression announce signalling
- `968836c` Retain delivery destination data
- `fbb5109` Honor peer resource compression support
- `a9781a8` Dispatch inbound delivery off callback path

The resource compression support required an `rns-rs` prerequisite that is
included in the crates.io releases listed below.

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

When integrating upstream changes, compare this commit against the new LXMF
upstream commit, update protocol constants, message formats, propagation
behavior, fixtures, and compatibility tests as needed, then update this file to
the new baseline commit.
